# SPDX-License-Identifier: Apache-2.0
"""Worker admission-service failure paths before jailer launch."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from sova.formats import FormatError, canonical_json_bytes, sha256_digest
from sova.worker.brokers import SecretBroker
from sova.worker.cas import ContentAddressedStore
from sova.worker.contracts import assess_worker_attestation
from sova.worker.firecracker import FirecrackerHostPolicy, WorkerCleanupReceipt
from sova.worker.identity import IdentitySlotLeaseTable
from sova.worker.network_plane import NetworkPlaneHostPolicy, NetworkPlaneReceipt
from sova.worker.protocol import (
    ProtocolMessage,
    ProtocolMessageType,
    ProtocolRole,
    certificate_digest,
    sign_protocol_message,
)
from sova.worker.service import WorkerAdmissionService
from tests.support.worker import (
    digest,
    guest_keypair,
    unprivileged_lease_root,
    worker_attestation,
    worker_manifest,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sova.trace.integrity import Ed25519Keypair
    from sova.worker.contracts import WorkerAdmission, WorkerJobManifest

NOW = datetime(2026, 8, 27, 10, 0, 30, tzinfo=UTC)
CERTIFICATE = b"controller-certificate"


@dataclass(frozen=True, slots=True)
class _Context:
    guest: Ed25519Keypair
    controller: Ed25519Keypair
    store: ContentAddressedStore
    manifest: WorkerJobManifest
    raw: bytes
    policy: FirecrackerHostPolicy
    admission: WorkerAdmission
    service: WorkerAdmissionService


def _context(tmp_path: Path, *, allow_nonproduction: bool = True) -> _Context:
    guest = guest_keypair()
    controller = guest_keypair()
    store = ContentAddressedStore((tmp_path / "cas").resolve())
    manifest = replace(
        worker_manifest(guest),
        guest_kernel=store.put(
            name="guest-kernel", media_type="application/octet-stream", data=b"kernel"
        ),
        root_filesystem=store.put(
            name="root-filesystem", media_type="application/octet-stream", data=b"rootfs"
        ),
        writable_layer_seed=store.put(
            name="writable-seed", media_type="application/octet-stream", data=b"writable"
        ),
        inputs=(store.put(name="target-input", media_type="application/zip", data=b"input"),),
    )
    raw = canonical_json_bytes(manifest.to_mapping())
    policy = FirecrackerHostPolicy(
        firecracker_binary=tmp_path / "bin" / "firecracker",
        jailer_binary=tmp_path / "bin" / "jailer",
        chroot_base=tmp_path / "jailer",
        network_namespace_base=tmp_path / "netns",
        content_store=store.root,
        cgroup_base=tmp_path / "cgroup",
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )
    admission = assess_worker_attestation(
        worker_attestation(),
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    service = WorkerAdmissionService(
        worker_id="worker:primary",
        controller_id="controller:primary",
        controller_public_key=controller.public_key,
        content_store=store,
        host_policy=policy,
        worker_admission=admission,
        allow_nonproduction=allow_nonproduction,
    )
    return _Context(guest, controller, store, manifest, raw, policy, admission, service)


def _network_policy(tmp_path: Path) -> NetworkPlaneHostPolicy:
    return NetworkPlaneHostPolicy(
        ip_binary=(tmp_path / "bin" / "ip").resolve(),
        nft_binary=(tmp_path / "bin" / "nft").resolve(),
        setpriv_binary=(tmp_path / "bin" / "setpriv").resolve(),
        mediator_binary=(tmp_path / "bin" / "sova-network-mediator").resolve(),
        state_directory=(tmp_path / "network-state").resolve(),
        approved_ip_digest=digest("ip"),
        approved_nft_digest=digest("nft"),
        approved_setpriv_digest=digest("setpriv"),
        approved_mediator_digest=digest("mediator"),
        egress_interface="eth0",
        mediator_uid_base=700_000,
        mediator_gid_base=700_000,
    )


def _message(
    raw: bytes,
    *,
    message_id: str = "message:service",
    nonce: str = "ABCDEFGHIJKLMNOPQRSTUV",
    message_type: ProtocolMessageType = ProtocolMessageType.SUBMIT_JOB,
    job_id: str = "job:p5-fixture",
) -> ProtocolMessage:
    return ProtocolMessage(
        message_type=message_type,
        message_id=message_id,
        job_id=job_id,
        sender_role=ProtocolRole.CONTROLLER,
        sender_id="controller:primary",
        recipient_id="worker:primary",
        issued_at="2026-08-27T10:00:00Z",
        expires_at="2026-08-27T10:01:00Z",
        nonce=nonce,
        sender_certificate_digest=certificate_digest(CERTIFICATE),
        payload_digest=sha256_digest(raw),
    )


def test_service_rejects_nonproduction_without_explicit_development_mode(tmp_path: Path) -> None:
    context = _context(tmp_path, allow_nonproduction=False)
    with pytest.raises(FormatError, match="production admission"):
        context.service.admit_signed_job(
            envelope=sign_protocol_message(_message(context.raw), context.controller),
            peer_certificate_der=CERTIFICATE,
            raw_manifest=context.raw,
            now=NOW,
            identity_slot=1,
        )


def test_service_rejects_cancel_message_payload_and_job_drift(tmp_path: Path) -> None:
    context = _context(tmp_path)
    cancel = _message(context.raw, message_type=ProtocolMessageType.CANCEL_JOB)
    with pytest.raises(FormatError, match="not a job submission"):
        context.service.admit_signed_job(
            envelope=sign_protocol_message(cancel, context.controller),
            peer_certificate_der=CERTIFICATE,
            raw_manifest=context.raw,
            now=NOW,
            identity_slot=1,
        )
    context.service.replay_cache._entries.clear()
    wrong_payload = replace(
        _message(context.raw, message_id="message:payload", nonce="ZYXWVUTSRQPONMLKJIHGFE"),
        payload_digest=digest("wrong"),
    )
    with pytest.raises(FormatError, match="payload digest"):
        context.service.admit_signed_job(
            envelope=sign_protocol_message(wrong_payload, context.controller),
            peer_certificate_der=CERTIFICATE,
            raw_manifest=context.raw,
            now=NOW,
            identity_slot=1,
        )
    changed = replace(context.manifest, job_id="job:other")
    changed_raw = canonical_json_bytes(changed.to_mapping())
    wrong_job = _message(
        changed_raw,
        message_id="message:job",
        nonce="1234567890123456789012",
        job_id=context.manifest.job_id,
    )
    with pytest.raises(FormatError, match="job differ"):
        context.service.admit_signed_job(
            envelope=sign_protocol_message(wrong_job, context.controller),
            peer_certificate_der=CERTIFICATE,
            raw_manifest=changed_raw,
            now=NOW,
            identity_slot=1,
        )


def test_service_rejects_unbound_content_and_mismatched_store(tmp_path: Path) -> None:
    context = _context(tmp_path)
    another_store = ContentAddressedStore((tmp_path / "other-cas").resolve())
    with pytest.raises(FormatError, match="same content store"):
        WorkerAdmissionService(
            worker_id="worker:primary",
            controller_id="controller:primary",
            controller_public_key=context.controller.public_key,
            content_store=another_store,
            host_policy=context.policy,
            worker_admission=context.admission,
        )
    missing_manifest = worker_manifest(context.guest)
    raw = canonical_json_bytes(missing_manifest.to_mapping())
    with pytest.raises(FormatError, match="CAS object"):
        context.service.admit_signed_job(
            envelope=sign_protocol_message(_message(raw), context.controller),
            peer_certificate_der=CERTIFICATE,
            raw_manifest=raw,
            now=NOW,
            identity_slot=1,
        )
    assert context.store.root == context.policy.content_store


def test_service_reconstructs_plan_before_lifecycle_execution(tmp_path: Path) -> None:
    context = _context(tmp_path)
    admitted = context.service.admit_signed_job(
        envelope=sign_protocol_message(_message(context.raw), context.controller),
        peer_certificate_der=CERTIFICATE,
        raw_manifest=context.raw,
        now=NOW,
        identity_slot=4,
    )
    backend = Mock()
    backend.live_execution = False
    backend.launch.return_value = 0
    backend.wait_for_api_socket.return_value = True
    backend.wait_for_process_id.return_value = 4242
    backend.put_api.return_value = 204
    backend.wait_for_process.return_value = 0
    backend.cleanup.side_effect = lambda plan, completed_at, secret_broker_revoked: (
        WorkerCleanupReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            completed_at=completed_at,
            process_terminated=True,
            api_socket_removed=True,
            cgroup_removed=True,
            network_namespace_removed=True,
            chroot_removed=True,
            writable_layer_removed=True,
            secret_broker_revoked=secret_broker_revoked,
        )
    )
    result = context.service.execute_admitted_job(
        admitted,
        backend=backend,
        secret_broker=SecretBroker(admitted.manifest),
    )
    assert result.execution.execution_status == "process-exited"
    assert result.cleanup.complete is True
    backend.prepare.assert_called_once_with(admitted.launch_plan)

    with pytest.raises(FormatError, match="secret broker"):
        context.service.execute_admitted_job(
            admitted,
            backend=backend,
            secret_broker=SecretBroker(replace(admitted.manifest, job_id="job:other")),
        )
    drifted = replace(admitted, launch_plan=replace(admitted.launch_plan, watchdog_seconds=1))
    with pytest.raises(FormatError, match="launch plan"):
        context.service.execute_admitted_job(
            drifted,
            backend=backend,
            secret_broker=SecretBroker(admitted.manifest),
        )

    backend.live_execution = True
    with pytest.raises(FormatError, match="compiled network-plane"):
        context.service.execute_admitted_job(
            admitted,
            backend=backend,
            secret_broker=SecretBroker(admitted.manifest),
        )


def test_service_rejects_live_execution_without_post_cleanup_network_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    context.service.network_policy = _network_policy(tmp_path)
    lease_root = (tmp_path / "identity-leases").resolve()
    lease_root.mkdir()
    context.service.identity_leases = IdentitySlotLeaseTable(
        unprivileged_lease_root(lease_root, monkeypatch)
    )
    admitted = context.service.admit_signed_job(
        envelope=sign_protocol_message(_message(context.raw), context.controller),
        peer_certificate_der=CERTIFICATE,
        raw_manifest=context.raw,
        now=NOW,
        identity_slot=5,
    )
    assert admitted.network_plan is not None
    backend = Mock()
    backend.live_execution = True
    backend.network_evidence.return_value = (admitted.network_plan.digest, None)
    backend.launch.return_value = 0
    backend.wait_for_api_socket.return_value = True
    backend.wait_for_process_id.return_value = 4242
    backend.put_api.return_value = 204
    backend.wait_for_process.return_value = 0
    backend.cleanup.side_effect = lambda plan, completed_at, secret_broker_revoked: (
        WorkerCleanupReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            completed_at=completed_at,
            process_terminated=True,
            api_socket_removed=True,
            cgroup_removed=True,
            network_namespace_removed=True,
            chroot_removed=True,
            writable_layer_removed=True,
            secret_broker_revoked=secret_broker_revoked,
        )
    )
    with pytest.raises(FormatError, match="did not emit"):
        context.service.execute_admitted_job(
            admitted,
            backend=backend,
            secret_broker=SecretBroker(admitted.manifest),
        )
    assert (lease_root / "000005.lease").is_file()


def test_service_releases_identity_slot_only_after_complete_live_network_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    context.service.network_policy = _network_policy(tmp_path)
    lease_root = (tmp_path / "identity-leases").resolve()
    lease_root.mkdir()
    context.service.identity_leases = IdentitySlotLeaseTable(
        unprivileged_lease_root(lease_root, monkeypatch)
    )
    admitted = context.service.admit_signed_job(
        envelope=sign_protocol_message(_message(context.raw), context.controller),
        peer_certificate_der=CERTIFICATE,
        raw_manifest=context.raw,
        now=NOW,
        identity_slot=6,
    )
    assert admitted.network_plan is not None
    network_receipt = NetworkPlaneReceipt(
        job_id=admitted.manifest.job_id,
        vm_id=admitted.launch_plan.vm_id,
        plan_digest=admitted.network_plan.digest,
        completed_at="2026-08-27T10:00:30Z",
        enabled=True,
        namespace_created=True,
        firewall_loaded=True,
        mediator_started=True,
        mediator_process_id=4243,
        mediator_receipt_set_digest=digest("network-receipt-set"),
        mediator_terminated=True,
        host_rules_removed=True,
        root_veth_removed=True,
        namespace_removed=True,
        state_removed=True,
        failure_code=None,
    )
    network_digest = network_receipt.to_mapping()["contentDigest"]
    backend = Mock()
    backend.live_execution = True
    backend.network_evidence.side_effect = (
        (admitted.network_plan.digest, None),
        (admitted.network_plan.digest, network_digest),
    )
    backend.network_receipt.return_value = network_receipt
    backend.launch.return_value = 0
    backend.wait_for_api_socket.return_value = True
    backend.wait_for_process_id.return_value = 4242
    backend.put_api.return_value = 204
    backend.wait_for_process.return_value = 0
    backend.cleanup.side_effect = lambda plan, completed_at, secret_broker_revoked: (
        WorkerCleanupReceipt(
            job_id=plan.job_id,
            vm_id=plan.vm_id,
            completed_at=completed_at,
            process_terminated=True,
            api_socket_removed=True,
            cgroup_removed=True,
            network_namespace_removed=True,
            chroot_removed=True,
            writable_layer_removed=True,
            secret_broker_revoked=secret_broker_revoked,
        )
    )
    result = context.service.execute_admitted_job(
        admitted,
        backend=backend,
        secret_broker=SecretBroker(admitted.manifest),
    )
    assert result.network == network_receipt
    assert not (lease_root / "000006.lease").exists()
