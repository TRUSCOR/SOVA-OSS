# SPDX-License-Identifier: Apache-2.0
"""P5 vertical slice from signed controller job to immutable microVM launch plan."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.worker.cas import ContentAddressedStore
from sova.worker.contracts import assess_worker_attestation
from sova.worker.firecracker import FirecrackerHostPolicy
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
    host_path,
    worker_attestation,
    worker_manifest,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_signed_job_is_peer_bound_cas_verified_and_compiled(tmp_path: Path) -> None:
    guest = guest_keypair()
    controller = guest_keypair()
    store = ContentAddressedStore((tmp_path / "cas").resolve())
    kernel = store.put(name="guest-kernel", media_type="application/octet-stream", data=b"kernel")
    rootfs = store.put(
        name="root-filesystem", media_type="application/octet-stream", data=b"rootfs"
    )
    writable = store.put(
        name="writable-seed", media_type="application/octet-stream", data=b"writable"
    )
    target_input = store.put(name="target-input", media_type="application/zip", data=b"input")
    manifest = replace(
        worker_manifest(guest),
        guest_kernel=kernel,
        root_filesystem=rootfs,
        writable_layer_seed=writable,
        inputs=(target_input,),
    )
    raw_manifest = canonical_json_bytes(manifest.to_mapping())
    peer_certificate = b"controller-certificate-der"
    message = ProtocolMessage(
        message_type=ProtocolMessageType.SUBMIT_JOB,
        message_id="message:p5-vertical",
        job_id=manifest.job_id,
        sender_role=ProtocolRole.CONTROLLER,
        sender_id="controller:primary",
        recipient_id="worker:primary",
        issued_at="2026-08-27T10:00:00Z",
        expires_at="2026-08-27T10:01:00Z",
        nonce="ABCDEFGHIJKLMNOPQRSTUV",
        sender_certificate_digest=certificate_digest(peer_certificate),
        payload_digest=sha256_digest(raw_manifest),
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
        host_policy=FirecrackerHostPolicy(
            firecracker_binary=host_path("sova-worker", "bin", "firecracker"),
            jailer_binary=host_path("sova-worker", "bin", "jailer"),
            chroot_base=host_path("sova-worker", "jailer"),
            network_namespace_base=host_path("sova-worker", "netns"),
            content_store=store.root,
            cgroup_base=host_path("sova-worker", "cgroup"),
            approved_firecracker_digest=digest("firecracker"),
            approved_jailer_digest=digest("jailer"),
        ),
        worker_admission=admission,
        allow_nonproduction=True,
    )
    accepted = service.admit_signed_job(
        envelope=sign_protocol_message(message, controller),
        peer_certificate_der=peer_certificate,
        raw_manifest=raw_manifest,
        now=datetime(2026, 8, 27, 10, 0, 30, tzinfo=UTC),
        identity_slot=42,
    )
    validate_document(accepted.manifest.to_mapping())
    validate_document(accepted.launch_plan.to_mapping())
    assert accepted.launch_plan.identity_slot == 42
    assert accepted.to_mapping()["productionIsolationClaimAllowed"] is False
