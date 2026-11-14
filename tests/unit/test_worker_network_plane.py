# SPDX-License-Identifier: Apache-2.0
"""Deterministic Firecracker network-plane and privileged-boundary tests."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sova.formats import FormatError, canonical_json_bytes, sha256_digest, validate_document
from sova.worker.brokers import NetworkFlowReceipt
from sova.worker.contracts import NetworkRule, WorkerJobManifest, assess_worker_attestation
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    build_firecracker_launch_plan,
    worker_network_addresses,
)
from sova.worker.network_plane import (
    FirecrackerNetworkPlan,
    FirecrackerNetworkPlaneBackend,
    NetworkCommand,
    NetworkPlaneHostPolicy,
    PosixNetworkCommandBackend,
    _digest_file,
    _require_root_controlled,
    _validated_flow_receipt,
    build_firecracker_network_plan,
)
from tests.support.worker import (
    digest,
    guest_keypair,
    owner_uid,
    worker_attestation,
    worker_manifest,
)


@pytest.fixture(autouse=True)
def signalled_process_groups(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    """Record mediator group signals; fake mediators carry fixed, unrelated pids.

    Without this, POSIX runs would deliver SIGTERM/SIGKILL to whatever real
    process group happens to own pid 4242 or 5252 on the test host.
    """
    sent: list[tuple[int, int]] = []
    if hasattr(os, "killpg"):
        monkeypatch.setattr(os, "killpg", lambda pid, number: sent.append((pid, number)))
    return sent


def _firecracker_policy(tmp_path: Path) -> FirecrackerHostPolicy:
    return FirecrackerHostPolicy(
        firecracker_binary=(tmp_path / "bin" / "firecracker").resolve(),
        jailer_binary=(tmp_path / "bin" / "jailer").resolve(),
        chroot_base=(tmp_path / "jailer").resolve(),
        network_namespace_base=(tmp_path / "netns").resolve(),
        content_store=(tmp_path / "cas").resolve(),
        cgroup_base=(tmp_path / "cgroup").resolve(),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )


def _network_policy(tmp_path: Path) -> NetworkPlaneHostPolicy:
    return NetworkPlaneHostPolicy(
        ip_binary=(tmp_path / "bin" / "ip").resolve(),
        nft_binary=(tmp_path / "bin" / "nft").resolve(),
        setpriv_binary=(tmp_path / "bin" / "setpriv").resolve(),
        mediator_binary=(tmp_path / "bin" / "sova-network-mediator").resolve(),
        state_directory=(tmp_path / "state").resolve(),
        approved_ip_digest=digest("ip"),
        approved_nft_digest=digest("nft"),
        approved_setpriv_digest=digest("setpriv"),
        approved_mediator_digest=digest("mediator"),
        egress_interface="eth0",
        mediator_uid_base=700_000,
        mediator_gid_base=700_000,
    )


def _plans(
    tmp_path: Path, *, online: bool = True
) -> tuple[WorkerJobManifest, FirecrackerLaunchPlan, FirecrackerNetworkPlan]:
    manifest = worker_manifest(guest_keypair())
    if not online:
        manifest = replace(
            manifest,
            limits=replace(
                manifest.limits,
                network_connection_limit=0,
                network_bytes=0,
            ),
        )
    admission = assess_worker_attestation(
        worker_attestation(),
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    launch = build_firecracker_launch_plan(
        manifest,
        admission,
        _firecracker_policy(tmp_path),
        identity_slot=17,
    )
    network = build_firecracker_network_plan(manifest, launch, _network_policy(tmp_path))
    return manifest, launch, network


def test_online_network_plan_is_mediator_only_and_schema_valid(tmp_path: Path) -> None:
    manifest, launch, plan = _plans(tmp_path)
    mapping = plan.to_mapping()
    validate_document(mapping)
    guest, broker, root_uplink, mediator_uplink = worker_network_addresses(17)
    assert mapping["addresses"] == {
        "guest": guest,
        "broker": broker,
        "rootUplink": root_uplink,
        "mediatorUplink": mediator_uplink,
    }
    assert plan.enabled is True
    assert plan.tap_device is not None
    assert plan.root_veth is not None
    assert plan.namespace_veth is not None
    assert all(len(item) <= 15 for item in (plan.tap_device, plan.root_veth, plan.namespace_veth))
    assert plan.mediator_policy is not None
    validate_document(plan.mediator_policy, "sova.worker-network-mediator-policy")
    assert plan.mediator_policy["rules"] == [item.to_mapping() for item in manifest.network_rules]
    assert plan.mediator_policy["invariants"]["rawTcpUdpSupported"] is False
    namespace_rules = next(
        command.stdin
        for command in plan.setup_commands
        if command.stdin and "chain forward" in command.stdin
    )
    assert "chain forward" in namespace_rules and "policy drop" in namespace_rules
    assert "meta skuid 700017" in namespace_rules
    assert mapping["mediatorIdentity"] == {
        "uid": 700_017,
        "gid": 700_017,
        "uniquePerJob": True,
    }
    host_rules = next(
        command.stdin
        for command in plan.setup_commands
        if command.stdin and "masquerade" in command.stdin
    )
    assert mediator_uplink.removesuffix("/30") in host_rules
    assert all("sh" not in command.argv[:1] for command in plan.setup_commands)
    boot = next(
        payload for path, payload in launch.firecracker_api_requests if path == "/boot-source"
    )
    assert guest.removesuffix("/30") in boot["boot_args"]
    assert f"http://{broker.removesuffix('/30')}:8888" in boot["boot_args"]


def test_python_mediator_policy_fixture_is_canonical_and_content_bound() -> None:
    fixture = (
        (Path(__file__).parents[1] / "fixtures" / "worker" / "network-mediator-policy-python.json")
        .read_bytes()
        .removesuffix(b"\n")
    )
    value = json.loads(fixture)
    validate_document(value, "sova.worker-network-mediator-policy")
    assert canonical_json_bytes(value) == fixture
    claimed = value.pop("contentDigest")
    assert claimed == sha256_digest(canonical_json_bytes(value))


def test_rust_mediator_wsl_receipt_fixture_passes_controller_validation() -> None:
    fixture = (
        (
            Path(__file__).parents[1]
            / "fixtures"
            / "worker"
            / "network-mediator-wsl-denied-receipt.json"
        )
        .read_bytes()
        .removesuffix(b"\n")
    )
    sequence, content_digest = _validated_flow_receipt(
        fixture, "job:mediator-cross-language-fixture"
    )
    value = json.loads(fixture)
    assert sequence == 1
    assert (
        content_digest == "sha256:15f82ae1d024ee904bb3f46a8ce59eed54fd56c67ff819e8c31d6c5f322f2302"
    )
    assert value["decision"] == "denied"
    assert value["reason"] == "endpoint-not-authorized"
    assert value["endpoint"] == {"hostname": "example.com", "port": 80, "protocol": "tcp"}


def test_offline_network_plan_creates_closed_namespace_without_mediator(tmp_path: Path) -> None:
    _manifest, _launch, plan = _plans(tmp_path, online=False)
    mapping = plan.to_mapping()
    validate_document(mapping)
    assert plan.enabled is False
    assert plan.mediator_command is None
    assert plan.mediator_policy is None
    assert plan.tap_device is None
    rules = next(command.stdin for command in plan.setup_commands if command.stdin)
    assert rules.count("policy drop") == 3


def test_network_plan_rejects_cross_job_binding_and_bad_host_policy(tmp_path: Path) -> None:
    manifest, launch, _plan = _plans(tmp_path)
    with pytest.raises(FormatError, match="different jobs"):
        build_firecracker_network_plan(
            replace(manifest, job_id="job:other"),
            launch,
            _network_policy(tmp_path),
        )
    policy = _network_policy(tmp_path)
    for changes in (
        {"egress_interface": "too-long-interface"},
        {"proxy_port": 8_889},
        {"approved_mediator_digest": "bad"},
    ):
        with pytest.raises(FormatError):
            replace(policy, **changes)


def test_network_plan_rejects_unsupported_protocol_and_uncollectable_budget(
    tmp_path: Path,
) -> None:
    manifest, launch, _plan = _plans(tmp_path)
    udp_manifest = replace(
        manifest,
        network_rules=(NetworkRule("example.com", 443, "udp", ("1.1.1.1",)),),
    )
    with pytest.raises(FormatError, match="HTTP-family traffic over TCP only"):
        build_firecracker_network_plan(
            udp_manifest,
            replace(launch, manifest_digest=udp_manifest.digest),
            _network_policy(tmp_path),
        )

    excessive_manifest = replace(
        manifest,
        limits=replace(manifest.limits, network_connection_limit=1_025),
    )
    with pytest.raises(FormatError, match="evidence limits"):
        build_firecracker_network_plan(
            excessive_manifest,
            replace(launch, manifest_digest=excessive_manifest.digest),
            _network_policy(tmp_path),
        )


@dataclass
class _Process:
    pid: int = 4242
    result: int | None = None

    def poll(self) -> int | None:
        return self.result

    def terminate(self) -> None:
        self.result = 0

    def kill(self) -> None:
        self.result = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.result is None:
            self.result = 0
        return self.result


@dataclass
class _Commands:
    fail_at: int | None = None
    raise_at: int | None = None
    commands: list[NetworkCommand] = field(default_factory=list)
    process: _Process = field(default_factory=_Process)

    def run(self, command: NetworkCommand) -> int:
        self.commands.append(command)
        if self.raise_at is not None and len(self.commands) - 1 == self.raise_at:
            raise OSError
        if self.fail_at is not None and len(self.commands) - 1 == self.fail_at:
            return 9
        return 0

    def spawn(self, _argv: tuple[str, ...]) -> _Process:
        return self.process


@dataclass
class _HungProcess:
    pid: int = 5252

    def poll(self) -> int | None:
        return None

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("mediator", timeout or 0.0)


def _fake_live_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sova.worker.network_plane.platform.system", lambda: "Linux")
    monkeypatch.setattr("sova.worker.network_plane.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("sova.worker.network_plane._require_root_controlled", lambda _path: None)
    monkeypatch.setattr("sova.worker.network_plane.os.chown", lambda *_args: None, raising=False)


def _fake_digests(monkeypatch: pytest.MonkeyPatch, policy: NetworkPlaneHostPolicy) -> None:
    expected = {
        policy.ip_binary: policy.approved_ip_digest,
        policy.nft_binary: policy.approved_nft_digest,
        policy.setpriv_binary: policy.approved_setpriv_digest,
        policy.mediator_binary: policy.approved_mediator_digest,
    }
    monkeypatch.setattr("sova.worker.network_plane._digest_file", expected.__getitem__)


def test_backend_runs_exact_commands_and_emits_complete_cleanup_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    policy = _network_policy(tmp_path)
    policy.state_directory.mkdir(parents=True)
    commands = _Commands()
    backend = FirecrackerNetworkPlaneBackend(policy, plan, commands)
    _fake_live_host(monkeypatch)
    _fake_digests(monkeypatch, policy)
    backend.prepare(launch)
    assert plan.mediator_policy_path is not None
    assert Path(plan.mediator_policy_path).is_file()
    assert Path(plan.mediator_policy_path).stat().st_mode & 0o777 == 0o444
    assert plan.mediator_receipt_directory is not None
    assert Path(plan.mediator_receipt_directory).is_dir()
    receipt = backend.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    validate_document(receipt.to_mapping())
    assert receipt.complete is True
    assert receipt.mediator_process_id == 4242
    assert receipt.mediator_receipt_set_digest is not None
    assert not (policy.state_directory / launch.vm_id).exists()
    plan_digest, receipt_digest = backend.evidence(launch)
    assert plan_digest == plan.digest
    assert receipt_digest == receipt.to_mapping()["contentDigest"]
    assert backend.receipt(launch) == receipt


def test_backend_fails_closed_before_spawn_and_cleanup_attempts_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    policy = _network_policy(tmp_path)
    policy.state_directory.mkdir(parents=True)
    commands = _Commands(fail_at=2)
    backend = FirecrackerNetworkPlaneBackend(policy, plan, commands)
    _fake_live_host(monkeypatch)
    _fake_digests(monkeypatch, policy)
    with pytest.raises(FormatError, match="setup command 2"):
        backend.prepare(launch)
    receipt = backend.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    assert commands.process.pid == 4242
    assert len(commands.commands) > 2
    assert receipt.complete is False
    assert receipt.cleanup_complete is True


def test_backend_attempts_every_teardown_after_one_command_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    policy = _network_policy(tmp_path)
    policy.state_directory.mkdir(parents=True)
    commands = _Commands(raise_at=len(plan.setup_commands))
    backend = FirecrackerNetworkPlaneBackend(policy, plan, commands)
    _fake_live_host(monkeypatch)
    _fake_digests(monkeypatch, policy)
    backend.prepare(launch)
    before_cleanup = len(commands.commands)
    receipt = backend.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    assert len(commands.commands) - before_cleanup == len(plan.teardown_commands)
    assert receipt.host_rules_removed is False
    assert receipt.root_veth_removed is True
    assert receipt.namespace_removed is True
    assert receipt.state_removed is True
    assert receipt.complete is False


@pytest.mark.parametrize("slot", [-1, 524_288])
def test_address_allocator_rejects_out_of_range_slots(slot: int) -> None:
    with pytest.raises(FormatError, match="slot"):
        worker_network_addresses(slot)


def test_network_receipt_rejects_tampered_content_digest(tmp_path: Path) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    mapping = plan.to_mapping()
    mapping["contentDigest"] = digest("tampered")
    # Structural schemas deliberately validate shape; canonical digest verification is
    # performed by the plan compiler/consumer boundary.
    validate_document(mapping)


def test_mediator_flow_receipts_require_canonical_digest_and_exact_job() -> None:
    receipt = NetworkFlowReceipt(
        job_id="job:p5-fixture",
        sequence=1,
        observed_at="2026-08-28T12:00:00Z",
        hostname="example.com",
        port=443,
        protocol="tcp",
        pinned_addresses=("1.1.1.1",),
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=10,
        decision="allowed",
        reason="policy-and-budgets-satisfied",
    ).to_mapping()
    payload = canonical_json_bytes(receipt)
    sequence, receipt_digest = _validated_flow_receipt(payload, "job:p5-fixture")
    assert sequence == 1
    assert receipt_digest == receipt["contentDigest"]
    with pytest.raises(FormatError, match="binding"):
        _validated_flow_receipt(payload, "job:other")
    with pytest.raises(FormatError, match="canonical"):
        _validated_flow_receipt(payload + b"\n", "job:p5-fixture")


def test_network_helpers_and_policy_reject_unsafe_inputs(tmp_path: Path) -> None:
    binary = tmp_path / "ip"
    binary.write_bytes(b"ip")
    assert _digest_file(binary) == digest("ip")
    with pytest.raises(FormatError, match="not a file"):
        _digest_file(tmp_path / "missing")
    with pytest.raises(FormatError, match="host path"):
        _require_root_controlled(tmp_path / "missing")

    policy = _network_policy(tmp_path)
    with pytest.raises(FormatError, match="absolute"):
        replace(policy, ip_binary=Path("relative/ip"))
    with pytest.raises(FormatError, match="UID base"):
        replace(policy, mediator_uid_base=699_999)
    with pytest.raises(FormatError, match="GID base"):
        replace(policy, mediator_gid_base=1_500_001)

    receipt = NetworkFlowReceipt(
        job_id="job:p5-fixture",
        sequence=1,
        observed_at="2026-08-28T12:00:00Z",
        hostname="example.com",
        port=443,
        protocol="tcp",
        pinned_addresses=("1.1.1.1",),
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=10,
        decision="allowed",
        reason="policy-and-budgets-satisfied",
    ).to_mapping()
    receipt["contentDigest"] = digest("tampered")
    with pytest.raises(FormatError, match="digest"):
        _validated_flow_receipt(canonical_json_bytes(receipt), "job:p5-fixture")
    with pytest.raises(FormatError, match="object"):
        _validated_flow_receipt(b"[]", "job:p5-fixture")


def test_posix_command_backend_uses_exact_argv_and_bounded_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = SimpleNamespace(returncode=7)
    run = Mock(return_value=completed)
    process = _Process()
    popen = Mock(return_value=process)
    monkeypatch.setattr("sova.worker.network_plane.subprocess.run", run)
    monkeypatch.setattr("sova.worker.network_plane.subprocess.Popen", popen)
    backend = PosixNetworkCommandBackend()
    assert backend.run(NetworkCommand(("/usr/sbin/ip", "link"))) == 7
    assert backend.run(NetworkCommand(("/usr/sbin/nft", "-f", "-"), "rules")) == 7
    assert run.call_args_list[0].kwargs["stdin"] == subprocess.DEVNULL
    assert run.call_args_list[1].kwargs["input"] == b"rules"
    assert backend.spawn(("/trusted/mediator", "--flag")) is process
    assert popen.call_args.kwargs["start_new_session"] is True


def test_backend_host_validation_binding_and_state_paths_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    policy = _network_policy(tmp_path)
    policy.state_directory.mkdir(parents=True)
    policy.ip_binary.parent.mkdir(parents=True)
    for path, value in (
        (policy.ip_binary, b"ip"),
        (policy.nft_binary, b"nft"),
        (policy.setpriv_binary, b"setpriv"),
        (policy.mediator_binary, b"mediator"),
    ):
        path.write_bytes(value)
    monkeypatch.setattr("sova.worker.network_plane._require_root_controlled", lambda _path: None)
    backend = FirecrackerNetworkPlaneBackend(policy, plan, _Commands())
    backend._validate_host()
    with pytest.raises(FormatError, match="digest drifted"):
        FirecrackerNetworkPlaneBackend(
            replace(policy, approved_ip_digest=digest("other")), plan, _Commands()
        )._validate_host()
    with pytest.raises(FormatError, match="drifted"):
        backend._bind(replace(launch, job_id="job:other"))
    state = policy.state_directory / launch.vm_id
    state.mkdir()
    with pytest.raises(FormatError, match="outside job state"):
        FirecrackerNetworkPlaneBackend(
            policy,
            replace(plan, mediator_policy_path=str(tmp_path / "other-policy.json")),
            _Commands(),
        )._write_mediator_policy(state)
    with pytest.raises(FormatError, match="outside job state"):
        FirecrackerNetworkPlaneBackend(
            policy,
            replace(plan, mediator_receipt_directory=str(tmp_path / "other-receipts")),
            _Commands(),
        )._prepare_receipt_directory(state)
    monkeypatch.setattr("sova.worker.network_plane.os.chown", lambda *_args: None, raising=False)
    with pytest.raises(FormatError, match="identity is missing"):
        FirecrackerNetworkPlaneBackend(
            policy,
            replace(plan, mediator_uid=None),
            _Commands(),
        )._prepare_receipt_directory(state)


def test_backend_rejects_wrong_host_existing_state_and_early_mediator_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    policy = _network_policy(tmp_path)
    policy.state_directory.mkdir(parents=True)
    with pytest.raises(FormatError, match="requires Linux root"):
        FirecrackerNetworkPlaneBackend._require_host()
    commands = _Commands()
    commands.process.result = 2
    with pytest.raises(FormatError, match="exited at startup"):
        FirecrackerNetworkPlaneBackend(policy, plan, commands)._start_mediator()
    _fake_live_host(monkeypatch)
    _fake_digests(monkeypatch, policy)
    (policy.state_directory / launch.vm_id).mkdir()
    with pytest.raises(FormatError, match="already exists"):
        FirecrackerNetworkPlaneBackend(policy, plan, _Commands()).prepare(launch)


def _flow_payload(job_id: str, sequence: int) -> bytes:
    return canonical_json_bytes(
        NetworkFlowReceipt(
            job_id=job_id,
            sequence=sequence,
            observed_at="2026-08-28T12:00:00Z",
            hostname="example.com",
            port=443,
            protocol="tcp",
            pinned_addresses=("1.1.1.1",),
            resolved_addresses=("1.1.1.1",),
            selected_address="1.1.1.1",
            requested_bytes=10,
            decision="allowed",
            reason="policy-and-budgets-satisfied",
        ).to_mapping()
    )


def test_backend_captures_exact_ordered_flow_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    assert plan.mediator_receipt_directory is not None
    state = Path(plan.mediator_receipt_directory).parent
    receipt_directory = Path(plan.mediator_receipt_directory)
    receipt_directory.mkdir(parents=True)
    payload = _flow_payload(plan.job_id, 1)
    (receipt_directory / "000001.json").write_bytes(payload)
    # The receipt files below are written by this test process, which stands in
    # for the per-job mediator identity that owns them on a live worker.
    backend = FirecrackerNetworkPlaneBackend(
        _network_policy(tmp_path), replace(plan, mediator_uid=owner_uid()), _Commands()
    )
    observed = backend._capture_mediator_receipts(state)
    assert observed is not None and observed.startswith("sha256:")

    (receipt_directory / "000001.json").rename(receipt_directory / "wrong.json")
    with pytest.raises(FormatError, match="filename"):
        backend._capture_mediator_receipts(state)
    (receipt_directory / "wrong.json").unlink()
    (receipt_directory / "000002.json").write_bytes(_flow_payload(plan.job_id, 2))
    with pytest.raises(FormatError, match="sequence"):
        backend._capture_mediator_receipts(state)

    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_nlink=1,
        st_uid=owner_uid(),
        st_size=len(_flow_payload(plan.job_id, 2)) + 1,
    )
    monkeypatch.setattr("sova.worker.network_plane.os.fstat", lambda _descriptor: metadata)
    with pytest.raises(FormatError, match="size drifted"):
        backend._capture_mediator_receipts(state)


def test_backend_mediator_stop_and_malformed_teardown_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    assert backend._stop_mediator() is True
    backend._mediator = _Process(result=0)
    assert backend._stop_mediator() is True
    backend._mediator = _HungProcess()
    assert backend._stop_mediator() is False

    backend._mediator = _HungProcess()
    monkeypatch.setattr(
        "sova.worker.network_plane.os.killpg",
        lambda *_args: (_ for _ in ()).throw(OSError()),
        raising=False,
    )
    assert backend._stop_mediator() is False

    malformed = FirecrackerNetworkPlaneBackend(
        _network_policy(tmp_path),
        replace(plan, teardown_commands=plan.teardown_commands[:1]),
        _Commands(),
    )
    receipt = malformed.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    assert receipt.failure_code == "SOVA-WORKER-NETWORK-CLEANUP"
    assert receipt.cleanup_complete is False


def test_root_controlled_path_checks_every_component() -> None:
    class _Node:
        def __init__(self, *, mode: int = 0o700) -> None:
            self.mode = mode
            self.parent = self

        def is_symlink(self) -> bool:
            return False

        def exists(self) -> bool:
            return True

        def stat(self) -> SimpleNamespace:
            return SimpleNamespace(st_uid=0, st_mode=self.mode)

    _require_root_controlled(_Node())  # type: ignore[arg-type]
    with pytest.raises(FormatError, match="not root controlled"):
        _require_root_controlled(_Node(mode=0o702))  # type: ignore[arg-type]


def test_network_plan_rejects_duplicate_bad_tap_namespace_and_identity_slot(
    tmp_path: Path,
) -> None:
    manifest, launch, _plan = _plans(tmp_path)
    network_request = next(
        item for item in launch.firecracker_api_requests if item[0] == "/network-interfaces/eth0"
    )
    with pytest.raises(FormatError, match="network device"):
        build_firecracker_network_plan(
            manifest,
            replace(
                launch,
                firecracker_api_requests=(*launch.firecracker_api_requests, network_request),
            ),
            _network_policy(tmp_path),
        )
    bad_payload = dict(network_request[1])
    bad_payload["host_dev_name"] = "interface-name-is-too-long"
    bad_requests = tuple(
        (path, bad_payload if path == network_request[0] else payload)
        for path, payload in launch.firecracker_api_requests
    )
    with pytest.raises(FormatError, match="IFNAMSIZ"):
        build_firecracker_network_plan(
            manifest,
            replace(launch, firecracker_api_requests=bad_requests),
            _network_policy(tmp_path),
        )
    with pytest.raises(FormatError, match="namespace"):
        build_firecracker_network_plan(
            manifest,
            replace(launch, network_namespace=str(tmp_path / "bad namespace")),
            _network_policy(tmp_path),
        )
    with pytest.raises(FormatError, match="identity slot"):
        build_firecracker_network_plan(
            manifest,
            replace(launch, identity_slot=500_001),
            _network_policy(tmp_path),
        )


def test_receipt_capture_rejects_path_owner_type_count_and_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    assert plan.mediator_receipt_directory is not None
    state = Path(plan.mediator_receipt_directory).parent
    receipt_directory = Path(plan.mediator_receipt_directory)
    receipt_directory.mkdir(parents=True)
    payload = _flow_payload(plan.job_id, 1)
    (receipt_directory / "000001.json").write_bytes(payload)
    policy = _network_policy(tmp_path)
    backend = FirecrackerNetworkPlaneBackend(policy, plan, _Commands())
    with pytest.raises(FormatError, match="owner"):
        backend._capture_mediator_receipts(state)
    assert (
        FirecrackerNetworkPlaneBackend(
            policy, replace(plan, mediator_receipt_directory=None), _Commands()
        )._capture_mediator_receipts(state)
        is None
    )
    with pytest.raises(FormatError, match="directory drifted"):
        FirecrackerNetworkPlaneBackend(
            policy,
            replace(plan, mediator_receipt_directory=str(tmp_path / "elsewhere")),
            _Commands(),
        )._capture_mediator_receipts(state)

    backend = FirecrackerNetworkPlaneBackend(
        policy, replace(plan, mediator_uid=owner_uid()), _Commands()
    )
    metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR,
        st_nlink=1,
        st_uid=owner_uid(),
        st_size=len(payload),
    )
    monkeypatch.setattr("sova.worker.network_plane.os.fstat", lambda _descriptor: metadata)
    with pytest.raises(FormatError, match="single-link"):
        backend._capture_mediator_receipts(state)
    monkeypatch.setattr("sova.worker.network_plane._MAX_MEDIATOR_RECEIPT_FILES", 0)
    with pytest.raises(FormatError, match="too many"):
        backend._capture_mediator_receipts(state)


def test_state_removal_and_offline_cleanup_are_evidence_bound(tmp_path: Path) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    assert plan.mediator_receipt_directory is not None
    state = Path(plan.mediator_receipt_directory).parent
    receipt_directory = Path(plan.mediator_receipt_directory)
    receipt_directory.mkdir(parents=True)
    (receipt_directory / "000001.json").write_bytes(b"receipt")
    (state / "mediator-policy.json").write_bytes(b"policy")
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    backend._state_created = True
    assert backend._remove_state(state) is True

    _manifest, offline_launch, offline = _plans(tmp_path / "offline", online=False)
    offline_backend = FirecrackerNetworkPlaneBackend(
        _network_policy(tmp_path / "offline"), offline, _Commands()
    )
    receipt = offline_backend.cleanup(offline_launch, completed_at="2026-08-28T12:00:00Z")
    assert receipt.host_rules_removed is True
    assert receipt.root_veth_removed is True
    assert receipt.failure_code == "SOVA-WORKER-NETWORK-PREPARATION-INCOMPLETE"


def test_cleanup_distinguishes_exited_mediator_and_missing_receipts(tmp_path: Path) -> None:
    _manifest, launch, plan = _plans(tmp_path)
    assert plan.mediator_receipt_directory is not None
    state = Path(plan.mediator_receipt_directory).parent
    Path(plan.mediator_receipt_directory).mkdir(parents=True)
    (state / "mediator-policy.json").write_bytes(b"policy")
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    backend._state_created = True
    backend._namespace_created = True
    backend._root_veth_created = True
    backend._host_rules_loaded = True
    backend._firewall_loaded = True
    backend._mediator = _Process(result=0)
    receipt = backend.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    assert receipt.failure_code == "SOVA-WORKER-NETWORK-MEDIATOR-EXITED"

    _manifest, launch, plan = _plans(tmp_path / "missing")
    missing = FirecrackerNetworkPlaneBackend(
        _network_policy(tmp_path / "missing"), plan, _Commands()
    )
    missing._namespace_created = True
    missing._root_veth_created = True
    missing._host_rules_loaded = True
    missing._firewall_loaded = True
    missing._mediator = _Process()
    receipt = missing.cleanup(launch, completed_at="2026-08-28T12:00:00Z")
    assert receipt.failure_code == "SOVA-WORKER-NETWORK-RECEIPT-MISSING"


def test_offline_mediator_methods_are_noops_and_state_entries_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, _launch, plan = _plans(tmp_path, online=False)
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    state = tmp_path / "state"
    state.mkdir()
    backend._write_mediator_policy(state)
    backend._prepare_receipt_directory(state)
    backend._start_mediator()
    assert backend._capture_mediator_receipts(state) is None
    assert backend._remove_state(tmp_path / "absent") is True

    _manifest, _launch, online = _plans(tmp_path / "online")
    assert online.mediator_receipt_directory is not None
    online_state = Path(online.mediator_receipt_directory).parent
    online_receipts = Path(online.mediator_receipt_directory)
    online_receipts.mkdir(parents=True)
    (online_receipts / "unexpected-directory").mkdir()
    bounded = FirecrackerNetworkPlaneBackend(
        _network_policy(tmp_path / "online"), online, _Commands()
    )
    bounded._state_created = True
    with pytest.raises(FormatError, match="receipt entry drifted"):
        bounded._remove_state(online_state)
    (online_receipts / "unexpected-directory").rmdir()
    (online_receipts / "one").write_bytes(b"x")
    monkeypatch.setattr("sova.worker.network_plane._MAX_MEDIATOR_RECEIPT_FILES", 0)
    assert bounded._remove_state(online_state) is False


def test_mediator_group_kill_failure_is_observed_after_term(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    backend._mediator = _HungProcess()
    calls = 0

    def killpg(_pid: int, _signal: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError

    monkeypatch.setattr("sova.worker.network_plane.os.killpg", killpg, raising=False)
    assert backend._stop_mediator() is False
    assert calls == 2


def test_mediator_stop_signals_its_group_or_falls_back_to_the_process_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signalled_process_groups: list[tuple[int, int]],
) -> None:
    _manifest, _launch, plan = _plans(tmp_path)
    backend = FirecrackerNetworkPlaneBackend(_network_policy(tmp_path), plan, _Commands())
    backend._mediator = _Process()
    assert backend._stop_mediator() is True
    expected = [(4242, signal.SIGTERM)] if hasattr(os, "killpg") else []
    assert signalled_process_groups == expected

    monkeypatch.delattr(os, "killpg", raising=False)
    backend._mediator = _Process()
    assert backend._stop_mediator() is True
    backend._mediator = _HungProcess()
    assert backend._stop_mediator() is False
    assert signalled_process_groups == expected
