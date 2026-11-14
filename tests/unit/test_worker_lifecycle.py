# SPDX-License-Identifier: Apache-2.0
"""Firecracker lifecycle, Unix API, watchdog, and cleanup receipt tests."""

from __future__ import annotations

import os
import platform
import select
import signal
import stat
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from sova.formats import FormatError, sha256_digest, validate_document
from sova.worker.cas import ContentAddressedStore
from sova.worker.contracts import assess_worker_attestation
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    FirecrackerLaunchPlan,
    WorkerCleanupReceipt,
    build_firecracker_launch_plan,
)
from sova.worker.lifecycle import (
    FirecrackerLifecycleRunner,
    FirecrackerUnixApiClient,
    PosixFirecrackerBackend,
)
from tests.support.worker import digest, guest_keypair, worker_attestation, worker_manifest

_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _plan(tmp_path: Path) -> FirecrackerLaunchPlan:
    policy = FirecrackerHostPolicy(
        firecracker_binary=(tmp_path / "bin" / "firecracker").resolve(),
        jailer_binary=(tmp_path / "bin" / "jailer").resolve(),
        chroot_base=(tmp_path / "jailer").resolve(),
        network_namespace_base=(tmp_path / "netns").resolve(),
        content_store=(tmp_path / "cas").resolve(),
        cgroup_base=(tmp_path / "cgroup").resolve(),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )
    admission = assess_worker_attestation(
        worker_attestation(),
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    return build_firecracker_launch_plan(
        worker_manifest(guest_keypair()), admission, policy, identity_slot=9
    )


@dataclass
class _Backend:
    live_execution: bool = False
    jailer_exit: int = 0
    socket_ready: bool = True
    api_statuses: deque[int] = field(default_factory=deque)
    process_results: deque[int | None] = field(default_factory=lambda: deque([0]))
    cleanup_complete: bool = True
    cleanup_error: Exception | None = None
    prepare_error: Exception | None = None
    api_error: Exception | None = None
    events: list[str] = field(default_factory=list)

    def prepare(self, _plan: FirecrackerLaunchPlan) -> None:
        self.events.append("prepare")
        if self.prepare_error is not None:
            raise self.prepare_error

    def launch(self, _plan: FirecrackerLaunchPlan) -> int:
        self.events.append("launch")
        return self.jailer_exit

    def wait_for_api_socket(self, _plan: FirecrackerLaunchPlan, _timeout: float) -> bool:
        self.events.append("socket")
        return self.socket_ready

    def read_process_id(self, _plan: FirecrackerLaunchPlan) -> int:
        self.events.append("pid")
        return 4242

    def wait_for_process_id(self, _plan: FirecrackerLaunchPlan, _timeout: float) -> int:
        self.events.append("pid")
        return 4242

    def put_api(self, _plan: FirecrackerLaunchPlan, path: str, payload: dict[str, Any]) -> int:
        self.events.append(f"api:{path}:{payload.get('action_type', '-')}")
        if self.api_error is not None:
            raise self.api_error
        return self.api_statuses.popleft() if self.api_statuses else 204

    def wait_for_process(self, _process_id: int, _timeout: float) -> int | None:
        self.events.append("wait")
        return self.process_results.popleft()

    def terminate_process(self, _process_id: int) -> bool:
        self.events.append("terminate")
        return True

    def cleanup(
        self,
        plan: FirecrackerLaunchPlan,
        *,
        completed_at: str,
        secret_broker_revoked: bool,
    ) -> WorkerCleanupReceipt:
        self.events.append("cleanup")
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return WorkerCleanupReceipt(
            plan.job_id,
            plan.vm_id,
            completed_at,
            self.cleanup_complete,
            self.cleanup_complete,
            self.cleanup_complete,
            self.cleanup_complete,
            self.cleanup_complete,
            self.cleanup_complete,
            secret_broker_revoked,
        )


def _run(plan: FirecrackerLaunchPlan, backend: _Backend, *, revoke: bool = True) -> dict[str, Any]:
    result = FirecrackerLifecycleRunner(backend, clock=lambda: _NOW).run(
        plan, revoke_secrets=lambda: revoke
    )
    mapping = result.execution.to_mapping()
    validate_document(mapping)
    validate_document(result.cleanup.to_mapping())
    assert mapping["cleanupReceiptDigest"] == result.cleanup.to_mapping()["contentDigest"]
    return mapping


def test_lifecycle_completes_exact_api_sequence_and_remains_non_authorizing(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)
    backend = _Backend()
    receipt = _run(plan, backend)
    assert receipt["status"] == "process-exited"
    assert receipt["executionMode"] == "simulated"
    assert receipt["jailerExitCode"] == 0
    assert receipt["processId"] == 4242
    assert receipt["instanceStarted"] is True
    assert len(receipt["apiCalls"]) == len(plan.firecracker_api_requests)
    assert receipt["failureCode"] is None
    assert receipt["claims"] == {
        "liveFirecrackerExecuted": False,
        "productionIsolationClaimAllowed": False,
        "exactHostMatrixPassed": False,
        "independentlyReviewed": False,
        "escapeImpossible": False,
    }
    assert backend.events[-2:] == ["wait", "cleanup"]


def test_lifecycle_fails_closed_on_jailer_socket_and_api_failures(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    jailer = _Backend(jailer_exit=9)
    assert _run(plan, jailer)["failureCode"] == "SOVA-WORKER-JAILER-EXIT"
    assert "socket" not in jailer.events

    no_socket = _Backend(socket_ready=False)
    assert _run(plan, no_socket)["failureCode"] == "SOVA-WORKER-API-SOCKET-TIMEOUT"
    assert no_socket.events.index("pid") < no_socket.events.index("socket")

    statuses = deque([204, 500])
    rejected = _Backend(api_statuses=statuses)
    receipt = _run(plan, rejected)
    assert receipt["status"] == "failed"
    assert receipt["failureCode"] == "SOVA-WORKER-API-STATUS"
    assert receipt["instanceStarted"] is False
    assert "terminate" in rejected.events


def test_lifecycle_watchdog_requests_shutdown_then_forces_termination(tmp_path: Path) -> None:
    backend = _Backend(process_results=deque([None, None]))
    receipt = _run(_plan(tmp_path), backend)
    assert receipt["status"] == "timed-out"
    assert receipt["watchdogTriggered"] is True
    assert receipt["failureCode"] == "SOVA-WORKER-WATCHDOG"
    assert receipt["apiCalls"][-1]["path"] == "/actions"
    assert "api:/actions:SendCtrlAltDel" in backend.events
    assert "terminate" in backend.events

    graceful = _Backend(process_results=deque([None, 0]))
    graceful_receipt = _run(_plan(tmp_path), graceful)
    assert graceful_receipt["status"] == "timed-out"
    assert graceful.events.count("terminate") == 0


def test_cleanup_failure_overrides_execution_and_prepare_errors_are_receipted(
    tmp_path: Path,
) -> None:
    incomplete = _run(_plan(tmp_path), _Backend(cleanup_complete=False), revoke=False)
    assert incomplete["executionStatus"] == "process-exited"
    assert incomplete["status"] == "cleanup-failed"
    assert incomplete["cleanupComplete"] is False

    denied = _Backend(prepare_error=FormatError("SOVA-WORKER-HOST", "denied"))
    failed = _run(_plan(tmp_path), denied)
    assert failed["status"] == "failed"
    assert failed["failureCode"] == "SOVA-WORKER-HOST"
    assert denied.events == ["prepare", "cleanup"]

    timed_out = _Backend(prepare_error=subprocess.TimeoutExpired("jailer", 30))
    assert _run(_plan(tmp_path), timed_out)["failureCode"] == "SOVA-WORKER-JAILER-TIMEOUT"

    host_error = _Backend(prepare_error=OSError("unavailable"))
    assert _run(_plan(tmp_path), host_error)["failureCode"] == "SOVA-WORKER-HOST-IO"

    api_error = _Backend(api_error=OSError("api unavailable"))
    assert _run(_plan(tmp_path), api_error)["failureCode"] == "SOVA-WORKER-HOST-IO"
    assert "terminate" in api_error.events

    cleanup_error = _Backend(cleanup_error=OSError("cleanup failed"))
    assert _run(_plan(tmp_path), cleanup_error)["status"] == "cleanup-failed"


def test_lifecycle_rejects_missing_start_and_records_nonzero_process_exit(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    invalid = replace(plan, firecracker_api_requests=plan.firecracker_api_requests[:-1])
    with pytest.raises(FormatError, match="start action"):
        FirecrackerLifecycleRunner(_Backend(), clock=lambda: _NOW).run(
            invalid,
            revoke_secrets=lambda: True,
        )
    failed = _run(plan, _Backend(process_results=deque([7])))
    assert failed["status"] == "failed"
    assert failed["failureCode"] == "SOVA-WORKER-PROCESS-EXIT"


def test_secret_revocation_failure_is_visible_as_incomplete_cleanup(tmp_path: Path) -> None:
    def fail() -> bool:
        raise RuntimeError

    result = FirecrackerLifecycleRunner(_Backend(), clock=lambda: _NOW).run(
        _plan(tmp_path),
        revoke_secrets=fail,
    )
    assert result.execution.execution_status == "process-exited"
    assert result.execution.cleanup_complete is False
    assert result.execution.to_mapping()["status"] == "cleanup-failed"


def test_live_backend_receipt_proves_execution_only_not_production_isolation(
    tmp_path: Path,
) -> None:
    receipt = _run(_plan(tmp_path), _Backend(live_execution=True))
    assert receipt["claims"]["liveFirecrackerExecuted"] is True
    assert receipt["claims"]["productionIsolationClaimAllowed"] is False


class _Socket:
    def __init__(self, response: bytes | Exception) -> None:
        self.response = response
        self.sent = b""
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        return None

    def connect(self, _path: str) -> None:
        if isinstance(self.response, Exception):
            raise self.response

    def sendall(self, request: bytes) -> None:
        self.sent = request

    def recv(self, _size: int) -> bytes:
        if isinstance(self.response, Exception):
            raise TypeError
        response, self.response = self.response, b""
        return response

    def close(self) -> None:
        self.closed = True


def test_unix_api_client_emits_bounded_canonical_request_and_parses_status() -> None:
    stream = _Socket(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    client = FirecrackerUnixApiClient(socket_factory=lambda _family, _kind: stream)
    assert client.put(Path("/run/firecracker.socket"), "/actions", {"z": 1, "a": 2}) == 204
    assert b'{"a":2,"z":1}' in stream.sent
    assert stream.sent.startswith(b"PUT /actions HTTP/1.1\r\n")
    assert stream.closed is True


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (b"", "SOVA-WORKER-API-RESPONSE"),
        (b"not-http\r\n\r\n", "SOVA-WORKER-API-RESPONSE"),
        (b"HTTP/1.1 999 Nope\r\n\r\n", "SOVA-WORKER-API-RESPONSE"),
        (OSError("unavailable"), "SOVA-WORKER-API-IO"),
    ],
)
def test_unix_api_client_rejects_bad_responses_and_io(
    response: bytes | Exception,
    code: str,
) -> None:
    stream = _Socket(response)
    client = FirecrackerUnixApiClient(socket_factory=lambda _family, _kind: stream)
    with pytest.raises(FormatError) as failure:
        client.put(Path("/run/firecracker.socket"), "/actions", {})
    assert failure.value.issue.code == code
    assert stream.closed is True
    with pytest.raises(FormatError, match="path"):
        client.put(Path("/run/firecracker.socket"), "/bad path", {})


def test_unix_api_client_rejects_oversized_headers() -> None:
    stream = _Socket(b"HTTP/1.1 204 " + b"x" * (65 * 1024))
    client = FirecrackerUnixApiClient(socket_factory=lambda _family, _kind: stream)
    with pytest.raises(FormatError, match="too large"):
        client.put(Path("/run/firecracker.socket"), "/actions", {})


def test_posix_backend_refuses_non_linux_and_stages_digest_verified_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    # Present a non-Linux kernel even when the suite itself runs on Linux.
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    with pytest.raises(FormatError, match="requires Linux"):
        backend.prepare(plan)

    binary_payloads = {
        policy.firecracker_binary: b"firecracker-live",
        policy.jailer_binary: b"jailer-live",
    }
    policy.firecracker_binary.parent.mkdir(parents=True)
    for path, payload in binary_payloads.items():
        path.write_bytes(payload)
        path.chmod(0o500)
    policy.chroot_base.mkdir(parents=True)
    policy.content_store.mkdir(parents=True)
    policy.network_namespace_base.mkdir(parents=True)
    Path(plan.network_namespace).write_bytes(b"namespace-handle")
    Path(plan.network_namespace).chmod(0o400)
    store = ContentAddressedStore(policy.content_store)
    references = [
        store.put(
            name=f"item-{index}",
            media_type="application/octet-stream",
            data=data,
        )
        for index, data in enumerate((b"kernel", b"rootfs", b"writable"))
    ]
    staged = tuple(
        (str(store.verify(reference)), destination, mode)
        for reference, (_source, destination, mode) in zip(
            references, plan.staged_content, strict=True
        )
    )
    plan = replace(plan, staged_content=staged)
    policy = FirecrackerHostPolicy(
        policy.firecracker_binary,
        policy.jailer_binary,
        policy.chroot_base,
        policy.network_namespace_base,
        policy.content_store,
        sha256_digest(binary_payloads[policy.firecracker_binary]),
        sha256_digest(binary_payloads[policy.jailer_binary]),
        policy.cgroup_base,
    )
    backend = PosixFirecrackerBackend(policy)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        PosixFirecrackerBackend,
        "_require_root_controlled",
        staticmethod(lambda _path: None),
    )
    ownership: list[tuple[Path, int, int]] = []
    monkeypatch.setattr(
        os,
        "chown",
        lambda path, uid, gid: ownership.append((Path(path), uid, gid)),
        raising=False,
    )
    backend.prepare(plan)
    assert all(Path(destination).is_file() for _source, destination, _mode in staged)
    assert len(ownership) == len(staged)
    assert {(uid, gid) for _path, uid, gid in ownership} == {(plan.uid, plan.gid)}
    permissions = [Path(destination).stat().st_mode for _source, destination, _mode in staged]
    assert all(value & stat.S_IRUSR for value in permissions)
    assert not permissions[0] & stat.S_IWUSR
    assert not permissions[1] & stat.S_IWUSR
    assert permissions[2] & stat.S_IWUSR


def test_posix_backend_launch_uses_credential_free_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    backend._validate_jailer_command(plan)
    with pytest.raises(FormatError, match="boundary drifted"):
        backend._validate_jailer_command(replace(plan, jailer_command=()))
    separator = plan.jailer_command.index("--")
    drifted = replace(
        plan,
        jailer_command=(
            *plan.jailer_command[:separator],
            "--no-seccomp",
            *plan.jailer_command[separator:],
        ),
    )
    with pytest.raises(FormatError, match="not allowed"):
        backend._validate_jailer_command(drifted)
    forwarded = replace(plan, jailer_command=(*plan.jailer_command[:-1], "/other.socket"))
    with pytest.raises(FormatError, match="arguments drifted"):
        backend._validate_jailer_command(forwarded)
    duplicate_flag = replace(
        plan,
        jailer_command=(
            *plan.jailer_command[:separator],
            "--daemonize",
            *plan.jailer_command[separator:],
        ),
    )
    with pytest.raises(FormatError, match="duplicated"):
        backend._validate_jailer_command(duplicate_flag)
    duplicate_option = replace(
        plan,
        jailer_command=(
            *plan.jailer_command[:separator],
            "--id",
            plan.vm_id,
            *plan.jailer_command[separator:],
        ),
    )
    with pytest.raises(FormatError, match="duplicated"):
        backend._validate_jailer_command(duplicate_option)
    first_cgroup = plan.jailer_command.index("--cgroup")
    duplicated_cgroup = replace(
        plan,
        jailer_command=(
            *plan.jailer_command[:separator],
            *plan.jailer_command[first_cgroup : first_cgroup + 2],
            *plan.jailer_command[separator:],
        ),
    )
    with pytest.raises(FormatError, match="policy arguments drifted"):
        backend._validate_jailer_command(duplicated_cgroup)
    observed: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed.update({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(subprocess, "run", run)
    assert backend.launch(plan) == 0
    assert observed["argv"] == list(plan.jailer_command)
    assert observed["env"] == {"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    assert "shell" not in observed


def test_posix_root_control_and_staging_reject_unsafe_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Node:
        def __init__(self, *, exists: bool, uid: int = 0, mode: int = 0o755) -> None:
            self._exists = exists
            self._uid = uid
            self._mode = mode
            self.parent = self

        def is_symlink(self) -> bool:
            return False

        def exists(self) -> bool:
            return self._exists

        def stat(self) -> SimpleNamespace:
            return SimpleNamespace(st_uid=self._uid, st_mode=self._mode)

    with pytest.raises(FormatError, match="missing or linked"):
        PosixFirecrackerBackend._require_root_controlled(_Node(exists=False))  # type: ignore[arg-type]
    with pytest.raises(FormatError, match="not root controlled"):
        PosixFirecrackerBackend._require_root_controlled(
            _Node(exists=True, uid=1)  # type: ignore[arg-type]
        )
    PosixFirecrackerBackend._require_root_controlled(_Node(exists=True))  # type: ignore[arg-type]

    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    root = Path(plan.chroot_directory) / "root"
    root.mkdir(parents=True)
    monkeypatch.delattr(os, "chown", raising=False)
    with pytest.raises(FormatError, match="ownership"):
        backend._stage_content(plan, root)

    monkeypatch.setattr(os, "chown", lambda *_args: None, raising=False)
    outside = replace(
        plan,
        staged_content=((str(tmp_path / "outside"), str(root / "outside"), "copy-read-only"),),
    )
    with pytest.raises(FormatError, match="outside"):
        backend._stage_content(outside, root)

    source = policy.content_store / "sha256" / "aa" / ("a" * 64)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"wrong digest")
    monkeypatch.setattr(backend, "_require_root_controlled", lambda _path: None)
    drifted = replace(
        plan,
        staged_content=((str(source), str(root / "drifted"), "copy-read-only"),),
    )
    with pytest.raises(FormatError, match="source digest"):
        backend._stage_content(drifted, root)

    existing = root / "existing"
    existing.write_bytes(b"present")
    monkeypatch.setattr(backend, "_digest_file", lambda _path: f"sha256:{source.name}")
    unsafe_destination = replace(
        plan,
        staged_content=((str(source), str(existing), "copy-read-only"),),
    )
    with pytest.raises(FormatError, match="destination"):
        backend._stage_content(unsafe_destination, root)

    digests = iter((f"sha256:{source.name}", digest("copied-wrong")))
    monkeypatch.setattr(backend, "_digest_file", lambda _path: next(digests))
    copied_wrong = replace(
        plan,
        staged_content=((str(source), str(root / "copied"), "copy-read-only"),),
    )
    with pytest.raises(FormatError, match="copy digest"):
        backend._stage_content(copied_wrong, root)


def test_posix_prepare_rejects_binary_drift_and_rolls_back_partial_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(backend, "_require_root_controlled", lambda _path: None)
    monkeypatch.setattr(backend, "_digest_file", lambda _path: digest("wrong"))
    with pytest.raises(FormatError, match="binary digest"):
        backend.prepare(plan)

    def binary_digest(path: Path) -> str:
        return (
            policy.approved_firecracker_digest
            if path == policy.firecracker_binary
            else policy.approved_jailer_digest
        )

    monkeypatch.setattr(backend, "_digest_file", binary_digest)
    with pytest.raises(FormatError, match="jail root"):
        backend.prepare(replace(plan, chroot_directory=str(tmp_path / "other")))

    netns_index = plan.jailer_command.index("--netns") + 1
    other_namespace = str(tmp_path / "other-netns")
    network_drift = replace(
        plan,
        network_namespace=other_namespace,
        jailer_command=(
            *plan.jailer_command[:netns_index],
            other_namespace,
            *plan.jailer_command[netns_index + 1 :],
        ),
    )
    with pytest.raises(FormatError, match="network namespace"):
        backend.prepare(network_drift)

    policy.chroot_base.mkdir(parents=True)
    jailer_root = policy.chroot_base / policy.firecracker_binary.name
    jailer_root.write_bytes(b"not-a-directory")
    with pytest.raises(FormatError, match="not a directory"):
        backend.prepare(plan)
    jailer_root.unlink()

    monkeypatch.setattr(backend, "_stage_content", lambda *_args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        backend.prepare(plan)
    assert not Path(plan.chroot_directory).exists()


def test_posix_backend_rejects_non_root_and_unsafe_local_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(FormatError, match="root"):
        backend._require_live_host()
    with pytest.raises(FormatError, match="regular file"):
        backend._digest_file(tmp_path / "missing")
    with pytest.raises(FormatError, match="guest path"):
        backend._host_path(plan, "relative/path")
    with pytest.raises(FormatError, match="pidfd"):
        backend.wait_for_process(4242, 0)
    assert backend.terminate_process(4242) is False


def test_posix_backend_binds_process_control_to_pidfd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    pid_path = backend._host_path(plan, plan.pid_file)
    pid_path.parent.mkdir(parents=True)
    pid_path.write_text("not-a-pid\n", encoding="ascii")
    with pytest.raises(FormatError, match="pid file"):
        backend.read_process_id(plan)
    pid_path.write_text("1\n", encoding="ascii")
    with pytest.raises(FormatError, match="unsafe"):
        backend.read_process_id(plan)
    pid_path.write_text("4242\n", encoding="ascii")
    monkeypatch.delattr(os, "pidfd_open", raising=False)
    with pytest.raises(FormatError, match="pidfd"):
        backend.read_process_id(plan)

    monkeypatch.setattr(os, "pidfd_open", lambda _pid, _flags: 77, raising=False)
    assert backend.read_process_id(plan) == 4242
    assert backend.read_process_id(plan) == 4242
    assert backend.wait_for_process_id(plan, 1.0) == 4242
    monkeypatch.setattr(select, "select", lambda *_args: ([77], [], []))
    assert backend.wait_for_process(4242, 1.0) == 0
    observed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        signal,
        "pidfd_send_signal",
        lambda handle, sent, _info, _flags: observed.append((handle, sent)),
        raising=False,
    )
    monkeypatch.setattr(backend, "wait_for_process", lambda _pid, _timeout: 0)
    assert backend.terminate_process(4242) is True
    assert observed[0][0] == 77

    unavailable = PosixFirecrackerBackend(policy)
    monkeypatch.setattr(
        os,
        "pidfd_open",
        lambda _pid, _flags: (_ for _ in ()).throw(OSError()),
        raising=False,
    )
    with pytest.raises(FormatError, match="unavailable"):
        unavailable.read_process_id(plan)

    backend._pid_handles[4242] = 77
    monkeypatch.setattr(
        signal,
        "pidfd_send_signal",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
        raising=False,
    )
    assert backend.terminate_process(4242) is True
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *_args: None, raising=False)
    monkeypatch.setattr(backend, "wait_for_process", lambda _pid, _timeout: None)
    assert backend.terminate_process(4242) is False

    pid_path.unlink()
    waiting = PosixFirecrackerBackend(policy)
    moments = iter((0.0, 0.1, 1.0))
    monkeypatch.setattr(time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    with pytest.raises(FormatError, match="pid file was not created"):
        waiting.wait_for_process_id(plan, 0.5)


def test_posix_backend_waits_for_exact_socket_and_delegates_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    api = Mock()
    api.put.return_value = 204
    backend = PosixFirecrackerBackend(policy, api_client=api)
    socket_path = backend._host_path(plan, plan.api_socket)
    original_stat = Path.stat

    def socket_stat(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        if path == socket_path:
            values = list(original_stat(tmp_path, *args, **kwargs))
            values[0] = stat.S_IFSOCK
            return os.stat_result(values)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", socket_stat)
    assert backend.wait_for_api_socket(plan, 1.0) is True
    assert backend.put_api(plan, "/actions", {"action_type": "InstanceStart"}) == 204
    api.put.assert_called_once_with(
        socket_path,
        "/actions",
        {"action_type": "InstanceStart"},
    )

    moments = iter((0.0, 0.1, 1.0))
    monkeypatch.setattr(Path, "stat", original_stat)
    monkeypatch.setattr(time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    assert backend.wait_for_api_socket(plan, 0.5) is False


def test_posix_cleanup_removes_only_exact_job_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    policy = FirecrackerHostPolicy(
        Path(plan.jailer_command[4]),
        Path(plan.jailer_command[0]),
        Path(plan.chroot_directory).parent.parent,
        Path(plan.network_namespace).parent,
        Path(plan.staged_content[0][0]).parents[2],
        digest("firecracker"),
        digest("jailer"),
        Path(plan.cgroup_directory).parents[1],
    )
    backend = PosixFirecrackerBackend(policy)
    chroot = Path(plan.chroot_directory)
    chroot.joinpath("root", "run").mkdir(parents=True)
    backend._host_path(plan, plan.api_socket).write_bytes(b"socket-placeholder")
    namespace = Path(plan.network_namespace)
    namespace.parent.mkdir(parents=True)
    namespace.write_bytes(b"namespace-placeholder")

    def run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert argv == ["/usr/sbin/ip", "netns", "delete", plan.vm_id]
        namespace.unlink()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", run)
    receipt = backend.cleanup(
        plan,
        completed_at="2026-08-27T12:00:00Z",
        secret_broker_revoked=True,
    )
    assert receipt.complete is True
    assert chroot.exists() is False
    assert namespace.exists() is False

    chroot.joinpath("root").mkdir(parents=True)
    backend._host_path(plan, plan.pid_file).write_text("4242\n", encoding="ascii")
    terminate = Mock(return_value=True)
    monkeypatch.setattr(backend, "terminate_process", terminate)
    stale = backend.cleanup(
        plan,
        completed_at="2026-08-27T12:01:00Z",
        secret_broker_revoked=True,
    )
    assert stale.process_terminated is False
    terminate.assert_not_called()

    with pytest.raises(FormatError, match="cleanup resource path drifted"):
        backend.cleanup(
            replace(plan, cgroup_directory=str(tmp_path / "other-cgroup")),
            completed_at="2026-08-27T12:00:00Z",
            secret_broker_revoked=True,
        )
