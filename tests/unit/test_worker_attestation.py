# SPDX-License-Identifier: Apache-2.0
"""Worker host-measurement tests without claiming an independent review."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from sova.formats import FormatError
from sova.worker import attestation as attestation_module
from sova.worker.attestation import collect_worker_attestation
from sova.worker.firecracker import FirecrackerHostPolicy
from tests.support.worker import digest


def _policy(root: Path) -> FirecrackerHostPolicy:
    return FirecrackerHostPolicy(
        firecracker_binary=root / "firecracker",
        jailer_binary=root / "jailer",
        chroot_base=root / "jailer-root",
        network_namespace_base=root / "netns",
        content_store=root / "cas",
        cgroup_base=root / "cgroup",
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )


def test_digest_file_rejects_missing_and_hashes_regular_file(tmp_path: Path) -> None:
    value = tmp_path / "value"
    value.write_bytes(b"content")
    assert attestation_module._digest_file(value) == digest("content")
    with pytest.raises(FormatError, match="regular file"):
        attestation_module._digest_file(tmp_path / "missing")


def test_root_owned_probe_fails_closed_when_path_cannot_be_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unresolved(_path: Path, *, strict: bool = False) -> Path:
        del strict
        raise OSError("unresolvable")

    monkeypatch.setattr(Path, "resolve", unresolved)
    assert not attestation_module._root_owned(Path("/untrusted"))


def test_firecracker_version_measurement_parses_and_rejects_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sova.worker.attestation.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="Firecracker v1.16.1", stderr=""),
    )
    assert attestation_module._firecracker_version(Path("/bin/firecracker")) == "1.16.1"
    monkeypatch.setattr(
        "sova.worker.attestation.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="unknown", stderr=""),
    )
    with pytest.raises(FormatError, match="unparseable"):
        attestation_module._firecracker_version(Path("/bin/firecracker"))

    def fail(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired("firecracker", 5)

    monkeypatch.setattr("sova.worker.attestation.subprocess.run", fail)
    with pytest.raises(FormatError, match="could not be measured"):
        attestation_module._firecracker_version(Path("/bin/firecracker"))


def test_swap_probe_distinguishes_empty_active_and_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty(_path: Path, *_args: object, **_kwargs: object) -> str:
        return "Filename Type Size Used Priority\n"

    monkeypatch.setattr(Path, "read_text", empty)
    assert attestation_module._swap_disabled()

    def active(_path: Path, *_args: object, **_kwargs: object) -> str:
        return "Filename Type Size Used Priority\n/swap file 1 0 -2\n"

    monkeypatch.setattr(Path, "read_text", active)
    assert not attestation_module._swap_disabled()

    def unreadable(_path: Path, *_args: object, **_kwargs: object) -> str:
        raise OSError

    monkeypatch.setattr(Path, "read_text", unreadable)
    assert not attestation_module._swap_disabled()


@pytest.mark.parametrize("system", ["Windows", "Darwin"])
def test_collect_attestation_rejects_non_linux_host(
    system: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Present a non-Linux kernel even when the suite itself runs on Linux.
    monkeypatch.setattr("sova.worker.attestation.platform.system", lambda: system)
    with pytest.raises(FormatError, match="requires Linux"):
        collect_worker_attestation(
            worker_id="worker:test",
            measured_at="2026-08-27T10:00:00Z",
            policy=_policy(tmp_path),
            host_kernel_image=tmp_path / "host-kernel",
            microcode_image=tmp_path / "microcode",
            guest_kernel_image=tmp_path / "guest-kernel",
            root_filesystem_image=tmp_path / "rootfs",
            worker_policy_bytes=b"policy",
            advisory_snapshot_bytes=b"advisories",
        )


def test_collect_attestation_measures_development_host_without_promoting_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    policy = _policy(tmp_path)
    monkeypatch.setattr("sova.worker.attestation.platform.system", lambda: "Linux")
    monkeypatch.setattr("sova.worker.attestation.platform.release", lambda: "6.6-microsoft-wsl2")
    monkeypatch.setattr(attestation_module, "_digest_file", lambda path: digest(path.name))
    monkeypatch.setattr(attestation_module, "_root_owned", lambda _path: True)
    monkeypatch.setattr(attestation_module, "_firecracker_version", lambda _path: "1.16.1")
    monkeypatch.setattr(attestation_module, "_swap_disabled", lambda: True)
    monkeypatch.setattr("sova.worker.attestation.os.access", lambda *_args: True)
    monkeypatch.setattr(Path, "is_file", lambda _path: True)

    def proc_version(_path: Path, *_args: object, **_kwargs: object) -> str:
        return "Microsoft WSL2"

    monkeypatch.setattr(Path, "read_text", proc_version)
    attestation = collect_worker_attestation(
        worker_id="worker:test",
        measured_at="2026-08-27T10:00:00Z",
        policy=policy,
        host_kernel_image=tmp_path / "host-kernel",
        microcode_image=tmp_path / "microcode",
        guest_kernel_image=tmp_path / "guest-kernel",
        root_filesystem_image=tmp_path / "rootfs",
        worker_policy_bytes=b"policy",
        advisory_snapshot_bytes=b"advisories",
        default_seccomp_enforced=True,
        unique_uid_gid_enforced=True,
    )
    assert attestation.wsl_environment is True
    assert attestation.dedicated_linux_host is False
    assert attestation.independent_review_receipt is None


def test_collect_attestation_rejects_binary_pin_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("sova.worker.attestation.platform.system", lambda: "Linux")
    monkeypatch.setattr("sova.worker.attestation.platform.release", lambda: "linux")
    monkeypatch.setattr(attestation_module, "_digest_file", lambda _path: digest("wrong"))
    with pytest.raises(FormatError, match="Firecracker binary"):
        collect_worker_attestation(
            worker_id="worker:test",
            measured_at="2026-08-27T10:00:00Z",
            policy=_policy(tmp_path),
            host_kernel_image=tmp_path / "host-kernel",
            microcode_image=tmp_path / "microcode",
            guest_kernel_image=tmp_path / "guest-kernel",
            root_filesystem_image=tmp_path / "rootfs",
            worker_policy_bytes=b"policy",
            advisory_snapshot_bytes=b"advisories",
        )
