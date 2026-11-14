# SPDX-License-Identifier: Apache-2.0
"""Persistent identity-slot lease conflict and release tests."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sova.formats import FormatError, canonical_json_bytes
from sova.worker.identity import IdentitySlotLease, IdentitySlotLeaseTable
from tests.support.worker import digest, owner_uid, unprivileged_lease_root


def _lease(slot: int = 7) -> IdentitySlotLease:
    return IdentitySlotLease(slot, "job:lease-test", digest("manifest"))


def _lease_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = (tmp_path / "leases").resolve()
    root.mkdir()
    return unprivileged_lease_root(root, monkeypatch)


def test_identity_slot_lease_is_exclusive_and_survives_incomplete_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    table = IdentitySlotLeaseTable(_lease_root(tmp_path, monkeypatch))
    lease = _lease()
    table.acquire(lease)
    with pytest.raises(FormatError, match="already reserved"):
        table.acquire(lease)
    assert table.release(lease, cleanup_complete=False) is False
    with pytest.raises(FormatError, match="already reserved"):
        table.acquire(lease)
    assert table.release(lease, cleanup_complete=True) is True
    table.acquire(lease)


def test_identity_slot_release_rejects_tampered_or_different_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _lease_root(tmp_path, monkeypatch)
    table = IdentitySlotLeaseTable(root)
    lease = _lease()
    table.acquire(lease)
    with pytest.raises(FormatError, match="binding drifted"):
        table.release(
            IdentitySlotLease(lease.slot, "job:other", lease.manifest_digest),
            cleanup_complete=True,
        )
    path = root / f"{lease.slot:06d}.lease"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(FormatError, match="fields"):
        table.release(lease, cleanup_complete=True)


def test_identity_slot_release_rejects_noncanonical_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _lease_root(tmp_path, monkeypatch)
    table = IdentitySlotLeaseTable(root)
    lease = _lease()
    table.acquire(lease)
    path = root / f"{lease.slot:06d}.lease"
    path.write_bytes(b" " + canonical_json_bytes(lease.to_mapping()) + b"\n")
    with pytest.raises(FormatError, match="canonical"):
        table.release(lease, cleanup_complete=True)


@pytest.mark.parametrize("slot", [-1, 500_001])
def test_identity_slot_range_is_bounded(slot: int, tmp_path: Path) -> None:
    root = (tmp_path / "leases").resolve()
    root.mkdir()
    with pytest.raises(FormatError, match="slot"):
        IdentitySlotLeaseTable(root).acquire(
            IdentitySlotLease(slot, "job:lease-test", digest("manifest"))
        )


def test_identity_lease_rejects_invalid_binding_and_root(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="binding"):
        IdentitySlotLease(1, "", digest("manifest"))
    with pytest.raises(FormatError, match="binding"):
        IdentitySlotLease(1, "job:test", "not-a-digest")
    with pytest.raises(FormatError, match="absolute"):
        IdentitySlotLeaseTable(Path("relative-leases"))
    missing = (tmp_path / "missing").resolve()
    with pytest.raises(FormatError, match="unavailable"):
        IdentitySlotLeaseTable(missing).acquire(_lease())
    root = (tmp_path / "leases").resolve()
    root.mkdir()
    with pytest.raises(FormatError, match="slot"):
        IdentitySlotLeaseTable(root)._path(500_001)


def test_identity_write_all_handles_partial_and_zero_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes = iter((2, 2))
    monkeypatch.setattr("sova.worker.identity.os.write", lambda *_args: next(writes))
    IdentitySlotLeaseTable._write_all(1, b"data")
    monkeypatch.setattr("sova.worker.identity.os.write", lambda *_args: 0)
    with pytest.raises(OSError):
        IdentitySlotLeaseTable._write_all(1, b"data")


def test_identity_acquire_removes_partial_file_after_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _lease_root(tmp_path, monkeypatch)
    table = IdentitySlotLeaseTable(root)
    real_fsync = os.fsync
    monkeypatch.setattr(
        "sova.worker.identity.os.fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(OSError):
        table.acquire(_lease())
    assert not (root / "000007.lease").exists()
    monkeypatch.setattr("sova.worker.identity.os.fsync", real_fsync)


def test_identity_read_rejects_unsafe_empty_and_bad_digest_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _lease_root(tmp_path, monkeypatch)
    table = IdentitySlotLeaseTable(root)
    unsafe = root / "000007.lease"
    unsafe.mkdir()
    with pytest.raises(FormatError, match="unsafe"):
        table._read(unsafe)
    unsafe.rmdir()
    unsafe.write_bytes(b"")
    unsafe.chmod(0o600)  # Match the writer's mode regardless of the process umask.
    with pytest.raises(FormatError, match="invalid"):
        table._read(unsafe)
    mapping = _lease().to_mapping()
    mapping["contentDigest"] = digest("other")
    unsafe.write_bytes(canonical_json_bytes(mapping) + b"\n")
    with pytest.raises(FormatError, match="content"):
        table._read(unsafe)


def test_identity_release_rejects_missing_lease(tmp_path: Path) -> None:
    root = (tmp_path / "leases").resolve()
    root.mkdir()
    with pytest.raises(FormatError, match="missing"):
        IdentitySlotLeaseTable(root).release(_lease(), cleanup_complete=True)


def test_identity_posix_root_checks_and_directory_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "leases").resolve()
    root.mkdir()
    table = IdentitySlotLeaseTable(root)

    class _Node:
        def __init__(self, *, safe: bool) -> None:
            self.safe = safe
            self.parent = self

        def lstat(self) -> SimpleNamespace:
            return SimpleNamespace(st_uid=0, st_mode=0o700 if self.safe else 0o702)

        def is_symlink(self) -> bool:
            return False

    monkeypatch.setattr("sova.worker.identity.os.name", "posix")
    table.root = _Node(safe=True)  # type: ignore[assignment]
    table._require_root_controlled()
    table.root = _Node(safe=False)  # type: ignore[assignment]
    with pytest.raises(FormatError, match="not root controlled"):
        table._require_root_controlled()

    table.root = root
    opened = Mock(return_value=123)
    fsync = Mock()
    closed = Mock()
    monkeypatch.setattr("sova.worker.identity.os.open", opened)
    monkeypatch.setattr("sova.worker.identity.os.fsync", fsync)
    monkeypatch.setattr("sova.worker.identity.os.close", closed)
    table._sync_root()
    fsync.assert_called_once_with(123)
    closed.assert_called_once_with(123)


@pytest.mark.skipif(os.name != "posix", reason="lease ownership is enforced only on POSIX")
def test_identity_unprivileged_lease_tree_is_rejected_on_posix(tmp_path: Path) -> None:
    if owner_uid() == 0:
        pytest.skip("an unprivileged process is required to own the lease tree")
    root = (tmp_path / "leases").resolve()
    root.mkdir(mode=0o700)
    table = IdentitySlotLeaseTable(root)
    with pytest.raises(FormatError, match="not root controlled"):
        table.acquire(_lease())
    assert list(root.iterdir()) == []

    lease_file = root / "000007.lease"
    lease_file.write_bytes(canonical_json_bytes(_lease().to_mapping()) + b"\n")
    lease_file.chmod(0o600)
    with pytest.raises(FormatError, match="mutable"):
        table._read(lease_file)
    with pytest.raises(FormatError, match="mutable"):
        table.release(_lease(), cleanup_complete=True)
    assert lease_file.is_file()
