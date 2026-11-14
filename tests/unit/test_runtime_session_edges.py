# SPDX-License-Identifier: Apache-2.0
"""Fail-closed profile-vault and cross-process lease edge tests."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sova.formats.errors import FormatError
from sova.runtime import sessions
from sova.runtime.sessions import BrowserProfileVault


def test_windows_pid_probe_fails_closed_when_platform_apis_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ctypes.WinDLL and ctypes.get_last_error exist only on Windows; the probe is
    # driven through fakes so its fail-closed branches run on every platform.
    monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)
    assert sessions._windows_pid_is_alive(42) is True

    class _Function:
        def __init__(self, result: object) -> None:
            self.result = result

        def __call__(self, *_args: object) -> object:
            return self.result

    kernel = SimpleNamespace(
        OpenProcess=_Function(0),
        GetExitCodeProcess=_Function(0),
        CloseHandle=_Function(1),
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: kernel, raising=False)
    monkeypatch.delattr(ctypes, "get_last_error", raising=False)
    assert sessions._windows_pid_is_alive(42) is True

    kernel.OpenProcess.result = 1
    assert sessions._windows_pid_is_alive(42) is True

    # Only ERROR_INVALID_PARAMETER proves absence; any other open failure stays live.
    kernel.OpenProcess.result = 0
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87, raising=False)
    assert sessions._windows_pid_is_alive(42) is False
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    assert sessions._windows_pid_is_alive(42) is True

    class _ExitCode:
        def __init__(self, code: int) -> None:
            self.code = code

        def __call__(self, _handle: object, exit_code: Any) -> int:
            exit_code._obj.value = self.code
            return 1

    kernel.OpenProcess.result = 1
    kernel.GetExitCodeProcess = _ExitCode(259)
    assert sessions._windows_pid_is_alive(42) is True
    kernel.GetExitCodeProcess = _ExitCode(0)
    assert sessions._windows_pid_is_alive(42) is False


def test_profile_root_handle_identity_symlink_and_metadata_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_is_symlink = Path.is_symlink
    root = (tmp_path / "rejected-root").resolve()
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path.resolve() == root or original_is_symlink(path),
    )
    with pytest.raises(FormatError, match="real directory"):
        BrowserProfileVault(root)
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    vault = BrowserProfileVault(tmp_path / "profiles")
    for handle in ("bad", "profile:" + "g" * 32):
        with pytest.raises(FormatError, match="malformed"):
            vault.path_for_executor(handle)
    handle = "profile:" + "a" * 32
    with pytest.raises(FormatError, match="identity and target"):
        vault.provision(handle, identity_id="", target="owned.example")

    profile_path = vault._directory(handle)
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path.resolve() == profile_path or original_is_symlink(path),
    )
    with pytest.raises(FormatError, match="directory is a symlink"):
        vault.provision(handle, identity_id="operator", target="owned.example")
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    record = vault.provision(handle, identity_id="operator", target="owned.example")
    assert vault.provision(handle, identity_id="operator", target="owned.example") == record
    metadata = profile_path / "sova-profile.json"
    metadata.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="metadata is malformed"):
        vault.path_for_executor(handle)
    metadata.write_text(json.dumps({"schemaVersion": "9"}), encoding="utf-8")
    with pytest.raises(FormatError, match="metadata is malformed"):
        vault.path_for_executor(handle)
    metadata.unlink()
    with pytest.raises(FormatError, match="was not provisioned"):
        vault.path_for_executor(handle)


def test_non_windows_pid_probe_treats_absence_as_dead_and_denial_as_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")

    def absent(_pid: int, _signal: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", absent, raising=False)
    assert BrowserProfileVault._pid_is_alive(42) is False

    def denied(_pid: int, _signal: int) -> None:
        raise PermissionError

    monkeypatch.setattr(os, "kill", denied, raising=False)
    assert BrowserProfileVault._pid_is_alive(42) is True
    monkeypatch.setattr(os, "kill", lambda _pid, _signal: None, raising=False)
    assert BrowserProfileVault._pid_is_alive(42) is True


def test_profile_lease_metadata_request_and_recovery_race_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing.lease"
    with pytest.raises(FormatError, match="changed during acquisition"):
        BrowserProfileVault._read_lease(missing)
    missing.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="lease is malformed"):
        BrowserProfileVault._read_lease(missing)
    missing.write_text(json.dumps({"schemaVersion": "9"}), encoding="utf-8")
    with pytest.raises(FormatError, match="lease is malformed"):
        BrowserProfileVault._read_lease(missing)

    vault = BrowserProfileVault(tmp_path / "profiles")
    record = vault.create(identity_id="operator", target="owned.example")
    with pytest.raises(FormatError, match="invalid browser profile lease"):
        vault.acquire(record.handle, owner_id="", ttl_seconds=1)
    with pytest.raises(FormatError, match="invalid browser profile lease"):
        vault.acquire(record.handle, owner_id="campaign", ttl_seconds=3601)

    profile = vault.path_for_executor(record.handle)
    lease_path = profile / "sova-profile.lease.json"
    lease_path.write_text("fixture", encoding="utf-8")
    first: dict[str, Any] = {
        "schemaVersion": "0.1.0",
        "leaseId": "profile-lease:stale",
        "ownerId": "old",
        "processId": 999999,
        "acquiredUnixMs": 0,
        "expiresUnixMs": 1,
    }
    changed = {**first, "leaseId": "profile-lease:replacement"}
    reads = iter((first, changed))
    monkeypatch.setattr(vault, "_read_lease", lambda _path: next(reads))
    monkeypatch.setattr(vault, "_pid_is_alive", lambda _pid: False)
    with pytest.raises(FormatError, match="changed during recovery"):
        vault.acquire(record.handle, owner_id="campaign", recover_stale=True)


def test_profile_permissions_are_narrowed_on_non_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chmod_calls: list[tuple[Path, int]] = []
    original_chmod = Path.chmod
    original_os_name = os.name
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(
        Path,
        "chmod",
        lambda path, mode: chmod_calls.append((path, mode)),
    )
    vault = BrowserProfileVault(tmp_path / "profiles")
    record = vault.create(identity_id="operator", target="owned.example")
    lease = vault.acquire(record.handle, owner_id="campaign")
    assert [mode for _path, mode in chmod_calls] == [0o700, 0o600, 0o600]
    monkeypatch.setattr(Path, "chmod", original_chmod)
    monkeypatch.setattr(os, "name", original_os_name)
    lease.release()
