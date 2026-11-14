# SPDX-License-Identifier: Apache-2.0
"""Measured process-generation admission for local software targets."""

from __future__ import annotations

import ctypes
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime import software_target
from sova.runtime.software_target import (
    attest_software_target,
    observed_process_executable,
    wait_for_owned_window,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_PROCESS_IDENTITY_UNAVAILABLE = os.name != "nt" and not Path("/proc").is_dir()


@pytest.mark.skipif(
    _PROCESS_IDENTITY_UNAVAILABLE,
    reason="process identity attestation is unavailable on this platform",
)
def test_current_process_attestation_measures_and_revalidates_generation() -> None:
    measured_executable = observed_process_executable(os.getpid())
    attestation = attest_software_target(measured_executable, pid=os.getpid())
    assert attestation.executable_digest.startswith("sha256:")
    assert attestation.process_start_digest.startswith("sha256:")
    assert attestation.generation_digest.startswith("sha256:")
    assert attestation.to_mapping()["rawExecutablePathCaptured"] is False
    assert attestation.to_mapping()["codeSignatureMeasured"] is False
    attestation.assert_still_live()


@pytest.mark.skipif(
    _PROCESS_IDENTITY_UNAVAILABLE,
    reason="process identity attestation is unavailable on this platform",
)
def test_running_process_rejects_substituted_executable() -> None:
    other = Path(os.__file__).resolve()
    if other == Path(sys.executable).resolve():
        pytest.skip("no distinct regular fixture file is available")
    with pytest.raises(FormatError, match="differs from the admitted executable"):
        attest_software_target(other, pid=os.getpid())


def test_attestation_rejects_invalid_pid_and_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="positive integer"):
        attest_software_target(Path(sys.executable), pid=0)
    with pytest.raises(FormatError, match="existing regular"):
        attest_software_target(tmp_path / "missing.exe", pid=os.getpid())


def test_executable_digest_rejects_empty_and_oversized_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    with pytest.raises(FormatError, match="size is outside"):
        software_target._file_digest(empty)
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(b"x")
    monkeypatch.setattr(software_target, "_MAX_EXECUTABLE_BYTES", 0)
    with pytest.raises(FormatError, match="size is outside"):
        software_target._file_digest(fixture)


class _PlatformOs:
    """Present one platform name to a single module; the os module stays untouched."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> object:
        return getattr(os, attribute)


def test_window_discovery_validates_selector_ambiguity_timeout_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(software_target, "os", _PlatformOs("posix"))
    with pytest.raises(FormatError, match="available only on Windows"):
        wait_for_owned_window(1, timeout_seconds=1.0)
    # Window enumeration itself is faked below, so the selector, ambiguity and
    # deadline logic runs on every platform.
    monkeypatch.setattr(software_target, "os", _PlatformOs("nt"))
    for values in (
        {"pid": 0},
        {"pid": 1, "timeout_seconds": True},
        {"pid": 1, "timeout_seconds": 121},
        {"pid": 1, "title_contains": ""},
        {"pid": 1, "title_contains": "x" * 257},
    ):
        arguments: dict[str, Any] = {"pid": 1, "timeout_seconds": 1.0, **values}
        with pytest.raises(FormatError, match="bounded timeout"):
            wait_for_owned_window(**arguments)

    monkeypatch.setattr(
        software_target, "_windows_owned_top_level_windows", lambda *_args: (10, 11)
    )
    with pytest.raises(FormatError, match="ambiguous"):
        wait_for_owned_window(1, timeout_seconds=0.1)

    monkeypatch.setattr(software_target, "_windows_owned_top_level_windows", lambda *_args: (77,))
    assert wait_for_owned_window(1, timeout_seconds=0.1) == 77

    moments = iter((0.0, 0.0, 0.2))
    monkeypatch.setattr(time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(software_target, "_windows_owned_top_level_windows", lambda *_args: ())
    with pytest.raises(FormatError, match="startup deadline"):
        wait_for_owned_window(1, timeout_seconds=0.1)


def test_attestation_detects_stale_generation_and_byte_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "owned.exe"
    executable.write_bytes(b"owned")
    attestation = software_target.SoftwareTargetAttestation(
        pid=10,
        executable_name=executable.name,
        executable_digest="sha256:" + "1" * 64,
        executable_size=5,
        process_start_digest="sha256:" + "2" * 64,
        window_id=None,
        window_handle_digest=None,
        window_title_digest=None,
        method="fixture",
        code_signature_measured=False,
        _executable_path=executable,
    )
    original_attest = software_target.attest_software_target
    monkeypatch.setattr(
        software_target,
        "attest_software_target",
        lambda *_args, **_kwargs: replace(attestation, process_start_digest="sha256:" + "3" * 64),
    )
    with pytest.raises(FormatError, match="generation changed"):
        attestation.assert_still_live()
    monkeypatch.setattr(software_target, "attest_software_target", original_attest)

    calls = 0

    def digest(_path: Path) -> tuple[str, int]:
        nonlocal calls
        calls += 1
        return ("sha256:" + ("a" if calls == 1 else "b") * 64, 5)

    monkeypatch.setattr(software_target, "_file_digest", digest)
    if _PROCESS_IDENTITY_UNAVAILABLE:
        # Without Windows process APIs or procfs the measurement fails closed
        # before any executable bytes could be compared.
        with pytest.raises(FormatError, match="unavailable on this platform"):
            software_target.attest_software_target(executable, pid=10)
        return
    if os.name == "nt":
        monkeypatch.setattr(
            software_target, "_windows_process_identity", lambda _pid: (executable, 123)
        )
    else:
        monkeypatch.setattr(
            software_target, "_procfs_process_identity", lambda _pid: (executable, 123)
        )
    with pytest.raises(FormatError, match="bytes changed"):
        software_target.attest_software_target(executable, pid=10)


def test_observed_process_executable_rejects_invalid_pid() -> None:
    for pid in (0, -1, True):
        with pytest.raises(FormatError, match="positive integer"):
            observed_process_executable(pid)


class _ForeignFunction:
    """Stand-in for a ctypes foreign function that accepts argtypes/restype."""

    def __init__(self, behaviour: Callable[..., object]) -> None:
        self.behaviour = behaviour
        self.calls = 0

    def __call__(self, *args: object) -> object:
        self.calls += 1
        return self.behaviour(*args)


def _install_dll(monkeypatch: pytest.MonkeyPatch, library: object) -> None:
    # The Win32 bindings are driven through fakes so their fail-closed branches
    # run on every platform; ctypes.WinDLL exists only on Windows.
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: library, raising=False)


def _kernel32(
    image: str, *, handle: int = 77, image_ok: bool = True, times_ok: bool = True
) -> SimpleNamespace:
    def query(_handle: object, _flags: object, buffer: Any, _size: object) -> int:
        buffer.value = image
        return int(image_ok)

    def times(_handle: object, creation: Any, *_rest: object) -> int:
        creation._obj.dwHighDateTime = 1
        creation._obj.dwLowDateTime = 2
        return int(times_ok)

    return SimpleNamespace(
        OpenProcess=_ForeignFunction(lambda *_args: handle),
        QueryFullProcessImageNameW=_ForeignFunction(query),
        GetProcessTimes=_ForeignFunction(times),
        CloseHandle=_ForeignFunction(lambda _handle: 1),
    )


def test_windows_process_identity_binding_measures_image_and_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = tmp_path / "owned.exe"
    image.write_bytes(b"owned")
    absent = _kernel32(str(image), handle=0)
    _install_dll(monkeypatch, absent)
    with pytest.raises(FormatError, match="absent or cannot be identity-queried"):
        software_target._windows_process_identity(10)
    assert absent.CloseHandle.calls == 0

    for kernel, message in (
        (_kernel32(str(image), image_ok=False), "executable identity could not be queried"),
        (_kernel32(str(image), times_ok=False), "generation could not be queried"),
    ):
        _install_dll(monkeypatch, kernel)
        with pytest.raises(FormatError, match=message):
            software_target._windows_process_identity(10)
        assert kernel.CloseHandle.calls == 1

    measured = _kernel32(str(image))
    _install_dll(monkeypatch, measured)
    assert software_target._windows_process_identity(10) == (image.resolve(), (1 << 32) | 2)
    assert measured.CloseHandle.calls == 1


def _user32(windows: dict[int, tuple[int, bool, str]], *, live: bool = True) -> SimpleNamespace:
    def owner(window: int, pid: Any) -> int:
        pid._obj.value = windows[window][0]
        return 1

    def text(window: int, buffer: Any, _length: object) -> int:
        buffer.value = windows[window][2]
        return len(buffer.value)

    return SimpleNamespace(
        IsWindow=_ForeignFunction(lambda _window: int(live)),
        IsWindowVisible=_ForeignFunction(lambda window: int(windows[window][1])),
        GetWindowThreadProcessId=_ForeignFunction(owner),
        GetWindowTextLengthW=_ForeignFunction(lambda window: len(windows[window][2])),
        GetWindowTextW=_ForeignFunction(text),
    )


def test_windows_window_identity_binding_requires_live_owned_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows = {5: (10, True, "Owned App"), 6: (11, True, "Other App")}
    _install_dll(monkeypatch, _user32(windows, live=False))
    with pytest.raises(FormatError, match="not live"):
        software_target._windows_window_identity(5, 10)

    _install_dll(monkeypatch, _user32(windows))
    with pytest.raises(FormatError, match="another process generation"):
        software_target._windows_window_identity(6, 10)
    assert software_target._windows_window_identity(5, 10) == (
        sha256_digest(canonical_json_bytes({"pid": 10, "windowId": 5})),
        sha256_digest(b"Owned App"),
    )


def test_windows_top_level_window_binding_filters_owner_visibility_and_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows = {
        21: (99, True, "Owned App"),
        22: (10, False, "Owned App"),
        23: (10, True, "Owned App - main"),
        24: (10, True, "Settings"),
    }
    user32 = _user32(windows)
    outcome = {"completed": 1, "error": 0}

    def enumerate_windows(callback: Callable[[int, int], object], _parameter: object) -> int:
        for window in windows:
            callback(window, 0)
        return outcome["completed"]

    user32.EnumWindows = _ForeignFunction(enumerate_windows)
    _install_dll(monkeypatch, user32)
    if not hasattr(ctypes, "WINFUNCTYPE"):
        monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
    monkeypatch.setattr(ctypes, "set_last_error", lambda _value: 0, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: outcome["error"], raising=False)

    assert software_target._windows_owned_top_level_windows(10, None) == (23, 24)
    assert software_target._windows_owned_top_level_windows(10, "OWNED app") == (23,)
    # A zero return with an unchanged last error is a transient empty enumeration.
    outcome["completed"] = 0
    assert software_target._windows_owned_top_level_windows(10, "settings") == (24,)
    outcome["error"] = 5
    with pytest.raises(FormatError, match="could not be enumerated") as captured:
        software_target._windows_owned_top_level_windows(10, None)
    assert captured.value.issue.details == {"windowsError": 5}
