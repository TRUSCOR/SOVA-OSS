# SPDX-License-Identifier: Apache-2.0
"""Measured process/window identity for authorized local software targets."""

from __future__ import annotations

import ctypes
import hashlib
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_DIGEST_CHUNK_BYTES = 1024 * 1024
_MAX_WINDOW_WAIT_SECONDS = 120.0
_MAX_WINDOW_TITLE_SELECTOR_CHARACTERS = 256


def _file_digest(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-EXECUTABLE",
            "software executable must be one existing regular non-link file",
        )
    size = path.stat().st_size
    if size < 1 or size > _MAX_EXECUTABLE_BYTES:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-EXECUTABLE",
            "software executable size is outside the measured admission limit",
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_DIGEST_CHUNK_BYTES):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}", size


def _same_path(left: Path, right: Path) -> bool:
    left_value = str(left.resolve())
    right_value = str(right.resolve())
    return (
        left_value.casefold() == right_value.casefold()
        if os.name == "nt"
        else left_value == right_value
    )


def _windows_process_identity(pid: int) -> tuple[Path, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    process_query_limited_information = 0x1000
    handle = kernel32.OpenProcess(
        process_query_limited_information,
        wintypes.BOOL(0),
        pid,
    )
    if not handle:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-PROCESS",
            "software target process is absent or cannot be identity-queried",
        )
    try:
        capacity = wintypes.DWORD(32_768)
        buffer = ctypes.create_unicode_buffer(capacity.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-PROCESS",
                "software target executable identity could not be queried",
            )
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-PROCESS",
                "software target process generation could not be queried",
            )
        creation_ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return Path(buffer.value).resolve(), creation_ticks
    finally:
        kernel32.CloseHandle(handle)


def _windows_window_identity(window_id: int, pid: int) -> tuple[str, str]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    user32.IsWindow.argtypes = (wintypes.HWND,)
    user32.IsWindow.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextW.restype = ctypes.c_int
    if not user32.IsWindow(window_id):
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-WINDOW",
            "software target window handle is not live",
        )
    owner_pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(window_id, ctypes.byref(owner_pid))
    if owner_pid.value != pid:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-WINDOW",
            "software target window belongs to another process generation",
        )
    length = user32.GetWindowTextLengthW(window_id)
    title = ctypes.create_unicode_buffer(max(1, length + 1))
    user32.GetWindowTextW(window_id, title, len(title))
    title_digest = sha256_digest(title.value.encode("utf-8"))
    handle_digest = sha256_digest(canonical_json_bytes({"pid": pid, "windowId": window_id}))
    return handle_digest, title_digest


def _windows_owned_top_level_windows(pid: int, title_contains: str | None) -> tuple[int, ...]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    enum_callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)  # type: ignore[attr-defined,unused-ignore]
    user32.EnumWindows.argtypes = (enum_callback, wintypes.LPARAM)
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextW.restype = ctypes.c_int
    matches: list[int] = []
    expected = None if title_contains is None else title_contains.casefold()

    @enum_callback  # type: ignore[untyped-decorator]
    def visit(window: int, _parameter: int) -> bool:
        owner_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner_pid))
        if owner_pid.value != pid or not user32.IsWindowVisible(window):
            return True
        length = user32.GetWindowTextLengthW(window)
        title = ctypes.create_unicode_buffer(max(1, length + 1))
        user32.GetWindowTextW(window, title, len(title))
        if expected is None or expected in title.value.casefold():
            matches.append(int(window))
        return True

    ctypes.set_last_error(0)  # type: ignore[attr-defined,unused-ignore]
    completed = bool(user32.EnumWindows(visit, 0))
    error_code = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
    # Win32 documents a zero return both for a real API failure and when an
    # enumeration callback stops. Some isolated/initializing window stations
    # also report zero with GetLastError unchanged. Our callback never stops;
    # therefore only a non-zero OS error is fatal, while an empty transient
    # enumeration is retried by wait_for_owned_window.
    if not completed and error_code != 0:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-WINDOW",
            "top-level software windows could not be enumerated",
            details={"windowsError": error_code},
        )
    return tuple(sorted(matches))


def wait_for_owned_window(
    pid: int,
    *,
    title_contains: str | None = None,
    timeout_seconds: float = 30.0,
) -> int:
    """Wait for one unambiguous visible top-level window owned by the exact pid."""
    if os.name != "nt":
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-WINDOW",
            "owned top-level window discovery is available only on Windows",
        )
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > _MAX_WINDOW_WAIT_SECONDS
        or (
            title_contains is not None
            and (not title_contains or len(title_contains) > _MAX_WINDOW_TITLE_SELECTOR_CHARACTERS)
        )
    ):
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-WINDOW",
            "window discovery requires a pid, bounded timeout, and optional bounded title selector",
        )
    deadline = time.monotonic() + float(timeout_seconds)
    while time.monotonic() < deadline:
        matches = _windows_owned_top_level_windows(pid, title_contains)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-WINDOW",
                "window selector is ambiguous for the admitted target process",
            )
        time.sleep(0.05)
    raise FormatError(
        "SOVA-SOFTWARE-ATTESTATION-WINDOW",
        "admitted target did not expose a matching window before the startup deadline",
    )


def _procfs_process_identity(pid: int) -> tuple[Path, int]:
    executable_link = Path(f"/proc/{pid}/exe")
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        executable = executable_link.resolve(strict=True)
        fields = stat_path.read_text(encoding="utf-8").split()
        start_ticks = int(fields[21])
    except (OSError, ValueError, IndexError) as error:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-PROCESS",
            "software target process is absent or cannot be identity-queried",
        ) from error
    return executable, start_ticks


@dataclass(frozen=True, slots=True)
class SoftwareTargetAttestation:
    """Fresh measured identity for one process and optional owned top-level window."""

    pid: int
    executable_name: str
    executable_digest: str
    executable_size: int
    process_start_digest: str
    window_id: int | None
    window_handle_digest: str | None
    window_title_digest: str | None
    method: str
    code_signature_measured: bool
    _executable_path: Path

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    @property
    def executable_path_for_executor(self) -> Path:
        return self._executable_path

    @property
    def generation_digest(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "pid": self.pid,
                    "executableDigest": self.executable_digest,
                    "processStartDigest": self.process_start_digest,
                    "windowId": self.window_id,
                    "windowHandleDigest": self.window_handle_digest,
                }
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.software-target-attestation",
            "schemaVersion": "0.1.0",
            "pid": self.pid,
            "executableName": self.executable_name,
            "executableDigest": self.executable_digest,
            "executableSize": self.executable_size,
            "processStartDigest": self.process_start_digest,
            "windowId": self.window_id,
            "windowHandleDigest": self.window_handle_digest,
            "windowTitleDigest": self.window_title_digest,
            "method": self.method,
            "codeSignatureMeasured": self.code_signature_measured,
            "rawExecutablePathCaptured": False,
        }

    def assert_still_live(self) -> None:
        current = attest_software_target(
            self._executable_path,
            pid=self.pid,
            window_id=self.window_id,
        )
        if current.generation_digest != self.generation_digest:
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-STALE",
                "software target process or window generation changed after admission",
            )


def attest_software_target(
    executable: Path,
    *,
    pid: int,
    window_id: int | None = None,
) -> SoftwareTargetAttestation:
    """Measure the OS-owned executable, creation generation, and optional window owner."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-PROCESS",
            "software target pid must be a positive integer",
        )
    expected = executable.resolve()
    expected_digest, size = _file_digest(expected)
    if os.name == "nt":
        observed, start_value = _windows_process_identity(pid)
        method = "windows-process-image-times-window-owner/0.1"
    elif Path("/proc").is_dir():
        if window_id is not None:
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-WINDOW",
                "window identity attestation is not implemented on this platform",
            )
        observed, start_value = _procfs_process_identity(pid)
        method = "procfs-executable-starttime/0.1"
    else:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-PLATFORM",
            "software target attestation is unavailable on this platform",
        )
    if not _same_path(expected, observed):
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-SUBSTITUTION",
            "running software process executable differs from the admitted executable",
        )
    observed_digest, observed_size = _file_digest(observed)
    if observed_digest != expected_digest or observed_size != size:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-SUBSTITUTION",
            "running software executable bytes changed during admission",
        )
    process_start_digest = sha256_digest(
        canonical_json_bytes(
            {
                "pid": pid,
                "startValue": str(start_value),
                "executableDigest": expected_digest,
            }
        )
    )
    window_handle_digest: str | None = None
    window_title_digest: str | None = None
    if window_id is not None:
        if os.name != "nt":  # pragma: no cover - rejected above on procfs
            raise FormatError(
                "SOVA-SOFTWARE-ATTESTATION-WINDOW",
                "window identity attestation is unavailable on this platform",
            )
        window_handle_digest, window_title_digest = _windows_window_identity(window_id, pid)
    return SoftwareTargetAttestation(
        pid=pid,
        executable_name=expected.name,
        executable_digest=expected_digest,
        executable_size=size,
        process_start_digest=process_start_digest,
        window_id=window_id,
        window_handle_digest=window_handle_digest,
        window_title_digest=window_title_digest,
        method=method,
        code_signature_measured=False,
        _executable_path=expected,
    )


def observed_process_executable(pid: int) -> Path:
    """Return the OS-measured process image path for trusted launch orchestration."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise FormatError(
            "SOVA-SOFTWARE-ATTESTATION-PROCESS",
            "software target pid must be a positive integer",
        )
    if os.name == "nt":
        return _windows_process_identity(pid)[0]
    if Path("/proc").is_dir():
        return _procfs_process_identity(pid)[0]
    raise FormatError(
        "SOVA-SOFTWARE-ATTESTATION-PLATFORM",
        "software target attestation is unavailable on this platform",
    )


__all__ = [
    "SoftwareTargetAttestation",
    "attest_software_target",
    "observed_process_executable",
    "wait_for_owned_window",
]
