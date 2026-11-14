# SPDX-License-Identifier: Apache-2.0
"""Exact-HWND native Windows computer-use surface with operator-reviewed targets.

This adapter is deliberately narrower than ambient desktop automation.  It can
inspect and send bounded click/type messages only to the OS-attested target
window and only at coordinates loaded once from an operator-reviewed UI map.
The planner sees target references, never raw coordinates.
"""

from __future__ import annotations

import ctypes
import os
import re
import time
from ctypes import wintypes
from typing import TYPE_CHECKING

from sova.community.executor_surfaces import computer_surface_generation
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import ReviewedComputerTarget
from sova.runtime.computer_surface import ComputerSurfaceSnapshot, ManagedComputerSurface
from sova.runtime.window_recording import capture_attested_window_bmp

if TYPE_CHECKING:
    from collections.abc import Callable

    from sova.community.executor_engine import EngineSurfaceGeneration
    from sova.executors import ExecutionContext
    from sova.runtime.software_target import SoftwareTargetAttestation

_MAX_TARGETS = 256
_MAX_COORDINATE = 32_767
_MAX_TEXT_CODE_UNITS = 16_384
_VERSION = "0.1"
_READ_ACTION = "computer.inspect"
_ADMITTED_MUTATIONS = frozenset({"computer.click", "computer.type"})
_WM_LBUTTONDOWN = 0x0201
_WM_LBUTTONUP = 0x0202
_WM_CHAR = 0x0102
_MK_LBUTTON = 0x0001
_SMTO_ABORTIFHUNG = 0x0002
_MAX_CONTROL_TEXT_CHARS = 256
_SAFE_REF_PART = re.compile(r"[^a-z0-9_-]+")


def native_window_targets_from_mapping(value: object) -> tuple[ReviewedComputerTarget, ...]:
    """Parse one inert, explicit coordinate map prepared by the target operator."""
    if not isinstance(value, dict) or set(value) != {
        "artifactType",
        "schemaVersion",
        "targets",
    }:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-MAP",
            "native window map must contain artifactType, schemaVersion, and targets",
        )
    rows = value.get("targets")
    if (
        value.get("artifactType") != "sova.native-window-map"
        or value.get("schemaVersion") != "0.1.0"
        or not isinstance(rows, list)
        or not 1 <= len(rows) <= _MAX_TARGETS
    ):
        raise FormatError(
            "SOVA-NATIVE-WINDOW-MAP",
            "native window map type, version, or target count is invalid",
        )
    targets: list[ReviewedComputerTarget] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"reference", "actions", "x", "y"}:
            raise FormatError(
                "SOVA-NATIVE-WINDOW-MAP",
                "native window target must contain reference, actions, x, and y",
            )
        actions = row.get("actions")
        reference = row.get("reference")
        x = row.get("x")
        y = row.get("y")
        if (
            not isinstance(reference, str)
            or not isinstance(actions, list)
            or not actions
            or not all(isinstance(action, str) for action in actions)
            or not set(actions) <= _ADMITTED_MUTATIONS
            or len(actions) != len(set(actions))
            or isinstance(x, bool)
            or not isinstance(x, int)
            or isinstance(y, bool)
            or not isinstance(y, int)
            or not 0 <= x <= _MAX_COORDINATE
            or not 0 <= y <= _MAX_COORDINATE
        ):
            raise FormatError(
                "SOVA-NATIVE-WINDOW-MAP",
                "native window target actions or coordinates are invalid",
            )
        targets.append(
            ReviewedComputerTarget(
                reference,
                tuple(actions),
                {"x": x, "y": y},
            )
        )
    ordered = tuple(sorted(targets, key=lambda item: item.reference))
    if len({item.reference for item in ordered}) != len(ordered):
        raise FormatError(
            "SOVA-NATIVE-WINDOW-MAP",
            "native window target references must be unique",
        )
    return ordered


def _send_message(
    window_id: int,
    message: int,
    wparam: int,
    lparam: int,
    timeout_seconds: float,
) -> None:
    if os.name != "nt":
        raise FormatError(
            "SOVA-NATIVE-WINDOW-PLATFORM",
            "native exact-window computer use is available only on Windows",
        )
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    user32.SendMessageTimeoutW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_size_t),
    )
    user32.SendMessageTimeoutW.restype = wintypes.LPARAM
    result = ctypes.c_size_t()
    timeout_ms = max(1, min(5000, int(timeout_seconds * 1000)))
    delivered = user32.SendMessageTimeoutW(
        window_id,
        message,
        wparam,
        lparam,
        _SMTO_ABORTIFHUNG,
        timeout_ms,
        ctypes.byref(result),
    )
    if not delivered:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-MESSAGE",
            "the attested target window did not process a bounded computer action",
        )


def _bound_child_at_point(
    attestation: SoftwareTargetAttestation,
    x: int,
    y: int,
) -> tuple[int, int, int]:
    """Resolve only a visible/enabled descendant of the exact attested HWND."""
    if os.name != "nt" or attestation.window_id is None:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-PLATFORM",
            "native exact-window child resolution is unavailable",
        )
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    user32.ChildWindowFromPointEx.argtypes = (
        wintypes.HWND,
        wintypes.POINT,
        wintypes.UINT,
    )
    user32.ChildWindowFromPointEx.restype = wintypes.HWND
    user32.IsChild.argtypes = (wintypes.HWND, wintypes.HWND)
    user32.IsChild.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.MapWindowPoints.argtypes = (
        wintypes.HWND,
        wintypes.HWND,
        ctypes.POINTER(wintypes.POINT),
        wintypes.UINT,
    )
    user32.MapWindowPoints.restype = ctypes.c_int
    point = wintypes.POINT(x, y)
    # CWP_SKIPINVISIBLE | CWP_SKIPDISABLED prevents selection of a control the
    # reviewed human could not currently operate.
    child = user32.ChildWindowFromPointEx(attestation.window_id, point, 0x0001 | 0x0002)
    target = int(child or attestation.window_id)
    if target != attestation.window_id and not user32.IsChild(attestation.window_id, target):
        raise FormatError(
            "SOVA-NATIVE-WINDOW-BINDING",
            "reviewed coordinate resolved outside the attested target window",
        )
    owner_pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(target, ctypes.byref(owner_pid))
    if owner_pid.value != attestation.pid:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-BINDING",
            "reviewed coordinate resolved to another process",
        )
    if target != attestation.window_id:
        user32.MapWindowPoints(attestation.window_id, target, ctypes.byref(point), 1)
    return target, int(point.x), int(point.y)


def _control_reference(class_name: str, control_id: int, ordinal: int) -> str:
    safe_class = _SAFE_REF_PART.sub("-", class_name.casefold()).strip("-") or "control"
    identity = f"id-{control_id}" if control_id > 0 else f"ordinal-{ordinal}"
    return f"win32:{safe_class}:{identity}"[:255]


def _discover_owned_controls(
    attestation: SoftwareTargetAttestation,
) -> tuple[ReviewedComputerTarget, ...]:
    """Enumerate visible enabled descendants of only the attested root HWND."""
    if os.name != "nt" or attestation.window_id is None:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-PLATFORM",
            "native exact-window control discovery is available only on Windows",
        )
    attestation.assert_still_live()
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)  # type: ignore[attr-defined,unused-ignore]
    user32.EnumChildWindows.argtypes = (wintypes.HWND, callback_type, wintypes.LPARAM)
    user32.EnumChildWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.IsWindowEnabled.argtypes = (wintypes.HWND,)
    user32.IsWindowEnabled.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetDlgCtrlID.argtypes = (wintypes.HWND,)
    user32.GetDlgCtrlID.restype = ctypes.c_int
    user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.ScreenToClient.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.POINT))
    user32.ScreenToClient.restype = wintypes.BOOL
    rows: list[tuple[str, int, int, tuple[str, ...]]] = []

    def collect(window: int, _lparam: int) -> bool:
        if len(rows) >= _MAX_TARGETS:
            return False
        owner_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner_pid))
        if (
            owner_pid.value != attestation.pid
            or not user32.IsWindowVisible(window)
            or not user32.IsWindowEnabled(window)
        ):
            return True
        rect = wintypes.RECT()
        class_buffer = ctypes.create_unicode_buffer(_MAX_CONTROL_TEXT_CHARS)
        if not user32.GetWindowRect(window, ctypes.byref(rect)) or not user32.GetClassNameW(
            window,
            class_buffer,
            len(class_buffer),
        ):
            return True
        center = wintypes.POINT((rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2)
        if not user32.ScreenToClient(attestation.window_id, ctypes.byref(center)):
            return True
        if not 0 <= center.x <= _MAX_COORDINATE or not 0 <= center.y <= _MAX_COORDINATE:
            return True
        class_name = class_buffer.value
        actions = (
            ("computer.click", "computer.type")
            if "edit" in class_name.casefold()
            else ("computer.click",)
        )
        rows.append(
            (
                _control_reference(class_name, int(user32.GetDlgCtrlID(window)), len(rows)),
                int(center.x),
                int(center.y),
                actions,
            )
        )
        return True

    ctypes.set_last_error(0)  # type: ignore[attr-defined,unused-ignore]
    callback = callback_type(collect)
    completed = user32.EnumChildWindows(attestation.window_id, callback, 0)
    error = ctypes.get_last_error()  # type: ignore[attr-defined,unused-ignore]
    if not completed and len(rows) < _MAX_TARGETS and error:
        raise FormatError(
            "SOVA-NATIVE-WINDOW-DISCOVERY",
            "the attested target control tree could not be enumerated",
        )
    targets = tuple(
        ReviewedComputerTarget(reference, actions, {"x": x, "y": y})
        for reference, x, y, actions in rows
    )
    if len({item.reference for item in targets}) != len(targets):
        # Duplicate Win32 control IDs are legal. Fall back to an ordinal suffix
        # without exposing raw HWNDs or coordinates in the planner reference.
        targets = tuple(
            ReviewedComputerTarget(
                f"{item.reference}:n-{index}"[:255],
                item.actions,
                item.canonical_locator(),
            )
            for index, item in enumerate(targets)
        )
    return targets


class NativeWindowsComputerExecutor:
    """Send target-bound messages while continuously re-attesting the HWND."""

    def __init__(
        self,
        attestation: SoftwareTargetAttestation,
        mutations: tuple[str, ...],
    ) -> None:
        if (
            attestation.window_id is None
            or attestation.window_handle_digest is None
            or not mutations
            or len(mutations) != len(set(mutations))
            or not set(mutations) <= _ADMITTED_MUTATIONS
        ):
            raise FormatError(
                "SOVA-NATIVE-WINDOW-CONTRACT",
                "native computer executor requires an attested HWND and reviewed mutations",
            )
        self._attestation = attestation
        self._mutations = mutations
        self._closed = False

    @property
    def name(self) -> str:
        return "sova-native-windows-exact-window"

    def capabilities(self) -> tuple[Capability, ...]:
        capabilities = [
            Capability(
                _READ_ACTION,
                _VERSION,
                SideEffect.READ,
                idempotent=True,
                evidence=("ui-state",),
            )
        ]
        capabilities.extend(
            Capability(
                action,
                _VERSION,
                SideEffect.MUTATE,
                idempotent=False,
                evidence=("ui-state-before", "ui-state-after"),
            )
            for action in self._mutations
        )
        return tuple(sorted(capabilities, key=lambda item: item.identifier))

    def _validate_binding(self, request: ActionRequest) -> tuple[int, int]:
        window_id = request.inputs.get("windowId")
        pid = request.inputs.get("pid")
        x = request.inputs.get("x")
        y = request.inputs.get("y")
        if (
            window_id != self._attestation.window_id
            or pid != self._attestation.pid
            or isinstance(x, bool)
            or not isinstance(x, int)
            or isinstance(y, bool)
            or not isinstance(y, int)
            or not 0 <= x <= _MAX_COORDINATE
            or not 0 <= y <= _MAX_COORDINATE
        ):
            raise FormatError(
                "SOVA-NATIVE-WINDOW-BINDING",
                "computer action differs from the reviewed target/window binding",
            )
        return x, y

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        if self._closed:
            raise FormatError("SOVA-NATIVE-WINDOW-CLOSED", "native computer executor is closed")
        capability = next(
            (item for item in self.capabilities() if item.name == request.action),
            None,
        )
        if capability is None:
            raise FormatError(
                "SOVA-NATIVE-WINDOW-ACTION",
                "native computer action is outside the reviewed algebra",
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                capability.side_effect,
                {},
            )
        self._attestation.assert_still_live()
        if request.action == _READ_ACTION:
            bmp = capture_attested_window_bmp(self._attestation)
            return ActionOutcome(
                request.id,
                OutcomeStatus.SUCCEEDED,
                SideEffect.READ,
                {"frameDigest": sha256_digest(bmp), "windowBound": True},
                verification="exact-attested-window-frame",
            )
        x, y = self._validate_binding(request)
        click_window, click_x, click_y = _bound_child_at_point(self._attestation, x, y)
        packed = ((click_y & 0xFFFF) << 16) | (click_x & 0xFFFF)
        _send_message(click_window, _WM_LBUTTONDOWN, _MK_LBUTTON, packed, request.timeout_seconds)
        _send_message(click_window, _WM_LBUTTONUP, 0, packed, request.timeout_seconds)
        units: list[int] = []
        if request.action == "computer.type":
            text = request.inputs.get("text")
            if not isinstance(text, str) or "\x00" in text:
                raise FormatError(
                    "SOVA-NATIVE-WINDOW-TEXT",
                    "native window typing requires bounded valid text",
                )
            encoded = text.encode("utf-16-le", errors="strict")
            units = [
                int.from_bytes(encoded[index : index + 2], "little")
                for index in range(0, len(encoded), 2)
            ]
            if len(units) > _MAX_TEXT_CODE_UNITS:
                raise FormatError(
                    "SOVA-NATIVE-WINDOW-TEXT",
                    "native window typing exceeds the UTF-16 code-unit limit",
                )
            for unit in units:
                _send_message(click_window, _WM_CHAR, unit, 1, request.timeout_seconds)
        # Give the target message loop one bounded scheduling window before the
        # independent post-action screenshot is taken by ManagedComputerSurface.
        time.sleep(min(0.05, request.timeout_seconds / 4))
        self._attestation.assert_still_live()
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {
                "windowBound": True,
                "messageDelivered": True,
                "typedCodeUnits": 0 if request.action == "computer.click" else len(units),
            },
            verification="exact-attested-window-message-and-post-state",
        )

    def close(self) -> None:
        self._closed = True


def native_windows_computer_surface_factory(
    targets: tuple[ReviewedComputerTarget, ...],
) -> Callable[[SoftwareTargetAttestation, str], EngineSurfaceGeneration]:
    """Return a software-engine factory bound to one immutable reviewed UI map."""
    if (
        not isinstance(targets, tuple)
        or not targets
        or any(type(item) is not ReviewedComputerTarget for item in targets)
    ):
        raise FormatError(
            "SOVA-NATIVE-WINDOW-CONTRACT",
            "native computer surface requires immutable reviewed targets",
        )
    detached = strict_json_loads(
        canonical_json_bytes(
            [
                {
                    "reference": item.reference,
                    "actions": list(item.actions),
                    "locator": item.canonical_locator(),
                }
                for item in targets
            ]
        )
    )
    if not isinstance(detached, list):  # pragma: no cover - encoded source is a list
        raise TypeError
    immutable_targets = tuple(
        ReviewedComputerTarget(
            item["reference"],
            tuple(item["actions"]),
            item["locator"],
        )
        for item in detached
    )
    mutations = tuple(sorted({action for item in immutable_targets for action in item.actions}))

    def factory(
        attestation: SoftwareTargetAttestation,
        identity_digest: str,
    ) -> EngineSurfaceGeneration:
        executor = NativeWindowsComputerExecutor(attestation, mutations)

        def snapshot() -> ComputerSurfaceSnapshot:
            bmp = capture_attested_window_bmp(attestation)
            return ComputerSurfaceSnapshot(
                {
                    "captureMethod": "windows-gdi-exact-attested-hwnd/0.1",
                    "frameDigest": sha256_digest(bmp),
                    "windowHandleDigest": attestation.window_handle_digest,
                    "processStartDigest": attestation.process_start_digest,
                    "targetMapDigest": sha256_digest(canonical_json_bytes(detached)),
                },
                immutable_targets,
            )

        surface = ManagedComputerSurface(
            executor=executor,
            kind="window",
            identity_digest=identity_digest,
            snapshot=snapshot,
            pid=attestation.pid,
            window_id=attestation.window_id,
            mutations=mutations,
        )
        return computer_surface_generation(surface)

    return factory


def native_windows_discovery_surface_factory() -> Callable[
    [SoftwareTargetAttestation, str], EngineSurfaceGeneration
]:
    """Build a dynamic exact-HWND surface from trusted Win32 control discovery."""

    def factory(
        attestation: SoftwareTargetAttestation,
        identity_digest: str,
    ) -> EngineSurfaceGeneration:
        mutations = ("computer.click", "computer.type")
        executor = NativeWindowsComputerExecutor(attestation, mutations)

        def snapshot() -> ComputerSurfaceSnapshot:
            targets = _discover_owned_controls(attestation)
            bmp = capture_attested_window_bmp(attestation)
            target_document = [
                {
                    "reference": item.reference,
                    "actions": list(item.actions),
                    "locator": item.canonical_locator(),
                }
                for item in targets
            ]
            return ComputerSurfaceSnapshot(
                {
                    "captureMethod": "windows-gdi-exact-attested-hwnd/0.1",
                    "controlDiscovery": "win32-visible-enabled-owned-descendants/0.1",
                    "frameDigest": sha256_digest(bmp),
                    "windowHandleDigest": attestation.window_handle_digest,
                    "processStartDigest": attestation.process_start_digest,
                    "targetMapDigest": sha256_digest(canonical_json_bytes(target_document)),
                    "targetCount": len(targets),
                },
                targets,
            )

        surface = ManagedComputerSurface(
            executor=executor,
            kind="window",
            identity_digest=identity_digest,
            snapshot=snapshot,
            pid=attestation.pid,
            window_id=attestation.window_id,
            mutations=mutations,
        )
        return computer_surface_generation(surface)

    return factory


__all__ = [
    "NativeWindowsComputerExecutor",
    "native_window_targets_from_mapping",
    "native_windows_computer_surface_factory",
    "native_windows_discovery_surface_factory",
]
