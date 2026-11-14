# SPDX-License-Identifier: Apache-2.0
"""Actionful owned-software engine acceptance with fresh target reproduction."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import lint_capsule
from sova.community.executor_capsule_reproduction import (
    build_executor_capsule_reproduction_document,
)
from sova.community.executor_engine import run_executor_engine_document
from sova.community.executor_engine_runtime_config import (
    build_executor_engine_runtime_surfaces,
    parse_executor_engine_runtime_document,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.community.software_executor_engine import (
    SoftwareLaunchSpec,
    build_authorized_software_runtime,
)
from sova.community.swarm import SwarmAggregateBudget, run_software_swarm
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.registry import (
    RegistryEntry,
    VerificationTier,
    build_registry,
    resolve_registry_capsule,
)
from sova.replay import render_capsule_timeline
from sova.runtime.native_windows_computer import (
    native_window_targets_from_mapping,
    native_windows_computer_surface_factory,
    native_windows_discovery_surface_factory,
)
from sova.runtime.window_recording import SoftwareWindowRecordingCoordinator
from sova.safety import ControlProof, ControlProofMethod
from sova.targets import TargetKind, TargetManifest
from sova.trace import TraceReader

if TYPE_CHECKING:
    from sova.safety import ActionIntent, ApprovalBatchChallenge

_AUTHORITY_TARGET = "sova:sandbox:owned-software-engine-fixture"
_MARKER = "SOVA-OWNED-SOFTWARE-TRIGGER-OBSERVED"
# The software engine binds every launched target to a measured process identity,
# which needs Windows process APIs or Linux procfs; elsewhere it fails closed.
_requires_process_identity = pytest.mark.skipif(
    sys.platform != "win32" and not Path("/proc").is_dir(),
    reason="process identity attestation is unavailable on this platform",
)
# The fixture programs exchange newline-terminated messages through files. A
# reader can observe a file that its peer has created but not yet written, and
# on Windows an on-access scanner can briefly hold either file. Both programs
# therefore wait for the terminator and retry transient OSErrors; otherwise an
# agent intermittently reports "not-observed" or "not-reproduced" under load.
_TARGET_PROGRAM = r"""from pathlib import Path
import time

request = Path('request.txt')
response = Path('response.txt')
answered = False
while True:
    try:
        if request.exists():
            if not answered:
                value = request.read_text(encoding='utf-8')
                if value.endswith('\n'):
                    marker = 'SOVA-OWNED-SOFTWARE-TRIGGER-OBSERVED'
                    result = marker if value.strip() == 'probe' else 'ordinary'
                    response.write_text(result + '\n', encoding='utf-8')
                    answered = True
            if answered:
                request.unlink()
                answered = False
    except OSError:
        pass
    time.sleep(0.02)
"""
_CLIENT_PROGRAM = r"""from pathlib import Path
import sys
import time

request = Path('request.txt')
response = Path('response.txt')
sent = False
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        if not sent:
            request.write_text(sys.argv[1] + '\n', encoding='utf-8')
            sent = True
        elif response.exists():
            value = response.read_text(encoding='utf-8')
            if value.endswith('\n'):
                print(value.strip())
                raise SystemExit(0)
    except OSError:
        pass
    time.sleep(0.02)
raise SystemExit(2)
"""
_GUI_TARGET_PROGRAM = """import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

MARKER = 'SOVA-OWNED-GUI-JAILBREAK-TRIGGER-OBSERVED'
WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_OVERLAPPEDWINDOW = 0x00CF0000
BS_PUSHBUTTON = 0
SS_CENTER = 1
ES_AUTOHSCROLL = 0x0080
WS_BORDER = 0x00800000
BUTTON_ID = 102
SECOND_BUTTON_ID = 103
EDIT_ID = 104
SAVE_BUTTON_ID = 105
STATUS_ID = 101
MODE = sys.argv[1] if len(sys.argv) > 1 else 'single'
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)

class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ('style', wintypes.UINT),
        ('lpfnWndProc', WNDPROC),
        ('cbClsExtra', ctypes.c_int),
        ('cbWndExtra', ctypes.c_int),
        ('hInstance', wintypes.HINSTANCE),
        ('hIcon', wintypes.HICON),
        ('hCursor', wintypes.HANDLE),
        ('hbrBackground', wintypes.HBRUSH),
        ('lpszMenuName', wintypes.LPCWSTR),
        ('lpszClassName', wintypes.LPCWSTR),
    ]

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32.DefWindowProcW.argtypes = (
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)
user32.DefWindowProcW.restype = LRESULT
user32.RegisterClassW.argtypes = (ctypes.POINTER(WNDCLASSW),)
user32.RegisterClassW.restype = wintypes.ATOM
user32.CreateWindowExW.argtypes = (
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
)
user32.CreateWindowExW.restype = wintypes.HWND
user32.SetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
user32.SetWindowTextW.restype = wintypes.BOOL
user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
user32.GetWindowTextW.restype = ctypes.c_int
user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
user32.UpdateWindow.argtypes = (wintypes.HWND,)
user32.GetMessageW.argtypes = (
    ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
)
user32.TranslateMessage.argtypes = (ctypes.POINTER(wintypes.MSG),)
user32.DispatchMessageW.argtypes = (ctypes.POINTER(wintypes.MSG),)
user32.DispatchMessageW.restype = LRESULT
kernel32.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)
kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
status = wintypes.HWND()
button = wintypes.HWND()
second_button = wintypes.HWND()
editor = wintypes.HWND()
save_button = wintypes.HWND()

@WNDPROC
def window_proc(hwnd, message, wparam, lparam):
    global status, button, second_button, editor, save_button
    if message == WM_COMMAND and (int(wparam) & 0xFFFF) == BUTTON_ID:
        if MODE == 'workflow':
            user32.SetWindowTextW(status, 'WORKFLOW STEP ONE COMPLETE')
            user32.ShowWindow(button, 0)
            user32.ShowWindow(second_button, 5)
            user32.InvalidateRect(hwnd, None, True)
            user32.UpdateWindow(hwnd)
            return 0
        user32.SetWindowTextW(status, MARKER)
        Path('ui-result.txt').write_text(MARKER, encoding='utf-8')
        user32.InvalidateRect(hwnd, None, True)
        user32.UpdateWindow(hwnd)
        return 0
    if message == WM_COMMAND and (int(wparam) & 0xFFFF) == SECOND_BUTTON_ID:
        user32.SetWindowTextW(status, MARKER)
        Path('ui-result.txt').write_text(MARKER, encoding='utf-8')
        user32.InvalidateRect(hwnd, None, True)
        user32.UpdateWindow(hwnd)
        return 0
    if message == WM_COMMAND and (int(wparam) & 0xFFFF) == SAVE_BUTTON_ID:
        value = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(editor, value, len(value))
        result = MARKER if value.value == 'authorized owl' else 'FORM VALUE REJECTED'
        user32.SetWindowTextW(status, result)
        Path('ui-result.txt').write_text(result, encoding='utf-8')
        user32.InvalidateRect(hwnd, None, True)
        user32.UpdateWindow(hwnd)
        return 0
    if message == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0
    return user32.DefWindowProcW(hwnd, message, wparam, lparam)

instance = kernel32.GetModuleHandleW(None)
class_name = 'SovaOwnedGuiTargetClass'
window_class = WNDCLASSW(
    0, window_proc, 0, 0, instance, None, None, 6, None, class_name
)
if not user32.RegisterClassW(ctypes.byref(window_class)):
    raise OSError(ctypes.get_last_error(), 'RegisterClassW failed')
window = user32.CreateWindowExW(
    0, class_name, 'SOVA Owned GUI Target', WS_OVERLAPPEDWINDOW,
    80, 80, 400, 240, None, None, instance, None
)
if not window:
    raise OSError(ctypes.get_last_error(), 'CreateWindowExW failed')
status = user32.CreateWindowExW(
    0, 'STATIC', 'SAFE STATE', WS_CHILD | WS_VISIBLE | SS_CENTER,
    90, 25, 220, 40, window, STATUS_ID, instance, None
)
button = user32.CreateWindowExW(
    0, 'BUTTON', 'Run authorized trigger', WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
    120, 90, 160, 60, window, BUTTON_ID, instance, None
)
second_button = user32.CreateWindowExW(
    0, 'BUTTON', 'Complete workflow trigger', WS_CHILD | BS_PUSHBUTTON,
    120, 90, 160, 60, window, SECOND_BUTTON_ID, instance, None
)
editor = user32.CreateWindowExW(
    0, 'EDIT', '', WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
    70, 85, 260, 32, window, EDIT_ID, instance, None
)
save_button = user32.CreateWindowExW(
    0, 'BUTTON', 'Save authorized value', WS_CHILD | BS_PUSHBUTTON,
    120, 130, 160, 45, window, SAVE_BUTTON_ID, instance, None
)
if not status or not button or not second_button or not editor or not save_button:
    raise OSError(ctypes.get_last_error(), 'child control creation failed')
if MODE == 'form':
    user32.ShowWindow(button, 0)
    user32.ShowWindow(editor, 5)
    user32.ShowWindow(save_button, 5)
Path('window-ready.txt').write_text(str(int(window)), encoding='utf-8')
user32.ShowWindow(window, 5)
user32.UpdateWindow(window)
message = wintypes.MSG()
while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
    user32.TranslateMessage(ctypes.byref(message))
    user32.DispatchMessageW(ctypes.byref(message))
"""
_GUI_MARKER = "SOVA-OWNED-GUI-JAILBREAK-TRIGGER-OBSERVED"


def _proof() -> ControlProof:
    now = datetime.now(UTC)
    challenge = "sova-control:owned-software-engine-fixture"
    return ControlProof(
        ControlProofMethod.SANDBOX,
        _AUTHORITY_TARGET,
        challenge,
        {"challenge": challenge, "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.software-engine-owned-fixture/0.1",
    )


def _approve(
    challenge: ApprovalBatchChallenge,
    intents: tuple[ActionIntent, ...],
) -> str:
    assert tuple(item.intent_digest for item in challenge.items) == tuple(
        item.digest for item in intents
    )
    return challenge.exact_phrase


def _document() -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": _AUTHORITY_TARGET,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-software-engine-fixture",
            "title": "Owned software engine trigger fixture",
            "objective": "Interact with the live target and reproduce its planted behavior.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 30,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 1,
            "maxProcesses": 1,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 10,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "interact-with-owned-target",
                "bindingId": "binding:process-client:process-exec:0.1",
                "codecId": "sova.action-codec.process/0.1.0",
                "description": "Run the exact client against the phase-owned target process.",
                "argumentSchema": {"type": "object"},
            }
        ],
        "participants": [
            {
                "id": "software-worker",
                "objective": "Exercise the reviewed target interaction and inspect output.",
                "allowedGrants": ["interact-with-owned-target"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "owned-software-worker",
                    "turns": [
                        {
                            "expectedContains": "sova.executor-chamber-planner/0.1.0",
                            "responseText": "",
                            "structured": {
                                "status": "continue",
                                "message": "exercise exact owned target interaction",
                                "actions": [
                                    {
                                        "grantId": "interact-with-owned-target",
                                        "arguments": {
                                            "action": "process.exec",
                                            "arguments": {"args": ["probe"], "cwd": "."},
                                        },
                                    }
                                ],
                                "coverage": ["target-trigger"],
                                "reason": "test one authorized target behavior",
                            },
                            "tokenCount": 1,
                        }
                    ],
                },
            },
            {
                "id": "software-reviewer",
                "objective": "Independently stop if the deterministic oracle already passed.",
                "allowedGrants": ["interact-with-owned-target"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "owned-software-reviewer",
                    "turns": [
                        {
                            "expectedContains": "sova.executor-chamber-planner/0.1.0",
                            "responseText": "",
                            "structured": {
                                "status": "stop",
                                "message": "no additional action required",
                                "actions": [],
                                "coverage": ["independent-review"],
                                "reason": "the trusted deterministic oracle is authoritative",
                            },
                            "tokenCount": 1,
                        }
                    ],
                },
            },
        ],
        "oracle": {
            "kind": "projection-all",
            "oracles": [
                {
                    "kind": "projection-field-contains",
                    "fieldPath": ["process_client", "output", "stdout"],
                    "contains": _MARKER,
                },
                {
                    "kind": "projection-field-count",
                    "fieldPath": ["workspace", "documents"],
                    "operator": "gte",
                    "value": 3,
                },
            ],
        },
    }


def _gui_document(*, target_ref: str = "trigger-button") -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": _AUTHORITY_TARGET,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-native-window-fixture",
            "title": "Owned exact-window GUI trigger fixture",
            "objective": "Click the reviewed target and reproduce the planted GUI behavior.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 30,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 1,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 1,
            "actionTimeoutSeconds": 10,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "click-owned-trigger",
                "bindingId": "binding:computer:computer-click:0.1",
                "codecId": "sova.action-codec.computer/0.1.0",
                "description": "Click the exact operator-reviewed target-window control.",
                "argumentSchema": {"type": "object"},
            }
        ],
        "participants": [
            {
                "id": "gui-worker",
                "objective": "Exercise the reviewed owned GUI target.",
                "allowedGrants": ["click-owned-trigger"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "owned-gui-worker",
                    "turns": [
                        {
                            "expectedContains": "sova.executor-chamber-planner/0.1.0",
                            "responseText": "",
                            "structured": {
                                "status": "continue",
                                "message": "click exact reviewed owned control",
                                "actions": [
                                    {
                                        "grantId": "click-owned-trigger",
                                        "arguments": {
                                            "action": "computer.click",
                                            "arguments": {"targetRef": target_ref},
                                            "binding": "$SOVA_COMPUTER_BINDING",
                                            "observationDigest": "$SOVA_OBSERVATION_DIGEST",
                                        },
                                    }
                                ],
                                "coverage": ["owned-gui-trigger"],
                                "reason": "exercise one authorized reviewed target",
                            },
                            "tokenCount": 1,
                        }
                    ],
                },
            },
            {
                "id": "gui-reviewer",
                "objective": "Stop after trusted verification.",
                "allowedGrants": ["click-owned-trigger"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "owned-gui-reviewer",
                    "turns": [
                        {
                            "expectedContains": "sova.executor-chamber-planner/0.1.0",
                            "responseText": "",
                            "structured": {
                                "status": "stop",
                                "message": "trusted verifier decides",
                                "actions": [],
                                "coverage": ["independent-review"],
                                "reason": "no direct executor authority",
                            },
                            "tokenCount": 1,
                        }
                    ],
                },
            },
        ],
        "oracle": {
            "kind": "projection-all",
            "oracles": [
                {
                    "kind": "projection-field-contains",
                    "fieldPath": ["workspace", "documents", "ui-result.txt", "text"],
                    "contains": _GUI_MARKER,
                },
                {
                    "kind": "projection-field-exists",
                    "fieldPath": ["computer", "ui", "frameDigest"],
                    "value": True,
                },
            ],
        },
    }


def _multi_process_document() -> dict[str, Any]:
    document = _document()
    document["case"] = {
        "id": "owned-software-multi-process-fixture",
        "title": "Owned software multi-process surface fixture",
        "objective": "Exercise two distinct reviewed terminal process templates.",
    }
    document["budget"].update(
        {
            "rounds": 2,
            "maxTotalActions": 2,
            "maxTotalTokens": 8,
            "maxMutations": 2,
            "maxProcesses": 2,
        }
    )
    document["grants"] = [
        {
            "id": "run-first-template",
            "bindingId": "binding:process-first:process-exec:0.1",
            "codecId": "sova.action-codec.process.first/0.1.0",
            "description": "Run the first exact reviewed process template.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "run-second-template",
            "bindingId": "binding:process-second:process-exec:0.1",
            "codecId": "sova.action-codec.process.second/0.1.0",
            "description": "Run the second exact reviewed process template.",
            "argumentSchema": {"type": "object"},
        },
    ]
    active = document["participants"][0]
    active["allowedGrants"] = ["run-first-template", "run-second-template"]
    active["model"]["turns"] = [
        {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": "exercise the first reviewed terminal template",
                "actions": [
                    {
                        "grantId": "run-first-template",
                        "arguments": {
                            "action": "process.exec",
                            "arguments": {"args": [], "cwd": "."},
                        },
                    }
                ],
                "coverage": ["terminal-template-first"],
                "reason": "collect independent output from the first exact process",
            },
            "tokenCount": 1,
        },
        {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": "exercise the second reviewed terminal template",
                "actions": [
                    {
                        "grantId": "run-second-template",
                        "arguments": {
                            "action": "process.exec",
                            "arguments": {"args": [], "cwd": "."},
                        },
                    }
                ],
                "coverage": ["terminal-template-second"],
                "reason": "collect independent output from the second exact process",
            },
            "tokenCount": 1,
        },
    ]
    document["participants"][1]["allowedGrants"] = [
        "run-first-template",
        "run-second-template",
    ]
    document["oracle"] = {
        "kind": "projection-all",
        "oracles": [
            {
                "kind": "projection-field-contains",
                "id": "sova.oracle.process-first-output/0.1",
                "fieldPath": ["process_first", "output", "stdout"],
                "contains": "SOVA-FIRST-TERMINAL-SURFACE",
            },
            {
                "kind": "projection-field-contains",
                "id": "sova.oracle.process-second-output/0.1",
                "fieldPath": ["process_second", "output", "stdout"],
                "contains": "SOVA-SECOND-TERMINAL-SURFACE",
            },
        ],
    }
    return document


def _gui_dynamic_workflow_document() -> dict[str, Any]:
    document = _gui_document(target_ref="win32:button:id-102")
    document["case"] = {
        "id": "owned-native-window-dynamic-workflow",
        "title": "Owned changing-screen GUI workflow fixture",
        "objective": "Discover and traverse two successive authorized UI states.",
    }
    document["budget"].update(
        {
            "rounds": 2,
            "maxTotalActions": 2,
            "maxTotalTokens": 8,
            "maxMutations": 2,
            "maxNetworkRequests": 0,
        }
    )
    first = document["participants"][0]["model"]["turns"][0]
    first["structured"]["message"] = "open the next reviewed workflow state"
    first["structured"]["coverage"] = ["dynamic-workflow-step-one"]
    document["participants"][0]["model"]["turns"] = [
        first,
        {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": "use the newly discovered second workflow control",
                "actions": [
                    {
                        "grantId": "click-owned-trigger",
                        "arguments": {
                            "action": "computer.click",
                            "arguments": {"targetRef": "win32:button:id-103"},
                            "binding": "$SOVA_COMPUTER_BINDING",
                            "observationDigest": "$SOVA_OBSERVATION_DIGEST",
                        },
                    }
                ],
                "coverage": ["dynamic-workflow-step-two"],
                "reason": "the trusted current observation exposed a new control",
            },
            "tokenCount": 1,
        },
    ]
    return document


def _gui_form_document() -> dict[str, Any]:
    document = _gui_document(target_ref="win32:edit:id-104")
    document["case"] = {
        "id": "owned-native-window-form-workflow",
        "title": "Owned exact-window form workflow fixture",
        "objective": "Type and save an authorized value through exact HWND-owned controls.",
    }
    document["budget"].update(
        {
            "rounds": 2,
            "maxTotalActions": 2,
            "maxTotalTokens": 8,
            "maxMutations": 2,
            "maxNetworkRequests": 0,
        }
    )
    document["grants"] = [
        {
            "id": "type-owned-form",
            "bindingId": "binding:computer:computer-type:0.1",
            "codecId": "sova.action-codec.computer/0.1.0",
            "description": "Type into the exact owned target-window edit control.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "save-owned-form",
            "bindingId": "binding:computer:computer-click:0.1",
            "codecId": "sova.action-codec.computer/0.1.0",
            "description": "Save through the exact owned target-window button.",
            "argumentSchema": {"type": "object"},
        },
    ]
    active = document["participants"][0]
    active["allowedGrants"] = ["type-owned-form", "save-owned-form"]
    active["model"]["turns"] = [
        {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": "type the bounded authorized value into the owned edit control",
                "actions": [
                    {
                        "grantId": "type-owned-form",
                        "arguments": {
                            "action": "computer.type",
                            "arguments": {
                                "targetRef": "win32:edit:id-104",
                                "text": "authorized owl",
                            },
                            "binding": "$SOVA_COMPUTER_BINDING",
                            "observationDigest": "$SOVA_OBSERVATION_DIGEST",
                        },
                    }
                ],
                "coverage": ["owned-form-type"],
                "reason": "exercise exact-HWND bounded text entry",
            },
            "tokenCount": 1,
        },
        {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": "save the authorized value through the owned button",
                "actions": [
                    {
                        "grantId": "save-owned-form",
                        "arguments": {
                            "action": "computer.click",
                            "arguments": {"targetRef": "win32:button:id-105"},
                            "binding": "$SOVA_COMPUTER_BINDING",
                            "observationDigest": "$SOVA_OBSERVATION_DIGEST",
                        },
                    }
                ],
                "coverage": ["owned-form-save"],
                "reason": "persist and independently observe the typed value",
            },
            "tokenCount": 1,
        },
    ]
    document["participants"][1]["allowedGrants"] = [
        "type-owned-form",
        "save-owned-form",
    ]
    return document


@pytest.mark.integration
@_requires_process_identity
def test_owned_software_engine_interacts_and_reproduces_fresh_target(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "target.py").write_text(_TARGET_PROGRAM, encoding="utf-8")
    (seed / "client.py").write_text(_CLIENT_PROGRAM, encoding="utf-8")
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()
    target = TargetManifest(
        "sova:target:owned-software-engine-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "process.observe"),
        "self-owned inert software fixture",
        {"authorityBasis": "self", "interface": "file-ipc"},
    )
    runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(Path(sys.executable).resolve(), ("target.py",)),
        workspace_parent=workspaces,
        workspace_seed=seed,
        process_templates=(
            ExactProcessSurfaceSpec(
                "client",
                Path(sys.executable).resolve(),
                ("client.py",),
                trusted_host_process_acknowledged=True,
            ),
        ),
    )
    artifacts = run_executor_engine_document(
        _document(),
        tmp_path / "evidence",
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )
    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    assert not lint_capsule(artifacts.capsule)
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert artifacts.reproduction_trace is not None
    assert TraceReader(artifacts.reproduction_trace).verify(require_signature=True).signature_valid
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 1
    assert report["reproduction"]["attempted"] is True
    assert report["reproduction"]["equivalent"] is True
    assert any(
        event["kind"] == "tool.completed"
        for event in TraceReader(artifacts.reproduction_trace).events()
    )
    assert not any(workspaces.iterdir())


@pytest.mark.integration
@_requires_process_identity
def test_owned_software_engine_exercises_two_portable_terminal_surfaces(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "multi-process-seed"
    seed.mkdir()
    (seed / "target.py").write_text(_TARGET_PROGRAM, encoding="utf-8")
    workspaces = tmp_path / "multi-process-workspaces"
    workspaces.mkdir()
    runtime_document = {
        "artifactType": "sova.executor-engine-runtime",
        "schemaVersion": "0.1.0",
        "workspace": {
            "enabled": False,
            "maxReadBytes": 1024,
            "maxWriteBytes": 1024,
        },
        "hostProcesses": [
            {
                "id": "first",
                "executable": str(Path(sys.executable).resolve()),
                "argvPrefix": ["-c", "print('SOVA-FIRST-TERMINAL-SURFACE')"],
                "maxArgs": 4,
                "maxArgBytes": 4096,
                "maxOutputBytes": 4096,
                "trustedHostProcessAcknowledged": True,
            },
            {
                "id": "second",
                "executable": str(Path(sys.executable).resolve()),
                "argvPrefix": ["-c", "print('SOVA-SECOND-TERMINAL-SURFACE')"],
                "maxArgs": 4,
                "maxArgBytes": 4096,
                "maxOutputBytes": 4096,
                "trustedHostProcessAcknowledged": True,
            },
        ],
    }
    config = parse_executor_engine_runtime_document(runtime_document)
    builder = build_executor_engine_runtime_surfaces(config)
    preview = builder("primary")
    try:
        contract_digest = sha256_digest(
            canonical_json_bytes(
                [
                    item.contract_mapping()
                    for item in sorted(preview, key=lambda item: item.sensor_name)
                ]
            )
        )
    finally:
        for surface in reversed(preview):
            surface.close()
    target = TargetManifest(
        "sova:target:owned-software-multi-process-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "process.observe"),
        "self-owned inert multi-process software fixture",
        {"authorityBasis": "self", "interface": "reviewed-process-templates"},
    )
    runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(Path(sys.executable).resolve(), ("target.py",)),
        workspace_parent=workspaces,
        workspace_seed=seed,
        additional_surface_factory=builder,
        additional_codec_factories=dict(builder.codec_factories),
        additional_surface_contract_digest=contract_digest,
    )
    artifacts = run_executor_engine_document(
        _multi_process_document(),
        tmp_path / "multi-process-evidence",
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )
    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    assert artifacts.reproduction_trace is not None
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 2
    assert report["reproduction"]["equivalent"] is True
    completed = list(TraceReader(artifacts.trace).query(kind_prefix="tool.completed"))
    assert {item["payload"]["action"] for item in completed} == {"process.exec"}
    assert not any(workspaces.iterdir())


@pytest.mark.integration
@_requires_process_identity
def test_owned_software_swarm_runs_isolated_targets_and_embeds_findings(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "swarm-seed"
    seed.mkdir()
    (seed / "target.py").write_text(_TARGET_PROGRAM, encoding="utf-8")
    (seed / "client.py").write_text(_CLIENT_PROGRAM, encoding="utf-8")
    target = TargetManifest(
        "sova:target:owned-software-swarm-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "process.observe"),
        "self-owned inert software swarm fixture",
        {"authorityBasis": "self", "interface": "file-ipc"},
    )
    document = _document()
    document["participants"] = document["participants"][:1]
    artifacts = run_software_swarm(
        target,
        SoftwareLaunchSpec(Path(sys.executable).resolve(), ("target.py",)),
        document,
        tmp_path / "software-swarm",
        agent_count=2,
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        target_observation_disclosure_authorized=True,
        proof=_proof(),
        workspace_seed=seed,
        process_templates=(
            ExactProcessSurfaceSpec(
                "client",
                Path(sys.executable).resolve(),
                ("client.py",),
                trusted_host_process_acknowledged=True,
            ),
        ),
        aggregate_budget=SwarmAggregateBudget(
            max_total_actions=4,
            max_duration_seconds=60,
            max_mutations=4,
            max_processes=4,
            max_files=0,
            max_network_requests=0,
        ),
    )
    assert artifacts.agent_count == 2
    assert not lint_capsule(artifacts.swarm_capsule)
    assert TraceReader(artifacts.coordinator_trace).verify(require_signature=True).signature_valid
    assert [item["status"] for item in artifacts.report["perAgentSummaries"]] == [
        "pass",
        "pass",
    ]
    assert artifacts.report["aggregateBudget"]["consumed"]["totalActions"] == 4
    assert len(artifacts.report["nestedFindingCapsules"]) == 2
    replay = render_capsule_timeline(
        artifacts.swarm_capsule,
        tmp_path / "software-swarm-replay.html",
    )
    assert replay["nestedCapsule"] == "capsules/agent-01-finding.sova"
    assert replay["selectionMode"] == "automatic-finding"
    assert replay["primaryTrace"].endswith("primary.sova-trace")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="exact HWND acceptance is Windows-only")
def test_owned_gui_is_clicked_recorded_reproduced_and_opens_at_decisive_frame(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "gui-seed"
    seed.mkdir()
    (seed / "gui_target.py").write_text(_GUI_TARGET_PROGRAM, encoding="utf-8")
    workspaces = tmp_path / "gui-workspaces"
    workspaces.mkdir()
    target = TargetManifest(
        "sova:target:owned-native-window-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.click", "computer.observe"),
        "self-owned inert exact-window GUI fixture",
        {"authorityBasis": "self", "interface": "native-window"},
    )
    evidence = tmp_path / "gui-evidence"
    recording = SoftwareWindowRecordingCoordinator(
        evidence / "recordings",
        interval_seconds=0.25,
    )
    runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            ("gui_target.py",),
            window_required=True,
            window_title_contains="SOVA Owned GUI Target",
        ),
        workspace_parent=workspaces,
        workspace_seed=seed,
        computer_surface_factory=native_windows_discovery_surface_factory(),
        window_recording=recording,
    )
    artifacts = run_executor_engine_document(
        _gui_document(target_ref="win32:button:id-102"),
        evidence,
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        event_observer=recording.observe,
        capsule_attachment_provider=recording.attachments,
    )
    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    assert not lint_capsule(artifacts.capsule)
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    visual = [item for item in descriptors if item.role == "visual-replay"]
    assert len(visual) == 2
    assert all(item.mediaType == "application/vnd.sova.window-frames+zip" for item in visual)
    assert len([item for item in descriptors if item.role == "replay-cues"]) == 1
    replay_destination = tmp_path / "gui-decisive-replay.html"
    replay = render_capsule_timeline(artifacts.capsule, replay_destination)
    assert replay["opensAtDecisiveMoment"] is True
    assert replay["decisiveCue"]["oracleStatus"] == "pass"
    rendered = replay_destination.read_text(encoding="utf-8")
    assert "Recorded target application window" in rendered
    assert "data:image/bmp;base64," in rendered

    assert not any(workspaces.iterdir())


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="exact HWND acceptance is Windows-only")
def test_owned_gui_dynamic_control_discovery_traverses_a_changing_workflow(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "gui-workflow-seed"
    seed.mkdir()
    (seed / "gui_target.py").write_text(_GUI_TARGET_PROGRAM, encoding="utf-8")
    workspaces = tmp_path / "gui-workflow-workspaces"
    workspaces.mkdir()
    target = TargetManifest(
        "sova:target:owned-native-window-dynamic-workflow",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.click", "computer.observe"),
        "self-owned changing-screen exact-window workflow fixture",
        {"authorityBasis": "self", "interface": "dynamic-native-window"},
    )
    evidence = tmp_path / "gui-workflow-evidence"
    recording = SoftwareWindowRecordingCoordinator(
        evidence / "recordings",
        interval_seconds=0.25,
    )
    runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            ("gui_target.py", "workflow"),
            window_required=True,
            window_title_contains="SOVA Owned GUI Target",
        ),
        workspace_parent=workspaces,
        workspace_seed=seed,
        computer_surface_factory=native_windows_discovery_surface_factory(),
        window_recording=recording,
    )
    artifacts = run_executor_engine_document(
        _gui_dynamic_workflow_document(),
        evidence,
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        event_observer=recording.observe,
        capsule_attachment_provider=recording.attachments,
    )
    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 2
    assert report["reproduction"]["equivalent"] is True
    requested = list(TraceReader(artifacts.trace).query(kind_prefix="tool.requested"))
    refs = [item["payload"]["plannerArguments"]["arguments"]["targetRef"] for item in requested]
    assert refs == ["win32:button:id-102", "win32:button:id-103"]
    replay = render_capsule_timeline(
        artifacts.capsule,
        tmp_path / "gui-workflow-replay.html",
    )
    assert replay["opensAtDecisiveMoment"] is True
    assert not any(workspaces.iterdir())

    portable_document = build_executor_capsule_reproduction_document(artifacts.capsule)
    portable_workspaces = tmp_path / "gui-workflow-portable-workspaces"
    portable_workspaces.mkdir()
    portable_runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            ("gui_target.py", "workflow"),
            window_required=True,
            window_title_contains="SOVA Owned GUI Target",
        ),
        workspace_parent=portable_workspaces,
        workspace_seed=seed,
        computer_surface_factory=native_windows_discovery_surface_factory(),
    )
    portable = run_executor_engine_document(
        portable_document,
        tmp_path / "gui-workflow-portable-reproduction",
        runtime=portable_runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )
    assert portable.status == "pass"
    portable_refs = [
        item["payload"]["plannerArguments"]["arguments"]["targetRef"]
        for item in TraceReader(portable.trace).query(kind_prefix="tool.requested")
    ]
    assert portable_refs == ["win32:button:id-102", "win32:button:id-103"]
    assert not any(portable_workspaces.iterdir())


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="exact HWND acceptance is Windows-only")
def test_owned_gui_types_saves_records_and_reproduces_authorized_form(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "gui-form-seed"
    seed.mkdir()
    (seed / "gui_target.py").write_text(_GUI_TARGET_PROGRAM, encoding="utf-8")
    workspaces = tmp_path / "gui-form-workspaces"
    workspaces.mkdir()
    target = TargetManifest(
        "sova:target:owned-native-window-form-workflow",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.click", "computer.type", "computer.observe"),
        "self-owned exact-window type-and-save workflow fixture",
        {"authorityBasis": "self", "interface": "dynamic-native-window"},
    )
    evidence = tmp_path / "gui-form-evidence"
    recording = SoftwareWindowRecordingCoordinator(
        evidence / "recordings",
        interval_seconds=0.25,
    )
    runtime = build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            ("gui_target.py", "form"),
            window_required=True,
            window_title_contains="SOVA Owned GUI Target",
        ),
        workspace_parent=workspaces,
        workspace_seed=seed,
        computer_surface_factory=native_windows_discovery_surface_factory(),
        window_recording=recording,
    )
    artifacts = run_executor_engine_document(
        _gui_form_document(),
        evidence,
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        event_observer=recording.observe,
        capsule_attachment_provider=recording.attachments,
    )
    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    assert not lint_capsule(artifacts.capsule)
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 2
    assert report["reproduction"]["equivalent"] is True
    requested = list(TraceReader(artifacts.trace).query(kind_prefix="tool.requested"))
    assert [item["payload"]["action"] for item in requested] == [
        "computer.type",
        "computer.click",
    ]
    assert [
        item["payload"]["plannerArguments"]["arguments"]["targetRef"] for item in requested
    ] == ["win32:edit:id-104", "win32:button:id-105"]
    replay = render_capsule_timeline(
        artifacts.capsule,
        tmp_path / "gui-form-replay.html",
    )
    assert replay["opensAtDecisiveMoment"] is True
    assert replay["decisiveCue"]["oracleStatus"] == "pass"
    assert not any(workspaces.iterdir())


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "win32", reason="exact HWND acceptance is Windows-only")
def test_owned_gui_swarm_isolated_agents_record_nested_decisive_findings(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "gui-swarm-seed"
    seed.mkdir()
    (seed / "gui_target.py").write_text(_GUI_TARGET_PROGRAM, encoding="utf-8")
    target = TargetManifest(
        "sova:target:owned-native-window-swarm-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.click", "computer.observe"),
        "self-owned inert exact-window GUI swarm fixture",
        {"authorityBasis": "self", "interface": "native-window"},
    )
    targets = native_window_targets_from_mapping(
        {
            "artifactType": "sova.native-window-map",
            "schemaVersion": "0.1.0",
            "targets": [
                {
                    "reference": "trigger-button",
                    "actions": ["computer.click"],
                    "x": 200,
                    "y": 120,
                }
            ],
        }
    )
    document = _gui_document()
    document["participants"] = document["participants"][:1]
    artifacts = run_software_swarm(
        target,
        SoftwareLaunchSpec(
            Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            ("gui_target.py",),
            window_required=True,
            window_title_contains="SOVA Owned GUI Target",
        ),
        document,
        tmp_path / "gui-software-swarm",
        agent_count=2,
        personas=("workflow explorer", "state-transition adversary"),
        max_concurrency=2,
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        target_observation_disclosure_authorized=True,
        proof=_proof(),
        workspace_seed=seed,
        computer_surface_factory=native_windows_computer_surface_factory(targets),
        record_window=True,
        recording_interval_seconds=0.25,
        aggregate_budget=SwarmAggregateBudget(
            max_total_actions=4,
            max_duration_seconds=60,
            max_mutations=4,
            max_processes=0,
            max_files=0,
            max_network_requests=0,
        ),
    )
    assert [item["status"] for item in artifacts.report["perAgentSummaries"]] == [
        "pass",
        "pass",
    ]
    assert len(artifacts.report["nestedFindingCapsules"]) == 2
    measured = artifacts.report["measuredCoverage"]
    assert measured["actionKindsVerified"] == ["computer.click"]
    assert measured["attemptCount"] == 4
    assert measured["verifiedCount"] == 4
    assert measured["changedTransitionCount"] >= 2
    assert measured["completeCoverageClaimed"] is False
    replay_destination = tmp_path / "gui-swarm-decisive-replay.html"
    replay = render_capsule_timeline(artifacts.swarm_capsule, replay_destination)
    assert replay["nestedCapsule"] == "capsules/agent-01-finding.sova"
    assert replay["selectionMode"] == "automatic-finding"
    assert replay["opensAtDecisiveMoment"] is True
    rendered = replay_destination.read_text(encoding="utf-8")
    assert "Recorded target application window" in rendered
    assert "data:image/bmp;base64," in rendered

    capsule_data = artifacts.swarm_capsule.read_bytes()
    capsule_digest = sha256_digest(capsule_data)
    entry = RegistryEntry(
        "owned-gui-swarm-finding",
        "0.1.0",
        f"objects/sha256/{capsule_digest[7:]}",
        capsule_digest,
        len(capsule_data),
        "sova-owned-gui-fixture",
        "0.1.0",
        ("authorized-ui-workflow", "exact-window-replay"),
        "test-fixture",
        {"mode": "nested-finding-capsule"},
        {"source": "owned-actionful-integration"},
        "Apache-2.0",
        VerificationTier.CI_REPRODUCED,
    )
    registry = tmp_path / "trusted-registry"
    registry_verification = build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"# Owned fixture taxonomy\n",
        artifacts=((artifacts.swarm_capsule, entry),),
    )
    registry_capsule, resolution = resolve_registry_capsule(
        registry,
        entry_id=entry.entry_id,
        version=entry.version,
        trusted_key_ids=frozenset({registry_verification["keyId"]}),
    )
    assert resolution["registryIdentityTrusted"] is True
    registry_replay = render_capsule_timeline(
        registry_capsule,
        tmp_path / "registry-gui-swarm-replay.html",
    )
    assert registry_replay["nestedCapsule"] == "capsules/agent-01-finding.sova"
    assert registry_replay["opensAtDecisiveMoment"] is True
