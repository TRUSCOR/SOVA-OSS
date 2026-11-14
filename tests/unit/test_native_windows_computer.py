# SPDX-License-Identifier: Apache-2.0
"""Native exact-window reviewed-target computer-use contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

from sova.executors import ActionRequest, CancellationToken, ExecutionContext, OutcomeStatus
from sova.formats.errors import FormatError
from sova.runtime import native_windows_computer as native_module
from sova.runtime.native_windows_computer import (
    NativeWindowsComputerExecutor,
    native_window_targets_from_mapping,
    native_windows_computer_surface_factory,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sova.runtime.software_target import SoftwareTargetAttestation


@dataclass
class _Attestation:
    pid: int = 81
    window_id: int = 91
    window_handle_digest: str = "sha256:" + "1" * 64
    process_start_digest: str = "sha256:" + "2" * 64
    checks: int = 0

    def assert_still_live(self) -> None:
        self.checks += 1


def _map() -> dict[str, object]:
    return {
        "artifactType": "sova.native-window-map",
        "schemaVersion": "0.1.0",
        "targets": [
            {
                "reference": "arm-button",
                "actions": ["computer.click"],
                "x": 120,
                "y": 80,
            },
            {
                "reference": "editor",
                "actions": ["computer.click", "computer.type"],
                "x": 120,
                "y": 140,
            },
        ],
    }


def test_native_window_map_is_explicit_bounded_and_immutable() -> None:
    targets = native_window_targets_from_mapping(_map())
    assert [item.reference for item in targets] == ["arm-button", "editor"]
    assert targets[0].canonical_locator() == {"x": 120, "y": 80}
    assert callable(native_windows_computer_surface_factory(targets))

    malformed = _map()
    malformed["targets"] = [
        {
            "reference": "ambient",
            "actions": ["computer.click"],
            "x": 99_999,
            "y": 1,
        }
    ]
    with pytest.raises(FormatError, match="coordinates"):
        native_window_targets_from_mapping(malformed)


def _map_variant(**changes: object) -> dict[str, object]:
    value = _map()
    value.update(changes)
    return value


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ([], "must contain artifactType"),
        ({**_map(), "unreviewed": True}, "must contain artifactType"),
        (_map_variant(artifactType="sova.other-map"), "target count is invalid"),
        (_map_variant(targets=[]), "target count is invalid"),
        (_map_variant(targets=["arm-button"]), "must contain reference"),
        (
            _map_variant(
                targets=[
                    {"reference": "same", "actions": ["computer.click"], "x": 1, "y": 1},
                    {"reference": "same", "actions": ["computer.click"], "x": 2, "y": 2},
                ]
            ),
            "must be unique",
        ),
    ],
)
def test_native_window_map_rejects_malformed_shapes(value: object, message: str) -> None:
    with pytest.raises(FormatError, match=message):
        native_window_targets_from_mapping(value)


def test_native_executor_sends_only_bound_click_and_type_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _Attestation()
    messages: list[tuple[int, int, int, int]] = []
    monkeypatch.setattr(
        native_module,
        "_send_message",
        lambda window, message, wparam, lparam, _timeout: messages.append(
            (window, message, wparam, lparam)
        ),
    )
    monkeypatch.setattr(
        native_module,
        "_bound_child_at_point",
        lambda attestation, x, y: (attestation.window_id, x, y),
    )
    executor = NativeWindowsComputerExecutor(
        cast("SoftwareTargetAttestation", attestation),
        ("computer.click", "computer.type"),
    )
    context = ExecutionContext(tmp_path, {"decision": "allowed"})
    click = executor.execute(
        ActionRequest(
            "click",
            "computer.click",
            {"pid": 81, "windowId": 91, "x": 10, "y": 20},
            1,
        ),
        context,
        CancellationToken(),
    )
    typed = executor.execute(
        ActionRequest(
            "type",
            "computer.type",
            {"pid": 81, "windowId": 91, "x": 30, "y": 40, "text": "owl"},
            1,
        ),
        context,
        CancellationToken(),
    )
    assert click.status is OutcomeStatus.SUCCEEDED
    assert typed.output["typedCodeUnits"] == 3
    assert [item[1] for item in messages] == [
        0x0201,
        0x0202,
        0x0201,
        0x0202,
        0x0102,
        0x0102,
        0x0102,
    ]
    assert all(item[0] == 91 for item in messages)
    assert attestation.checks == 4

    with pytest.raises(FormatError, match="reviewed target/window binding"):
        executor.execute(
            ActionRequest(
                "escape",
                "computer.click",
                {"pid": 999, "windowId": 91, "x": 10, "y": 20},
                1,
            ),
            context,
            CancellationToken(),
        )
