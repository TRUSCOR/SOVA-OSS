# SPDX-License-Identifier: Apache-2.0
"""The front door: `sova --help` leads with the core commands; `sova show` reads both formats."""

from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING

import pytest

from sova.cli import main
from sova.front_door import CORE_COMMANDS, front_door_description
from sova.interoperability.agentdojo import record_agentdojo_log

if TYPE_CHECKING:
    from pathlib import Path

CORE_ORDER = ["record", "verify", "show", "compare", "rerun", "audit", "matrix"]


def recorded(tmp_path: Path) -> tuple[Path, Path]:
    log = {
        "suite_name": "travel",
        "pipeline_name": "model-x",
        "user_task_id": "user_task_1",
        "injection_task_id": "injection_task_6",
        "attack_type": "important_instructions",
        "messages": [
            {"role": "user", "content": "Find me a hotel."},
            {"role": "assistant", "content": "Try Riverside View Hotel."},
        ],
        "error": None,
        "security": True,
        "utility": False,
    }
    source = tmp_path / "log.json"
    source.write_text(json.dumps(log), encoding="utf-8")
    episode = record_agentdojo_log(source, tmp_path / "out", author="a")
    assert episode.capsule is not None
    assert episode.trace is not None
    return episode.capsule, episode.trace


def test_help_leads_with_the_core_commands_in_order(capsys: pytest.CaptureFixture[str]) -> None:
    assert [name for name, _summary in CORE_COMMANDS] == CORE_ORDER
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert output.startswith("usage: sova [-h] [--version] COMMAND ...")
    assert "pre-alpha" in output
    core = output[output.index("core commands:") :].splitlines()[1 : 1 + len(CORE_ORDER)]
    assert [line.split()[0] for line in core] == CORE_ORDER
    assert output.index("core commands:") < output.index("positional arguments:")
    for word in ("first", "only", "best", "revolutionary"):
        assert word not in front_door_description().lower().split()


def test_show_prints_capsules_like_inspect_and_traces_like_playback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsule, trace = recorded(tmp_path)
    assert main(["show", str(capsule)]) == 0
    shown_capsule = capsys.readouterr().out
    assert main(["inspect", str(capsule)]) == 0
    assert shown_capsule == capsys.readouterr().out
    assert "Rendering is inert" in shown_capsule
    assert main(["show", str(trace)]) == 0
    shown_trace = capsys.readouterr().out
    assert main(["playback", str(trace)]) == 0
    assert shown_trace == capsys.readouterr().out
    assert "oracle.completed" in shown_trace


def test_show_rejects_other_packages_and_missing_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as archive:
        archive.writestr("manifest.json", json.dumps({"artifactType": "sova.other"}))
    assert main(["show", str(other)]) == 2
    assert "SOVA-SHOW-UNSUPPORTED" in capsys.readouterr().err
    assert main(["show", str(tmp_path / "missing.sova")]) == 2
    assert "SOVA-PACKAGE-INVALID-ARCHIVE" in capsys.readouterr().err


def test_record_without_subcommand_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["record"]) == 0
    assert "usage: sova" in capsys.readouterr().out
