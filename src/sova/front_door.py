# SPDX-License-Identifier: Apache-2.0
"""The short path through the CLI: core commands, their help text, and `sova show`."""

from __future__ import annotations

from typing import TYPE_CHECKING, TextIO

from sova.capsule import render_capsule
from sova.formats import PackageReader
from sova.formats.errors import FormatError
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

#: Core commands in the order `sova --help` presents them.
CORE_COMMANDS: tuple[tuple[str, str], ...] = (
    ("record", "turn an AgentDojo run log into a .sova-trace and a .sova capsule"),
    ("verify", "check a capsule or trace offline: digests, event chain, signature"),
    ("show", "print a capsule summary or a trace timeline; runs nothing"),
    ("compare", "compare declared outcomes of two traces without re-running them"),
    ("rerun", "run a recorded scenario again from its capsule"),
    ("audit", "check benchmark attack verdicts against the tool calls in each episode"),
    ("matrix", "run scenarios across several models and tabulate the outcomes"),
)


def front_door_description() -> str:
    """Return the top-level help description, leading with the core commands."""
    width = max(len(name) for name, _summary in CORE_COMMANDS)
    lines = [
        "SOVA OSS pre-alpha: record, verify, show, compare, re-run, and audit portable records",
        "of attacks on AI agents. Opening a record runs nothing; re-running needs --authorize.",
        "",
        "core commands:",
        *(f"  {name.ljust(width)}  {summary}" for name, summary in CORE_COMMANDS),
        "",
        "Every command, including the lower-level ones, is listed below.",
        "Run `sova COMMAND --help` for its options.",
    ]
    return "\n".join(lines)


def show_artifact(path: Path, stdout: TextIO) -> int:
    """Print a capsule like `sova inspect` or a trace like `sova playback`."""
    artifact_type = PackageReader(path).raw_manifest().get("artifactType")
    if artifact_type == "sova.capsule":
        stdout.write(render_capsule(path))
        return 0
    if artifact_type == "sova.trace":
        stdout.write("\n".join(TraceReader(path).playback()) + "\n")
        return 0
    raise FormatError(
        "SOVA-SHOW-UNSUPPORTED",
        "show accepts a .sova capsule or a .sova-trace file",
        details={"artifactType": artifact_type},
    )


__all__ = ["CORE_COMMANDS", "front_door_description", "show_artifact"]
