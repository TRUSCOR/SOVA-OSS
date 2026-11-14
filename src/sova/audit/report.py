# SPDX-License-Identifier: Apache-2.0
"""Audit report document, terminal table, and the `sova audit` command body."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TextIO

from sova.audit.agentdojo import collect_inputs
from sova.audit.engine import (
    CATEGORIES,
    AuditResult,
    AuditSpec,
    AuditSummary,
    audit_episodes,
    load_spec,
    summarize,
    summarize_by_pipeline,
)
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from sova.audit.agentdojo import SkippedInput

REPORT_LIMITATIONS = (
    "An executed decisive call means the agent requested the attacker's action and the "
    "benchmark's simulated tool returned no error; it says nothing about real-world effect.",
    "Each rule names the attacker's own identifier in one tool call; an attack carried out "
    "some other way is not detected.",
    "Text-goal labels come from a fixed warning-language rule over the final reply "
    "(basis 'rule'); a rule cannot read intent reliably.",
    "Arguments removed by capture-time redaction cannot be checked; such episodes are "
    "'evidence-redacted' and left out of the attacker action rate.",
)
_TOTAL_LABEL = "all pipelines"


def report_json_bytes(report: dict[str, Any]) -> bytes:
    """Encode a report as canonical SOVA JSON, one list item at a time.

    A large audit holds more values than one bounded canonical encoding allows, so the
    top-level object and its lists are assembled from canonical pieces. The bytes are
    identical to encoding the whole report at once.
    """
    members: list[bytes] = []
    for key in sorted(report, key=lambda name: name.encode("utf-16-be")):
        value = report[key]
        if isinstance(value, list):
            encoded = b"[" + b",".join(canonical_json_bytes(item) for item in value) + b"]"
        else:
            encoded = canonical_json_bytes(value)
        members.append(canonical_json_bytes(key) + b":" + encoded)
    return b"{" + b",".join(members) + b"}"


def build_report(
    results: Sequence[AuditResult],
    spec: AuditSpec,
    *,
    source: str,
    skipped: Sequence[SkippedInput] = (),
) -> dict[str, Any]:
    """Return the full canonical-JSON-safe audit report."""
    return {
        "artifactType": "sova.audit-report",
        "schemaVersion": "0.1.0",
        "source": source,
        "spec": spec.to_mapping(),
        "episodeCount": len(results),
        "skippedCount": len(skipped),
        "summary": {
            "pipelines": {
                pipeline: summary.to_mapping()
                for pipeline, summary in summarize_by_pipeline(results).items()
            },
            "total": summarize(results).to_mapping(),
        },
        "episodes": [result.to_mapping() for result in results],
        "skipped": [item.to_mapping() for item in skipped],
        "limitations": list(REPORT_LIMITATIONS),
    }


def _rate(value: str | None) -> str:
    return "-" if value is None else value


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    widths = [max(len(row[index]) for row in [header, *rows]) for index in range(len(header))]
    lines = []
    for row in [header, *rows]:
        cells = [row[0].ljust(widths[0])]
        cells.extend(cell.rjust(width) for cell, width in zip(row[1:], widths[1:], strict=True))
        lines.append("  ".join(cells).rstrip())
    return lines


def render_summary(
    summaries: dict[str, AuditSummary],
    total: AuditSummary,
) -> str:
    """Render two compact tables: verdict rates, then category counts per pipeline."""
    labelled = [*summaries.items(), (_TOTAL_LABEL, total)]
    rate_rows = [
        [
            name,
            str(summary.episodes),
            str(summary.benchmark_scored_attacks),
            _rate(summary.benchmark_asr.value),
            _rate(summary.attacker_action_rate.value),
        ]
        for name, summary in labelled
    ]
    lines = _table(
        ["pipeline", "episodes", "scored", "benchmark-asr", "attacker-action-rate"], rate_rows
    )
    shown = [category for category in CATEGORIES if total.categories.get(category)]
    if shown:
        category_rows = [
            [name, *(str(summary.categories.get(category, 0)) for category in shown)]
            for name, summary in labelled
        ]
        lines.extend(["", *_table(["pipeline", *shown], category_rows)])
    return "\n".join(lines) + "\n"


def run_audit(
    path: Path,
    *,
    spec_reference: str,
    json_destination: Path | None,
    limit: int | None,
    stdout: TextIO,
) -> int:
    """Audit every episode found at ``path``, print the tables, optionally write JSON."""
    spec = load_spec(spec_reference)
    inputs = collect_inputs(path, limit=limit)
    if not inputs.episodes:
        reason = f"; {inputs.skipped[0].reason}" if len(inputs.skipped) == 1 else ""
        raise FormatError(
            "SOVA-AUDIT-NO-EPISODES",
            f"no auditable AgentDojo episodes found ({len(inputs.skipped)} file(s) "
            f"skipped){reason}",
        )
    results = audit_episodes(inputs.episodes, spec)
    stdout.write(
        f"{spec.benchmark} audit with spec {spec.name} ({spec.digest}): "
        f"{len(results)} episode(s), {len(inputs.skipped)} file(s) skipped\n\n"
    )
    stdout.write(render_summary(summarize_by_pipeline(results), summarize(results)))
    if json_destination is not None:
        report = build_report(results, spec, source=str(path), skipped=inputs.skipped)
        json_destination.parent.mkdir(parents=True, exist_ok=True)
        json_destination.write_bytes(report_json_bytes(report) + b"\n")
        stdout.write(f"\nper-episode results written to {json_destination}\n")
    return 0


__all__ = [
    "REPORT_LIMITATIONS",
    "build_report",
    "render_summary",
    "report_json_bytes",
    "run_audit",
]
