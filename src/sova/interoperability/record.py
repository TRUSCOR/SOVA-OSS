# SPDX-License-Identifier: Apache-2.0
"""Command bodies for `sova record`: turn external run records into SOVA artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TextIO

from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.interoperability.agentdojo import (
    find_agentdojo_logs,
    record_agentdojo_bundle,
    record_agentdojo_log,
)
from sova.interoperability.inspect_ai import import_inspect_samples
from sova.interoperability.trace_attestation import import_trace_records

if TYPE_CHECKING:
    from pathlib import Path


def record_agentdojo(  # noqa: PLR0913 - every option is an explicit CLI input
    source: Path,
    out_dir: Path,
    *,
    author: str,
    bundle: bool,
    bundle_name: str | None,
    stdout: TextIO,
) -> int:
    """Record one AgentDojo log, or every log under a directory, as SOVA artifacts."""
    if source.is_dir():
        logs, other = find_agentdojo_logs(source)
    elif source.is_file():
        logs, other = [source], 0
    else:
        raise FormatError("SOVA-RECORD-PATH", "record source is neither a file nor a directory")
    if not logs:
        raise FormatError(
            "SOVA-RECORD-NO-LOGS",
            f"no AgentDojo run logs found ({other} other JSON file(s) skipped)",
        )
    if bundle:
        name = bundle_name or f"{(source if source.is_dir() else source.parent).name}-bundle"
        destination = out_dir / (name if name.endswith(".sova") else f"{name}.sova")
        recorded = record_agentdojo_bundle(logs, destination, author=author)
        stdout.write(f"{recorded.capsule_digest}  {recorded.capsule}\n")
    else:
        used_stems: set[str] = set()
        for log in logs:
            episode = record_agentdojo_log(log, out_dir, author=author, used_stems=used_stems)
            stdout.write(f"{episode.capsule_digest}  {episode.capsule}\n")
    layout = "one bundle capsule" if bundle else "a .sova capsule and its .sova-trace each"
    stdout.write(
        f"recorded {len(logs)} AgentDojo episode(s) into {out_dir} as {layout}; "
        f"{other} other JSON file(s) skipped\n"
    )
    return 0


def _emit(document: dict[str, Any], destination: Path | None, stdout: TextIO) -> int:
    encoded = canonical_json_bytes(document) + b"\n"
    if destination is None:
        buffer = getattr(stdout, "buffer", None)
        if buffer is not None:
            stdout.flush()
            buffer.write(encoded)
        else:
            stdout.write(encoded.decode("utf-8"))
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    stdout.write(f"wrote {document['artifactType']} to {destination}\n")
    return 0


def record_inspect(
    source: Path,
    *,
    license_expression: str,
    source_url: str,
    destination: Path | None,
    stdout: TextIO,
) -> int:
    """Import an Inspect AI sample dataset as an inert SOVA external scenario set."""
    document = import_inspect_samples(
        source, license_expression=license_expression, source_url=source_url
    )
    return _emit(document, destination, stdout)


def record_trace_attestation(
    source: Path,
    *,
    license_expression: str,
    source_url: str,
    destination: Path | None,
    stdout: TextIO,
) -> int:
    """Import TRACE trust records as declared trust inputs, never as observations."""
    document = import_trace_records(
        source, license_expression=license_expression, source_url=source_url
    )
    return _emit(document, destination, stdout)


__all__ = ["record_agentdojo", "record_inspect", "record_trace_attestation"]
