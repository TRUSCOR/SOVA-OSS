# SPDX-License-Identifier: Apache-2.0
"""Record Inspect AI eval logs as `.sova-trace` files and one `.sova` capsule per log.

Inspect AI writes an eval log either as one JSON document (``.json``) or as a zip archive
(``.eval``) holding ``header.json`` and one ``samples/<id>_epoch_<n>.json`` per sample. This
bridge turns every sample and epoch into a tamper-evident `.sova-trace` of what the agent
observably did, and seals the traces of one log in a `.sova` capsule that anyone can verify
offline. It reads the log as data: it imports no Inspect code, calls no model, and runs no
task, solver, scorer, or sandbox.

Event mapping (the same kinds as ``sova record agentdojo``):

* ``artifact.imported`` -- log file name, its SHA-256 digest, and the archive entry;
* ``run.started`` -- harness, Inspect version, task, ids, sample id, epoch, model;
* ``prompt.system`` / ``prompt.user`` -- ``text``;
* ``model.response`` -- ``text``, ``toolCalls``, and ``omittedBlocks`` counting content
  blocks that are not text (reasoning is never copied);
* ``tool.requested`` / ``tool.result`` -- ``function``, ``args``, ``callId``, ``output``,
  ``error``;
* ``environment.model.returned`` -- the model name the sample's output reports;
* ``error.reported`` -- only when the sample records an error;
* ``oracle.completed`` -- one per scorer: ``oracle: "inspect.scorer:<name>"``, ``value``,
  ``answer`` and ``explanation`` as the scorer recorded them;
* ``run.completed`` -- every score value, the sample's limit if one stopped it, and ``error``.

A scorer's value is the scorer's claim, not SOVA's: the capsule says so. Binary floats are
stored as decimal strings. Fields that the trace does not carry (Inspect's own event log,
store, token usage, sandbox details) are listed in the capsule's limitations.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from sova.capsule.model import (
    CaptureProfile,
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.interoperability.agentdojo import decimals
from sova.trace.writer import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_MAX_LOG_BYTES: Final = 256 * 1024 * 1024
_MAX_ENTRY_BYTES: Final = 64 * 1024 * 1024
_MAX_ENTRIES: Final = 100_000
_MAX_ITEMS: Final = 10_000_000
_MAX_STRING: Final = 64 * 1024 * 1024
_ATTACHMENT: Final = "attachment://"
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_RECORDER = {"id": "sova:actor:converter", "kind": "recorder", "name": "sova record inspect-log"}
_USER = {"id": "inspect:user", "kind": "user", "name": "task input"}
_LIMITATIONS: Final = [
    "Converted from an Inspect AI eval log after the run; the run itself did not write a trace.",
    "Each oracle.completed event is a scorer's recorded value, not a judgment by SOVA.",
    "Not carried: Inspect's own event log, the sample store, token usage, sandbox details, "
    "and the content of reasoning blocks (counted, never copied).",
    "Opening or verifying this capsule runs nothing.",
]


@dataclass(frozen=True, slots=True)
class InspectSample:
    """One sample and epoch read from an eval log."""

    entry: str
    sample: dict[str, Any]


@dataclass(frozen=True, slots=True)
class InspectLog:
    """An eval log's header and its samples, with the digest of the file read."""

    path: Path
    digest: str
    header: dict[str, Any]
    samples: tuple[InspectSample, ...]

    @property
    def task(self) -> str:
        """Return the task name."""
        return str(_eval(self.header).get("task") or "task")

    @property
    def model(self) -> str:
        """Return the model the eval ran."""
        return str(_eval(self.header).get("model") or "not-recorded")


@dataclass(frozen=True, slots=True)
class InspectRecording:
    """Where one log's traces and capsule went."""

    source: Path
    traces: tuple[Path, ...]
    capsule: Path
    capsule_digest: str
    samples: int
    scored: dict[str, dict[str, int]]


def _eval(header: dict[str, Any]) -> dict[str, Any]:
    value = header.get("eval")
    return value if isinstance(value, dict) else {}


def _json(raw: bytes) -> Any:
    return strict_json_loads(
        raw, max_bytes=_MAX_LOG_BYTES, max_items=_MAX_ITEMS, max_string_bytes=_MAX_STRING
    )


def _is_header(document: Any) -> bool:
    return isinstance(document, dict) and isinstance(document.get("eval"), dict)


def read_inspect_log(path: Path) -> InspectLog:
    """Read a ``.json`` or ``.eval`` Inspect AI eval log, bounded and without executing it."""
    size = path.stat().st_size
    if size > _MAX_LOG_BYTES:
        raise FormatError("SOVA-INSPECT-LOG-SIZE", "Inspect log exceeds the size limit")
    raw = path.read_bytes()
    digest = sha256_digest(raw)
    if zipfile.is_zipfile(path):
        try:
            header, samples = _read_eval_archive(path)
        except zipfile.BadZipFile as error:
            raise FormatError("SOVA-INSPECT-LOG", "the .eval archive is damaged") from error
    else:
        document = _json(raw)
        if not _is_header(document) or not isinstance(document.get("samples", []), list):
            raise FormatError("SOVA-INSPECT-LOG", "JSON file is not an Inspect AI eval log")
        header = {key: value for key, value in document.items() if key != "samples"}
        samples = [
            InspectSample(f"samples[{index}]", sample)
            for index, sample in enumerate(document.get("samples") or [])
            if isinstance(sample, dict)
        ]
    if not samples:
        raise FormatError("SOVA-INSPECT-NO-SAMPLES", "the Inspect log holds no samples")
    return InspectLog(path, digest, header, tuple(samples))


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> Any:
    if info.file_size > _MAX_ENTRY_BYTES:
        raise FormatError("SOVA-INSPECT-ENTRY-SIZE", f"archive entry too large: {info.filename}")
    try:
        with archive.open(info) as handle:
            data = handle.read(_MAX_ENTRY_BYTES + 1)
    except NotImplementedError as error:
        raise FormatError(
            "SOVA-INSPECT-COMPRESSION",
            "this .eval archive uses a compression this Python cannot read (Inspect writes "
            "zstd, readable from Python 3.14); convert it first with "
            "`inspect log convert --to json --output-dir DIR LOG` and record the .json",
        ) from error
    if len(data) > _MAX_ENTRY_BYTES:
        raise FormatError("SOVA-INSPECT-ENTRY-SIZE", f"archive entry too large: {info.filename}")
    return _json(data)


def _read_eval_archive(path: Path) -> tuple[dict[str, Any], list[InspectSample]]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ENTRIES:
            raise FormatError("SOVA-INSPECT-ENTRIES", "the Inspect archive has too many entries")
        names = {info.filename: info for info in infos}
        header_info = names.get("header.json") or names.get("_journal/start.json")
        if header_info is None:
            raise FormatError("SOVA-INSPECT-LOG", "the archive has no Inspect header")
        header = _read_entry(archive, header_info)
        if not _is_header(header):
            raise FormatError("SOVA-INSPECT-LOG", "the archive header is not an Inspect header")
        samples = []
        for name in sorted(names):
            if name.startswith("samples/") and name.endswith(".json"):
                sample = _read_entry(archive, names[name])
                if isinstance(sample, dict):
                    samples.append(InspectSample(name, sample))
    return dict(header), samples


def find_inspect_logs(root: Path) -> list[Path]:
    """Return Inspect logs under ``root`` (a file, or a directory searched recursively).

    Every ``.eval`` file is returned, so that one that cannot be read is reported rather than
    skipped; a ``.json`` file is returned only if it parses as an eval log.
    """
    if root.is_file():
        return [root]
    found = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".eval"}:
            continue
        if path.suffix == ".json":
            try:
                read_inspect_log(path)
            except (FormatError, OSError):
                continue
        found.append(path)
    return found


def _resolve(value: Any, attachments: dict[str, Any]) -> Any:
    """Replace Inspect's ``attachment://`` references by the content they stand for."""
    if isinstance(value, str) and value.startswith(_ATTACHMENT):
        resolved = attachments.get(value[len(_ATTACHMENT) :])
        return resolved if isinstance(resolved, str) else value
    if isinstance(value, dict):
        return {key: _resolve(child, attachments) for key, child in value.items()}
    if isinstance(value, list):
        return [_resolve(child, attachments) for child in value]
    return value


def _text_and_omitted(content: Any) -> tuple[str, dict[str, int]]:
    if content is None:
        return "", {}
    if isinstance(content, str):
        return content, {}
    if not isinstance(content, list):
        return str(content), {}
    parts: list[str] = []
    omitted: dict[str, int] = {}
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
        else:
            kind = str(item.get("type") or "unknown") if isinstance(item, dict) else "unknown"
            omitted[kind] = omitted.get(kind, 0) + 1
    return "".join(parts), omitted


def _error_text(error: Any) -> str | None:
    if error is None:
        return None
    if isinstance(error, dict):
        kind, message = error.get("type"), error.get("message")
        text = ": ".join(str(part) for part in (kind, message) if part)
        return text or "error"
    return str(error)


def _stem(text: str) -> str:
    return _UNSAFE_NAME.sub("-", text).strip("-")[:120] or "sample"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class _TraceBuilder:
    """Append one sample's messages, scores and outcome to a trace writer."""

    def __init__(self, writer: TraceWriter, log: InspectLog) -> None:
        self.writer = writer
        self.agent = {"id": f"model:{log.model}", "kind": "model", "name": log.model}
        self.environment = {
            "id": f"inspect:{log.task}",
            "kind": "task-environment",
            "name": log.task,
        }
        self.calls: dict[str, str] = {}

    def append(self, kind: str, payload: dict[str, Any], **context: Any) -> None:
        self.writer.append(kind, decimals(payload), **context)

    def assistant(self, message: dict[str, Any], text: str, omitted: dict[str, int]) -> None:
        requested = [call for call in (message.get("tool_calls") or []) if isinstance(call, dict)]
        response: dict[str, Any] = {
            "text": text,
            "toolCalls": [
                {"function": call.get("function"), "args": call.get("arguments")}
                for call in requested
            ],
        }
        if omitted:
            response["omittedBlocks"] = omitted
        self.append("model.response", response, actor=self.agent)
        for call in requested:
            identifier = call.get("id") if isinstance(call.get("id"), str) else None
            if identifier:
                self.calls[identifier] = str(call.get("function"))
            self.append(
                "tool.requested",
                {
                    "function": call.get("function"),
                    "args": call.get("arguments"),
                    "callId": identifier,
                },
                actor=self.agent,
                target=self.environment,
            )

    def tool(self, message: dict[str, Any], text: str, omitted: dict[str, int]) -> None:
        raw = message.get("tool_call_id")
        identifier = raw if isinstance(raw, str) else None
        result: dict[str, Any] = {
            "function": message.get("function") or self.calls.get(identifier or "", "unknown"),
            "callId": identifier,
            "output": text,
            "error": _error_text(message.get("error")),
        }
        if omitted:
            result["omittedBlocks"] = omitted
        self.append("tool.result", result, actor=self.environment, target=self.agent)

    def messages(self, messages: Any) -> None:
        for message in messages if isinstance(messages, list) else []:
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            text, omitted = _text_and_omitted(message.get("content"))
            if role == "system":
                self.append("prompt.system", {"text": text}, actor=_RECORDER, target=self.agent)
            elif role == "user":
                self.append("prompt.user", {"text": text}, actor=_USER, target=self.agent)
            elif role == "assistant":
                self.assistant(message, text, omitted)
            elif role == "tool":
                self.tool(message, text, omitted)

    def scores(self, scores: dict[str, Any]) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for name, raw in sorted(scores.items()):
            score = raw if isinstance(raw, dict) else {"value": raw}
            values[name] = score.get("value")
            checker = {"id": f"inspect:scorer:{name}", "kind": "observer", "name": f"scorer {name}"}
            self.append(
                "oracle.completed",
                {
                    "oracle": f"inspect.scorer:{name}",
                    "value": score.get("value"),
                    "answer": score.get("answer"),
                    "explanation": score.get("explanation"),
                },
                actor=checker,
            )
        return values


def write_inspect_trace(
    destination: Path,
    log: InspectLog,
    item: InspectSample,
) -> str:
    """Write one sample and epoch as a `.sova-trace` and return the trace digest."""
    header = _eval(log.header)
    sample = _mapping(_resolve(item.sample, _mapping(item.sample.get("attachments"))))
    inspect_version = str(_mapping(header.get("packages")).get("inspect_ai") or "not-recorded")
    writer = TraceWriter(
        destination,
        capture_profile="standard",
        content_capture="full",
        authorization={
            "decision": "not-required",
            "scopeDigest": None,
            "decidedBy": "converted record; no execution",
        },
        environment={
            "platform": "not-recorded",
            "python": "not-recorded",
            "codeDigest": None,
            "model": {"requested": log.model, "returned": "not-recorded"},
            "dependencies": [{"name": "inspect_ai", "version": inspect_version}],
        },
        executor={
            "id": "sova:executor:inspect-ai",
            "name": "Inspect AI",
            "version": inspect_version,
            "capabilityDigest": None,
        },
    )
    build = _TraceBuilder(writer, log)
    run_info = {
        "harness": "Inspect AI",
        "inspectVersion": inspect_version,
        "task": log.task,
        "taskVersion": header.get("task_version"),
        "taskId": header.get("task_id"),
        "evalId": header.get("eval_id"),
        "runId": header.get("run_id"),
        "dataset": _mapping(header.get("dataset")).get("name"),
        "sampleId": str(sample.get("id")),
        "epoch": sample.get("epoch"),
        "model": log.model,
        "created": header.get("created"),
    }
    build.append(
        "artifact.imported",
        {
            "from": "Inspect AI eval log",
            "path": log.path.name,
            "sha256": log.digest,
            "entry": item.entry,
            "note": "Converted from the eval log; recorded by whoever ran the evaluation.",
        },
        actor=_RECORDER,
    )
    build.append(
        "run.started",
        {key: value for key, value in run_info.items() if value is not None},
        actor=_RECORDER,
        target=build.environment,
    )
    build.messages(sample.get("messages"))
    returned = _mapping(sample.get("output")).get("model")
    if returned:
        build.append("environment.model.returned", {"returned": str(returned)}, actor=_RECORDER)
    error = _error_text(sample.get("error"))
    if error is not None:
        build.append("error.reported", {"source": "Inspect AI", "error": error}, actor=_RECORDER)
    completed: dict[str, Any] = {
        "scores": build.scores(_mapping(sample.get("scores"))),
        "error": error,
    }
    if isinstance(sample.get("limit"), dict):
        completed["limit"] = sample["limit"]
    build.append("run.completed", completed, actor=_RECORDER)
    return writer.finalize()


def _score_tally(log: InspectLog) -> dict[str, dict[str, int]]:
    tally: dict[str, dict[str, int]] = {}
    for item in log.samples:
        scores = item.sample.get("scores")
        for name, score in (scores if isinstance(scores, dict) else {}).items():
            value = score.get("value") if isinstance(score, dict) else score
            key = canonical_json_bytes(decimals(value)).decode("utf-8")
            tally.setdefault(name, {})
            tally[name][key] = tally[name].get(key, 0) + 1
    return tally


def _iter_names(log: InspectLog) -> Iterator[tuple[InspectSample, str]]:
    used: set[str] = set()
    for item in log.samples:
        base = _stem(f"{log.task}-{item.sample.get('id')}-epoch{item.sample.get('epoch')}")
        name, suffix = base, 2
        while name in used:
            name, suffix = f"{base}-{suffix}", suffix + 1
        used.add(name)
        yield item, name


def record_inspect_log(source: Path, out_dir: Path, *, author: str) -> InspectRecording:
    """Convert one eval log into one trace per sample and epoch, sealed in one capsule."""
    log = read_inspect_log(source)
    out_dir.mkdir(parents=True, exist_ok=True)
    capsule = out_dir / f"{_stem(source.stem)}.sova"
    planned = [(item, out_dir / f"{name}.sova-trace") for item, name in _iter_names(log)]
    for path in [capsule, *(trace for _item, trace in planned)]:
        if path.exists():
            raise FormatError(
                "SOVA-RECORD-DESTINATION-EXISTS",
                f"refusing to overwrite an existing file: {path.name}",
            )
    for item, trace in planned:
        write_inspect_trace(trace, log, item)
    tally = _score_tally(log)
    summary = "; ".join(
        f"{name}: " + ", ".join(f"{count} x {value}" for value, count in sorted(counts.items()))
        for name, counts in sorted(tally.items())
    )
    manifest = capsule_manifest_template(
        title=f"Inspect AI eval log: {log.task} on {log.model}"[:200],
        summary=f"{len(planned)} recorded sample run(s). Scorer values as recorded: "
        f"{summary or 'none'}.",
        author=author,
        domain_profile=DomainProfile.SECURITY,
        capture_profile=CaptureProfile.STANDARD,
    )
    manifest["provenance"]["sourceDigests"] = [log.digest]
    manifest["provenance"]["transformations"] = [
        "Inspect AI eval log converted to .sova-trace events by sova record inspect-log."
    ]
    manifest["compatibility"] = {
        "runtime": "sova-runtime>=0.1.0a0",
        "models": [log.model],
        "tools": ["inspect_ai"],
        "platforms": [],
    }
    manifest["safety"] = {"impact": "none", "forbiddenEffects": [], "cleanupRequired": False}
    manifest["limitations"] = list(_LIMITATIONS)
    digest = build_capsule(
        capsule, manifest, named_traces={trace.name: trace for _item, trace in planned}
    )
    return InspectRecording(
        source, tuple(trace for _item, trace in planned), capsule, digest, len(planned), tally
    )


__all__ = [
    "InspectLog",
    "InspectRecording",
    "InspectSample",
    "find_inspect_logs",
    "read_inspect_log",
    "record_inspect_log",
    "write_inspect_trace",
]
