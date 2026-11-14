# SPDX-License-Identifier: Apache-2.0
"""Read AgentDojo run logs, and `.sova-trace` files recorded from them, as audit episodes.

AgentDojo writes one JSON log per episode, published under
``runs/<pipeline>/<suite>/<user_task>/<attack>/<injection_task>.json``. A log carries
``suite_name``, ``pipeline_name``, ``user_task_id``, ``injection_task_id``,
``attack_type``, ``messages``, ``error``, ``utility`` and ``security``.

A `.sova-trace` written by ``sova record agentdojo`` maps back to the same shape:

* ``run.started`` with ``benchmark: "AgentDojo"`` gives the suite, user task,
  injection task, attack and model;
* ``model.response`` starts an assistant message (``content``, else ``text``);
* each following ``tool.requested`` (``function``, ``args``, ``callId``) is one of
  its tool calls;
* ``tool.result`` (``function``, ``args``, ``callId``, ``output``, ``error``) is a
  tool message; ``prompt.system`` and ``prompt.user`` are system and user messages;
* ``oracle.completed`` with ``oracle: "agentdojo.injection-task.security"`` gives the
  verdict in ``attackSucceeded`` (true, false or null);
* an ``error`` value in ``run.completed``, or any ``error.*`` event, marks the
  episode as crashed.

Reading never executes recorded content.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sova.audit.engine import Episode
from sova.formats import PackageReader, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceReader

SECURITY_ORACLE = "agentdojo.injection-task.security"
_MAX_LOG_BYTES = 256 * 1024 * 1024
_MAX_LOG_ITEMS = 10_000_000
_TRACE_SUFFIX = ".sova-trace"


@dataclass(frozen=True, slots=True)
class SkippedInput:
    """A file that was found but not audited, and why."""

    path: str
    reason: str

    def to_mapping(self) -> dict[str, str]:
        """Return a canonical-JSON-safe mapping."""
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class AuditInputs:
    """Episodes ready to audit plus every file that was passed over."""

    episodes: tuple[Episode, ...]
    skipped: tuple[SkippedInput, ...]


def is_agentdojo_log(document: Any) -> bool:
    """Return whether a parsed JSON document has the shape of an AgentDojo run log."""
    return (
        isinstance(document, dict)
        and isinstance(document.get("suite_name"), str)
        and isinstance(document.get("user_task_id"), str)
        and isinstance(document.get("messages"), list)
    )


def parse_agentdojo_log(raw: bytes) -> dict[str, Any]:
    """Parse AgentDojo log bytes strictly (no duplicate keys, no NaN) and check the shape."""
    document = strict_json_loads(raw, max_bytes=_MAX_LOG_BYTES, max_items=_MAX_LOG_ITEMS)
    if not is_agentdojo_log(document):
        raise FormatError("SOVA-AGENTDOJO-LOG", "JSON file is not an AgentDojo run log")
    return dict(document)


def read_agentdojo_log(path: Path) -> dict[str, Any]:
    """Read and parse one AgentDojo log file."""
    if path.stat().st_size > _MAX_LOG_BYTES:
        raise FormatError("SOVA-AGENTDOJO-LOG-SIZE", "AgentDojo log exceeds the size limit")
    return parse_agentdojo_log(path.read_bytes())


def verdict_value(value: Any) -> bool | None:
    """Normalise a recorded security verdict: missing or null means no verdict."""
    return None if value is None else bool(value)


def _error_text(value: Any) -> str | None:
    return str(value) if value else None


def _name(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def episode_from_log(document: dict[str, Any], *, source: str) -> Episode | SkippedInput:
    """Turn one AgentDojo log into an episode; runs without an injection are skipped."""
    injection = document.get("injection_task_id")
    if not injection:
        return SkippedInput(source, "no injection task (a run without an attack)")
    attack = document.get("attack_type")
    return Episode(
        source=source,
        pipeline=_name(document.get("pipeline_name"), "unknown-pipeline"),
        suite=str(document["suite_name"]),
        user_task=str(document["user_task_id"]),
        injection_task=str(injection),
        attack=str(attack) if attack else None,
        verdict=verdict_value(document.get("security")),
        error=_error_text(document.get("error")),
        messages=tuple(document["messages"]),
    )


def _messages_from_events(
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool | None, str | None]:
    messages: list[dict[str, Any]] = []
    verdict: bool | None = None
    error: str | None = None
    for event in events:
        kind, payload = event["kind"], event["payload"]
        if kind == "model.response":
            content = payload.get("content", payload.get("text"))
            messages.append({"role": "assistant", "content": content, "tool_calls": []})
        elif kind == "tool.requested":
            if not messages or messages[-1].get("role") != "assistant":
                messages.append({"role": "assistant", "content": None, "tool_calls": []})
            messages[-1]["tool_calls"].append(
                {
                    "function": payload.get("function"),
                    "args": payload.get("args"),
                    "id": payload.get("callId"),
                }
            )
        elif kind == "tool.result":
            messages.append(
                {
                    "role": "tool",
                    "content": payload.get("output"),
                    "tool_call_id": payload.get("callId"),
                    "tool_call": {
                        "function": payload.get("function"),
                        "args": payload.get("args"),
                        "id": payload.get("callId"),
                    },
                    "error": payload.get("error"),
                }
            )
        elif kind in {"prompt.system", "prompt.user"}:
            messages.append({"role": kind.removeprefix("prompt."), "content": payload.get("text")})
        elif kind == "oracle.completed" and payload.get("oracle") == SECURITY_ORACLE:
            verdict = verdict_value(payload.get("attackSucceeded"))
        elif kind == "run.completed":
            error = error or _error_text(payload.get("error"))
        elif kind.startswith("error."):
            error = error or _error_text(payload.get("error")) or kind
    return messages, verdict, error


def episode_from_trace(path: Path) -> Episode | SkippedInput:
    """Verify one `.sova-trace` offline and map its AgentDojo events to an episode."""
    reader = TraceReader(path)
    reader.verify()
    events = reader.events()
    run = next(
        (
            event["payload"]
            for event in events
            if event["kind"] == "run.started" and event["payload"].get("benchmark") == "AgentDojo"
        ),
        None,
    )
    source = str(path)
    if run is None or not isinstance(run.get("suite"), str):
        return SkippedInput(source, "trace has no AgentDojo run.started event")
    injection = run.get("injectionTask")
    if not injection:
        return SkippedInput(source, "no injection task (a run without an attack)")
    messages, verdict, error = _messages_from_events(events)
    attack = run.get("attack")
    return Episode(
        source=source,
        pipeline=_name(run.get("model"), "unknown-pipeline"),
        suite=run["suite"],
        user_task=str(run.get("userTask")),
        injection_task=str(injection),
        attack=str(attack) if attack else None,
        verdict=verdict,
        error=error,
        messages=tuple(messages),
    )


def _is_trace(path: Path) -> bool:
    return path.name.lower().endswith(_TRACE_SUFFIX)


def read_episode(path: Path) -> Episode | SkippedInput:
    """Read one AgentDojo log (``.json``) or recorded ``.sova-trace``."""
    if _is_trace(path):
        return episode_from_trace(path)
    return episode_from_log(read_agentdojo_log(path), source=str(path))


def _is_capsule(path: Path) -> bool:
    return path.suffix.lower() == ".sova"


def episodes_from_capsule(
    path: Path, *, seen: set[str] | None = None, label: str | None = None
) -> list[Episode | SkippedInput]:
    """Verify a ``.sova`` capsule offline and audit every trace inside it.

    Nested capsules (bundles written by ``sova record agentdojo --bundle``) are opened
    in turn. A trace whose digest is already in ``seen`` is not counted twice.
    """
    seen = set() if seen is None else seen
    name = label or str(path)
    out: list[Episode | SkippedInput] = []
    reader = PackageReader(path)
    with tempfile.TemporaryDirectory(prefix=".sova-audit-") as staging:
        for index, descriptor in enumerate(reader.verify("sova.capsule")):
            if descriptor.role not in {"trace", "capsule"}:
                continue
            if descriptor.digest in seen:
                continue
            seen.add(descriptor.digest)
            data = reader.read_object(descriptor)
            suffix = ".sova-trace" if descriptor.role == "trace" else ".sova"
            local = Path(staging) / f"object-{index:05d}{suffix}"
            local.write_bytes(data)
            inner = f"{name}#{descriptor.path}"
            if descriptor.role == "trace":
                item = episode_from_trace(local)
                if isinstance(item, Episode):
                    item = Episode(
                        source=inner,
                        pipeline=item.pipeline,
                        suite=item.suite,
                        user_task=item.user_task,
                        injection_task=item.injection_task,
                        attack=item.attack,
                        verdict=item.verdict,
                        error=item.error,
                        messages=item.messages,
                    )
                out.append(item)
            else:
                out.extend(episodes_from_capsule(local, seen=seen, label=inner))
    return out


def _candidates(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and (path.suffix.lower() == ".json" or _is_trace(path) or _is_capsule(path))
    )


def _items_for(candidate: Path, seen: set[str]) -> list[Episode | SkippedInput]:
    """Episodes in one directory entry; a trace already seen (by digest) yields none."""
    if _is_capsule(candidate):
        return episodes_from_capsule(candidate, seen=seen)
    if _is_trace(candidate):
        digest = sha256_digest(candidate.read_bytes())
        if digest in seen:
            return []
        seen.add(digest)
    return [read_episode(candidate)]


def collect_inputs(path: Path, *, limit: int | None = None) -> AuditInputs:
    """Collect episodes from one file, or from every log and trace under a directory.

    A single file must be an AgentDojo log or trace. In a directory, files that cannot
    be read as either are skipped with a reason rather than failing the whole audit.
    ``limit`` stops after that many episodes.
    """
    if path.is_file():
        items: list[Episode | SkippedInput] = (
            episodes_from_capsule(path) if _is_capsule(path) else [read_episode(path)]
        )
        if limit is not None:
            items = items[:limit]
        return AuditInputs(
            episodes=tuple(i for i in items if isinstance(i, Episode)),
            skipped=tuple(i for i in items if isinstance(i, SkippedInput)),
        )
    if not path.is_dir():
        raise FormatError("SOVA-AUDIT-PATH", "audit path is neither a file nor a directory")
    episodes: list[Episode] = []
    skipped: list[SkippedInput] = []
    seen: set[str] = set()
    # Loose traces first, so a capsule holding the same trace is not counted again.
    ordered = sorted(_candidates(path), key=lambda candidate: (_is_capsule(candidate), candidate))
    for candidate in ordered:
        if limit is not None and len(episodes) >= limit:
            break
        try:
            items = _items_for(candidate, seen)
        except FormatError as error:
            skipped.append(
                SkippedInput(str(candidate), f"{error.issue.code}: {error.issue.message}")
            )
            continue
        for item in items:
            if isinstance(item, SkippedInput):
                skipped.append(item)
            elif limit is None or len(episodes) < limit:
                episodes.append(item)
    return AuditInputs(episodes=tuple(episodes), skipped=tuple(skipped))


__all__ = [
    "SECURITY_ORACLE",
    "AuditInputs",
    "SkippedInput",
    "collect_inputs",
    "episode_from_log",
    "episode_from_trace",
    "episodes_from_capsule",
    "is_agentdojo_log",
    "parse_agentdojo_log",
    "read_agentdojo_log",
    "read_episode",
    "verdict_value",
]
