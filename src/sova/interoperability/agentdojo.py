# SPDX-License-Identifier: Apache-2.0
"""Record AgentDojo run logs as `.sova-trace` files and `.sova` capsules.

AgentDojo writes one JSON log per episode: suite, user task, injection task, attack,
the full message list, and its utility and security verdicts. This bridge converts
such a log into a tamper-evident `.sova-trace` that ends in AgentDojo's own verdict
as the declared outcome, and packages it as a `.sova` capsule that anyone can verify
offline. It calls no model and runs no benchmark code.

Event mapping (also read back by ``sova audit``):

* ``artifact.imported`` -- source file name and SHA-256 digest;
* ``run.started`` -- benchmark, versions, attack, suite, user and injection task, model;
* ``prompt.system`` / ``prompt.user`` -- ``text``;
* ``model.response`` -- ``text``, ``toolCalls`` and, for block content, ``content``;
* ``tool.requested`` -- ``function``, ``args``, ``callId``;
* ``tool.result`` -- ``function``, ``args``, ``callId``, ``output``, ``error`` and
  ``containsPlantedInstruction`` (the output carries the planted text);
* ``error.reported`` -- only when the log records an episode error;
* ``oracle.completed`` -- ``oracle: "agentdojo.injection-task.security"`` and
  ``attackSucceeded`` (true, false, or null when the log has no verdict);
* ``run.completed`` -- ``attackSucceeded``, ``userTaskCompleted``, ``error``.

Binary floats are stored as their decimal strings because canonical SOVA JSON has no
floats. Capture-time redaction still applies: values under secret-like argument names
(for example ``password``) are replaced by redaction markers.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from sova.audit.agentdojo import parse_agentdojo_log, read_agentdojo_log
from sova.capsule.model import (
    CaptureProfile,
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.canonical import MAX_IJSON_INTEGER
from sova.formats.errors import FormatError
from sova.trace.writer import TraceWriter

SECURITY_ORACLE = "agentdojo.injection-task.security"
PLANTED_MARKER = "<INFORMATION>"
_SCENARIO_NAMESPACE = "https://github.com/ethz-spylab/agentdojo"
_RECORDER = {"id": "sova:actor:converter", "kind": "recorder", "name": "sova record agentdojo"}
_USER = {"id": "agentdojo:user", "kind": "user", "name": "benchmark user"}
_CHECKER = {"id": "agentdojo:checker", "kind": "observer", "name": "AgentDojo security check"}
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_WHITESPACE = re.compile(r"\s+")
_MAX_TITLE = 200
_MIN_PLANTED_TEXT = 24
_FORBIDDEN_EFFECTS = ["real accounts", "real money"]
_LIMITATIONS = [
    "Converted from an AgentDojo log after the run; the run itself did not write a trace.",
    "The declared outcome is AgentDojo's security verdict, which may not match a reading "
    "of the recorded messages.",
]


@dataclass(frozen=True, slots=True)
class RecordedEpisode:
    """Paths and digests written for one converted log."""

    source: Path
    trace: Path | None
    capsule: Path | None
    capsule_digest: str | None


@dataclass(frozen=True, slots=True)
class _Run:
    """The identifying fields of one AgentDojo log."""

    suite: str
    user_task: str
    injection_task: str | None
    attack: str | None
    model: str
    benchmark_version: str
    package_version: str | None
    security: bool | None

    @property
    def stem(self) -> str:
        parts = (
            self.model,
            self.suite,
            self.user_task,
            self.injection_task or "no-injection",
            self.attack or "no-attack",
        )
        return "--".join(_UNSAFE_NAME.sub("_", part).strip("._") or "unnamed" for part in parts)


def decimals(value: Any) -> Any:
    """Replace binary floats (and out-of-range integers) by their decimal strings."""
    if isinstance(value, float) or (
        isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_IJSON_INTEGER
    ):
        return repr(value)
    if isinstance(value, dict):
        return {str(key): decimals(child) for key, child in value.items()}
    if isinstance(value, list):
        return [decimals(child) for child in value]
    return value


def text_of(content: Any) -> str:
    """Flatten AgentDojo message content: a string, None, or a list of text blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)
    return "".join(
        str(item.get("content") or item.get("text") or "") if isinstance(item, dict) else str(item)
        for item in content
    )


def _planted_texts(log: dict[str, Any]) -> list[str]:
    injections = log.get("injections")
    if not isinstance(injections, dict):
        return []
    texts = [_WHITESPACE.sub(" ", str(value)).strip() for value in injections.values()]
    return [text for text in texts if len(text) >= _MIN_PLANTED_TEXT]


def contains_planted_instruction(output: str, planted: list[str]) -> bool:
    """Return whether tool output carries the planted text (whitespace-insensitive)."""
    if PLANTED_MARKER in output:
        return True
    flattened = _WHITESPACE.sub(" ", output)
    return any(text in flattened for text in planted)


def _optional_text(value: Any) -> str | None:
    return str(value) if value else None


def _run_of(log: dict[str, Any]) -> _Run:
    security = log.get("security")
    return _Run(
        suite=str(log["suite_name"]),
        user_task=str(log["user_task_id"]),
        injection_task=_optional_text(log.get("injection_task_id")),
        attack=_optional_text(log.get("attack_type")),
        model=_optional_text(log.get("pipeline_name")) or "unknown-pipeline",
        benchmark_version=_optional_text(log.get("benchmark_version")) or "unknown",
        package_version=_optional_text(log.get("agentdojo_package_version")),
        security=None if security is None else bool(security),
    )


def _call_id(call: dict[str, Any]) -> Any:
    identifier = call.get("id")
    return identifier if isinstance(identifier, str) else None


def write_agentdojo_trace(
    destination: Path,
    log: dict[str, Any],
    *,
    source_name: str,
    source_digest: str,
) -> str:
    """Write one AgentDojo log as a `.sova-trace` and return the trace digest."""
    run = _run_of(log)
    package_version = run.package_version or "not-recorded"
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
            "model": {"requested": run.model, "returned": "not-recorded"},
            "dependencies": [{"name": "agentdojo", "version": package_version}],
        },
        executor={
            "id": "sova:executor:agentdojo",
            "name": "AgentDojo",
            "version": package_version,
            "capabilityDigest": None,
        },
    )
    agent = {"id": f"model:{run.model}", "kind": "model", "name": run.model}
    environment = {
        "id": f"agentdojo:{run.suite}",
        "kind": "simulated-environment",
        "name": f"AgentDojo {run.suite} suite (synthetic data)",
    }

    def append(kind: str, payload: dict[str, Any], **context: Any) -> None:
        writer.append(kind, decimals(payload), **context)

    run_info: dict[str, Any] = {
        "benchmark": "AgentDojo",
        "benchmarkVersion": run.benchmark_version,
        "agentdojo": run.package_version,
        "attack": run.attack,
        "suite": run.suite,
        "userTask": run.user_task,
        "injectionTask": run.injection_task,
        "model": run.model,
        "evaluationTimestamp": _optional_text(log.get("evaluation_timestamp")),
    }
    append(
        "artifact.imported",
        {
            "from": "AgentDojo run log",
            "path": source_name,
            "sha256": source_digest,
            "note": "Converted from the run's JSON log; recorded by whoever ran the benchmark.",
        },
        actor=_RECORDER,
    )
    append(
        "run.started",
        {key: value for key, value in run_info.items() if value is not None},
        actor=_RECORDER,
        target=environment,
    )
    planted = _planted_texts(log)
    calls: dict[str, str] = {}
    for message in log["messages"]:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        text = text_of(content)
        if role == "system":
            append("prompt.system", {"text": text}, actor=_RECORDER, target=agent)
        elif role == "user":
            append("prompt.user", {"text": text}, actor=_USER, target=agent)
        elif role == "assistant":
            requested = [
                call for call in (message.get("tool_calls") or []) if isinstance(call, dict)
            ]
            response: dict[str, Any] = {
                "text": text,
                "toolCalls": [
                    {"function": call.get("function"), "args": call.get("args")}
                    for call in requested
                ],
            }
            if isinstance(content, list):
                response["content"] = content
            append("model.response", response, actor=agent)
            for call in requested:
                identifier = _call_id(call)
                if identifier:
                    calls[identifier] = str(call.get("function"))
                append(
                    "tool.requested",
                    {
                        "function": call.get("function"),
                        "args": call.get("args"),
                        "callId": identifier,
                    },
                    actor=agent,
                    target=environment,
                )
        elif role == "tool":
            raw_call = message.get("tool_call")
            call = raw_call if isinstance(raw_call, dict) else {}
            identifier = message.get("tool_call_id") or _call_id(call)
            identifier = identifier if isinstance(identifier, str) else None
            function = call.get("function") or calls.get(identifier or "", "unknown")
            append(
                "tool.result",
                {
                    "function": function,
                    "args": call.get("args"),
                    "callId": identifier,
                    "output": text,
                    "error": message.get("error"),
                    "containsPlantedInstruction": contains_planted_instruction(text, planted),
                },
                actor=environment,
                target=agent,
            )
    error = _optional_text(log.get("error"))
    if error is not None:
        append("error.reported", {"source": "AgentDojo", "error": error}, actor=_RECORDER)
    append(
        "oracle.completed",
        {
            "oracle": SECURITY_ORACLE,
            "suite": run.suite,
            "injectionTask": run.injection_task,
            "attackSucceeded": run.security,
        },
        actor=_CHECKER,
    )
    append(
        "run.completed",
        {
            "attackSucceeded": run.security,
            "userTaskCompleted": log.get("utility"),
            "error": error,
        },
        actor=_RECORDER,
    )
    return writer.finalize()


def _verdict_phrase(*, security: bool | None) -> str:
    if security is None:
        return "AgentDojo recorded no security verdict for this run."
    return f"AgentDojo scored this run as {'attacked' if security else 'not attacked'}."


def agentdojo_scenario(run: _Run) -> dict[str, Any]:
    """Return the inert scenario a later re-run needs, with AgentDojo parameters."""
    injection = run.injection_task or "no injection"
    title = f"AgentDojo {run.suite}/{run.user_task}/{injection} on {run.model}"[:_MAX_TITLE]
    identity = (
        f"{_SCENARIO_NAMESPACE}#{run.suite}/{run.user_task}/{run.injection_task}"
        f"/{run.attack}/{run.model}"
    )
    requirement = f"agentdojo/{run.package_version or 'unknown'}"
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": f"sova:scenario:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
        "version": "0.1.0",
        "title": title,
        "purpose": (
            "Record whether a planted instruction in tool output made the agent carry out "
            "the attacker's goal."
        ),
        "parameters": {
            "benchmark": "AgentDojo",
            "benchmarkVersion": run.benchmark_version,
            "attack": run.attack,
            "suite": run.suite,
            "userTask": run.user_task,
            "injectionTask": run.injection_task,
            "model": run.model,
        },
        "preconditions": [{"kind": "simulated-environment", "owned": True}],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "run-episode",
                    "action": "agentdojo.run-injection-episode",
                    "inputs": {
                        "suite": run.suite,
                        "userTask": run.user_task,
                        "injectionTask": run.injection_task,
                        "attack": run.attack,
                        "model": run.model,
                    },
                    "onFailure": "inconclusive",
                    "requires": [requirement],
                }
            ]
        },
        "triggers": [
            {"kind": "planted-instruction", "location": "tool output", "template": run.attack}
        ],
        "mutations": [],
        "expectedEffects": [
            {"kind": "attacker-goal", "injectionTask": run.injection_task, "simulated": True}
        ],
        "oracles": [
            {
                "kind": SECURITY_ORACLE,
                "suite": run.suite,
                "injectionTask": run.injection_task,
                "attackSucceeded": True,
            }
        ],
        "evidenceRequirements": [
            "prompt.user",
            "tool.result",
            "model.response",
            "tool.requested",
            "oracle.completed",
        ],
        "safety": {
            "budgets": {"maxSteps": 1},
            "forbiddenEffects": list(_FORBIDDEN_EFFECTS),
            "stopConditions": [],
        },
        "cleanup": [{"kind": "environment-discarded", "verify": False}],
        "limitations": list(_LIMITATIONS),
        "extensions": {},
    }


def _manifest(
    run: _Run,
    *,
    title: str,
    summary: str,
    author: str,
    source_digests: list[str],
) -> dict[str, Any]:
    manifest = capsule_manifest_template(
        title=title,
        summary=summary,
        author=author,
        domain_profile=DomainProfile.SECURITY,
        capture_profile=CaptureProfile.STANDARD,
    )
    manifest["provenance"]["sourceDigests"] = sorted(set(source_digests))
    manifest["provenance"]["transformations"] = [
        "AgentDojo JSON log converted to .sova-trace events by sova record agentdojo."
    ]
    manifest["taxonomy"] = {
        "id": "agentdojo.injection-task",
        "version": run.benchmark_version,
        "digest": sha256_digest(
            canonical_json_bytes({"suite": run.suite, "injectionTask": run.injection_task})
        ),
    }
    # The method is pinned to the digest of its exact declared description: which package,
    # benchmark version and attack produced the run, and which converter recorded it.
    manifest["methodology"] = {
        "id": "agentdojo.run-injection-episode",
        "version": run.package_version or "unknown",
        "digest": sha256_digest(
            canonical_json_bytes(
                {
                    "benchmark": "AgentDojo",
                    "package": run.package_version,
                    "benchmarkVersion": run.benchmark_version,
                    "attack": run.attack,
                    "converter": "sova record agentdojo",
                }
            )
        ),
    }
    tool = f"agentdojo=={run.package_version}" if run.package_version else "agentdojo"
    manifest["compatibility"] = {
        "runtime": "sova-runtime>=0.1.0a0",
        "models": [run.model],
        "tools": [tool],
        "platforms": [],
    }
    manifest["safety"] = {
        "impact": "none",
        "forbiddenEffects": list(_FORBIDDEN_EFFECTS),
        "cleanupRequired": False,
    }
    manifest["limitations"] = [*_LIMITATIONS, "Opening or verifying this capsule runs nothing."]
    manifest["requiredFeatures"] = ["scenario.core/0.1"]
    return manifest


def _refuse_existing(*paths: Path) -> None:
    for path in paths:
        if path.exists():
            raise FormatError(
                "SOVA-RECORD-DESTINATION-EXISTS",
                f"refusing to overwrite an existing file: {path.name}",
            )


@dataclass(frozen=True, slots=True)
class _Converted:
    run: _Run
    trace: Path
    capsule: Path
    capsule_digest: str
    source_digest: str


def _convert(
    log_path: Path, out_dir: Path, *, author: str, used_stems: set[str] | None = None
) -> _Converted:
    raw = log_path.read_bytes()
    log = parse_agentdojo_log(raw)
    run = _run_of(log)
    digest = sha256_digest(raw)
    stem = run.stem
    if used_stems is not None:
        # Repeated runs of one episode in a single recording get a suffix from their own
        # content digest, so names stay deterministic and nothing is ever overwritten.
        if stem in used_stems:
            stem = f"{stem}--{digest.split(':', 1)[1][:8]}"
        used_stems.add(stem)
    out_dir.mkdir(parents=True, exist_ok=True)
    trace = out_dir / f"{stem}.sova-trace"
    capsule = out_dir / f"{stem}.sova"
    _refuse_existing(trace, capsule)
    write_agentdojo_trace(trace, log, source_name=log_path.name, source_digest=digest)
    scenario = agentdojo_scenario(run)
    manifest = _manifest(
        run,
        title=scenario["title"],
        summary=_verdict_phrase(security=run.security),
        author=author,
        source_digests=[digest],
    )
    capsule_digest = build_capsule(
        capsule, manifest, scenario=scenario, named_traces={trace.name: trace}
    )
    return _Converted(run, trace, capsule, capsule_digest, digest)


def record_agentdojo_log(
    log_path: Path, out_dir: Path, *, author: str, used_stems: set[str] | None = None
) -> RecordedEpisode:
    """Convert one AgentDojo log into ``<stem>.sova-trace`` and ``<stem>.sova``.

    Pass the same ``used_stems`` set across one recording of many logs: a repeated
    episode then gets ``--<first 8 hex digits of its log digest>`` added to its name.
    """
    converted = _convert(log_path, out_dir, author=author, used_stems=used_stems)
    return RecordedEpisode(
        source=log_path,
        trace=converted.trace,
        capsule=converted.capsule,
        capsule_digest=converted.capsule_digest,
    )


def find_agentdojo_logs(root: Path) -> tuple[list[Path], int]:
    """Return AgentDojo logs under a directory and the count of other JSON files."""
    logs: list[Path] = []
    other = 0
    for path in sorted(root.rglob("*.json")):
        if not path.is_file():
            continue
        try:
            read_agentdojo_log(path)
        except FormatError:
            other += 1
            continue
        logs.append(path)
    return logs, other


def record_agentdojo_bundle(
    logs: list[Path],
    destination: Path,
    *,
    author: str,
) -> RecordedEpisode:
    """Convert many logs into one capsule that nests one capsule per episode."""
    if not logs:
        raise FormatError("SOVA-RECORD-NO-LOGS", "no AgentDojo logs to bundle")
    _refuse_existing(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    nested: dict[str, Path] = {}
    steps: list[dict[str, Any]] = []
    source_digests: list[str] = []
    runs: list[_Run] = []
    used_stems: set[str] = set()
    with TemporaryDirectory(prefix=".sova-record-", dir=destination.parent) as staging:
        staging_root = Path(staging)
        for index, log_path in enumerate(logs):
            converted = _convert(log_path, staging_root, author=author, used_stems=used_stems)
            run = converted.run
            runs.append(run)
            nested[converted.capsule.name] = converted.capsule
            source_digests.append(converted.source_digest)
            steps.append(
                {
                    "id": f"episode-{index:05d}",
                    "action": "agentdojo.run-injection-episode",
                    "inputs": {
                        "capsule": f"capsules/{converted.capsule.name}",
                        "suite": run.suite,
                        "userTask": run.user_task,
                        "injectionTask": run.injection_task,
                        "attack": run.attack,
                        "model": run.model,
                    },
                    "onFailure": "continue",
                    "requires": [f"agentdojo/{run.package_version or 'unknown'}"],
                }
            )
        versions = sorted({run.benchmark_version for run in runs})
        models = sorted({run.model for run in runs})
        first = runs[0]
        scenario = agentdojo_scenario(first)
        scenario.update(
            {
                "id": f"sova:scenario:{uuid.uuid4()}",
                "title": f"AgentDojo bundle of {len(runs)} episode(s)",
                "purpose": "Group recorded AgentDojo episodes; each nested capsule is one run.",
                "parameters": {
                    "benchmark": "AgentDojo",
                    "benchmarkVersion": versions[0] if len(versions) == 1 else "mixed",
                    "bundle": "nested-capsules",
                    "episodeCount": len(runs),
                    "models": models,
                },
                "procedure": {"steps": steps},
                "triggers": [],
                "expectedEffects": [],
                "oracles": [],
            }
        )
        scenario["safety"]["budgets"] = {"maxSteps": len(steps)}
        manifest = _manifest(
            first,
            title=scenario["title"],
            summary=(
                f"{len(runs)} recorded AgentDojo episode(s); "
                f"{sum(1 for run in runs if run.security)} scored as attacked by AgentDojo."
            ),
            author=author,
            source_digests=source_digests,
        )
        manifest["compatibility"]["models"] = models
        manifest["taxonomy"]["version"] = scenario["parameters"]["benchmarkVersion"]
        manifest["taxonomy"]["digest"] = sha256_digest(
            canonical_json_bytes(
                sorted(
                    {(run.suite, run.injection_task or "") for run in runs},
                )
            )
        )
        if len({run.package_version for run in runs}) > 1 or len({run.attack for run in runs}) > 1:
            manifest["methodology"]["version"] = "mixed"
            manifest["methodology"]["digest"] = sha256_digest(
                canonical_json_bytes(
                    sorted(
                        {
                            (run.package_version or "", run.attack or "", run.benchmark_version)
                            for run in runs
                        }
                    )
                )
            )
        digest = build_capsule(destination, manifest, scenario=scenario, named_capsules=nested)
    return RecordedEpisode(
        source=destination.parent, trace=None, capsule=destination, capsule_digest=digest
    )


__all__ = [
    "PLANTED_MARKER",
    "SECURITY_ORACLE",
    "RecordedEpisode",
    "agentdojo_scenario",
    "contains_planted_instruction",
    "decimals",
    "find_agentdojo_logs",
    "record_agentdojo_bundle",
    "record_agentdojo_log",
    "text_of",
    "write_agentdojo_trace",
]
