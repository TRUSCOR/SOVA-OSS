# SPDX-License-Identifier: Apache-2.0
"""Write one fresh run as a `.sova-trace` with the AgentDojo converter's event kinds.

Event order: ``run.started`` (model, provider, condition, attack), ``prompt.system``,
``prompt.user``, then per assistant turn ``model.response`` followed by
``environment.model.returned`` (the model string the provider reported for that
call, its usage and failed attempts) and ``tool.requested``; ``tool.result`` per
tool message; ``error.run`` when the run failed; ``oracle.completed`` with the
benchmark's security and utility verdicts; ``judge.completed`` with the judged
outcome; and ``run.completed``.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from sova.formats import canonical_json_bytes, sha256_digest
from sova.rerun.records import CallRecord, RunRecord, Verdict, decimal_text, jsonable
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

RECORDER: Final = {"id": "sova:actor:rerun", "kind": "recorder", "name": "sova rerun"}
CHECKER: Final = {"id": "agentdojo:checker", "kind": "observer", "name": "AgentDojo checks"}
USER: Final = {"id": "agentdojo:user", "kind": "user", "name": "benchmark user"}
PLANTED_MARKER: Final = "<INFORMATION>"


@dataclass(frozen=True, slots=True)
class Judgment:
    """The judged outcome of a run and its estimated cost."""

    verdict: Verdict
    judge: str
    reason: str | None
    cost_usd: float | None


def authorization_scope(record: RunRecord) -> dict[str, Any]:
    """Return the exact scope the operator authorized for this run."""
    job = record.job
    return {
        "action": "agentdojo.run-injection-episode",
        "environment": "AgentDojo simulated suite",
        "sourceCapsule": job.source_capsule_digest,
        "model": job.model,
        "provider": record.provider,
        "condition": job.condition.describe(),
        "trial": job.trial,
    }


def _writer(record: RunRecord, destination: Path) -> TraceWriter:
    job = record.job
    returned = list(record.returned_models())
    return TraceWriter(
        destination,
        durability="standard",
        capture_profile="standard",
        content_capture="full",
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(canonical_json_bytes(authorization_scope(record))),
            "decidedBy": "operator via --authorize",
        },
        environment={
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": None,
            "model": {
                "requested": job.model,
                "returned": returned or "not-reported",
                "provider": record.provider,
                "api": record.api,
            },
            "dependencies": [
                {"name": name, "version": version}
                for name, version in sorted(record.software.items())
            ],
        },
        executor={
            "id": "sova:executor:agentdojo",
            "name": "AgentDojo",
            "version": str(record.software.get("agentdojo", "unknown")),
            "capabilityDigest": None,
        },
        reviewed_for_export=False,
    )


class _RunTrace:
    """Append the events of one run record to a trace writer."""

    def __init__(self, record: RunRecord, writer: TraceWriter) -> None:
        job = record.job
        self.record = record
        self.writer = writer
        self.agent = {"id": f"model:{job.model}", "kind": "model", "name": job.model}
        self.environment = {
            "id": f"agentdojo:{job.suite}",
            "kind": "simulated-environment",
            "name": f"AgentDojo {job.suite} suite (synthetic data)",
        }
        self.time = record.started_at

    def append(self, kind: str, payload: Mapping[str, Any], **kwargs: Any) -> None:
        self.writer.append(
            kind, jsonable(payload), wall_time=kwargs.pop("when", self.time), **kwargs
        )

    def started(self) -> None:
        record, job = self.record, self.record.job
        self.append(
            "run.started",
            {
                "benchmark": "AgentDojo",
                "benchmarkVersion": job.benchmark_version,
                "agentdojo": record.software.get("agentdojo"),
                "attack": job.attack,
                "attackName": job.attack_name,
                "suite": job.suite,
                "userTask": job.user_task,
                "injectionTask": job.injection_task,
                "model": job.model,
                "provider": record.provider,
                "api": record.api,
                "temperature": record.temperature,
                "defense": job.condition.defense,
                "toolOutputFormat": job.condition.normalized_tool_output_format,
                "condition": job.condition.describe(),
                "trial": job.trial,
                "runKey": job.key,
                "sourceCapsule": job.source_capsule_digest,
                "injectionDigest": record.injection_digest,
                "startedAt": record.started_at,
            },
            actor=RECORDER,
            target=self.environment,
        )

    def assistant(self, message: Mapping[str, Any], call: CallRecord | None) -> None:
        if call is not None:
            self.time = call.started_at
        tool_calls = list(message.get("toolCalls") or [])
        response: dict[str, Any] = {"text": str(message.get("text") or ""), "toolCalls": tool_calls}
        if message.get("omittedBlocks"):
            response["omittedBlocks"] = message["omittedBlocks"]
        self.append("model.response", response, actor=self.agent, target=self.environment)
        if call is not None:
            self.append(
                "environment.model.returned", call.to_json(), actor=self.agent, target=RECORDER
            )
        for tool_call in tool_calls:
            self.append("tool.requested", tool_call, actor=self.agent, target=self.environment)

    def tool(self, message: Mapping[str, Any]) -> None:
        text = str(message.get("text") or "")
        self.append(
            "tool.result",
            {
                "function": message.get("function") or "unknown",
                "toolCallId": message.get("toolCallId"),
                "output": text,
                "error": message.get("error"),
                "containsPlantedInstruction": PLANTED_MARKER in text,
            },
            actor=self.environment,
            target=self.agent,
        )

    def messages(self) -> None:
        calls = list(self.record.calls)
        used = 0
        for message in self.record.messages:
            role = message.get("role")
            if role in {"system", "user"}:
                kind = "prompt.system" if role == "system" else "prompt.user"
                actor = RECORDER if role == "system" else USER
                self.append(
                    kind, {"text": str(message.get("text") or "")}, actor=actor, target=self.agent
                )
            elif role == "assistant":
                self.assistant(message, calls[used] if used < len(calls) else None)
                used += 1
            elif role == "tool":
                self.tool(message)
        for call in calls[used:]:
            # A failed final call, or a pipeline retry that replaced earlier messages.
            self.append(
                "environment.model.returned",
                {**call.to_json(), "unmatchedTurn": True},
                actor=self.agent,
                target=RECORDER,
                when=call.started_at,
            )

    def verdicts(self, judgment: Judgment) -> None:
        record, job = self.record, self.record.job
        end = record.finished_at
        if record.error is not None:
            self.append(
                "error.run", {"error": record.error}, actor=RECORDER, target=self.agent, when=end
            )
        oracle: dict[str, Any] = {
            "oracle": "agentdojo.injection-task.security",
            "suite": job.suite,
            "injectionTask": job.injection_task,
            "utilityOracle": "agentdojo.user-task.utility",
            "userTask": job.user_task,
            "status": "not-evaluated" if record.security is None else "evaluated",
        }
        if record.security is not None:
            oracle["attackSucceeded"] = record.security
            oracle["userTaskCompleted"] = record.utility
        if record.model_output_missing:
            oracle["modelOutputMissing"] = True
        self.append("oracle.completed", oracle, actor=CHECKER, target=self.environment, when=end)
        judged: dict[str, Any] = {
            "judge": judgment.judge,
            "verdict": judgment.verdict,
            "reason": judgment.reason,
        }
        if judgment.verdict != "cant-tell":
            judged["attackObserved"] = judgment.verdict == "attack"
        self.append("judge.completed", judged, actor=RECORDER, target=self.agent, when=end)
        self.append(
            "run.completed",
            {
                "attackSucceeded": record.security,
                "userTaskCompleted": record.utility,
                "verdict": judgment.verdict,
                "error": record.error,
                "tokens": record.usage_total().to_json(),
                "costUsdEstimate": decimal_text(judgment.cost_usd, 6),
                "seconds": decimal_text(record.seconds, 2),
                "returnedModels": list(record.returned_models()),
            },
            actor=RECORDER,
            target=self.environment,
            when=end,
        )


def write_run_trace(record: RunRecord, destination: Path, judgment: Judgment) -> str:
    """Write ``record`` as a sealed trace at ``destination`` and return its digest."""
    writer = _writer(record, destination)
    trace = _RunTrace(record, writer)
    trace.started()
    trace.messages()
    trace.verdicts(judgment)
    return writer.finalize(completion="completed" if record.error is None else "failed")


__all__ = ["Judgment", "authorization_scope", "write_run_trace"]
