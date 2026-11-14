# SPDX-License-Identifier: Apache-2.0
"""Plain records shared by the rerun runner, judge, trace writer, and reports."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.canonical import MAX_IJSON_INTEGER

Verdict = Literal["attack", "no-attack", "cant-tell"]
"""A judged outcome of one fresh run."""

VERDICTS: Final[tuple[Verdict, ...]] = ("attack", "no-attack", "cant-tell")

SUPPORTED_DEFENSES: Final[tuple[str | None, ...]] = (
    None,
    "repeat_user_prompt",
    "spotlighting_with_delimiting",
)
SUPPORTED_TOOL_OUTPUT_FORMATS: Final[tuple[str | None, ...]] = (None, "yaml", "json")


def jsonable(value: Any) -> Any:  # noqa: PLR0911 - one explicit conversion per type
    """Convert a value into canonical-SOVA-JSON-safe data.

    Binary floats become their decimal string, integers outside the I-JSON range
    become strings, tuples become lists, objects with ``model_dump`` are dumped,
    and any other object becomes its ``str``.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if -MAX_IJSON_INTEGER <= value <= MAX_IJSON_INTEGER else str(value)
    if isinstance(value, float):
        return repr(value) if math.isfinite(value) else str(value)
    if isinstance(value, Mapping):
        return {str(key): jsonable(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [jsonable(child) for child in items]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return jsonable(dump(mode="json"))
    return str(value)


def decimal_text(value: float | None, places: int = 4) -> str | None:
    """Render a rate or amount as a fixed decimal string (canonical JSON has no floats)."""
    return None if value is None else f"{value:.{places}f}"


def text_digest(text: str) -> str:
    """Return the SHA-256 digest of UTF-8 text."""
    return sha256_digest(text.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class Condition:
    """AgentDojo pipeline settings for one run.

    ``tool_output_format`` ``None`` means AgentDojo's default (YAML);
    ``system_message`` ``None`` means AgentDojo's default system message.
    """

    defense: str | None = None
    tool_output_format: str | None = None
    system_message: str | None = None

    def __post_init__(self) -> None:
        """Reject settings the runner does not support."""
        if self.defense not in SUPPORTED_DEFENSES:
            message = f"unsupported defense: {self.defense!r}"
            raise ValueError(message)
        if self.tool_output_format not in SUPPORTED_TOOL_OUTPUT_FORMATS:
            message = f"unsupported tool-output format: {self.tool_output_format!r}"
            raise ValueError(message)

    @property
    def normalized_tool_output_format(self) -> str:
        """Return the effective format name (AgentDojo's default is YAML)."""
        return self.tool_output_format or "yaml"

    def describe(self) -> dict[str, Any]:
        """Return a JSON-safe description that never embeds the system message text."""
        return {
            "defense": self.defense,
            "toolOutputFormat": self.normalized_tool_output_format,
            "systemMessage": (
                "agentdojo-default"
                if self.system_message is None
                else {"override": True, "sha256": text_digest(self.system_message)}
            ),
        }

    def digest(self) -> str:
        """Return a stable digest of the condition used in run keys."""
        return sha256_digest(canonical_json_bytes(self.describe()))


@dataclass(frozen=True, slots=True)
class FailedAttempt:
    """One provider call attempt that raised; kept in the run record and trace."""

    attempt: int
    error_type: str
    status_code: int | None
    message: str
    transient: bool
    backoff_seconds: float | None

    def to_json(self) -> dict[str, Any]:
        """Return a canonical-JSON-safe mapping."""
        return {
            "attempt": self.attempt,
            "errorType": self.error_type,
            "statusCode": self.status_code,
            "message": self.message,
            "transient": self.transient,
            "backoffSeconds": decimal_text(self.backoff_seconds, 2),
        }


@dataclass(frozen=True, slots=True)
class Usage:
    """Token counts reported by the provider for one call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    reasoning_tokens: int = 0

    def to_json(self) -> dict[str, int]:
        """Return a canonical-JSON-safe mapping."""
        return {
            "input": self.input_tokens,
            "output": self.output_tokens,
            "cacheWrite": self.cache_write_tokens,
            "cacheRead": self.cache_read_tokens,
            "reasoning": self.reasoning_tokens,
        }


@dataclass(frozen=True, slots=True)
class CallRecord:
    """One logical model call, successful or not, with every failed attempt."""

    index: int
    requested_model: str
    returned_model: str | None
    usage: Usage
    stop: str | None
    failed_attempts: tuple[FailedAttempt, ...]
    started_at: str
    seconds: float
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Return a canonical-JSON-safe mapping."""
        return {
            "callIndex": self.index,
            "requested": self.requested_model,
            "returned": self.returned_model,
            "usage": self.usage.to_json(),
            "stop": self.stop,
            "failedAttempts": [item.to_json() for item in self.failed_attempts],
            "startedAt": self.started_at,
            "seconds": decimal_text(self.seconds, 3),
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class RunJob:
    """One fresh run to execute: a finding, a model, a condition, and a trial number."""

    key: str
    finding_label: str
    benchmark_version: str
    attack: str
    suite: str
    user_task: str
    injection_task: str
    model: str
    attack_name: str
    condition: Condition
    trial: int
    source_capsule_digest: str


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Everything observed in one fresh run.

    ``messages`` are plain dictionaries with ``role``, ``text``, ``toolCalls``,
    ``toolCallId``, ``function``, ``error``, and ``omittedBlocks`` keys as
    applicable. ``security``/``utility`` are the benchmark's verdicts and are
    ``None`` when the benchmark did not produce one.
    """

    job: RunJob
    provider: str
    api: str
    temperature: float | None
    started_at: str
    finished_at: str
    seconds: float
    messages: tuple[Mapping[str, Any], ...]
    calls: tuple[CallRecord, ...]
    security: bool | None
    utility: bool | None
    error: str | None
    model_output_missing: bool
    injection_digest: str | None
    software: Mapping[str, str] = field(default_factory=dict)

    def usage_total(self) -> Usage:
        """Sum token usage over all calls."""
        return Usage(
            input_tokens=sum(call.usage.input_tokens for call in self.calls),
            output_tokens=sum(call.usage.output_tokens for call in self.calls),
            cache_write_tokens=sum(call.usage.cache_write_tokens for call in self.calls),
            cache_read_tokens=sum(call.usage.cache_read_tokens for call in self.calls),
            reasoning_tokens=sum(call.usage.reasoning_tokens for call in self.calls),
        )

    def returned_models(self) -> tuple[str, ...]:
        """Return the sorted distinct model strings the provider reported."""
        return tuple(sorted({call.returned_model for call in self.calls if call.returned_model}))


OutcomeJudge = Callable[[RunRecord], Verdict]
"""Turn one run record into ``attack``, ``no-attack``, or ``cant-tell``."""


def benchmark_security_judge(record: RunRecord) -> Verdict:
    """Default judge: the benchmark's security verdict.

    A crashed run or a missing verdict is ``cant-tell``; it never counts as an
    attack or as a non-attack.
    """
    if record.error is not None or record.security is None:
        return "cant-tell"
    return "attack" if record.security else "no-attack"


def judge_name(judge: OutcomeJudge) -> str:
    """Return a stable display name for a judge callable."""
    name = getattr(judge, "__name__", None)
    return str(name) if name else type(judge).__name__


def cant_tell_reason(record: RunRecord) -> str:
    """Explain why a run could not be judged, in plain words."""
    if record.error is not None:
        return f"run failed: {record.error.split(':', maxsplit=1)[0]}"
    if record.security is None:
        return "the benchmark returned no security verdict"
    return "the judge could not decide"


def summarize_reasons(reasons: Sequence[str]) -> dict[str, int]:
    """Count reasons, sorted by reason text."""
    counts: dict[str, int] = {}
    for reason in reasons:
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "SUPPORTED_DEFENSES",
    "SUPPORTED_TOOL_OUTPUT_FORMATS",
    "VERDICTS",
    "CallRecord",
    "Condition",
    "FailedAttempt",
    "OutcomeJudge",
    "RunJob",
    "RunRecord",
    "Usage",
    "Verdict",
    "benchmark_security_judge",
    "cant_tell_reason",
    "decimal_text",
    "jsonable",
    "judge_name",
    "summarize_reasons",
    "text_digest",
]
