# SPDX-License-Identifier: Apache-2.0
"""Decide whether a fresh run reproduced a recorded outcome, and estimate how often.

The method has three parts:

1. **Outcome predicates** read only observable trace events (no hidden inference).
   A predicate passes, fails, or is ``unknown`` when the evidence it needs was not
   observably available.
2. **Context rules** say which differences between the recorded run and the fresh
   run are material (``exact``/``one-of``/``tolerance``), recorded but not blocking
   (``record``), or ignored.
3. :func:`decide_reproduction` combines both into one of six states:
   ``reproduced``, ``not-reproduced``, ``inconclusive``, ``incompatible``,
   ``unsafe``, and ``evidence-invalid``.

Missing evidence never becomes a pass or a fail: it yields ``inconclusive`` and is
kept separately in every rate estimate (see :func:`estimate_reproduction`, which
reports Wilson and Clopper-Pearson intervals over conclusive trials plus
partial-identification bounds that place the inconclusive trials at either end).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

_Z_95: Final = 1.959963984540054
_BISECTION_STEPS: Final = 80


class PredicateOperator(StrEnum):
    """Deterministic operators over observable trace events."""

    EXISTS = "exists"
    ABSENT = "absent"
    EQUALS = "equals"
    CONTAINS = "contains"
    COUNT_AT_LEAST = "count-at-least"
    ORDERED_BEFORE = "ordered-before"


class PredicateStatus(StrEnum):
    """Result of one predicate; ``unknown`` means the evidence was not available."""

    PASS = "pass"  # noqa: S105 - a predicate status, not a credential
    FAIL = "fail"
    UNKNOWN = "unknown"


class SemanticOutcome(StrEnum):
    """The six reproduction states.

    ``EQUIVALENT`` and ``DIVERGENT`` are aliases of ``REPRODUCED`` and
    ``NOT_REPRODUCED`` kept for the original prototype vocabulary; iterating the
    enumeration yields the six canonical states only.
    """

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not-reproduced"
    INCONCLUSIVE = "inconclusive"
    INCOMPATIBLE = "incompatible"
    UNSAFE = "unsafe"
    EVIDENCE_INVALID = "evidence-invalid"
    EQUIVALENT = "reproduced"
    DIVERGENT = "not-reproduced"


class ContextMode(StrEnum):
    """How one context dimension is compared between two runs."""

    EXACT = "exact"
    ONE_OF = "one-of"
    TOLERANCE = "tolerance"
    RECORD = "record"
    IGNORE = "ignore"


class ContextStatus(StrEnum):
    """Result of comparing one context dimension, or the aggregate of all of them."""

    COMPATIBLE = "compatible"
    DRIFTED = "drifted"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class OutcomePredicate:
    """One observable condition the material outcome must satisfy.

    ``path`` addresses a value inside each selected event (for example
    ``("payload", "attackObserved")``). Non-required predicates are evaluated and
    reported but do not affect the contract outcome.
    """

    id: str
    event_kind: str
    operator: PredicateOperator
    path: tuple[str, ...] = ()
    expected: Any = None
    minimum: int = 1
    other_kind: str | None = None
    required: bool = True


@dataclass(frozen=True, slots=True)
class PredicateResult:
    """Outcome of one predicate with the identifiers of the events it read."""

    predicate_id: str
    status: PredicateStatus
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ContractEvaluation:
    """Aggregate of all predicate results over one run's events."""

    outcome: SemanticOutcome
    predicate_results: tuple[PredicateResult, ...]
    passed: int
    failed: int
    unknown: int


@dataclass(frozen=True, slots=True)
class ContextRule:
    """Comparison rule for one context dimension addressed by ``path``.

    A missing value on a ``required`` rule makes the dimension ``unknown``; on a
    non-required rule it is reported as ``drifted``.
    """

    path: tuple[str, ...]
    mode: ContextMode
    allowed: tuple[Any, ...] = ()
    tolerance: float | None = None
    required: bool = True


@dataclass(frozen=True, slots=True)
class ContextResult:
    """Comparison of one context dimension (``None`` stands for "not recorded")."""

    path: tuple[str, ...]
    status: ContextStatus
    source: Any
    candidate: Any
    reason: str


@dataclass(frozen=True, slots=True)
class ContextEvaluation:
    """Aggregate context status and the per-dimension results."""

    status: ContextStatus
    results: tuple[ContextResult, ...]


@dataclass(frozen=True, slots=True)
class ReproductionDecision:
    """One reproduction decision; ``contract`` is ``None`` when it was not evaluated."""

    outcome: SemanticOutcome
    contract: ContractEvaluation | None
    context: ContextEvaluation
    reason: str


@dataclass(frozen=True, slots=True)
class TrialRecord:
    """One fresh trial's decision, its stratum, judge, and evidence digest."""

    id: str
    outcome: SemanticOutcome
    stratum: str
    judge: str
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class ReproductionEstimate:
    """Counts per state, rate over conclusive trials, and interval estimates.

    ``conclusive_rate`` and its intervals are ``None`` when no trial was
    conclusive. ``identification_low``/``identification_high`` bound the rate
    among reproduced, not-reproduced, and inconclusive trials by counting every
    inconclusive trial first as not reproduced and then as reproduced.
    """

    successes: int
    divergences: int
    inconclusive: int
    incompatible: int
    unsafe: int
    evidence_invalid: int
    conclusive_rate: float | None
    wilson_low: float | None
    wilson_high: float | None
    exact_low: float | None
    exact_high: float | None
    identification_low: float | None
    identification_high: float | None
    method: str = "sova.reproduction-rate/exact-wilson-partial-identification-0.2"


class _Missing:
    """Sentinel for a value that was not recorded."""

    __slots__ = ()


_MISSING: Final = _Missing()


def _value_at(value: Any, path: Sequence[str]) -> Any:
    current = value
    for component in path:
        if not isinstance(current, Mapping) or component not in current:
            return _MISSING
        current = current[component]
    return current


def _is_kind_available(kind: str, availability: Mapping[str, bool] | None) -> bool:
    if availability is None:
        return True
    if kind in availability:
        return availability[kind]
    return any(kind.startswith(prefix) and present for prefix, present in availability.items())


def _event_id(event: Mapping[str, Any]) -> str:
    identifier = event.get("id")
    return str(identifier) if identifier is not None else "<unidentified>"


def _contains(container: Any, expected: Any) -> bool:
    if isinstance(container, str) and isinstance(expected, str):
        return expected in container
    if isinstance(container, Mapping):
        return expected in container or expected in container.values()
    if isinstance(container, (list, tuple, set, frozenset)):
        return expected in container
    return False


def evaluate_predicate(  # noqa: PLR0911 - one explicit result per operator
    predicate: OutcomePredicate,
    events: Sequence[Mapping[str, Any]],
    *,
    availability: Mapping[str, bool] | None = None,
) -> PredicateResult:
    """Evaluate one deterministic observable predicate without hidden inference.

    ``availability`` maps event kinds or kind prefixes to whether that family was
    observably captured. An unavailable family yields ``unknown``, never ``fail``.
    """
    if not _is_kind_available(predicate.event_kind, availability):
        return PredicateResult(
            predicate.id,
            PredicateStatus.UNKNOWN,
            (),
            f"required event family {predicate.event_kind!r} was not observably available",
        )
    selected = [event for event in events if event.get("kind") == predicate.event_kind]
    evidence = tuple(_event_id(event) for event in selected)

    if predicate.operator == PredicateOperator.EXISTS:
        status = PredicateStatus.PASS if selected else PredicateStatus.FAIL
        return PredicateResult(predicate.id, status, evidence, f"observed {len(selected)} event(s)")
    if predicate.operator == PredicateOperator.ABSENT:
        status = PredicateStatus.PASS if not selected else PredicateStatus.FAIL
        return PredicateResult(predicate.id, status, evidence, f"observed {len(selected)} event(s)")
    if predicate.operator == PredicateOperator.COUNT_AT_LEAST:
        status = (
            PredicateStatus.PASS if len(selected) >= predicate.minimum else PredicateStatus.FAIL
        )
        return PredicateResult(
            predicate.id,
            status,
            evidence,
            f"observed {len(selected)}; required at least {predicate.minimum}",
        )
    if predicate.operator == PredicateOperator.ORDERED_BEFORE:
        return _evaluate_ordered(predicate, events, selected, evidence, availability)

    values = [_value_at(event, predicate.path) for event in selected]
    visible = [value for value in values if value is not _MISSING]
    if not visible:
        return PredicateResult(
            predicate.id,
            PredicateStatus.UNKNOWN if selected else PredicateStatus.FAIL,
            evidence,
            "the required observable value was not available",
        )
    if predicate.operator == PredicateOperator.EQUALS:
        matched = any(value == predicate.expected for value in visible)
    elif predicate.operator == PredicateOperator.CONTAINS:
        matched = any(_contains(value, predicate.expected) for value in visible)
    else:  # reachable only with an operator outside the enumeration
        message = f"unsupported predicate operator: {predicate.operator}"  # type: ignore[unreachable]
        raise ValueError(message)
    return PredicateResult(
        predicate.id,
        PredicateStatus.PASS if matched else PredicateStatus.FAIL,
        evidence,
        "at least one observable value matched" if matched else "no observable value matched",
    )


def _evaluate_ordered(
    predicate: OutcomePredicate,
    events: Sequence[Mapping[str, Any]],
    selected: Sequence[Mapping[str, Any]],
    evidence: tuple[str, ...],
    availability: Mapping[str, bool] | None,
) -> PredicateResult:
    if predicate.other_kind is None:
        message = "ordered-before predicate requires other_kind"
        raise ValueError(message)
    if not _is_kind_available(predicate.other_kind, availability):
        return PredicateResult(
            predicate.id,
            PredicateStatus.UNKNOWN,
            evidence,
            f"comparison family {predicate.other_kind!r} was not observably available",
        )
    other = [event for event in events if event.get("kind") == predicate.other_kind]
    other_ids = tuple(_event_id(event) for event in other)
    if not selected or not other:
        return PredicateResult(
            predicate.id,
            PredicateStatus.FAIL,
            (*evidence, *other_ids),
            "one or both ordered event families were absent",
        )
    left = min(int(event.get("sequence", -1)) for event in selected)
    right = min(int(event.get("sequence", -1)) for event in other)
    status = PredicateStatus.PASS if left < right else PredicateStatus.FAIL
    return PredicateResult(
        predicate.id,
        status,
        (*evidence, *other_ids),
        f"first sequences were {left} and {right}",
    )


def evaluate_contract(
    predicates: Sequence[OutcomePredicate],
    events: Sequence[Mapping[str, Any]],
    *,
    availability: Mapping[str, bool] | None = None,
) -> ContractEvaluation:
    """Evaluate every predicate; any required failure means ``not-reproduced``.

    With no failure, any required ``unknown`` means ``inconclusive``; otherwise
    the contract outcome is ``reproduced``.
    """
    results = tuple(
        evaluate_predicate(predicate, events, availability=availability) for predicate in predicates
    )
    required = [
        result for predicate, result in zip(predicates, results, strict=True) if predicate.required
    ]
    failed = sum(result.status == PredicateStatus.FAIL for result in required)
    unknown = sum(result.status == PredicateStatus.UNKNOWN for result in required)
    passed = sum(result.status == PredicateStatus.PASS for result in required)
    if failed:
        outcome = SemanticOutcome.NOT_REPRODUCED
    elif unknown:
        outcome = SemanticOutcome.INCONCLUSIVE
    else:
        outcome = SemanticOutcome.REPRODUCED
    return ContractEvaluation(outcome, results, passed, failed, unknown)


def _compare_rule(  # noqa: PLR0911 - one explicit result per context mode
    rule: ContextRule, left: Any, right: Any
) -> tuple[ContextStatus, str]:
    if rule.mode == ContextMode.IGNORE:
        return ContextStatus.COMPATIBLE, "dimension intentionally ignored"
    if left is _MISSING or right is _MISSING:
        status = ContextStatus.UNKNOWN if rule.required else ContextStatus.DRIFTED
        return status, "one or both context values were not recorded"
    if rule.mode == ContextMode.RECORD:
        status = ContextStatus.COMPATIBLE if left == right else ContextStatus.DRIFTED
        return status, "dimension is recorded but not compatibility-blocking"
    if rule.mode == ContextMode.EXACT:
        if left == right:
            return ContextStatus.COMPATIBLE, "exact values match"
        return ContextStatus.INCOMPATIBLE, "exact values differ"
    if rule.mode == ContextMode.ONE_OF:
        if right in rule.allowed:
            return ContextStatus.COMPATIBLE, "candidate is in the allowed set"
        return ContextStatus.INCOMPATIBLE, "not allowed"
    if rule.mode == ContextMode.TOLERANCE:
        if (
            isinstance(left, bool)
            or isinstance(right, bool)
            or not isinstance(left, (int, float))
            or not isinstance(right, (int, float))
            or rule.tolerance is None
        ):
            return (
                ContextStatus.UNKNOWN,
                "tolerance comparison lacked numeric values or tolerance",
            )
        delta = abs(float(left) - float(right))
        status = ContextStatus.COMPATIBLE if delta <= rule.tolerance else ContextStatus.INCOMPATIBLE
        return status, f"absolute difference {delta} versus tolerance {rule.tolerance}"
    # Reachable only with a mode outside the enumeration.
    message = f"unsupported context mode: {rule.mode}"  # type: ignore[unreachable]
    raise ValueError(message)


def compare_context(
    source: Mapping[str, Any],
    candidate: Mapping[str, Any],
    rules: Sequence[ContextRule],
) -> ContextEvaluation:
    """Compare the recorded (``source``) and fresh (``candidate``) run contexts.

    The aggregate is ``incompatible`` if any dimension is, else ``unknown`` if any
    is, else ``drifted`` if any is, else ``compatible``.
    """
    results: list[ContextResult] = []
    for rule in rules:
        left = _value_at(source, rule.path)
        right = _value_at(candidate, rule.path)
        status, reason = _compare_rule(rule, left, right)
        results.append(
            ContextResult(
                rule.path,
                status,
                None if left is _MISSING else left,
                None if right is _MISSING else right,
                reason,
            )
        )
    statuses = {result.status for result in results}
    if ContextStatus.INCOMPATIBLE in statuses:
        aggregate = ContextStatus.INCOMPATIBLE
    elif ContextStatus.UNKNOWN in statuses:
        aggregate = ContextStatus.UNKNOWN
    elif ContextStatus.DRIFTED in statuses:
        aggregate = ContextStatus.DRIFTED
    else:
        aggregate = ContextStatus.COMPATIBLE
    return ContextEvaluation(aggregate, tuple(results))


def decide_reproduction(  # noqa: PLR0913 - every input is an explicit, independent judgment
    *,
    predicates: Sequence[OutcomePredicate],
    events: Sequence[Mapping[str, Any]],
    source_context: Mapping[str, Any],
    candidate_context: Mapping[str, Any],
    context_rules: Sequence[ContextRule],
    availability: Mapping[str, bool] | None = None,
    safe_to_compare: bool = True,
    evidence_valid: bool = True,
) -> ReproductionDecision:
    """Decide one fresh run's reproduction state.

    Order of precedence: ``unsafe``, then ``evidence-invalid``, then
    ``incompatible`` context; only then is the outcome contract evaluated. A
    matched contract with ``unknown`` required context is ``inconclusive``.
    """
    context = compare_context(source_context, candidate_context, context_rules)
    if not safe_to_compare:
        return ReproductionDecision(SemanticOutcome.UNSAFE, None, context, "comparison unsafe")
    if not evidence_valid:
        return ReproductionDecision(
            SemanticOutcome.EVIDENCE_INVALID,
            None,
            context,
            "evidence integrity or structure was invalid",
        )
    if context.status == ContextStatus.INCOMPATIBLE:
        return ReproductionDecision(
            SemanticOutcome.INCOMPATIBLE,
            None,
            context,
            "a required context dimension was incompatible",
        )
    contract = evaluate_contract(predicates, events, availability=availability)
    if context.status == ContextStatus.UNKNOWN and contract.outcome == SemanticOutcome.REPRODUCED:
        return ReproductionDecision(
            SemanticOutcome.INCONCLUSIVE,
            contract,
            context,
            "behavior matched but required context equivalence was unknown",
        )
    return ReproductionDecision(contract.outcome, contract, context, "contract evaluated")


def wilson_interval(successes: int, total: int, z: float = _Z_95) -> tuple[float, float]:
    """Return the Wilson score interval for ``successes`` out of ``total`` trials."""
    if total <= 0:
        message = "Wilson interval requires at least one conclusive trial"
        raise ValueError(message)
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _binomial_cdf(observed: int, total: int, probability: float) -> float:
    if observed < 0:
        return 0.0
    if observed >= total:
        return 1.0
    return sum(
        math.comb(total, value) * probability**value * (1.0 - probability) ** (total - value)
        for value in range(observed + 1)
    )


def clopper_pearson_interval(  # noqa: PLR0912 - both tails are inverted explicitly
    successes: int,
    total: int,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Return a two-sided exact (Clopper-Pearson) binomial interval by tail inversion."""
    if total <= 0:
        message = "exact interval requires at least one conclusive trial"
        raise ValueError(message)
    if successes < 0 or successes > total:
        message = "successes must be between zero and total"
        raise ValueError(message)
    if not 0.0 < alpha < 1.0:
        message = "alpha must be between zero and one"
        raise ValueError(message)

    if successes == 0:
        lower = 0.0
    else:
        low, high = 0.0, successes / total
        target = 1.0 - alpha / 2.0
        for _ in range(_BISECTION_STEPS):
            midpoint = (low + high) / 2.0
            if _binomial_cdf(successes - 1, total, midpoint) > target:
                low = midpoint
            else:
                high = midpoint
        lower = (low + high) / 2.0

    if successes == total:
        upper = 1.0
    else:
        low, high = successes / total, 1.0
        target = alpha / 2.0
        for _ in range(_BISECTION_STEPS):
            midpoint = (low + high) / 2.0
            if _binomial_cdf(successes, total, midpoint) > target:
                low = midpoint
            else:
                high = midpoint
        upper = (low + high) / 2.0
    return lower, upper


def estimate_reproduction(trials: Iterable[TrialRecord]) -> ReproductionEstimate:
    """Estimate the reproduction rate while keeping every non-conclusive state visible."""
    records = tuple(trials)
    counts = dict.fromkeys(SemanticOutcome, 0)
    for record in records:
        counts[record.outcome] += 1
    successes = counts[SemanticOutcome.REPRODUCED]
    divergences = counts[SemanticOutcome.NOT_REPRODUCED]
    inconclusive = counts[SemanticOutcome.INCONCLUSIVE]
    conclusive = successes + divergences
    eligible = conclusive + inconclusive
    rate: float | None = None
    low: float | None = None
    high: float | None = None
    exact_low: float | None = None
    exact_high: float | None = None
    if conclusive:
        rate = successes / conclusive
        low, high = wilson_interval(successes, conclusive)
        exact_low, exact_high = clopper_pearson_interval(successes, conclusive)
    identification_low: float | None = None
    identification_high: float | None = None
    if eligible:
        identification_low = successes / eligible
        identification_high = (successes + inconclusive) / eligible
    return ReproductionEstimate(
        successes=successes,
        divergences=divergences,
        inconclusive=inconclusive,
        incompatible=counts[SemanticOutcome.INCOMPATIBLE],
        unsafe=counts[SemanticOutcome.UNSAFE],
        evidence_invalid=counts[SemanticOutcome.EVIDENCE_INVALID],
        conclusive_rate=rate,
        wilson_low=low,
        wilson_high=high,
        exact_low=exact_low,
        exact_high=exact_high,
        identification_low=identification_low,
        identification_high=identification_high,
    )


def estimate_by_stratum(
    trials: Iterable[TrialRecord],
) -> dict[str, ReproductionEstimate]:
    """Estimate the reproduction rate separately for each stratum, in sorted order."""
    grouped: dict[str, list[TrialRecord]] = {}
    for trial in trials:
        grouped.setdefault(trial.stratum, []).append(trial)
    return {stratum: estimate_reproduction(records) for stratum, records in sorted(grouped.items())}


__all__ = [
    "ContextEvaluation",
    "ContextMode",
    "ContextResult",
    "ContextRule",
    "ContextStatus",
    "ContractEvaluation",
    "OutcomePredicate",
    "PredicateOperator",
    "PredicateResult",
    "PredicateStatus",
    "ReproductionDecision",
    "ReproductionEstimate",
    "SemanticOutcome",
    "TrialRecord",
    "clopper_pearson_interval",
    "compare_context",
    "decide_reproduction",
    "estimate_by_stratum",
    "estimate_reproduction",
    "evaluate_contract",
    "evaluate_predicate",
    "wilson_interval",
]
