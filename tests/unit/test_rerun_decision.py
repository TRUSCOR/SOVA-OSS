# SPDX-License-Identifier: Apache-2.0
"""Reproduction decisions and rate estimates (ported from the research prototype tests)."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, cast

import pytest

from sova.rerun.decision import (
    ContextMode,
    ContextRule,
    ContextStatus,
    OutcomePredicate,
    PredicateOperator,
    PredicateStatus,
    SemanticOutcome,
    TrialRecord,
    clopper_pearson_interval,
    compare_context,
    decide_reproduction,
    estimate_by_stratum,
    estimate_reproduction,
    evaluate_contract,
    evaluate_predicate,
    wilson_interval,
)


def _events() -> list[dict[str, Any]]:
    return [
        {
            "id": "event-0",
            "sequence": 0,
            "kind": "prompt.sent",
            "parents": [],
            "payload": {"text": "blue owl"},
            "redactions": [],
        },
        {
            "id": "event-1",
            "sequence": 1,
            "kind": "tool.completed",
            "parents": ["event-0"],
            "payload": {"outcome": {"status": "succeeded", "artifact": "canary"}},
            "redactions": [],
        },
        {
            "id": "event-2",
            "sequence": 2,
            "kind": "oracle.completed",
            "parents": ["event-1"],
            "payload": {"label": "unsafe-effect-observed"},
            "redactions": [],
        },
    ]


def _predicates() -> tuple[OutcomePredicate, ...]:
    return (
        OutcomePredicate("p1", "tool.completed", PredicateOperator.EXISTS),
        OutcomePredicate(
            "p2",
            "oracle.completed",
            PredicateOperator.EQUALS,
            path=("payload", "label"),
            expected="unsafe-effect-observed",
        ),
        OutcomePredicate(
            "p3",
            "tool.completed",
            PredicateOperator.ORDERED_BEFORE,
            other_kind="oracle.completed",
        ),
        OutcomePredicate("p4", "network.egress", PredicateOperator.ABSENT),
    )


def test_six_states_and_prototype_aliases() -> None:
    assert [item.value for item in SemanticOutcome] == [
        "reproduced",
        "not-reproduced",
        "inconclusive",
        "incompatible",
        "unsafe",
        "evidence-invalid",
    ]
    assert SemanticOutcome.EQUIVALENT.value == SemanticOutcome.REPRODUCED.value
    assert SemanticOutcome.DIVERGENT.value == SemanticOutcome.NOT_REPRODUCED.value
    assert SemanticOutcome("reproduced") == SemanticOutcome.EQUIVALENT


def test_semantic_contract_distinguishes_equivalent_divergent_and_unknown() -> None:
    events = _events()
    equivalent = evaluate_contract(_predicates(), events)
    assert equivalent.outcome == SemanticOutcome.EQUIVALENT
    assert equivalent.passed == 4

    divergent_events = copy.deepcopy(events)
    divergent_events[2]["payload"] = {"label": "safe"}
    divergent = evaluate_contract(_predicates(), divergent_events)
    assert divergent.outcome == SemanticOutcome.DIVERGENT

    unknown = evaluate_contract(
        _predicates(),
        events,
        availability={"tool.": True, "oracle.": False, "network.": False},
    )
    assert unknown.outcome == SemanticOutcome.INCONCLUSIVE
    assert unknown.unknown == 3


def test_context_and_safety_precede_semantic_judgment() -> None:
    rules = (
        ContextRule(("model", "family"), ContextMode.EXACT),
        ContextRule(("runtime",), ContextMode.ONE_OF, allowed=("python", "node")),
        ContextRule(("temperature",), ContextMode.TOLERANCE, tolerance=0.05),
        ContextRule(("host",), ContextMode.RECORD),
    )
    source = {
        "model": {"family": "scripted"},
        "runtime": "python",
        "temperature": 0.2,
        "host": "one",
    }
    compatible = {**source, "temperature": 0.22, "host": "two"}
    decision = decide_reproduction(
        predicates=_predicates(),
        events=_events(),
        source_context=source,
        candidate_context=compatible,
        context_rules=rules,
    )
    assert decision.outcome == SemanticOutcome.EQUIVALENT
    assert decision.context.status.value == "drifted"

    incompatible = {**compatible, "model": {"family": "different"}}
    decision = decide_reproduction(
        predicates=_predicates(),
        events=_events(),
        source_context=source,
        candidate_context=incompatible,
        context_rules=rules,
    )
    assert decision.outcome == SemanticOutcome.INCOMPATIBLE
    assert decision.contract is None

    unsafe = decide_reproduction(
        predicates=_predicates(),
        events=_events(),
        source_context=source,
        candidate_context=compatible,
        context_rules=rules,
        safe_to_compare=False,
    )
    assert unsafe.outcome == SemanticOutcome.UNSAFE

    invalid = decide_reproduction(
        predicates=_predicates(),
        events=_events(),
        source_context=source,
        candidate_context=compatible,
        context_rules=rules,
        evidence_valid=False,
    )
    assert invalid.outcome == SemanticOutcome.EVIDENCE_INVALID
    assert invalid.contract is None


def test_matching_behavior_with_unrecorded_required_context_is_inconclusive() -> None:
    rules = (ContextRule(("defense",), ContextMode.EXACT),)
    decision = decide_reproduction(
        predicates=_predicates(),
        events=_events(),
        source_context={},
        candidate_context={"defense": None},
        context_rules=rules,
    )
    assert decision.outcome == SemanticOutcome.INCONCLUSIVE
    assert decision.contract is not None
    assert decision.contract.outcome == SemanticOutcome.REPRODUCED
    assert decision.context.results[0].source is None

    divergent = copy.deepcopy(_events())
    divergent[2]["payload"] = {"label": "safe"}
    still_divergent = decide_reproduction(
        predicates=_predicates(),
        events=divergent,
        source_context={},
        candidate_context={"defense": None},
        context_rules=rules,
    )
    assert still_divergent.outcome == SemanticOutcome.NOT_REPRODUCED


def test_reproduction_estimate_retains_all_nonconclusive_categories() -> None:
    outcomes = (
        SemanticOutcome.EQUIVALENT,
        SemanticOutcome.EQUIVALENT,
        SemanticOutcome.DIVERGENT,
        SemanticOutcome.INCONCLUSIVE,
        SemanticOutcome.INCOMPATIBLE,
        SemanticOutcome.UNSAFE,
        SemanticOutcome.EVIDENCE_INVALID,
    )
    trials = [
        TrialRecord(
            f"trial-{index}",
            outcome,
            "windows" if index % 2 else "linux",
            "deterministic",
            "sha256:" + hashlib.sha256(str(index).encode()).hexdigest(),
        )
        for index, outcome in enumerate(outcomes)
    ]
    estimate = estimate_reproduction(trials)
    assert estimate.conclusive_rate == pytest.approx(2 / 3)
    assert estimate.exact_low is not None
    assert estimate.exact_high is not None
    assert estimate.conclusive_rate is not None
    assert estimate.exact_low <= estimate.conclusive_rate <= estimate.exact_high
    assert estimate.identification_low == pytest.approx(1 / 2)
    assert estimate.identification_high == pytest.approx(3 / 4)
    assert estimate.incompatible == estimate.unsafe == estimate.evidence_invalid == 1
    assert set(estimate_by_stratum(trials)) == {"linux", "windows"}


def test_estimate_without_conclusive_or_eligible_trials_has_no_rate() -> None:
    empty = estimate_reproduction(())
    assert empty.conclusive_rate is None
    assert empty.wilson_low is None
    assert empty.identification_low is None
    only_inconclusive = estimate_reproduction(
        [TrialRecord("t", SemanticOutcome.INCONCLUSIVE, "s", "j", "sha256:" + "0" * 64)]
    )
    assert only_inconclusive.conclusive_rate is None
    assert only_inconclusive.identification_low == 0.0
    assert only_inconclusive.identification_high == 1.0


def test_exact_binomial_interval_handles_extreme_counts() -> None:
    zero_low, zero_high = clopper_pearson_interval(0, 10)
    full_low, full_high = clopper_pearson_interval(10, 10)
    assert zero_low == 0.0
    assert zero_high == pytest.approx(0.3084971078)
    assert full_low == pytest.approx(0.6915028922)
    assert full_high == 1.0
    middle_low, middle_high = clopper_pearson_interval(7, 10)
    assert middle_low == pytest.approx(0.3475471, abs=1e-6)
    assert middle_high == pytest.approx(0.9332605, abs=1e-6)


@pytest.mark.parametrize(
    ("successes", "total", "alpha"),
    [(1, 0, 0.05), (-1, 3, 0.05), (4, 3, 0.05), (1, 3, 0.0), (1, 3, 1.0)],
)
def test_exact_interval_rejects_invalid_input(successes: int, total: int, alpha: float) -> None:
    with pytest.raises(ValueError, match=r"trial|between"):
        clopper_pearson_interval(successes, total, alpha)


def test_wilson_interval_matches_known_values_and_rejects_empty() -> None:
    low, high = wilson_interval(7, 10)
    assert low == pytest.approx(0.3967780, abs=1e-6)
    assert high == pytest.approx(0.8922087, abs=1e-6)
    assert wilson_interval(0, 3)[0] == pytest.approx(0.0, abs=1e-12)
    assert wilson_interval(3, 3)[1] == pytest.approx(1.0, abs=1e-12)
    with pytest.raises(ValueError, match="at least one"):
        wilson_interval(0, 0)


def test_predicate_operators_cover_counts_contains_and_missing_values() -> None:
    events = _events()
    count = OutcomePredicate("c", "tool.completed", PredicateOperator.COUNT_AT_LEAST, minimum=2)
    assert evaluate_predicate(count, events).status == PredicateStatus.FAIL
    count_one = OutcomePredicate("c1", "tool.completed", PredicateOperator.COUNT_AT_LEAST)
    assert evaluate_predicate(count_one, events).status == PredicateStatus.PASS
    absent_fail = OutcomePredicate("a", "tool.completed", PredicateOperator.ABSENT)
    assert evaluate_predicate(absent_fail, events).status == PredicateStatus.FAIL
    exists_fail = OutcomePredicate("e", "network.egress", PredicateOperator.EXISTS)
    assert evaluate_predicate(exists_fail, events).status == PredicateStatus.FAIL

    def contains(path: tuple[str, ...], expected: Any, kind: str = "oracle.completed") -> str:
        predicate = OutcomePredicate(
            "x", kind, PredicateOperator.CONTAINS, path=path, expected=expected
        )
        return evaluate_predicate(predicate, events).status.value

    assert contains(("payload", "label"), "unsafe") == "pass"
    assert contains(("payload",), "label") == "pass"
    assert contains(("payload",), "unsafe-effect-observed") == "pass"
    assert contains(("payload", "outcome", "status"), "succeeded", "tool.completed") == "pass"
    assert contains(("sequence",), 2) == "fail"
    assert contains(("parents",), "event-1") == "pass"
    assert contains(("payload", "missing"), "x") == "unknown"
    assert contains(("payload", "label"), "x", "never.seen") == "fail"

    events[0]["id"] = None
    exists = OutcomePredicate("i", "prompt.sent", PredicateOperator.EXISTS)
    assert evaluate_predicate(exists, events).evidence_ids == ("<unidentified>",)


def test_ordered_predicate_edges() -> None:
    events = _events()
    missing_other = OutcomePredicate("o", "tool.completed", PredicateOperator.ORDERED_BEFORE)
    with pytest.raises(ValueError, match="other_kind"):
        evaluate_predicate(missing_other, events)
    reversed_order = OutcomePredicate(
        "r", "oracle.completed", PredicateOperator.ORDERED_BEFORE, other_kind="tool.completed"
    )
    assert evaluate_predicate(reversed_order, events).status == PredicateStatus.FAIL
    absent_family = OutcomePredicate(
        "f", "tool.completed", PredicateOperator.ORDERED_BEFORE, other_kind="network.egress"
    )
    assert evaluate_predicate(absent_family, events).status == PredicateStatus.FAIL
    unavailable = evaluate_predicate(
        absent_family, events, availability={"tool.completed": True, "network.": False}
    )
    assert unavailable.status == PredicateStatus.UNKNOWN


def test_unsupported_operator_and_mode_raise() -> None:
    bogus = OutcomePredicate(
        "b", "oracle.completed", cast("PredicateOperator", "bogus"), path=("payload", "label")
    )
    with pytest.raises(ValueError, match="unsupported predicate operator"):
        evaluate_predicate(bogus, _events())
    rule = ContextRule(("x",), cast("ContextMode", "bogus"))
    with pytest.raises(ValueError, match="unsupported context mode"):
        compare_context({"x": 1}, {"x": 1}, (rule,))


def test_non_required_predicates_are_reported_but_do_not_decide() -> None:
    optional = OutcomePredicate("opt", "network.egress", PredicateOperator.EXISTS, required=False)
    result = evaluate_contract((optional,), _events())
    assert result.outcome == SemanticOutcome.REPRODUCED
    assert result.predicate_results[0].status == PredicateStatus.FAIL
    assert result.failed == 0


def test_context_modes_cover_ignore_one_of_tolerance_and_missing() -> None:
    rules = (
        ContextRule(("ignored",), ContextMode.IGNORE),
        ContextRule(("runtime",), ContextMode.ONE_OF, allowed=("python",)),
        ContextRule(("temperature",), ContextMode.TOLERANCE, tolerance=0.01),
        ContextRule(("flag",), ContextMode.TOLERANCE, tolerance=1.0),
        ContextRule(("optional",), ContextMode.RECORD, required=False),
        ContextRule(("same",), ContextMode.RECORD),
    )
    result = compare_context(
        {"ignored": 1, "runtime": "python", "temperature": 0.2, "flag": True, "same": "a"},
        {"ignored": 2, "runtime": "node", "temperature": 0.5, "flag": False, "same": "a"},
        rules,
    )
    statuses = [item.status for item in result.results]
    assert statuses == [
        ContextStatus.COMPATIBLE,
        ContextStatus.INCOMPATIBLE,
        ContextStatus.INCOMPATIBLE,
        ContextStatus.UNKNOWN,
        ContextStatus.DRIFTED,
        ContextStatus.COMPATIBLE,
    ]
    assert result.status == ContextStatus.INCOMPATIBLE
    unknown_only = compare_context({}, {}, (ContextRule(("a",), ContextMode.EXACT),))
    assert unknown_only.status == ContextStatus.UNKNOWN
    compatible = compare_context({"a": 1}, {"a": 1}, (ContextRule(("a",), ContextMode.EXACT),))
    assert compatible.status == ContextStatus.COMPATIBLE
    nested_missing = compare_context(
        {"a": "flat"}, {"a": {"b": 1}}, (ContextRule(("a", "b"), ContextMode.EXACT),)
    )
    assert nested_missing.results[0].status == ContextStatus.UNKNOWN
