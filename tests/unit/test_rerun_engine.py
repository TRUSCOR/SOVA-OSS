# SPDX-License-Identifier: Apache-2.0
"""``sova rerun`` engine with a fake runner: answers, comparison, resume, budget, safety."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import PackageReader, PackageWriter, strict_json_loads
from sova.formats.errors import FormatError
from sova.rerun.decision import (
    ContextEvaluation,
    ContextMode,
    ContextResult,
    ContextRule,
    ContextStatus,
    SemanticOutcome,
)
from sova.rerun.engine import (
    DEFAULT_ENVELOPE,
    Execution,
    Reproduction,
    RerunError,
    RerunOptions,
    RunEntry,
    RunStore,
    compare_with_recorded,
    comparison_sentence,
    load_envelope,
    merge_contexts,
    outcome_of,
    outcome_sentence,
    plan_finding,
    rerun_finding,
    resolve_condition,
    spend_sentence,
)
from sova.rerun.findings import (
    context_from_events,
    discover_capsules,
    file_digest,
    load_finding,
    read_trace_events,
    verdict_from_events,
)
from sova.rerun.providers import Budget, Pricing
from sova.rerun.records import Condition, RunJob, RunRecord, benchmark_security_judge
from tests.support.rerun import (
    PARAMETERS,
    FakeRunner,
    by_model,
    finding_capsule,
    make_record,
    recorded_trace,
    scenario,
)

if TYPE_CHECKING:
    from pathlib import Path


def _options(out: Path, model: str = "gpt-5.5", **changes: Any) -> RerunOptions:
    values: dict[str, Any] = {
        "model": model,
        "provider": "openai-compatible",
        "trials": 3,
        "out_dir": out,
        "authorize": True,
        "concurrency": 2,
    }
    values.update(changes)
    return RerunOptions(**values)


def _free() -> Budget:
    return Budget(max_usd=None, pricing=None)


def test_new_model_answer_is_the_rate_and_comparison_is_not_comparable(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    runner = FakeRunner(by_model({"gpt-5.5": [True] * 7 + [False] * 3}))
    report = rerun_finding(
        finding,
        _options(tmp_path / "out", trials=10),
        runner=runner,
        budget=Budget(max_usd=None, pricing=Pricing(2.5, 10.0)),
    )
    text = report.render()
    assert "attack worked 7 of 10 runs (Wilson 95%: 40%-89%); 0 runs could not be judged" in text
    assert (
        "compared with the recorded run: not comparable (model changed: gpt-4o -> gpt-5.5); "
        "outcome on the new model reported above"
    ) in text
    assert 'addresses it as "GPT"' in text
    assert "spend: about $" in text
    assert runner.prepared == ["gpt-5.5"]
    assert report.reproduction.state == SemanticOutcome.INCOMPATIBLE
    assert report.capsule is not None
    reader = PackageReader(report.capsule)
    descriptors = reader.verify("sova.capsule")
    assert sum(item.role == "trace" for item in descriptors) == 10
    manifest = reader.manifest("sova.capsule")
    relationships = {item["artifactType"]: item["digest"] for item in manifest["relationships"]}
    assert relationships["sova.capsule"] == finding.digest
    assert relationships["sova.trace"] == finding.traces[0].digest
    attachment = next(item for item in descriptors if item.role == "attachment")
    summary = strict_json_loads(reader.read_object(attachment))
    assert summary["artifactType"] == "sova.rerun-summary"
    assert summary["outcome"]["attacks"] == 7
    assert summary["reproduction"]["state"] == "incompatible"
    assert summary["run"]["attackName"] == "GPT"
    assert "apiKey" not in json.dumps(summary)
    assert report.to_json()["spend"]["estimated"] is True


def test_same_model_reproduces_and_reports_drift_outside_the_envelope(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    runner = FakeRunner(by_model({"gpt-4o": [True, False, True]}))
    report = rerun_finding(
        finding, _options(tmp_path / "out", model="gpt-4o"), runner=runner, budget=_free()
    )
    sentence = comparison_sentence(report.reproduction)
    assert sentence.startswith(
        "reproduced: the recorded outcome (an attack) recurred in 2 of 3 judged runs"
    )
    assert "model string returned by the provider not recorded -> fake-model-2026" in sentence
    assert "system prompt" not in sentence  # same text as the recording
    assert report.plan.attack_name == "GPT-4"
    estimate = report.reproduction.estimate
    assert (estimate.successes, estimate.divergences) == (2, 1)
    assert "spend: not estimated" in report.render()


def test_not_reproduced_needs_three_judged_runs(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    three = rerun_finding(
        finding,
        _options(tmp_path / "a", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [False]})),
        budget=_free(),
    )
    assert three.reproduction.state == SemanticOutcome.NOT_REPRODUCED
    assert "recurred in 0 of 3 judged runs" in comparison_sentence(three.reproduction)
    two = rerun_finding(
        finding,
        _options(tmp_path / "b", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [False, False, None]})),
        budget=_free(),
    )
    assert two.reproduction.state == SemanticOutcome.INCONCLUSIVE
    assert "fewer than 3" in comparison_sentence(two.reproduction)


def test_cant_tell_runs_are_counted_with_reasons_never_as_outcomes(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    runner = FakeRunner(by_model({"gpt-5.5": [True, "RateLimitError: gave up", None]}))
    report = rerun_finding(finding, _options(tmp_path / "out"), runner=runner, budget=_free())
    assert report.outcome.attacks == 1
    assert report.outcome.judged == 1
    assert report.outcome.cant_tell == 2
    assert outcome_sentence(report.outcome).endswith(
        "2 runs could not be judged "
        "(1 run failed: RateLimitError, 1 the benchmark returned no security verdict)"
    )
    second = next(job for job in runner.runs if job.trial == 2)
    events = read_trace_events(report.options.out_dir / report.execution.entries[second.key].trace)
    kinds = [event["kind"] for event in events]
    assert "error.run" in kinds
    judged = next(event for event in events if event["kind"] == "judge.completed")
    assert judged["payload"]["verdict"] == "cant-tell"
    assert "attackObserved" not in judged["payload"]
    oracle = next(event for event in events if event["kind"] == "oracle.completed")
    assert oracle["payload"]["status"] == "not-evaluated"
    assert "attackSucceeded" not in oracle["payload"]


def test_without_authorize_nothing_runs(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    runner = FakeRunner(by_model({"gpt-5.5": [True]}))
    with pytest.raises(RerunError, match="Add --authorize") as refused:
        rerun_finding(
            finding, _options(tmp_path / "out", authorize=False), runner=runner, budget=_free()
        )
    assert refused.value.issue.code == "SOVA-RERUN-AUTHORIZATION"
    assert runner.prepared == []
    assert runner.runs == []
    assert not (tmp_path / "out").exists()


def test_resume_reuses_recorded_runs_without_new_calls(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    out = tmp_path / "out"
    first = FakeRunner(by_model({"gpt-5.5": [True, False]}))
    rerun_finding(finding, _options(out, trials=2), runner=first, budget=_free())
    again = FakeRunner(by_model({"gpt-5.5": [True]}))
    report = rerun_finding(
        finding, _options(out, trials=2, authorize=False), runner=again, budget=_free()
    )
    assert again.runs == []
    assert report.execution.reused == 2
    assert "reused 2 earlier run(s)" in report.render()
    more = rerun_finding(finding, _options(out, trials=3), runner=again, budget=_free())
    assert [job.trial for job in again.runs] == [3]
    assert more.outcome.runs == 3
    tampered = out / more.execution.entries[again.runs[0].key].trace
    tampered.write_bytes(b"tampered")
    with pytest.raises(RerunError, match="1 run"):
        rerun_finding(
            finding, _options(out, trials=3, authorize=False), runner=again, budget=_free()
        )


def test_budget_stops_new_runs_and_counts_earlier_spend(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    out = tmp_path / "out"
    runner = FakeRunner(by_model({"gpt-5.5": [True]}))
    budget = Budget(max_usd=0.001, pricing=Pricing(1.0, 1.0))
    report = rerun_finding(
        finding, _options(out, trials=4, concurrency=1), runner=runner, budget=budget
    )
    assert report.execution.budget_stopped
    assert report.execution.not_started == 3
    assert report.outcome.not_started == 3
    assert "budget stop at $0.00: 3 run(s) not started" in report.render()
    store = RunStore(out)
    assert store.spent() > 0
    later = Budget(max_usd=1.0, pricing=Pricing(1.0, 1.0), already_spent=store.spent())
    assert "in this output folder" in spend_sentence(later, Execution())


def test_judge_hook_failures_and_runner_crashes_become_cant_tell(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))

    def crashing(job: RunJob) -> RunRecord:
        if job.trial == 1:
            message = "runner bug"
            raise RuntimeError(message)
        return make_record(job)

    def bad_judge(record: RunRecord) -> Any:
        if record.job.trial == 2:
            message = "judge bug"
            raise ValueError(message)
        return "maybe" if record.job.trial == 3 else benchmark_security_judge(record)

    report = rerun_finding(
        finding,
        _options(tmp_path / "out"),
        runner=FakeRunner(crashing),
        budget=_free(),
        judge=bad_judge,
        progress=lambda _line: None,
    )
    reasons = report.outcome.reasons
    assert report.outcome.cant_tell == 3
    assert reasons == {
        "run failed: RuntimeError": 1,
        "the judge failed: ValueError": 1,
        "the judge returned an unknown verdict": 1,
    }


def test_envelope_file_changes_what_is_material(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    envelope = tmp_path / "envelope.json"
    envelope.write_text(
        json.dumps(
            {
                "dimensions": {
                    "model": "record",
                    "returnedModel": "ignore",
                    "attackName": {"mode": "record"},
                }
            }
        ),
        encoding="utf-8",
    )
    rules = load_envelope(envelope)
    assert next(rule for rule in rules if rule.path == ("model",)).required is False
    report = rerun_finding(
        finding,
        _options(tmp_path / "out", envelope=rules),
        runner=FakeRunner(by_model({"gpt-5.5": [True]})),
        budget=_free(),
    )
    sentence = comparison_sentence(report.reproduction)
    assert sentence.startswith("reproduced")
    assert "model gpt-4o -> gpt-5.5" in sentence
    assert "attack name not recorded -> GPT" in sentence
    assert report.to_json()["envelope"]["model"]["material"] is False


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "dimensions"),
        ({"dimensions": {"color": "exact"}}, "unknown envelope dimension"),
        ({"dimensions": {"model": 3}}, "invalid rule"),
        ({"dimensions": {"model": "sometimes"}}, "invalid mode"),
        ({"dimensions": {"model": {"mode": "tolerance", "tolerance": "x"}}}, "tolerance"),
    ],
)
def test_invalid_envelopes_are_rejected(tmp_path: Path, document: Any, message: str) -> None:
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RerunError, match=message):
        load_envelope(path)


def test_envelope_accepts_one_of_and_tolerance(tmp_path: Path) -> None:
    path = tmp_path / "envelope.json"
    path.write_text(
        json.dumps(
            {
                "dimensions": {
                    "defense": {"mode": "one-of", "allowed": [None, "repeat_user_prompt"]},
                    "benchmarkVersion": {"mode": "tolerance", "tolerance": 1, "required": False},
                }
            }
        ),
        encoding="utf-8",
    )
    rules = {rule.path[0]: rule for rule in load_envelope(path)}
    assert rules["defense"].allowed == (None, "repeat_user_prompt")
    assert rules["benchmarkVersion"].tolerance == 1.0
    assert rules["benchmarkVersion"].required is False


def test_reference_selection_prefers_comparable_attacks(tmp_path: Path) -> None:
    traces = {
        "a-other.sova-trace": recorded_trace(
            tmp_path / "a.sova-trace", model="gpt-5.5", attack_succeeded=False
        ),
        "b-spotlight.sova-trace": recorded_trace(
            tmp_path / "b.sova-trace",
            model="gpt-4o",
            started={"condition": "M3-spotlighting"},
        ),
        "c-baseline.sova-trace": recorded_trace(tmp_path / "c.sova-trace", model="gpt-4o"),
    }
    finding = load_finding(finding_capsule(tmp_path / "in", traces=traces))
    report = rerun_finding(
        finding,
        _options(tmp_path / "out", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert report.reproduction.reference is not None
    assert report.reproduction.reference.name == "c-baseline.sova-trace"
    assert "matches this run on every material dimension" in report.reproduction.selection
    chosen = rerun_finding(
        finding,
        _options(tmp_path / "out", model="gpt-4o", recorded_trace="b-spotlight.sova-trace"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert chosen.reproduction.state == SemanticOutcome.INCOMPATIBLE
    assert (
        "defense changed: spotlighting_with_delimiting -> not recorded"
        not in comparison_sentence(chosen.reproduction)
    )
    assert "defense changed: spotlighting_with_delimiting -> none" in comparison_sentence(
        chosen.reproduction
    )
    with pytest.raises(RerunError, match="no trace named"):
        rerun_finding(
            finding,
            _options(tmp_path / "out", model="gpt-4o", recorded_trace="missing"),
            runner=FakeRunner(by_model({"gpt-4o": [True]})),
            budget=_free(),
        )


def test_capsule_without_recorded_run_or_outcome_is_inconclusive(tmp_path: Path) -> None:
    empty = load_finding(finding_capsule(tmp_path / "e", traces={}))
    report = rerun_finding(
        empty,
        _options(tmp_path / "o1", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert report.reproduction.state == SemanticOutcome.INCONCLUSIVE
    assert report.reproduction.reason == "there is no recorded run to compare with"
    assert report.reproduction.to_json()["recordedRun"] is None
    unknown = load_finding(
        finding_capsule(
            tmp_path / "u",
            traces={
                "r.sova-trace": recorded_trace(tmp_path / "u.sova-trace", attack_succeeded=None)
            },
        )
    )
    assert unknown.traces[0].verdict == "cant-tell"
    report = rerun_finding(
        unknown,
        _options(tmp_path / "o2", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert report.reproduction.state == SemanticOutcome.INCONCLUSIVE
    assert report.reproduction.reason == "the recorded run's outcome could not be read"


def test_recorded_run_without_defense_makes_matching_runs_inconclusive(tmp_path: Path) -> None:
    trace = recorded_trace(tmp_path / "r.sova-trace", started={"condition": "custom-label"})
    parameters = dict(PARAMETERS)
    finding = load_finding(
        finding_capsule(tmp_path / "in", parameters=parameters, traces={"r.sova-trace": trace})
    )
    report = rerun_finding(
        finding,
        _options(tmp_path / "out", model="gpt-4o"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert report.reproduction.state == SemanticOutcome.INCONCLUSIVE
    assert "required context not recorded: defense" in comparison_sentence(report.reproduction)


def test_invalid_recorded_trace_makes_the_comparison_evidence_invalid(tmp_path: Path) -> None:
    base = finding_capsule(tmp_path / "base")
    reader = PackageReader(base)
    manifest = reader.manifest("sova.capsule")
    manifest.pop("objects")
    writer = PackageWriter(manifest)
    for descriptor in reader.verify("sova.capsule"):
        data = reader.read_object(descriptor)
        if descriptor.role == "trace":
            data = b"not a trace"
        writer.add_bytes(
            role=descriptor.role, path=descriptor.path, media_type=descriptor.mediaType, data=data
        )
    broken = tmp_path / "broken.sova"
    writer.write(broken)
    finding = load_finding(broken)
    assert finding.traces[0].valid is False
    assert finding.traces[0].problem is not None
    report = rerun_finding(
        finding,
        _options(tmp_path / "out", model="gpt-4o", benchmark_version="v1.2.2"),
        runner=FakeRunner(by_model({"gpt-4o": [True]})),
        budget=_free(),
    )
    assert report.reproduction.state == SemanticOutcome.EVIDENCE_INVALID
    assert comparison_sentence(report.reproduction).startswith("not comparable:")


def test_tampered_fresh_trace_is_evidence_invalid(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    store = RunStore(tmp_path / "out")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "bad.sova-trace").write_bytes(b"junk")
    entry = RunEntry(
        "k", "bad.sova-trace", "sha256:" + "0" * 64, "gpt-4o", "attack", None, None, None, "j", ()
    )
    planned = {"model": "gpt-4o"}
    result = compare_with_recorded(
        finding, [entry], store=store, rules=DEFAULT_ENVELOPE, planned=planned, requested=None
    )
    assert result.state == SemanticOutcome.EVIDENCE_INVALID


def test_finding_loading_rejects_unsupported_capsules(tmp_path: Path) -> None:
    other = finding_capsule(tmp_path / "o", parameters={**PARAMETERS, "benchmark": "Other"})
    with pytest.raises(FormatError, match="AgentDojo"):
        load_finding(other)
    missing = dict(PARAMETERS)
    del missing["suite"]
    with pytest.raises(FormatError, match="missing AgentDojo keys"):
        load_finding(finding_capsule(tmp_path / "m", parameters=missing))
    with pytest.raises(FormatError, match="no scenario"):
        load_finding(finding_capsule(tmp_path / "n", with_scenario=False))


def test_benchmark_version_from_traces_or_flag(tmp_path: Path) -> None:
    parameters = {key: value for key, value in PARAMETERS.items() if key != "benchmarkVersion"}
    finding = load_finding(finding_capsule(tmp_path / "a", parameters=parameters))
    assert finding.benchmark_version == "v1.2.2"  # from the recorded run
    bare = recorded_trace(tmp_path / "bare.sova-trace", started={"benchmarkVersion": None})
    unknown = load_finding(
        finding_capsule(tmp_path / "b", parameters=parameters, traces={"t.sova-trace": bare})
    )
    assert unknown.benchmark_version is None
    with pytest.raises(RerunError, match="--benchmark-version"):
        plan_finding(
            unknown, "m", trials=1, condition=Condition(), attack_name=None, benchmark_version=None
        )
    plan = plan_finding(
        unknown, "m", trials=2, condition=Condition(), attack_name="X", benchmark_version="v1.2.1"
    )
    assert [job.trial for job in plan.jobs] == [1, 2]
    assert plan.jobs[0].key.startswith("AgentDojo/v1.2.1/important_instructions/banking/")
    with pytest.raises(RerunError, match="at least 1"):
        plan_finding(
            unknown, "m", trials=0, condition=Condition(), attack_name=None, benchmark_version="v"
        )


def test_condition_resolution(tmp_path: Path) -> None:
    finding = load_finding(
        finding_capsule(
            tmp_path / "a",
            parameters={**PARAMETERS, "defense": "repeat_user_prompt", "toolOutputFormat": "json"},
        )
    )
    assert resolve_condition(finding, {}) == Condition("repeat_user_prompt", "json", None)
    assert resolve_condition(finding, {"defense": None, "ignored": 1}).defense is None
    with pytest.raises(RerunError, match="unsupported defense"):
        resolve_condition(finding, {"defense": "tool_filter"})
    with pytest.raises(ValueError, match="tool-output"):
        Condition(tool_output_format="xml")
    described = Condition(system_message="secret system text").describe()
    assert "secret system text" not in json.dumps(described)


def test_context_from_events_uses_trace_labels_and_parameters() -> None:
    events = [
        {
            "kind": "run.started",
            "payload": {
                "model": "m",
                "condition": "M2-repeat-user-prompt",
                "returnedModels": ["b", "a"],
                "attackModelName": "GPT-4",
            },
        },
        {"kind": "prompt.system", "payload": {"text": "s"}},
    ]
    context = context_from_events(events, {"benchmarkVersion": "v1", "attack": "x"})
    assert context["defense"] == "repeat_user_prompt"
    assert context["toolOutputFormat"] == "yaml"
    assert context["returnedModel"] == ["a", "b"]
    assert context["attackName"] == "GPT-4"
    assert context["benchmarkVersion"] == "v1"
    explicit = context_from_events(
        [{"kind": "run.started", "payload": {"defense": None, "toolOutputFormat": None}}], {}
    )
    assert explicit == {"defense": None, "toolOutputFormat": "yaml"}
    from_parameters = context_from_events(
        [], {"defense": "repeat_user_prompt", "toolOutputFormat": "json"}
    )
    assert from_parameters == {"defense": "repeat_user_prompt", "toolOutputFormat": "json"}
    assert context_from_events([{"kind": "run.started", "payload": "odd"}], {}) == {}
    assert (
        verdict_from_events([{"kind": "judge.completed", "payload": {"verdict": "no-attack"}}])
        == "no-attack"
    )
    assert (
        verdict_from_events([{"kind": "oracle.completed", "payload": {"attackSucceeded": False}}])
        == "no-attack"
    )


def test_discover_capsules(tmp_path: Path) -> None:
    first = finding_capsule(tmp_path / "dir", "one")
    second = finding_capsule(tmp_path / "dir", "two")
    found = discover_capsules([tmp_path / "dir", first])
    assert found == sorted({first.resolve(), second.resolve()})
    with pytest.raises(FormatError, match="no such"):
        discover_capsules([tmp_path / "missing"])
    (tmp_path / "empty").mkdir()
    with pytest.raises(FormatError, match=r"no \.sova"):
        discover_capsules([tmp_path / "empty"])


def test_run_store_ignores_damaged_ledger_lines(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    assert store.completed() == {}
    store.append(
        RunEntry(
            "k1",
            "missing.sova-trace",
            "sha256:" + "0" * 64,
            "m",
            "attack",
            None,
            None,
            "1.0",
            "j",
            (),
        )
    )
    with store.ledger.open("a", encoding="utf-8") as handle:
        handle.write("\n{not json\n" + json.dumps({"key": "k2", "verdict": "maybe"}) + "\n")
    assert store.completed() == {}
    assert store.spent() == 0.0
    outside = tmp_path / "outside.sova-trace"
    outside.write_bytes(b"x")
    escaping = RunEntry(
        "k3",
        "traces/../outside.sova-trace",
        file_digest(outside),
        "m",
        "attack",
        None,
        None,
        None,
        "j",
        (),
    )
    store.append(escaping)
    assert store.completed() == {}


def test_capsules_with_the_same_name_in_different_folders_keep_separate_traces(
    tmp_path: Path,
) -> None:
    first = load_finding(finding_capsule(tmp_path / "a", "same"))
    second = load_finding(finding_capsule(tmp_path / "b", "same", user_task="user_task_2"))
    store = RunStore(tmp_path / "out")
    jobs = [
        plan_finding(
            finding, "m", trials=1, condition=Condition(), attack_name=None, benchmark_version=None
        ).jobs[0]
        for finding in (first, second)
    ]
    assert store.trace_path(jobs[0]) != store.trace_path(jobs[1])


def test_merge_contexts_and_sentences_for_rare_states() -> None:
    def evaluation(status: ContextStatus) -> ContextEvaluation:
        return ContextEvaluation(
            status, (ContextResult(("returnedModel",), status, "a", "b", "r"),)
        )

    merged = merge_contexts(
        [evaluation(ContextStatus.COMPATIBLE), evaluation(ContextStatus.DRIFTED)]
    )
    assert merged.status == ContextStatus.DRIFTED
    assert merged.results[0].status == ContextStatus.DRIFTED
    base = Reproduction(None, "s", SemanticOutcome.UNSAFE, outcome_estimate(), None, "r")
    assert comparison_sentence(base) == "not compared: the comparison was unsafe"
    assert base.differences(ContextStatus.DRIFTED) == []
    inconclusive = replace(base, state=SemanticOutcome.INCONCLUSIVE, reason="no fresh run finished")
    assert comparison_sentence(inconclusive) == "inconclusive (no fresh run finished)"
    assert outcome_sentence(outcome_of([])) == (
        "attack worked 0 of 0 judged runs (no interval: no run could be judged); "
        "0 runs could not be judged"
    )
    single = outcome_of([RunEntry("k", "t", "d", "m", "cant-tell", "x", None, None, "j", ())])
    assert "1 run could not be judged (1 x)" in outcome_sentence(single)


def outcome_estimate() -> Any:
    from sova.rerun.decision import estimate_reproduction  # noqa: PLC0415 - test helper

    return estimate_reproduction(())


def test_scenario_helper_is_valid() -> None:
    assert scenario()["parameters"]["benchmark"] == "AgentDojo"
    assert ContextRule(("x",), ContextMode.EXACT).required is True
