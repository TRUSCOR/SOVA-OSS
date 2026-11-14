# SPDX-License-Identifier: Apache-2.0
"""Fresh-run traces, record helpers, and rare engine paths."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule.model import capsule_manifest_template
from sova.formats import PackageWriter
from sova.formats.errors import FormatError
from sova.rerun.decision import SemanticOutcome, estimate_reproduction
from sova.rerun.engine import (
    RerunOptions,
    RunStore,
    _aggregate_state,
    plan_finding,
    rerun_finding,
)
from sova.rerun.findings import load_finding, read_trace_events
from sova.rerun.providers import Budget, Pricing
from sova.rerun.records import (
    Condition,
    cant_tell_reason,
    jsonable,
    judge_name,
)
from sova.rerun.tracing import Judgment, authorization_scope, write_run_trace
from tests.support.rerun import FakeRunner, by_model, finding_capsule, make_record

if TYPE_CHECKING:
    from pathlib import Path


def _job(tmp_path: Path) -> Any:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    return plan_finding(
        finding,
        "gpt-5.5",
        trials=1,
        condition=Condition(),
        attack_name=None,
        benchmark_version=None,
    ).jobs[0]


def test_trace_records_each_turn_and_unmatched_calls(tmp_path: Path) -> None:
    job = _job(tmp_path)
    extra = make_record(job, extra_calls=2)
    extra_path = tmp_path / "extra.sova-trace"
    write_run_trace(extra, extra_path, Judgment("attack", "judge", None, None))
    extra_returned = [
        event
        for event in read_trace_events(extra_path)
        if event["kind"] == "environment.model.returned"
    ]
    assert len(extra_returned) == 5
    assert [event["payload"].get("unmatchedTurn") for event in extra_returned[-2:]] == [True, True]

    record = make_record(job, model_output_missing=True)
    odd = {"role": "developer", "text": "ignored role"}
    record = replace(record, messages=(*record.messages, odd), calls=record.calls[:1])
    path = tmp_path / "run.sova-trace"
    digest = write_run_trace(record, path, Judgment("attack", "judge", None, 0.0123))
    assert digest.startswith("sha256:")
    events = read_trace_events(path)
    kinds = [event["kind"] for event in events]
    assert kinds[:3] == ["run.started", "prompt.system", "prompt.user"]
    assert kinds.count("model.response") == 3
    returned = [event for event in events if event["kind"] == "environment.model.returned"]
    assert len(returned) == 1
    assert returned[0]["payload"]["failedAttempts"][0]["statusCode"] == 429
    response = next(
        event
        for event in events
        if event["kind"] == "model.response" and event["payload"].get("omittedBlocks")
    )
    assert response["payload"]["omittedBlocks"] == {"thinking": 1}
    oracle = next(event for event in events if event["kind"] == "oracle.completed")
    assert oracle["payload"]["modelOutputMissing"] is True
    assert oracle["payload"]["attackSucceeded"] is True
    judged = next(event for event in events if event["kind"] == "judge.completed")
    assert judged["payload"]["attackObserved"] is True
    completed = events[-1]
    assert completed["kind"] == "run.completed"
    assert completed["payload"]["costUsdEstimate"] == "0.012300"
    started = events[0]["payload"]
    assert started["toolOutputFormat"] == "yaml"
    assert started["defense"] is None
    tool = next(event for event in events if event["kind"] == "tool.result")
    assert tool["payload"]["containsPlantedInstruction"] is True
    scope = authorization_scope(record)
    assert scope["model"] == "gpt-5.5"
    assert "systemMessage" in scope["condition"]


def test_jsonable_and_record_helpers() -> None:
    class Dumpable:
        def model_dump(self, *, mode: str) -> dict[str, Any]:
            assert mode == "json"
            return {"value": 1.5}

    converted = jsonable(
        {
            "set": {3, 1},
            "big": 2**60,
            "nan": float("nan"),
            "obj": Dumpable(),
            "other": object(),
            "tuple": (1, None),
        }
    )
    assert converted["set"] == [1, 3]
    assert converted["big"] == str(2**60)
    assert converted["nan"] == "nan"
    assert converted["obj"] == {"value": "1.5"}
    assert converted["other"].startswith("<object")
    assert converted["tuple"] == [1, None]
    assert judge_name(lambda _record: "attack") == "<lambda>"
    assert judge_name(SimpleNamespace()) == "SimpleNamespace"  # type: ignore[arg-type]


def test_cant_tell_reason_when_a_custom_judge_abstains(tmp_path: Path) -> None:
    record = make_record(_job(tmp_path), security=False)
    assert cant_tell_reason(record) == "the judge could not decide"


def test_unsafe_aggregate_and_stale_staging_cleanup(tmp_path: Path) -> None:
    state, reason = _aggregate_state([SemanticOutcome.UNSAFE], estimate_reproduction(()))
    assert state == SemanticOutcome.UNSAFE
    assert reason == "comparison was unsafe"
    finding = load_finding(finding_capsule(tmp_path / "in"))
    options = RerunOptions(
        model="gpt-5.5",
        provider="openai-compatible",
        trials=1,
        out_dir=tmp_path / "out",
        authorize=True,
    )
    job = plan_finding(
        finding,
        "gpt-5.5",
        trials=1,
        condition=Condition(),
        attack_name=None,
        benchmark_version=None,
    ).jobs[0]
    trace = RunStore(tmp_path / "out").trace_path(job)
    staging = trace.with_name(f".{trace.name}.partial")
    (staging / "events").mkdir(parents=True)
    report = rerun_finding(
        finding,
        options,
        runner=FakeRunner(by_model({"gpt-5.5": [True]})),
        budget=Budget(max_usd=None, pricing=None),
    )
    assert report.outcome.attacks == 1
    assert not staging.exists()


def test_rerun_with_no_finished_run_writes_no_capsule(tmp_path: Path) -> None:
    finding = load_finding(finding_capsule(tmp_path / "in"))
    options = RerunOptions(
        model="gpt-5.5",
        provider="openai-compatible",
        trials=2,
        out_dir=tmp_path / "out",
        authorize=True,
    )
    report = rerun_finding(
        finding,
        options,
        runner=FakeRunner(by_model({"gpt-5.5": [True]})),
        budget=Budget(max_usd=0.01, pricing=Pricing(1.0, 1.0), already_spent=1.0),
    )
    assert report.capsule is None
    text = report.render()
    assert "wrote:" not in text
    assert "2 run(s) not started" in text
    assert report.reproduction.reason == "no fresh run finished"
    assert json.dumps(report.to_json())


def test_capsule_whose_scenario_is_not_an_object_is_rejected(tmp_path: Path) -> None:
    manifest = capsule_manifest_template(title="t", summary="s", author="a")
    writer = PackageWriter(manifest)
    writer.add_bytes(
        role="scenario", path="objects/scenario.json", media_type="application/json", data=b"[]"
    )
    path = tmp_path / "odd.sova"
    writer.write(path)
    with pytest.raises(FormatError, match="scenario root"):
        load_finding(path)
