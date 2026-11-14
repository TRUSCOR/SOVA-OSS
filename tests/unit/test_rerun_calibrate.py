# SPDX-License-Identifier: Apache-2.0
"""``sova calibrate``: measured per-model envelopes, with a fake runner and no model calls."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.cli import main
from sova.formats import strict_json_loads
from sova.rerun import command
from sova.rerun.calibrate import (
    PARAPHRASED_SYSTEM_MESSAGE,
    CalibrateOptions,
    ChangeResult,
    classify,
    envelope_from,
    measure_drop,
    percentile,
    run_calibration,
)
from sova.rerun.decision import ContextMode
from sova.rerun.engine import RerunError, load_envelope
from sova.rerun.findings import load_finding
from sova.rerun.providers import Budget, Pricing
from tests.support.rerun import FakeRunner, finding_capsule, make_record

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.rerun.findings import Finding
    from sova.rerun.providers import ModelSettings
    from sova.rerun.records import RunJob, RunRecord


def scripted(job: RunJob) -> RunRecord:
    """The attack recurs except on the other model and under the repeat-user-prompt defense."""
    blocked = job.model == "other" or job.condition.defense == "repeat_user_prompt"
    return make_record(job, security=not blocked)


def findings(tmp_path: Path, count: int = 3) -> list[Finding]:
    return [
        load_finding(finding_capsule(tmp_path / "in", f"f{index}", user_task=f"user_task_{index}"))
        for index in range(count)
    ]


def options(tmp_path: Path, **changes: Any) -> CalibrateOptions:
    values: dict[str, Any] = {
        "model": "gpt-4o",
        "provider": "openai-compatible",
        "trials": 3,
        "out_dir": tmp_path / "out",
        "authorize": True,
        "alternative": "other",
        "resamples": 200,
        "concurrency": 2,
    }
    values.update(changes)
    return CalibrateOptions(**values)


def test_measure_drop_and_classify() -> None:
    base, changed, drop, interval, used = measure_drop(
        [1.0, 1.0, 1.0], [0.0, 0.0, 0.0], resamples=100, seed=1
    )
    assert (base, changed, drop, interval, used) == (1.0, 0.0, 1.0, (1.0, 1.0), 3)
    assert classify(interval, 0.10) == "material"
    flat = measure_drop([1.0, 0.5], [1.0, 0.5], resamples=100, seed=1)
    assert flat[2] == 0.0
    assert classify(flat[3], 0.10) == "non-material"
    mixed = measure_drop([1.0, 0.0, 1.0, 0.0], [0.0, 0.0, 1.0, 1.0], resamples=500, seed=3)
    assert mixed[2] == 0.0
    assert classify(mixed[3], 0.10) == "undetermined"
    missing = measure_drop([1.0, None], [None, None], resamples=10, seed=1)
    assert missing == (1.0, None, None, None, 0)
    assert classify(None, 0.10) == "undetermined"
    assert measure_drop([], [], resamples=10, seed=1) == (None, None, None, None, 0)
    # The interval is reproducible from the seed.
    again = measure_drop([1.0, 0.0, 1.0, 0.0], [0.0, 0.0, 1.0, 1.0], resamples=500, seed=3)
    assert again == mixed


def test_percentile_interpolates_between_ranks() -> None:
    assert percentile([0.0, 1.0], 50) == 0.5
    assert percentile([0.0, 1.0, 2.0, 3.0, 4.0], 2.5) == 0.1
    assert percentile([0.0, 1.0, 2.0, 3.0, 4.0], 97.5) == 3.9
    assert percentile([7.0], 97.5) == 7.0


def test_measure_drop_with_no_usable_resample() -> None:
    # Each finding has runs on only one side: the point estimate exists, but a resample
    # can draw one side only, and a resample set where every draw is one-sided gives no
    # interval.
    base, changed, drop, interval, used = measure_drop(
        [1.0, None], [None, 0.0], resamples=1, seed=0
    )
    assert (base, changed, drop, used) == (1.0, 0.0, 1.0, 0)
    assert interval is None or interval == (1.0, 1.0)


def _result(name: str, dimension: str, measured: str) -> ChangeResult:
    return ChangeResult(name, dimension, 3, 1.0, 1.0, 0.0, (0.0, 0.0), measured)


def test_envelope_from_measured_classes_loads_as_rules(tmp_path: Path) -> None:
    results = [
        _result("json", "toolOutputFormat", "non-material"),
        _result("paraphrase", "systemPrompt", "undetermined"),
        _result("model", "model", "non-material"),
        _result("repeat-user-prompt", "defense", "non-material"),
        _result("spotlighting", "defense", "material"),
    ]
    envelope = envelope_from(results, model="m", alternative="alt", baseline_defense=None)
    assert envelope["dimensions"] == {
        "toolOutputFormat": "record",
        "systemPrompt": "exact",
        "model": {"mode": "one-of", "allowed": ["m", "alt"]},
        "defense": {"mode": "one-of", "allowed": [None, "repeat_user_prompt"]},
    }
    assert envelope["measured"]["classes"]["spotlighting"] == "material"
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    rules = {rule.path[0]: rule for rule in load_envelope(path)}
    assert rules["toolOutputFormat"].mode == ContextMode.RECORD
    assert rules["systemPrompt"].mode == ContextMode.EXACT
    assert rules["model"].allowed == ("m", "alt")
    assert rules["defense"].allowed == (None, "repeat_user_prompt")


def test_envelope_from_material_changes_is_exact() -> None:
    results = [
        _result("model", "model", "material"),
        _result("repeat-user-prompt", "defense", "undetermined"),
    ]
    envelope = envelope_from(results, model="m", alternative="alt", baseline_defense=None)
    assert envelope["dimensions"] == {"model": "exact", "defense": "exact"}
    assert envelope_from([], model="m", alternative=None, baseline_defense=None)["dimensions"] == {}
    # Without an alternative, the model dimension keeps its default rule.
    no_alt = envelope_from(
        [_result("model", "model", "non-material")],
        model="m",
        alternative=None,
        baseline_defense=None,
    )
    assert "model" not in no_alt["dimensions"]


def test_calibration_measures_each_change_and_resumes(tmp_path: Path) -> None:
    runner = FakeRunner(scripted)
    found = findings(tmp_path)
    report = run_calibration(
        found,
        options(tmp_path),
        runner=runner,
        budget=Budget(max_usd=None, pricing=Pricing(1.0, 1.0)),
    )
    assert len(runner.runs) == 3 * 6 * 3
    assert {job.model for job in runner.runs} == {"gpt-4o", "other"}
    systems = {job.condition.system_message for job in runner.runs}
    assert systems == {None, PARAPHRASED_SYSTEM_MESSAGE}
    measured = {result.name: result.measured for result in report.changes}
    assert measured == {
        "json": "non-material",
        "paraphrase": "non-material",
        "model": "material",
        "repeat-user-prompt": "material",
        "spotlighting": "non-material",
    }
    drops = {result.name: result.drop for result in report.changes}
    assert drops["model"] == 1.0
    assert drops["json"] == 0.0
    summary = strict_json_loads((tmp_path / "out" / "calibration.json").read_bytes())
    assert summary["artifactType"] == "sova.calibration"
    assert summary["runs"]["fresh"] == 54
    assert summary["changes"][2]["drop95"] == ["1.0000", "1.0000"]
    assert summary["threshold"] == "0.1000"
    assert summary["findings"][0]["outcomes"]["unchanged"]["attacks"] == 3
    assert summary["spend"]
    envelope = strict_json_loads((tmp_path / "out" / "envelope.json").read_bytes())
    assert envelope["dimensions"] == {
        "toolOutputFormat": "record",
        "systemPrompt": "record",
        "model": "exact",
        "defense": {"mode": "one-of", "allowed": [None, "spotlighting_with_delimiting"]},
    }
    text = report.render()
    assert "repeat-user-prompt" in text
    assert "use it: sova rerun FINDING.sova --model gpt-4o --envelope" in text
    assert "100.0 (100.0 to 100.0)" in text

    # A second call reuses every run and, without --authorize, calls no model.
    again = FakeRunner(scripted)
    rebuilt = run_calibration(
        found,
        options(tmp_path, authorize=False),
        runner=again,
        budget=Budget(max_usd=None, pricing=None),
    )
    assert again.runs == []
    assert rebuilt.execution.reused == 54
    assert [r.measured for r in rebuilt.changes] == [r.measured for r in report.changes]


def test_calibration_refuses_missing_runs_without_authorize(tmp_path: Path) -> None:
    runner = FakeRunner(scripted)
    with pytest.raises(RerunError) as error:
        run_calibration(
            findings(tmp_path, 1),
            options(tmp_path, authorize=False),
            runner=runner,
            budget=Budget(max_usd=None, pricing=None),
        )
    assert error.value.issue.code == "SOVA-RERUN-AUTHORIZATION"
    assert runner.runs == []


def test_calibration_with_a_base_condition_and_a_budget_stop(tmp_path: Path) -> None:
    runner = FakeRunner(scripted)
    report = run_calibration(
        findings(tmp_path, 2),
        options(
            tmp_path,
            changes=("json",),
            alternative=None,
            base_override={"defense": "spotlighting_with_delimiting"},
            concurrency=1,
        ),
        runner=runner,
        budget=Budget(max_usd=0.5, pricing=Pricing(1.0, 1.0), already_spent=1.0),
    )
    assert runner.runs == []
    assert report.execution.budget_stopped
    assert report.changes[0].measured == "undetermined"
    assert "no run completed, so nothing was written" in report.render()
    assert not (tmp_path / "out" / "calibration.json").exists()

    paid = FakeRunner(scripted)
    measured = run_calibration(
        findings(tmp_path, 2),
        options(
            tmp_path,
            changes=("json",),
            alternative=None,
            base_override={"defense": "spotlighting_with_delimiting"},
        ),
        runner=paid,
        budget=Budget(max_usd=None, pricing=None),
    )
    assert {job.condition.defense for job in paid.runs} == {"spotlighting_with_delimiting"}
    assert measured.envelope["dimensions"] == {"toolOutputFormat": "record"}


@pytest.mark.parametrize(
    ("changes", "alternative", "code"),
    [
        (("bogus",), "other", "SOVA-CALIBRATE-CHANGES"),
        (("model",), None, "SOVA-CALIBRATE-ALTERNATIVE"),
    ],
)
def test_calibration_rejects_bad_requests(
    tmp_path: Path, changes: tuple[str, ...], alternative: str | None, code: str
) -> None:
    with pytest.raises(RerunError) as error:
        run_calibration(
            findings(tmp_path, 1),
            options(tmp_path, changes=changes, alternative=alternative),
            runner=FakeRunner(scripted),
            budget=Budget(max_usd=None, pricing=None),
        )
    assert error.value.issue.code == code
    with pytest.raises(RerunError) as empty:
        run_calibration(
            [],
            options(tmp_path),
            runner=FakeRunner(scripted),
            budget=Budget(max_usd=None, pricing=None),
        )
    assert empty.value.issue.code == "SOVA-CALIBRATE-FINDINGS"


@pytest.fixture
def fake_factory(monkeypatch: pytest.MonkeyPatch) -> list[FakeRunner]:
    made: list[FakeRunner] = []

    def factory(settings_for: Callable[[str], ModelSettings]) -> FakeRunner:
        assert settings_for("gpt-4o").model == "gpt-4o"
        runner = FakeRunner(scripted)
        made.append(runner)
        return runner

    monkeypatch.setattr(command, "default_runner", factory)
    return made


def test_calibrate_command_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fake_factory: list[FakeRunner]
) -> None:
    for index in range(2):
        finding_capsule(tmp_path / "in", f"f{index}", user_task=f"user_task_{index}")
    out = tmp_path / "out"
    base = ["calibrate", str(tmp_path / "in"), "--model", "gpt-4o", "--out", str(out)]
    assert main(base) == 2
    assert "SOVA-RERUN-AUTHORIZATION" in capsys.readouterr().err
    assert fake_factory[0].runs == []

    assert main([*base, "--trials", "2", "--resamples", "50", "--authorize"]) == 0
    text = capsys.readouterr().out
    assert "json" in text
    assert "model " not in text.splitlines()[1]  # 'model' is skipped without --alternative
    assert len(fake_factory[1].runs) == 2 * 5 * 2

    code = main(
        [
            *base,
            "--trials",
            "2",
            "--resamples",
            "50",
            "--changes",
            "json,repeat-user-prompt",
            "--json",
        ]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert [change["change"] for change in summary["changes"]] == ["json", "repeat-user-prompt"]
    assert summary["changes"][1]["measured"] == "material"
    assert fake_factory[2].runs == []

    assert (
        main([*base, "--alternative", "other", "--authorize", "--trials", "1", "--resamples", "20"])
        == 0
    )
    assert "model" in capsys.readouterr().out
    # Runs on gpt-4o were recorded by the earlier call and are reused; only the other model runs.
    assert {job.model for job in fake_factory[3].runs} == {"other"}

    assert main([*base, "--alternative", "gpt-4o"]) == 2
    assert "SOVA-CALIBRATE-ALTERNATIVE" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [
        ["--changes", "json,bogus"],
        ["--changes", ","],
        ["--threshold", "1.5"],
        ["--envelope", "x.json"],
    ],
)
def test_calibrate_rejects_bad_arguments(
    tmp_path: Path, extra: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["calibrate", str(tmp_path), "--model", "m", *extra])
    assert exit_info.value.code == 2
    capsys.readouterr()
