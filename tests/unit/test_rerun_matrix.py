# SPDX-License-Identifier: Apache-2.0
"""``sova matrix``: findings x models x trials and the upgrade check, with a fake runner."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.rerun.engine import Outcome, RerunError
from sova.rerun.findings import load_finding
from sova.rerun.matrix import MatrixOptions, classify_upgrade, run_matrix
from sova.rerun.providers import Budget, Pricing
from tests.support.rerun import FakeRunner, by_model, finding_capsule

if TYPE_CHECKING:
    from pathlib import Path


def _outcome(attacks: int, judged: int, cant_tell: int = 0) -> Outcome:
    return Outcome(
        runs=judged + cant_tell,
        attacks=attacks,
        no_attacks=judged - attacks,
        cant_tell=cant_tell,
        reasons={},
    )


@pytest.mark.parametrize(
    ("baseline", "candidate", "expected"),
    [
        (_outcome(1, 1), _outcome(2, 5), "still-works"),
        (_outcome(2, 3), _outcome(0, 3), "stopped"),
        (_outcome(2, 3), _outcome(0, 2, 1), "cant-tell"),
        (_outcome(0, 3), _outcome(1, 1), "newly-works"),
        (_outcome(0, 2), _outcome(1, 3), "cant-tell"),
        (_outcome(0, 3), _outcome(0, 4), "no-attack-on-either"),
        (_outcome(0, 3), _outcome(0, 0, 3), "cant-tell"),
        (_outcome(0, 0, 3), _outcome(0, 0, 3), "cant-tell"),
    ],
)
def test_upgrade_classification(baseline: Outcome, candidate: Outcome, expected: str) -> None:
    assert classify_upgrade(baseline, candidate) == expected


def _options(out: Path, models: tuple[str, ...], **changes: Any) -> MatrixOptions:
    values: dict[str, Any] = {
        "models": models,
        "provider": "openai-compatible",
        "trials": 3,
        "out_dir": out,
        "authorize": True,
        "concurrency": 2,
    }
    values.update(changes)
    return MatrixOptions(**values)


def test_matrix_table_summary_capsule_and_resume(tmp_path: Path) -> None:
    findings = [
        load_finding(finding_capsule(tmp_path / "in", "alpha")),
        load_finding(finding_capsule(tmp_path / "in", "beta", user_task="user_task_2")),
    ]
    runner = FakeRunner(by_model({"a": [True, False, True], "b": [None, False, False]}))
    report = run_matrix(
        findings,
        _options(tmp_path / "out", ("a", "b")),
        runner=runner,
        budget=Budget(max_usd=None, pricing=Pricing(1.0, 1.0)),
    )
    assert len(runner.runs) == 12
    text = report.render()
    lines = text.splitlines()
    assert lines[0].split() == ["finding", "a", "b"]
    assert lines[1].split() == ["alpha", "2/3", "0/2", "(1?)"]
    assert "k/n = attacks among judged runs" in text
    summary = report.to_json()
    assert summary["artifactType"] == "sova.matrix-summary"
    assert summary["upgrade"] is None
    cell = summary["findings"][0]["models"]["a"]
    assert cell["outcome"]["attacks"] == 2
    assert cell["reproduction"]["state"] == "incompatible"
    assert len(cell["runs"]) == 3
    assert (tmp_path / "out" / "matrix.json").is_file()
    assert report.capsule is not None
    descriptors = PackageReader(report.capsule).verify("sova.capsule")
    assert sum(item.role == "trace" for item in descriptors) == 12
    attachment = next(item for item in descriptors if item.role == "attachment")
    bundled = strict_json_loads(PackageReader(report.capsule).read_object(attachment))
    assert bundled["runs"]["fresh"] == 12

    resumed = FakeRunner(by_model({"a": [True], "b": [True]}))
    again = run_matrix(
        findings,
        _options(tmp_path / "out", ("a", "b"), authorize=False),
        runner=resumed,
        budget=Budget(max_usd=None, pricing=None),
    )
    assert resumed.runs == []
    assert again.execution.reused == 12
    assert "reused 12 earlier run(s)" in again.render()


def test_upgrade_check_reports_each_finding(tmp_path: Path) -> None:
    findings = [
        load_finding(finding_capsule(tmp_path / "in", name, user_task=f"user_task_{name}"))
        for name in ("one", "two")
    ]
    runner = FakeRunner(by_model({"old": [True, True, False], "new": [False]}))
    report = run_matrix(
        findings,
        _options(tmp_path / "out", ("old", "new"), baseline="old", candidate="new"),
        runner=runner,
        budget=Budget(max_usd=None, pricing=None),
    )
    assert set(report.upgrades.values()) == {"stopped"}
    text = report.render()
    assert text.splitlines()[0].split() == [
        "finding",
        "baseline",
        "old",
        "candidate",
        "new",
        "result",
    ]
    assert "stopped working" in text
    assert "summary: 0 still works, 2 stopped working, 0 newly works" in text
    summary = report.to_json()
    assert summary["upgrade"]["counts"]["stopped"] == 2
    assert summary["findings"][0]["upgrade"] == "stopped"


def test_budget_stop_marks_cells_not_run(tmp_path: Path) -> None:
    findings = [load_finding(finding_capsule(tmp_path / "in"))]
    runner = FakeRunner(by_model({"a": [True]}))
    report = run_matrix(
        findings,
        _options(tmp_path / "out", ("a",), trials=3, concurrency=1),
        runner=runner,
        budget=Budget(max_usd=0.0001, pricing=Pricing(10.0, 10.0)),
    )
    assert "[2 not run]" in report.render()
    assert report.execution.budget_stopped


def test_matrix_rejects_bad_model_lists_and_writes_nothing_without_runs(tmp_path: Path) -> None:
    findings = [load_finding(finding_capsule(tmp_path / "in"))]
    runner = FakeRunner(by_model({"a": [True]}))
    with pytest.raises(RerunError, match="--models"):
        run_matrix(
            findings,
            _options(tmp_path / "out", ()),
            runner=runner,
            budget=Budget(max_usd=None, pricing=None),
        )
    with pytest.raises(RerunError, match="only once"):
        run_matrix(
            findings,
            _options(tmp_path / "out", ("a", "a")),
            runner=runner,
            budget=Budget(max_usd=None, pricing=None),
        )
    stopped = run_matrix(
        findings,
        _options(tmp_path / "out", ("a",)),
        runner=runner,
        budget=Budget(max_usd=0.0001, pricing=Pricing(1.0, 1.0), already_spent=1.0),
    )
    assert stopped.capsule is None
    assert runner.runs == []
    assert "budget stop" in stopped.render()
