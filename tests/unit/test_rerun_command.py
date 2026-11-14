# SPDX-License-Identifier: Apache-2.0
"""``sova rerun`` and ``sova matrix`` through the real command line, with a fake runner."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.cli import main
from sova.replay.verification import verify_artifact
from sova.rerun import command
from sova.rerun.agentdojo import AgentDojoRunner
from sova.rerun.providers import ModelEndpoint, ModelSettings
from tests.support.fake_agentdojo import ScriptedSDK, chat_response
from tests.support.rerun import FakeRunner, by_model, finding_capsule

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> list[FakeRunner]:
    """Replace the AgentDojo runner with a scripted fake for every model."""
    made: list[FakeRunner] = []

    def factory(settings_for: Callable[[str], ModelSettings]) -> FakeRunner:
        assert settings_for("gpt-5.5").model == "gpt-5.5"
        runner = FakeRunner(
            by_model({"gpt-5.5": [True, False], "gpt-4o": [True], "old": [True], "new": [False]})
        )
        made.append(runner)
        return runner

    monkeypatch.setattr(command, "default_runner", factory)
    return made


def test_rerun_without_authorize_refuses_before_any_call(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fake_runner: list[FakeRunner]
) -> None:
    capsule = finding_capsule(tmp_path / "in")
    code = main(["rerun", str(capsule), "--model", "gpt-5.5", "--out", str(tmp_path / "out")])
    assert code == 2
    error = capsys.readouterr().err
    assert "SOVA-RERUN-AUTHORIZATION" in error
    assert "nothing was run" in error
    assert fake_runner[0].runs == []
    assert fake_runner[0].prepared == []


@pytest.mark.usefixtures("fake_runner")
def test_rerun_prints_the_answer_and_writes_a_capsule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsule = finding_capsule(tmp_path / "in")
    system = tmp_path / "system.txt"
    system.write_text("You are careful.", encoding="utf-8")
    code = main(
        [
            "rerun",
            str(capsule),
            "--model",
            "gpt-5.5",
            "--trials",
            "4",
            "--out",
            str(tmp_path / "out"),
            "--authorize",
            "--price-in",
            "1.25",
            "--price-out",
            "10",
            "--max-usd",
            "5",
            "--defense",
            "none",
            "--tool-output-format",
            "json",
            "--system-message-file",
            str(system),
            "--attack-name",
            "GPT",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert (
        "-> attack worked 2 of 4 runs (Wilson 95%: 15%-85%); 0 runs could not be judged"
        in captured.out
    )
    assert "not comparable (model changed: gpt-4o -> gpt-5.5)" in captured.out
    assert "4/4 runs done" in captured.err
    written = list((tmp_path / "out").glob("*-rerun.sova"))
    assert written
    # Method and taxonomy are digest-pinned, so the new capsule verifies fully.
    assert verify_artifact(written[0]).state.value == "verified"


@pytest.mark.usefixtures("fake_runner")
def test_rerun_json_output_and_default_out_folder(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule = finding_capsule(tmp_path / "in")
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "rerun",
            str(capsule),
            "--model",
            "gpt-4o",
            "--trials",
            "1",
            "--authorize",
            "--json",
            "--api-key-env",
            "MY_KEY",
        ]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["reproduction"]["state"] == "reproduced"
    assert summary["run"]["settings"]["apiKeyEnv"] == "MY_KEY"
    assert summary["run"]["condition"]["toolOutputFormat"] == "yaml"
    assert (tmp_path / "finding-rerun").is_dir()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--price-in", "1"], "both --price-in and --price-out"),
        (["--max-usd", "1"], "--max-usd needs"),
        (["--provider", "anthropic", "--api", "responses"], "--api applies"),
    ],
)
@pytest.mark.usefixtures("fake_runner")
def test_rerun_argument_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str], message: str
) -> None:
    capsule = finding_capsule(tmp_path / "in")
    code = main(
        [
            "rerun",
            str(capsule),
            "--model",
            "gpt-5.5",
            "--authorize",
            "--out",
            str(tmp_path / "o"),
            *extra,
        ]
    )
    assert code == 2
    assert message in capsys.readouterr().err


@pytest.mark.usefixtures("fake_runner")
def test_matrix_without_authorize_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    finding_capsule(tmp_path / "in", "one")
    code = main(
        ["matrix", str(tmp_path / "in"), "--models", "old,new", "--out", str(tmp_path / "out")]
    )
    assert code == 2
    assert "Add --authorize" in capsys.readouterr().err


@pytest.mark.usefixtures("fake_runner")
def test_matrix_upgrade_check_through_the_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    finding_capsule(tmp_path / "in", "one")
    finding_capsule(tmp_path / "in", "two", user_task="user_task_2")
    code = main(
        [
            "matrix",
            str(tmp_path / "in"),
            "--baseline",
            "old",
            "--candidate",
            "new",
            "--authorize",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "stopped working" in out
    assert "summary: 0 still works, 2 stopped working" in out
    code = main(
        [
            "matrix",
            str(tmp_path / "in"),
            "--models",
            "old,new",
            "--json",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["runs"]["reused"] == 12


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--models", "a", "--baseline", "b"], "either --models"),
        (["--baseline", "b"], "both --baseline and --candidate"),
        (["--baseline", "b", "--candidate", "b"], "must differ"),
        ([], "give --models"),
    ],
)
@pytest.mark.usefixtures("fake_runner")
def test_matrix_argument_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str], message: str
) -> None:
    finding_capsule(tmp_path / "in")
    code = main(
        ["matrix", str(tmp_path / "in"), "--authorize", "--out", str(tmp_path / "o"), *extra]
    )
    assert code == 2
    assert message in capsys.readouterr().err


@pytest.mark.usefixtures("fake_runner")
def test_matrix_default_out_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capsule = finding_capsule(tmp_path / "in")
    monkeypatch.chdir(tmp_path)
    assert main(["matrix", str(capsule), "--models", "old", "--trials", "1", "--authorize"]) == 0
    assert (tmp_path / "sova-matrix" / "matrix.json").is_file()


def test_default_runner_builds_endpoints_from_named_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built: list[Any] = []

    def fake_client(settings: ModelSettings) -> tuple[Any, tuple[str, ...]]:
        built.append(settings)
        return ScriptedSDK(lambda _kwargs: chat_response(content="hi")), ("k",)

    monkeypatch.setattr(command, "build_sdk_client", fake_client)
    runner = command.default_runner(
        lambda model: ModelSettings(model=model, provider="anthropic", api="messages")
    )
    assert isinstance(runner, AgentDojoRunner)
    endpoint = runner._endpoint_factory("claude-x")
    assert isinstance(endpoint, ModelEndpoint)
    assert endpoint.settings.model == "claude-x"
    assert set(endpoint.software) == {"anthropic"}
    assert built[0].provider == "anthropic"
    assert command.installed_version("surely-not-an-installed-package-name") == "not-installed"


def test_cli_parser_registers_rerun_and_matrix() -> None:
    from sova.cli import build_parser  # noqa: PLC0415 - keep the import local to this check

    parser = build_parser()
    args = parser.parse_args(["rerun", "x.sova", "--model", "m"])
    assert args.trials is None
    assert args.provider == "openai-compatible"
    matrix = parser.parse_args(["matrix", "a", "b", "--models", "x,y", "--trials", "2"])
    assert matrix.trials == 2
    with pytest.raises(SystemExit):
        parser.parse_args(["rerun", "x.sova", "--model", "m", "--trials", "0"])
    with pytest.raises(SystemExit):
        parser.parse_args(["rerun", "x.sova", "--model", "m", "--max-usd", "-1"])
