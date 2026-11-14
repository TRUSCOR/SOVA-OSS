# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for the local format CLI."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import runpy
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

import sova
from sova import __version__
from sova.cli import build_parser, main
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path


def test_parser_is_named_sova() -> None:
    assert build_parser().prog == "sova"


def test_parser_exposes_multisurface_recording_and_replay_selection() -> None:
    parser = build_parser()
    engine = parser.parse_args(
        [
            "engine",
            "full-web",
            "target.json",
            "mission.json",
            "chamber.json",
            "result",
            "--record-video",
            "--record-computer-screen",
            "--computer-recording-interval-seconds",
            "0.25",
        ]
    )
    assert engine.record_video is True
    assert engine.record_computer_screen is True
    assert engine.computer_recording_interval_seconds == 0.25

    replay = parser.parse_args(
        ["replay", "open", "finding.sova", "--surface", "computer", "--no-open"]
    )
    assert replay.surface == "computer"
    assert replay.no_open is True


def test_empty_invocation_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("usage: sova")
    assert f"SOVA OSS {__version__}:" in captured.out


def test_version_is_machine_stable(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.err == ""
    assert captured.out == f"sova {__version__}\n"


def test_module_main_returns_cli_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["sova", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("sova.__main__", run_name="__main__")

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out == f"sova {__version__}\n"


def test_source_checkout_has_version_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_distribution(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    with monkeypatch.context() as context:
        context.setattr(importlib.metadata, "version", missing_distribution)
        reloaded = importlib.reload(sova)
        assert reloaded.__version__ == "0.1.0"

    importlib.reload(sova)


def test_template_pack_validate_inspect_and_hash_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"
    migrated = tmp_path / "behavior-migrated.sova"

    assert main(["template", "capsule", str(manifest), "--author", "Tester"]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capsys.readouterr()

    assert main(["validate", str(capsule)]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["inspect", str(capsule)]) == 0
    assert "Rendering is inert" in capsys.readouterr().out
    assert main(["hash", str(capsule)]) == 0
    assert "sha256:" in capsys.readouterr().out
    assert main(["hash", str(capsule), "--content"]) == 0
    assert "content:" in capsys.readouterr().out
    assert main(["compat", str(capsule)]) == 0
    assert json.loads(capsys.readouterr().out)["lossless"] is True
    assert main(["migrate", str(capsule), str(migrated)]) == 0
    assert migrated.is_file()
    assert migrated.read_bytes() == capsule.read_bytes()


def test_lint_verify_format_and_json_validation_commands(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"

    assert main(["template", "capsule", str(manifest)]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capfd.readouterr()

    assert main(["lint", str(capsule)]) == 1
    assert "SOVA-LINT-UNKNOWN-IMPACT" in capfd.readouterr().out
    assert main(["verify", str(capsule)]) == 0
    verification = json.loads(capfd.readouterr().out)
    assert verification["state"] == "partial"
    assert verification["objectCount"] == 1
    assert verification["offline"] is True
    for policy in (["--require-signature"], ["--key-id", "sova:key:absent"]):
        assert main(["verify", *policy, str(capsule)]) == 4
        refused = json.loads(capfd.readouterr().out)
        assert refused["state"] == "unsupported"
        assert refused["errorCode"] == "SOVA-VERIFY-CAPSULE-SIGNATURE-POLICY"
    assert main(["validate", str(scenario)]) == 0
    assert capfd.readouterr().out == "VALID\n"
    assert main(["format", str(scenario)]) == 0
    formatted = capfd.readouterr().out
    assert json.loads(formatted)["artifactType"] == "sova.scenario"
    assert (
        formatted
        == json.dumps(
            json.loads(formatted),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def test_trace_validate_verify_and_playback_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "run.sova-trace"
    writer = TraceWriter(
        trace,
        authorization={
            "decision": "allowed",
            "scopeDigest": None,
            "decidedBy": "tester",
        },
    )
    writer.append("run.started", {"objective": "CLI fixture"})
    writer.finalize()

    assert main(["validate", str(trace)]) == 0
    assert capsys.readouterr().out == "VALID\n"
    assert main(["verify", str(trace)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["eventCount"] == 1
    assert report["completion"] == "completed"
    assert report["signaturePresent"] is False
    assert main(["playback", str(trace)]) == 0
    assert "run.started" in capsys.readouterr().out
    assert main(["query", str(trace), "--kind-prefix", "run."]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "run.started"
    assert main(["export", str(trace), "--format", "otel-jsonl"]) == 0
    assert "trace_id" in capsys.readouterr().out
    assert (
        main(
            [
                "export",
                str(trace),
                "--format",
                "disclosure-json",
                "--sequence",
                "0",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["selectedEventCount"] == 1


def test_compare_command_reports_declared_outcome_equivalence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    left = tmp_path / "left.sova-trace"
    right = tmp_path / "right.sova-trace"
    for path in (left, right):
        writer = TraceWriter(path)
        writer.append(
            "oracle.completed",
            {
                "status": "pass",
                "results": [
                    {
                        "status": "pass",
                        "expected": "TRIGGERED",
                        "observed": ["TRIGGERED"],
                        "evidence_event_ids": [str(path)],
                    }
                ],
            },
        )
        writer.finalize()

    assert main(["compare", str(left), str(right), "--kind", "oracle.completed"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["equivalent"] is True
    assert report["method"] == "sova.declared-outcome-exact/0.4"
    assert report["status"] == "equivalent"


def test_cli_recovers_interrupted_trace(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    trace = tmp_path / "interrupted.sova-trace"
    writer = TraceWriter(trace, durability="forensic")
    writer.append("run.started", {})
    writer._close_segment()
    assert main(["recover-trace", str(trace)]) == 0
    assert "sha256:" in capsys.readouterr().out
    assert main(["verify", str(trace)]) == 0
    assert json.loads(capsys.readouterr().out)["completion"] == "recovered"


def test_cli_reports_format_and_io_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    assert main(["validate", str(array)]) == 2
    assert "SOVA-CLI-ROOT-TYPE" in capsys.readouterr().err

    missing = tmp_path / "missing.sova"
    assert main(["hash", str(missing)]) == 2
    assert "SOVA-IO-ERROR" in capsys.readouterr().err


def test_clean_lint_branch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"
    assert main(["template", "capsule", str(manifest)]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["safety"]["impact"] = "none"
    document["license"] = "Apache-2.0"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capsys.readouterr()
    assert main(["lint", str(capsule)]) == 0
    assert capsys.readouterr().out == "CLEAN\n"


def test_probe_issue_and_verify_cli_round_trip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = tmp_path / "probe-request.json"
    response = tmp_path / "probe-response.json"
    request.write_text(
        json.dumps(
            {
                "artifactType": "sova.probe-issuance",
                "schemaVersion": "0.1.0",
                "subject": "component:fixture/1",
                "nonce": "nonce-123",
                "scope": ["fixture.observe"],
                "assertions": [],
                "observations": [{"event": "fixture-observed"}],
                "conformanceStatus": "passed",
                "ttlSeconds": 300,
            }
        ),
        encoding="utf-8",
    )
    assert main(["probe", "issue", str(request), str(response)]) == 0
    issuance = json.loads(capsys.readouterr().out)
    assert issuance["identityTrustEstablished"] is False
    assert issuance["networkUsed"] is False
    assert (
        main(
            [
                "probe",
                "verify",
                str(response),
                "--nonce",
                "nonce-123",
                "--scope",
                "fixture.observe",
                "--key-id",
                issuance["keyId"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_direct_trace_command_requires_and_binds_exact_human_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = tmp_path / "fixture.py"
    fixture.write_text("print('SOVA_DIRECT_TRACE_OK')\n", encoding="utf-8")
    trace = tmp_path / "direct.sova-trace"
    arguments = [
        "trace",
        "command",
        str(trace),
        "--working-directory",
        str(tmp_path),
        "--",
        sys.executable,
        str(fixture),
    ]
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert main(arguments) == 2
    assert "human-operated" in capsys.readouterr().err

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda prompt: prompt.split("`")[1])
    assert main(arguments) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["directCommandFrontDoor"] is True
    assert report["processStatus"] == "succeeded"
    assert report["signed"] is True
    assert trace.is_file()

    secret_trace = tmp_path / "secret.sova-trace"
    assert (
        main(
            [
                "trace",
                "command",
                str(secret_trace),
                "--working-directory",
                str(tmp_path),
                "--",
                sys.executable,
                str(fixture),
                "--password",
                "not-recorded",
            ]
        )
        == 2
    )
    assert "credential-bearing" in capsys.readouterr().err


def test_map_command_emits_or_writes_a_distinct_local_report(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"fixture": {"command": "fixture-server"}}}),
        encoding="utf-8",
    )
    assert main(["map", str(project)]) == 0
    inline = json.loads(capfd.readouterr().out)
    assert inline["artifactType"] == "sova.map"
    assert inline["claims"]["executedVulnerability"] is False

    output = tmp_path / "result.sova-map.json"
    snapshot = tmp_path / "tools.json"
    assert (
        main(
            [
                "map",
                str(project),
                "--output",
                str(output),
                "--write-tool-snapshot",
                str(snapshot),
            ]
        )
        == 0
    )
    assert "sha256:" in capfd.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["artifactType"] == "sova.map"
    assert json.loads(snapshot.read_text(encoding="utf-8"))["artifactType"] == "sova.tool-snapshot"


def test_map_command_refuses_unauthorized_observed_inventory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    inventory = tmp_path / "observed.json"
    inventory.write_text(
        json.dumps({"mcpServers": {"fixture": {"command": "fixture-server"}}}),
        encoding="utf-8",
    )
    assert main(["map", str(project), "--observed-inventory", str(inventory)]) == 2
    assert "SOVA-MAP-RUNTIME-AUTHORIZATION" in capsys.readouterr().err
