# SPDX-License-Identifier: Apache-2.0
"""Complete command registration and audit-script contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import sova.command_audit as audit_module
from sova.cli import main
from sova.command_audit import AuditError, audit, command_handlers, function_body_lines


def test_every_cli_leaf_has_a_unique_registered_handler() -> None:
    handlers = command_handlers()
    assert len(handlers) == 157
    assert len(set(handlers)) == len(handlers)
    assert all(name.startswith("_") for name in handlers.values())
    assert {
        "case build",
        "detonate owned-software-fixture",
        "detonate action-lab",
        "detonate software",
        "target fixture",
        "target prove-software",
        "target browser-kit",
        "target profile-create",
        "target profile-validate",
        "target intake",
        "release sbom",
        "release cargo-sbom",
        "release keygen",
        "release sign-evidence",
        "release assemble-evidence",
        "release dossier",
        "conformance verify",
        "mcp serve",
        "extension discover",
        "extension prepare",
        "extension run",
        "arena chamber",
        "arena web",
        "arena explore-web",
        "arena run-software",
        "arena swarm-software",
        "arena full-web",
        "engine reproduce-plan",
        "agent conform-oci",
        "arena swarm-web",
        "probe issue",
        "trace command",
        "session browser-create",
        "session browser-handoff",
        "session browser-inspect",
        "safety attest-docker",
        "safety attest-gvisor",
        "registry serve",
        "registry init-service",
        "registry healthcheck",
        "registry prepare-upload",
        "registry verify-live-index",
        "registry replay",
        "monitor serve",
        "monitor status",
        "replay serve",
        "replay capsule",
        "replay open",
        "forensics blind-fixture",
        "forensics blind-run",
        "forensics blind-score",
        "forensics blind-keygen",
        "forensics blind-sign-key",
        "methodology library-export",
        "methodology playbook-validate",
        "methodology policy-create",
        "methodology compile",
        "methodology observations-template",
        "methodology replan",
        "methodology keygen",
        "methodology contribute",
        "adapter catalog",
        "adapter describe",
        "adapter plan",
        "adapter normalize",
        "audit",
        "record agentdojo",
        "record inspect",
        "record trace",
        "show",
        "rerun",
        "matrix",
        "calibrate",
    } <= set(handlers)


def test_every_cli_leaf_has_working_help() -> None:
    for command in command_handlers():
        arguments = [*command.split(), "--help"]
        try:
            main(arguments)
        except SystemExit as error:
            assert error.code == 0


def test_coverage_audit_detects_an_unexecuted_command(tmp_path: Path) -> None:
    bodies = function_body_lines(Path("src/sova/cli.py"))
    init_line = min(bodies["_init"])
    coverage = {
        "files": {
            "src/sova/cli.py": {
                "executed_lines": [init_line],
            }
        }
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(coverage), encoding="utf-8")
    report = audit(path)
    assert report["status"] == "fail"
    assert "doctor" in report["unexecutedCommands"]


def test_coverage_audit_passes_complete_lines_and_rejects_malformed_input(
    tmp_path: Path,
) -> None:
    bodies = function_body_lines(Path("src/sova/cli.py"))
    complete = sorted({line for lines in bodies.values() for line in lines})
    path = tmp_path / "complete.json"
    path.write_text(
        json.dumps({"files": {"src\\sova\\cli.py": {"executed_lines": complete}}}),
        encoding="utf-8",
    )
    assert audit(path)["status"] == "pass"

    path.write_text("{}", encoding="utf-8")
    with pytest.raises(AuditError, match="no files"):
        audit(path)
    path.write_text(json.dumps({"files": {"other.py": {}}}), encoding="utf-8")
    with pytest.raises(AuditError, match="no executed lines"):
        audit(path)


def test_command_audit_rejects_leaf_without_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit_module, "build_parser", argparse.ArgumentParser)
    with pytest.raises(AuditError, match="no callable handler"):
        command_handlers()


def test_remaining_safe_cli_administration_handlers_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert main(["safety", "backends"]) == 0
    assert json.loads(capfd.readouterr().out)
    assert main(["mcp", "manifest"]) == 0
    assert json.loads(capfd.readouterr().out)["artifactType"] == "sova.mcp-tool-manifest"

    key = tmp_path / "control.key"
    assert main(["mcp", "init-control", str(key)]) == 0
    assert key.stat().st_size >= 32
    capfd.readouterr()

    workspace = tmp_path / "workspace"
    evidence = tmp_path / "evidence"
    control = tmp_path / "control"
    workspace.mkdir()
    assert (
        main(
            [
                "mcp",
                "approve",
                "sova-mcp-missing",
                "--control-dir",
                str(control),
                "--key-file",
                str(key),
                "--workspace",
                str(workspace),
            ]
        )
        == 2
    )
    assert "interactive terminal" in capfd.readouterr().err

    served: list[object] = []
    monkeypatch.setattr("sova.cli.serve_stdio", served.append)
    assert (
        main(
            [
                "mcp",
                "serve",
                "--workspace",
                str(workspace),
                "--evidence-dir",
                str(evidence),
                "--control-dir",
                str(control),
                "--key-file",
                str(key),
            ]
        )
        == 0
    )
    assert len(served) == 1
