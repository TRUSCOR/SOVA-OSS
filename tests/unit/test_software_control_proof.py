# SPDX-License-Identifier: Apache-2.0
"""Exact local-software control-proof binding tests."""

from __future__ import annotations

import os
import signal
import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.community.software_executor_engine as software_engine
from sova.community.executor_surfaces import workspace_surface_generation
from sova.community.software_executor_engine import (
    SoftwareLaunchSpec,
    build_authorized_software_runtime,
    create_local_software_control_proof,
    local_software_authority_target,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.safety import ControlProof, ControlProofMethod
from sova.targets import TargetKind, TargetManifest

if TYPE_CHECKING:
    from pathlib import Path

    from sova.community.executor_engine import ExecutorEngineRuntime


def _target() -> TargetManifest:
    return TargetManifest(
        "sova:target:owned-software-proof-fixture",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "process.observe"),
        "self-owned inert software proof fixture",
        {"authorityBasis": "self", "interface": "local-process"},
    )


def _runtime(
    target: TargetManifest,
    executable: Path,
    workspace_seed: Path,
    workspace_parent: Path,
) -> ExecutorEngineRuntime:
    return build_authorized_software_runtime(
        target,
        SoftwareLaunchSpec(executable),
        workspace_parent=workspace_parent,
        workspace_seed=workspace_seed,
    )


def test_local_software_proof_is_bound_to_exact_inputs(tmp_path: Path) -> None:
    target = _target()
    executable = tmp_path / "owned-app.bin"
    executable.write_bytes(b"owned app v1")
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "configuration.txt").write_text("v1", encoding="utf-8")
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()

    proof = create_local_software_control_proof(target, executable, workspace_seed=seed)
    runtime = _runtime(target, executable, seed, workspaces)

    runtime.assert_control_proof(proof)
    assert proof.subject == local_software_authority_target(target)
    assert proof.evidence["targetDigest"] == target.digest
    assert proof.evidence["legalAuthorityIndependentlyVerified"] is False


@pytest.mark.parametrize("changed_input", ["executable", "workspace"])
def test_local_software_proof_rejects_changed_inputs(
    tmp_path: Path,
    changed_input: str,
) -> None:
    target = _target()
    executable = tmp_path / "owned-app.bin"
    executable.write_bytes(b"owned app v1")
    seed = tmp_path / "seed"
    seed.mkdir()
    seed_file = seed / "configuration.txt"
    seed_file.write_text("v1", encoding="utf-8")
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()
    proof = create_local_software_control_proof(target, executable, workspace_seed=seed)

    if changed_input == "executable":
        executable.write_bytes(b"owned app v2")
    else:
        seed_file.write_text("v2", encoding="utf-8")
    runtime = _runtime(target, executable, seed, workspaces)

    with pytest.raises(FormatError, match="not bound to this exact target"):
        runtime.assert_control_proof(proof)


def test_local_software_authority_rejects_non_local_target() -> None:
    target = TargetManifest(
        "sova:target:web-proof-fixture",
        TargetKind.BROWSER_AGENT,
        "0.1.0",
        ("browser.observe",),
        "not local software",
        {"allowedOrigins": ["https://example.invalid"]},
    )

    with pytest.raises(FormatError, match="local-process"):
        local_software_authority_target(target)


def test_software_proof_and_launch_contract_fail_closed_on_unsafe_inputs(
    tmp_path: Path,
) -> None:
    target = _target()
    executable = tmp_path / "owned-app.bin"
    executable.write_bytes(b"fixture")
    with pytest.raises(FormatError, match="unavailable"):
        create_local_software_control_proof(target, tmp_path / "missing")
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(FormatError, match="regular file"):
        create_local_software_control_proof(target, directory)
    with pytest.raises(FormatError, match="unavailable"):
        SoftwareLaunchSpec(tmp_path / "missing")

    invalid = (
        {"argv": ["not-a-tuple"]},
        {"argv": ("",)},
        {"argv": ("x\x00y",)},
        {"argv": ("x" * 4097,)},
        {"window_required": 1},
        {"window_title_contains": "title"},
        {"startup_timeout_seconds": True},
        {"startup_timeout_seconds": 0},
        {"startup_timeout_seconds": 121},
    )
    for options in invalid:
        with pytest.raises(FormatError, match="malformed"):
            SoftwareLaunchSpec(executable, **options)


def test_software_runtime_rejects_mismatched_surface_contracts_and_proofs(
    tmp_path: Path,
) -> None:
    target = _target()
    executable = tmp_path / "owned-app.bin"
    executable.write_bytes(b"fixture")
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()
    launch = SoftwareLaunchSpec(executable)
    invalid_runtime_options = (
        {"process_templates": (object(),)},
        {"computer_surface_factory": lambda *_args: None},
        {"additional_surface_factory": lambda _phase: ()},
        {
            "additional_surface_factory": lambda _phase: (),
            "additional_codec_factories": {},
            "additional_surface_contract_digest": "bad",
        },
    )
    for options in invalid_runtime_options:
        with pytest.raises(FormatError, match=r"matching UI surface|conformant local target"):
            build_authorized_software_runtime(
                target,
                launch,
                workspace_parent=workspaces,
                **options,
            )

    runtime = build_authorized_software_runtime(
        target,
        launch,
        workspace_parent=workspaces,
    )
    now = datetime.now(UTC)
    invalid_sandbox = ControlProof(
        ControlProofMethod.SANDBOX,
        "wrong-subject",
        "sova-control:fixture",
        {"challenge": "sova-control:fixture", "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=1),
        "fixture/0.1",
    )
    with pytest.raises(FormatError, match="sandbox-scoped"):
        runtime.assert_control_proof(invalid_sandbox)
    valid_sandbox = ControlProof(
        ControlProofMethod.SANDBOX,
        "sova:sandbox:fixture",
        "sova-control:fixture",
        {"challenge": "sova-control:fixture", "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=1),
        "fixture/0.1",
    )
    runtime.assert_control_proof(valid_sandbox)


def test_additional_software_surfaces_are_exact_and_cleanup_on_substitution() -> None:
    with pytest.raises(FormatError, match="differ from"):
        software_engine._additional_surfaces(
            cast("Any", lambda _phase: []), "primary", "sha256:" + "0" * 64
        )
    with pytest.raises(FormatError, match="differ from"):
        software_engine._additional_surfaces(lambda _phase: (), "primary", "sha256:" + "0" * 64)

    surface = workspace_surface_generation()
    expected = sha256_digest(canonical_json_bytes([surface.contract_mapping()]))
    assert software_engine._additional_surfaces(lambda _phase: (surface,), "primary", expected) == (
        surface,
    )
    replacement = workspace_surface_generation()
    with pytest.raises(FormatError, match="differ from"):
        software_engine._additional_surfaces(
            lambda _phase: (replacement,),
            "primary",
            "sha256:" + "0" * 64,
        )


def test_owned_process_and_phase_cleanup_cover_normal_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class Process:
        pid = 42

        def __init__(self, polls: list[int | None]) -> None:
            self.polls = polls
            self.terminated = 0
            self.killed = 0
            self.waited = 0

        def poll(self) -> int | None:
            return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

        def terminate(self) -> None:
            self.terminated += 1

        def kill(self) -> None:
            self.killed += 1

        def wait(self, timeout: int) -> None:
            del timeout
            self.waited += 1

    signals: list[tuple[int, int]] = []

    def record(pid: int, number: int) -> None:
        signals.append((pid, number))

    # The fake process carries a fixed pid; never signal a real POSIX process group.
    monkeypatch.setattr(os, "kill", record)
    finished = Process([0])
    software_engine._OwnedSoftwareProcess(cast("Any", finished)).close()
    assert finished.terminated == 0 and signals == []
    running = Process([None, None])
    software_engine._OwnedSoftwareProcess(cast("Any", running)).close()
    if os.name == "nt":
        assert running.terminated == 1 and signals == []
    else:
        assert running.terminated == 0 and signals == [(-42, signal.SIGTERM)]
    assert running.waited == 1 and running.killed == 0

    class Unsignalable(Process):
        def terminate(self) -> None:
            raise OSError

    def refuse(_pid: int, _number: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", refuse)
    stubborn = Unsignalable([None])
    software_engine._OwnedSoftwareProcess(cast("Any", stubborn)).close()
    assert stubborn.killed == 1 and stubborn.waited == 1

    target = SimpleNamespace(close=lambda: None)
    recording = SimpleNamespace(close=lambda: None)
    software_engine._SoftwarePhaseCloser(cast("Any", target), cast("Any", recording)).close()

    def fail() -> None:
        raise RuntimeError

    with pytest.raises(FormatError, match="could not be closed"):
        software_engine._SoftwarePhaseCloser(
            cast("Any", SimpleNamespace(close=fail)),
            cast("Any", SimpleNamespace(close=fail)),
        ).close()

    executable = tmp_path / "owned-app.bin"
    executable.write_bytes(b"fixture")
    spec = SoftwareLaunchSpec(executable)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(FormatError, match="could not be launched"):
        software_engine._launch(spec, tmp_path)

    exited = Process([1])
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: exited)
    with pytest.raises(FormatError, match="exited before identity"):
        software_engine._launch(spec, tmp_path)


def test_melra_software_surface_binds_only_a_live_measured_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = software_engine.melra_software_computer_surface_factory(
        node_executable=tmp_path / "node",
        cli_entrypoint=tmp_path / "melra",
        policy_factory=lambda path: path / "policy.json",
    )
    without_window = SimpleNamespace(
        window_id=None,
        window_handle_digest=None,
    )
    with pytest.raises(FormatError, match="measured target-owned window"):
        factory(cast("Any", without_window), "sha256:" + "1" * 64)

    observed: list[tuple[int, int]] = []
    attestation = SimpleNamespace(
        window_id=7,
        window_handle_digest="sha256:" + "2" * 64,
        pid=8,
        assert_still_live=lambda: observed.append((8, 7)),
    )
    expected = object()

    def generate(**options: Any) -> object:
        observed.append((options["pid"], options["window_id"]))
        return expected

    monkeypatch.setattr(software_engine, "melra_computer_surface_generation", generate)
    assert factory(cast("Any", attestation), "sha256:" + "3" * 64) is expected
    assert observed == [(8, 7), (8, 7)]
