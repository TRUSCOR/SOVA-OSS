# SPDX-License-Identifier: Apache-2.0
"""Trust-boundary acceptance tests for the concrete executor engine."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.community.executor_engine as engine_module
from sova.capsule import lint_capsule
from sova.community.executor_capsule_reproduction import (
    build_executor_capsule_reproduction_document,
)
from sova.community.executor_chamber import ChamberObservation, ExecutorChamberGrant
from sova.community.executor_engine import (
    EnginePhaseGeneration,
    EngineSurfaceGeneration,
    ExecutorEngineRuntime,
    run_executor_engine_document,
)
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.runtime.environment_builder import BackendAdmission, TargetEnvironmentAdmission
from sova.runtime.managed_surfaces import EvidenceSatisfactionPolicy
from sova.safety import ControlProof, ControlProofMethod
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sova.runtime.target_environment import SessionEnvelope, TargetInstance
    from sova.safety import ActionIntent, ApprovalBatchChallenge

_AUTHORITY_TARGET = "sova:sandbox:owned-engine-fixture"
_SET_BINDING = "binding:state-backend:fixture-set:0.1"
_CODEC_ID = "fixture-codec/0.1.0"


class _BindError(RuntimeError):
    pass


class _CloseError(RuntimeError):
    pass


class _SecretError(RuntimeError):
    pass


def _digest(value: str | bytes) -> str:
    return sha256_digest(value.encode("utf-8") if isinstance(value, str) else value)


def _set_capability(version: str = "0.1") -> Capability:
    return Capability(
        name="fixture.set",
        version=version,
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=("state-change",),
    )


def _audit_capability() -> Capability:
    return Capability(
        name="fixture.inspect",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("audit-state",),
    )


@dataclass(slots=True)
class _PhaseState:
    value: str = "clean"


class _StateExecutor:
    def __init__(
        self,
        state: _PhaseState,
        evidence: dict[str, bytes],
        capability: Capability,
        *,
        name: str = "fixture-state-executor",
    ) -> None:
        self.state = state
        self.evidence = evidence
        self.capability = capability
        self._name = name
        self.requests: list[ActionRequest] = []

    @property
    def name(self) -> str:
        return self._name

    def capabilities(self) -> tuple[Capability, ...]:
        return (self.capability,)

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, SideEffect.MUTATE, {})
        value = request.inputs.get("value")
        if not isinstance(value, str):
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.MUTATE,
                {},
                error_code="FIXTURE-INPUT",
            )
        self.requests.append(request)
        self.state.value = value
        payload = canonical_json_bytes({"state": value})
        digest = sha256_digest(payload)
        self.evidence[digest] = payload
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {"stateDigest": digest},
            (EvidenceReference("state-change", "application/json", digest, len(payload)),),
            verification="fixture-provider-observation",
        )


class _AuditExecutor:
    name = "fixture-audit-executor"

    def __init__(self, evidence: dict[str, bytes]) -> None:
        self.evidence = evidence

    def capabilities(self) -> tuple[Capability, ...]:
        return (_audit_capability(),)

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        status = OutcomeStatus.CANCELLED if cancellation.cancelled else OutcomeStatus.SUCCEEDED
        payload = canonical_json_bytes({"ready": True})
        digest = sha256_digest(payload)
        self.evidence[digest] = payload
        return ActionOutcome(
            request.id,
            status,
            SideEffect.READ,
            {"ready": True},
            (EvidenceReference("audit-state", "application/json", digest, len(payload)),),
        )


class _FixtureCodec:
    def __init__(self, codec_id: str = _CODEC_ID) -> None:
        self.codec_id = codec_id

    def decode(
        self,
        value: Mapping[str, Any],
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        if set(value) != {"value"} or not isinstance(value.get("value"), str):
            raise FormatError("FIXTURE-CODEC", "fixture codec requires one string value")
        return ActionRequest(
            request_id,
            "fixture.set",
            {"value": value["value"]},
            min(timeout_seconds, 1.0),
        )


class _SurfaceHarness:
    def __init__(
        self,
        *,
        drift_reproduction: bool = False,
        reuse_executors: bool = False,
        fail_bind_sensor: str | None = None,
        fail_close_sensor: str | None = None,
    ) -> None:
        self.drift_reproduction = drift_reproduction
        self.reuse_executors = reuse_executors
        self.fail_bind_sensor = fail_bind_sensor
        self.fail_close_sensor = fail_close_sensor
        self.evidence: dict[str, bytes] = {}
        self.calls: list[str] = []
        self.closed: list[tuple[str, str]] = []
        self.bound: list[tuple[str, str, str, Path]] = []
        self.executors: dict[str, tuple[_StateExecutor, _AuditExecutor]] = {}
        self._reused: tuple[_StateExecutor, _AuditExecutor] | None = None

    def __call__(self, phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        self.calls.append(phase)
        state = _PhaseState()
        version = "0.2" if phase == "reproduction" and self.drift_reproduction else "0.1"
        name = (
            "fixture-state-executor-drifted"
            if phase == "reproduction" and self.drift_reproduction
            else "fixture-state-executor"
        )
        if self.reuse_executors and self._reused is not None:
            state_executor, audit_executor = self._reused
        else:
            state_executor = _StateExecutor(
                state,
                self.evidence,
                _set_capability(version),
                name=name,
            )
            audit_executor = _AuditExecutor(self.evidence)
            if self.reuse_executors:
                self._reused = (state_executor, audit_executor)
        self.executors[phase] = (state_executor, audit_executor)

        def bind(
            sensor: str,
            session: SessionEnvelope,
            target: TargetInstance,
            workspace: Path,
        ) -> None:
            self.bound.append((phase, sensor, session.digest, workspace))
            assert target.ready
            if sensor == self.fail_bind_sensor:
                raise _BindError

        def close(sensor: str) -> None:
            self.closed.append((phase, sensor))
            if sensor == self.fail_close_sensor:
                raise _CloseError

        state_surface = EngineSurfaceGeneration(
            "state_sensor",
            BackendAdmission(
                "state-backend",
                state_executor,
                "verifier:state",
                ("fixture-state",),
                {"fixture.set": ("fixture-state",)},
            ),
            lambda: {"state": state_executor.state.value},
            (
                EvidenceSatisfactionPolicy(
                    f"fixture.set/{version}",
                    ("state-change",),
                    required_projection_paths=(("state_sensor", "state"),),
                    required_output_keys=("stateDigest",),
                    require_observation_change=True,
                ),
            ),
            bind=lambda session, target, workspace: bind(
                "state_sensor", session, target, workspace
            ),
            close=lambda: close("state_sensor"),
        )
        audit_surface = EngineSurfaceGeneration(
            "audit_sensor",
            BackendAdmission(
                "audit-backend",
                audit_executor,
                "verifier:audit",
                ("fixture-audit",),
                {},
            ),
            lambda: {"ready": True},
            (
                EvidenceSatisfactionPolicy(
                    "fixture.inspect/0.1",
                    ("audit-state",),
                    required_projection_paths=(("audit_sensor", "ready"),),
                    required_output_keys=("ready",),
                ),
            ),
            bind=lambda session, target, workspace: bind(
                "audit_sensor", session, target, workspace
            ),
            close=lambda: close("audit_sensor"),
        )
        return state_surface, audit_surface


def _target_admission() -> TargetEnvironmentAdmission:
    return TargetEnvironmentAdmission(
        instance_id="target:owned-engine-fixture",
        target_manifest_digest=_digest("target-manifest"),
        environment_digest=_digest("environment"),
        containment_digest=_digest("containment"),
        identity_digest=_digest("identity"),
        clock_domain="clock:engine-fixture",
    )


def _runtime(  # noqa: PLR0913 - fixture exposes independent runtime failure boundaries
    tmp_path: Path,
    harness: _SurfaceHarness,
    *,
    workspace_seed: Path | None = None,
    codec_factories: Mapping[str, Any] | None = None,
    workspace_parent: Path | None = None,
    secret_provider_factory: Any = None,
) -> ExecutorEngineRuntime:
    return ExecutorEngineRuntime(
        target_admission=_target_admission(),
        surface_factory=harness,
        codec_factories=(
            {_CODEC_ID: lambda _observation: _FixtureCodec()}
            if codec_factories is None
            else codec_factories
        ),
        workspace_parent=tmp_path if workspace_parent is None else workspace_parent,
        workspace_seed=workspace_seed,
        evidence_reader=lambda reference: harness.evidence[reference.digest],
        secret_provider_factory=secret_provider_factory,
    )


def test_phase_owned_runtime_uses_fresh_measured_target_and_workspace(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "fixture.txt").write_text("owned", encoding="utf-8")
    parent = tmp_path / "workspaces"
    parent.mkdir()
    harness = _SurfaceHarness()
    phase_closed: list[str] = []

    def phase_factory(phase: str, workspace: Path) -> EnginePhaseGeneration:
        assert (workspace / "fixture.txt").read_text(encoding="utf-8") == "owned"
        ordinal = 101 if phase == "primary" else 202
        admission = replace(
            _target_admission(),
            instance_id=f"target:owned-engine-fixture:{phase}",
            process_id=ordinal,
            process_start_digest=_digest(f"process:{phase}"),
        )
        return EnginePhaseGeneration(
            admission,
            harness(phase),
            _digest("stable-software-contract"),
            lambda: phase_closed.append(phase),
        )

    runtime = ExecutorEngineRuntime(
        codec_factories={_CODEC_ID: lambda _observation: _FixtureCodec()},
        phase_surface_factory=phase_factory,
        workspace_parent=parent,
        workspace_seed=seed,
        evidence_reader=lambda reference: harness.evidence[reference.digest],
    )
    primary = runtime.environment_factory("primary")
    assert primary.target.process_id == 101
    primary_workspace = primary.workspace
    primary.close()
    reproduction = runtime.environment_factory("reproduction")
    assert reproduction.target.process_id == 202
    reproduction_workspace = reproduction.workspace
    reproduction.close()
    assert phase_closed == ["primary", "reproduction"]
    assert not primary_workspace.exists()
    assert not reproduction_workspace.exists()


def test_phase_owned_runtime_rejects_target_contract_substitution(tmp_path: Path) -> None:
    harness = _SurfaceHarness()
    closed: list[str] = []

    def phase_factory(phase: str, _workspace: Path) -> EnginePhaseGeneration:
        return EnginePhaseGeneration(
            _target_admission(),
            harness(phase),
            _digest(phase),
            lambda: closed.append(phase),
        )

    runtime = ExecutorEngineRuntime(
        codec_factories={_CODEC_ID: lambda _observation: _FixtureCodec()},
        phase_surface_factory=phase_factory,
        workspace_parent=tmp_path,
    )
    primary = runtime.environment_factory("primary")
    primary.close()
    with pytest.raises(FormatError, match="target contract differs"):
        runtime.environment_factory("reproduction")
    assert closed == ["primary", "reproduction"]


def _scripted(identifier: str, value: str) -> dict[str, Any]:
    return {
        "adapter": "scripted",
        "modelId": f"fixture-{identifier}",
        "turns": [
            {
                "expectedContains": "sova.executor-chamber-planner/0.1.0",
                "responseText": "",
                "structured": {
                    "status": "continue",
                    "message": "bounded fixture action",
                    "actions": [{"grantId": "set-state", "arguments": {"value": value}}],
                    "coverage": ["fixture-state"],
                    "reason": "exercise the exact reviewed mutation",
                },
                "tokenCount": 1,
            }
        ],
    }


def _document(*, codec_id: str = _CODEC_ID) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": _AUTHORITY_TARGET,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-engine-fixture",
            "title": "Owned heterogeneous engine fixture",
            "objective": "Find and reproduce the declared observable state.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 2,
            "maxDurationSeconds": 30,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 2,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 5,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "set-state",
                "bindingId": _SET_BINDING,
                "codecId": codec_id,
                "description": "Set one harmless in-memory fixture value.",
                "argumentSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value"],
                    "properties": {"value": {"type": "string", "maxLength": 64}},
                },
            }
        ],
        "participants": [
            {
                "id": "agent-a",
                "objective": "Exercise only the exact state grant.",
                "allowedGrants": ["set-state"],
                "model": _scripted("agent-a", "scanned"),
            },
            {
                "id": "agent-b",
                "objective": "Confirm only the exact state grant.",
                "allowedGrants": ["set-state"],
                "model": _scripted("agent-b", "vulnerable-observed"),
            },
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["state_sensor", "state"],
            "contains": "vulnerable",
        },
    }


def _proof() -> ControlProof:
    now = datetime.now(UTC)
    challenge = "sova-control:owned-engine-fixture"
    return ControlProof(
        ControlProofMethod.SANDBOX,
        _AUTHORITY_TARGET,
        challenge,
        {"challenge": challenge, "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.executor-engine-test/0.1",
    )


def _approve(
    challenge: ApprovalBatchChallenge,
    intents: tuple[ActionIntent, ...],
) -> str:
    assert tuple(item.intent_digest for item in challenge.items) == tuple(
        item.digest for item in intents
    )
    return challenge.exact_phrase


def test_surface_contracts_are_exact_and_heterogeneous(tmp_path: Path) -> None:
    harness = _SurfaceHarness()
    runtime = _runtime(tmp_path, harness)
    environment = runtime.environment_factory("primary")
    try:
        assert set(environment.bindings) == {
            "binding:audit-backend:fixture-inspect:0.1",
            _SET_BINDING,
        }
        state_surface, audit_surface = harness("inspection-only")
        state_contract = state_surface.contract_mapping()
        audit_contract = audit_surface.contract_mapping()
        assert state_contract["executorName"] == "fixture-state-executor"
        assert state_contract["capabilities"] != audit_contract["capabilities"]
        assert state_contract["evidencePolicies"][0]["requireObservationChange"] is True
        assert audit_contract["evidencePolicies"][0]["independence"] == "agent-independent"
        state_surface.close()
        audit_surface.close()
    finally:
        environment.close()

    state_surface, _audit_surface = harness("malformed-policy")
    with pytest.raises(FormatError, match="exact immutable"):
        EngineSurfaceGeneration(
            state_surface.sensor_name,
            state_surface.backend,
            state_surface.observe,
            [state_surface.evidence_policies[0]],  # type: ignore[arg-type]
        )
    with pytest.raises(FormatError, match="every surface capability"):
        EngineSurfaceGeneration(
            state_surface.sensor_name,
            state_surface.backend,
            state_surface.observe,
            (),
        )
    state_surface.close()


def test_primary_and_reproduction_use_fresh_executor_and_session_identities(
    tmp_path: Path,
) -> None:
    harness = _SurfaceHarness()
    runtime = _runtime(tmp_path, harness)
    primary = runtime.environment_factory("primary")
    primary_session = primary.session.digest
    primary_ids = {id(item) for item in harness.executors["primary"]}
    primary.close()

    reproduction = runtime.environment_factory("reproduction")
    reproduction_session = reproduction.session.digest
    reproduction_ids = {id(item) for item in harness.executors["reproduction"]}
    reproduction.close()

    assert primary_session != reproduction_session
    assert primary_ids.isdisjoint(reproduction_ids)
    assert harness.closed.count(("primary", "state_sensor")) == 1
    assert harness.closed.count(("reproduction", "audit_sensor")) == 1


def test_executor_reuse_and_reproduction_contract_drift_are_rejected_and_closed(
    tmp_path: Path,
) -> None:
    reused = _SurfaceHarness(reuse_executors=True)
    reused_runtime = _runtime(tmp_path, reused)
    reused_runtime.environment_factory("primary").close()
    with pytest.raises(FormatError, match="fresh"):
        reused_runtime.environment_factory("reproduction")
    assert ("reproduction", "state_sensor") in reused.closed
    assert ("reproduction", "audit_sensor") in reused.closed

    drifted = _SurfaceHarness(drift_reproduction=True)
    drifted_runtime = _runtime(tmp_path, drifted)
    drifted_runtime.environment_factory("primary").close()
    with pytest.raises(FormatError, match="contracts differ"):
        drifted_runtime.environment_factory("reproduction")
    assert ("reproduction", "state_sensor") in drifted.closed
    assert ("reproduction", "audit_sensor") in drifted.closed


def test_bind_and_pre_environment_failures_cleanup_every_returned_surface(
    tmp_path: Path,
) -> None:
    bind_failure = _SurfaceHarness(fail_bind_sensor="audit_sensor")
    runtime = _runtime(tmp_path, bind_failure)
    with pytest.raises(_BindError):
        runtime.environment_factory("primary")
    assert set(bind_failure.closed) == {
        ("primary", "state_sensor"),
        ("primary", "audit_sensor"),
    }
    assert bind_failure.bound
    assert not bind_failure.bound[0][3].exists()

    secret_failure = _SurfaceHarness()

    def fail_secret(_phase: str) -> None:
        raise _SecretError

    secret_runtime = _runtime(
        tmp_path,
        secret_failure,
        secret_provider_factory=fail_secret,
    )
    with pytest.raises(_SecretError):
        secret_runtime.environment_factory("primary")
    assert set(secret_failure.closed) == {
        ("primary", "state_sensor"),
        ("primary", "audit_sensor"),
    }

    missing_parent = tmp_path / "absent"
    build_failure = _SurfaceHarness()
    build_runtime = _runtime(
        tmp_path,
        build_failure,
        workspace_parent=missing_parent,
    )
    with pytest.raises(FormatError, match="workspace parent"):
        build_runtime.environment_factory("primary")
    assert set(build_failure.closed) == {
        ("primary", "state_sensor"),
        ("primary", "audit_sensor"),
    }


def test_cleanup_attempts_every_surface_even_when_one_close_fails(tmp_path: Path) -> None:
    harness = _SurfaceHarness(fail_close_sensor="state_sensor")
    runtime = _runtime(tmp_path, harness)
    environment = runtime.environment_factory("primary")
    workspace = environment.workspace
    with pytest.raises(FormatError, match="cleanup"):
        environment.close()
    assert set(harness.closed) == {
        ("primary", "state_sensor"),
        ("primary", "audit_sensor"),
    }
    assert not workspace.exists()


def test_codec_registry_rejects_unknown_malformed_and_substituted_codecs(
    tmp_path: Path,
) -> None:
    harness = _SurfaceHarness()
    runtime = _runtime(
        tmp_path,
        harness,
        codec_factories={
            "z-codec/0.1": lambda _observation: _FixtureCodec("z-codec/0.1"),
            _CODEC_ID: lambda _observation: _FixtureCodec(),
        },
    )
    assert runtime.codec_ids == (_CODEC_ID, "z-codec/0.1")
    environment = runtime.environment_factory("primary")
    try:
        observation = ChamberObservation.capture(
            environment.session,
            environment.target,
            0,
            environment.observe(),
        )
        grant = ExecutorChamberGrant(
            "set-state",
            _SET_BINDING,
            _CODEC_ID,
            "Set fixture state.",
            {"type": "object"},
        )
        assert runtime.codec_resolver(grant, observation).codec_id == _CODEC_ID
        unknown = ExecutorChamberGrant(
            "unknown",
            _SET_BINDING,
            "unknown-codec/0.1",
            "Unknown codec.",
            {"type": "object"},
        )
        with pytest.raises(FormatError, match="unregistered"):
            runtime.codec_resolver(unknown, observation)
    finally:
        environment.close()

    substituted = _runtime(
        tmp_path,
        _SurfaceHarness(),
        codec_factories={_CODEC_ID: lambda _observation: _FixtureCodec("other-codec/0.1")},
    )
    substituted_environment = substituted.environment_factory("primary")
    try:
        observation = ChamberObservation.capture(
            substituted_environment.session,
            substituted_environment.target,
            0,
            substituted_environment.observe(),
        )
        with pytest.raises(FormatError, match="another codec"):
            substituted.codec_resolver(grant, observation)
    finally:
        substituted_environment.close()

    malformed = _runtime(
        tmp_path,
        _SurfaceHarness(),
        codec_factories={_CODEC_ID: lambda _observation: object()},
    )
    malformed_environment = malformed.environment_factory("primary")
    try:
        observation = ChamberObservation.capture(
            malformed_environment.session,
            malformed_environment.target,
            0,
            malformed_environment.observe(),
        )
        with pytest.raises(FormatError, match="usable"):
            malformed.codec_resolver(grant, observation)
    finally:
        malformed_environment.close()


def test_seed_capture_and_materialization_are_bounded_verified_and_secret_free(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed"
    (seed / "docs").mkdir(parents=True)
    (seed / "empty").mkdir()
    (seed / "docs" / "fixture.txt").write_text("harmless fixture", encoding="utf-8")
    harness = _SurfaceHarness()
    runtime = _runtime(tmp_path, harness, workspace_seed=seed)
    assert runtime.seed_digest.startswith("sha256:")
    environment = runtime.environment_factory("primary")
    workspace = environment.workspace
    try:
        assert (workspace / "docs" / "fixture.txt").read_text(encoding="utf-8") == (
            "harmless fixture"
        )
        assert (workspace / "empty").is_dir()
    finally:
        environment.close()
    assert not workspace.exists()

    secret_seed = tmp_path / "secret-seed"
    secret_seed.mkdir()
    (secret_seed / "fixture.txt").write_text(
        "Bearer synthetic-credential-value",
        encoding="utf-8",
    )
    with pytest.raises(FormatError, match="credential-shaped"):
        _runtime(tmp_path, _SurfaceHarness(), workspace_seed=secret_seed)

    reserved_seed = tmp_path / "reserved-seed"
    (reserved_seed / ".cache").mkdir(parents=True)
    (reserved_seed / ".cache" / "runtime.txt").write_text("forbidden", encoding="utf-8")
    with pytest.raises(FormatError, match="runtime directories"):
        _runtime(tmp_path, _SurfaceHarness(), workspace_seed=reserved_seed)

    profile_seed = tmp_path / "profile-seed"
    (profile_seed / "profiles").mkdir(parents=True)
    (profile_seed / "profiles" / "session.txt").write_text("forbidden", encoding="utf-8")
    with pytest.raises(FormatError, match="secret and profile"):
        _runtime(tmp_path, _SurfaceHarness(), workspace_seed=profile_seed)


def test_seed_link_nonempty_destination_and_descriptor_drift_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    fixture = seed / "fixture.txt"
    fixture.write_text("stable", encoding="utf-8")
    snapshot = engine_module._capture_seed(seed)
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "raced.txt").write_text("raced", encoding="utf-8")
    with pytest.raises(FormatError, match="empty"):
        snapshot.materialize(nonempty)

    original_fstat = os.fstat
    calls = 0

    def drifting_fstat(descriptor: int) -> Any:
        nonlocal calls
        value = original_fstat(descriptor)
        calls += 1
        if calls != 2:
            return value
        return SimpleNamespace(
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_mode=value.st_mode,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    with pytest.raises(FormatError, match="changed"):
        engine_module._capture_seed(seed)
    monkeypatch.setattr(os, "fstat", original_fstat)

    linked_seed = tmp_path / "linked-seed"
    linked_seed.mkdir()
    linked = linked_seed / "linked.txt"
    linked.write_text("synthetic link fixture", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def pretend_link(path: Path) -> bool:
        return path == linked or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", pretend_link)
    with pytest.raises(FormatError, match="links"):
        engine_module._capture_seed(linked_seed)


def test_seed_byte_and_file_limits_are_checked_before_unbounded_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = tmp_path / "bounded-seed"
    seed.mkdir()
    (seed / "one.txt").write_text("12345", encoding="utf-8")
    monkeypatch.setattr(engine_module, "_MAX_SEED_BYTES", 4)
    with pytest.raises(FormatError, match="remaining byte budget"):
        engine_module._capture_seed(seed)

    monkeypatch.setattr(engine_module, "_MAX_SEED_BYTES", 1024)
    monkeypatch.setattr(engine_module, "_MAX_SEED_FILES", 0)
    with pytest.raises(FormatError, match="256 files"):
        engine_module._capture_seed(seed)


def test_complete_document_and_unknown_codec_fail_before_surface_factory(
    tmp_path: Path,
) -> None:
    invalid_harness = _SurfaceHarness()
    invalid_runtime = _runtime(tmp_path, invalid_harness)
    invalid = _document(codec_id="unknown-codec/0.1")
    invalid["unexpected"] = True
    with pytest.raises(FormatError, match="fields are invalid"):
        run_executor_engine_document(
            invalid,
            tmp_path / "invalid-document",
            runtime=invalid_runtime,
            proof=_proof(),
            approval_prompt=_approve,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )
    assert invalid_harness.calls == []

    unknown_harness = _SurfaceHarness()
    unknown_runtime = _runtime(tmp_path, unknown_harness)
    with pytest.raises(FormatError, match="unavailable runtime codec"):
        run_executor_engine_document(
            _document(codec_id="unknown-codec/0.1"),
            tmp_path / "unknown-codec",
            runtime=unknown_runtime,
            proof=_proof(),
            approval_prompt=_approve,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )
    assert unknown_harness.calls == []


def test_two_agent_engine_pass_has_fresh_reproduction_signed_traces_and_capsule(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "success-seed"
    seed.mkdir()
    (seed / "fixture.txt").write_text("harmless owned fixture", encoding="utf-8")
    harness = _SurfaceHarness()
    runtime = _runtime(tmp_path, harness, workspace_seed=seed)
    artifacts = run_executor_engine_document(
        _document(),
        tmp_path / "engine-pass",
        runtime=runtime,
        proof=_proof(),
        approval_prompt=_approve,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        capsule_attachment_provider=lambda: {
            "visual-replay-01.webm": b"\x1a\x45\xdf\xa3fixture-video",
            "replay-cues.json": canonical_json_bytes(
                {
                    "artifactType": "sova.replay-cues",
                    "schemaVersion": "0.1.0",
                    "cues": [{"eventKind": "oracle.completed", "offsetSeconds": "1.0"}],
                }
            ),
        },
    )

    assert artifacts.status == "pass"
    assert artifacts.reproduction_trace is not None
    assert artifacts.capsule is not None
    assert harness.calls == ["primary", "reproduction"]
    primary_ids = {id(item) for item in harness.executors["primary"]}
    reproduction_ids = {id(item) for item in harness.executors["reproduction"]}
    assert primary_ids.isdisjoint(reproduction_ids)
    sessions = {
        session_digest
        for _phase, sensor, session_digest, _workspace in harness.bound
        if sensor == "state_sensor"
    }
    assert len(sessions) == 2
    assert set(harness.closed) == {
        ("primary", "state_sensor"),
        ("primary", "audit_sensor"),
        ("reproduction", "state_sensor"),
        ("reproduction", "audit_sensor"),
    }
    assert all(
        TraceReader(trace).verify(require_signature=True).signature_valid
        for trace in (artifacts.trace, artifacts.reproduction_trace)
    )
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "trace"]) == 2
    assert len([item for item in descriptors if item.role == "scenario"]) == 1
    assert len([item for item in descriptors if item.role == "visual-replay"]) == 1
    assert len([item for item in descriptors if item.role == "replay-cues"]) == 1
    assert not {
        "SOVA-LINT-NO-SCENARIO",
        "SOVA-LINT-UNSUPPORTED-REQUIRED-FEATURE",
    } & {item.code for item in lint_capsule(artifacts.capsule)}
    capsule_reader = PackageReader(artifacts.capsule)
    attachment_documents = [
        strict_json_loads(capsule_reader.read_object(item))
        for item in descriptors
        if item.role == "attachment"
    ]
    reproduction_plan = next(
        item
        for item in attachment_documents
        if isinstance(item, dict)
        and item.get("artifactType") == "sova.executor-chamber-reproduction-plan"
    )
    assert isinstance(reproduction_plan, dict)
    assert reproduction_plan["freshAuthorizationRequired"] is True
    assert reproduction_plan["credentialMaterialIncluded"] is False
    assert [item["plannerArguments"] for item in reproduction_plan["actions"]] == [
        {"value": "scanned"},
        {"value": "vulnerable-observed"},
    ]
    portable_reproduction = build_executor_capsule_reproduction_document(artifacts.capsule)
    assert portable_reproduction["authorization"] == {
        "authorityTarget": _AUTHORITY_TARGET,
        "providerCalls": False,
        "offensive": False,
    }
    assert portable_reproduction["oracle"] == _document()["oracle"]
    assert [
        turn["structured"]["actions"]
        for participant in portable_reproduction["participants"]
        for turn in participant["model"]["turns"]
    ] == [
        [{"grantId": "set-state", "arguments": {"value": "scanned"}}],
        [
            {
                "grantId": "set-state",
                "arguments": {"value": "vulnerable-observed"},
            }
        ],
    ]
    requested = [
        event
        for event in TraceReader(artifacts.trace).events()
        if event["kind"] == "tool.requested"
    ]
    assert requested
    assert all(event["payload"]["argumentsCaptured"] is True for event in requested)
    assert [event["payload"]["plannerArguments"] for event in requested] == [
        {"value": "scanned"},
        {"value": "vulnerable-observed"},
    ]
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["primary"]["independentlyConfirmed"] is True
    assert report["reproduction"]["equivalent"] is True
    assert report["evidence"]["capsuleDigest"] == sha256_digest(artifacts.capsule.read_bytes())
    assert len(harness.executors["primary"][0].requests) == 2
    assert len(harness.executors["reproduction"][0].requests) == 2


def test_surface_and_phase_generation_contracts_reject_malformed_values() -> None:
    surface = _SurfaceHarness()("primary")[0]
    with pytest.raises(FormatError, match="surface generation is malformed"):
        replace(surface, sensor_name="bad sensor name")
    with pytest.raises(FormatError, match="exact immutable policy"):
        replace(surface, evidence_policies=cast("Any", []))
    with pytest.raises(FormatError, match="one exact independent evidence"):
        replace(surface, evidence_policies=())

    surface.backend.executor._name = ""  # type: ignore[attr-defined]
    with pytest.raises(FormatError, match="executor name is invalid"):
        surface.contract_mapping()

    fresh = _SurfaceHarness()("primary")
    phase = EnginePhaseGeneration(
        _target_admission(), fresh, _digest("stable-contract"), lambda: None
    )
    with pytest.raises(FormatError, match="phase target, surfaces"):
        replace(phase, stable_target_contract_digest="invalid")
    with pytest.raises(FormatError, match="phase target, surfaces"):
        replace(phase, surfaces=())


def _shifted_ctime(value: os.stat_result, shift: int) -> Any:
    return SimpleNamespace(
        st_dev=value.st_dev,
        st_ino=value.st_ino,
        st_mode=value.st_mode,
        st_size=value.st_size,
        st_mtime_ns=value.st_mtime_ns,
        st_ctime_ns=value.st_ctime_ns + shift,
    )


def test_seed_file_accepts_path_and_handle_ctime_that_disagree_consistently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows with Python 3.14 reports st_ctime differently by path and by handle."""
    fixture = tmp_path / "fixture.txt"
    fixture.write_text("stable", encoding="utf-8")
    original_fstat = os.fstat
    monkeypatch.setattr(
        os, "fstat", lambda descriptor: _shifted_ctime(original_fstat(descriptor), 7)
    )

    assert engine_module._read_seed_file(fixture, max_bytes=100) == b"stable"


def test_seed_file_refuses_ctime_change_between_like_readings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "fixture.txt"
    fixture.write_text("stable", encoding="utf-8")

    original_fstat = os.fstat
    handle_calls = 0

    def drifting_fstat(descriptor: int) -> Any:
        nonlocal handle_calls
        handle_calls += 1
        value = original_fstat(descriptor)
        return _shifted_ctime(value, 1) if handle_calls == 2 else value

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    with pytest.raises(FormatError, match="changed while it was admitted"):
        engine_module._read_seed_file(fixture, max_bytes=100)
    monkeypatch.setattr(os, "fstat", original_fstat)

    original_stat = Path.stat
    path_calls = 0

    def drifting_stat(self: Path, *, follow_symlinks: bool = True) -> Any:
        nonlocal path_calls
        value = original_stat(self, follow_symlinks=follow_symlinks)
        if self != fixture:
            return value
        path_calls += 1
        return _shifted_ctime(value, 1) if path_calls == 2 else value

    monkeypatch.setattr(Path, "stat", drifting_stat)
    with pytest.raises(FormatError, match="changed while it was admitted"):
        engine_module._read_seed_file(fixture, max_bytes=100)


def test_seed_capture_rejects_missing_binary_nonregular_and_directory_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="real existing directory"):
        engine_module._capture_seed(tmp_path / "missing")
    with pytest.raises(FormatError, match="non-regular entry"):
        engine_module._read_seed_file(tmp_path, max_bytes=10)
    with pytest.raises(FormatError, match="could not be inspected"):
        engine_module._read_seed_file(tmp_path / "missing.bin", max_bytes=10)

    binary = tmp_path / "binary"
    binary.mkdir()
    (binary / "fixture.bin").write_bytes(b"\xff\xfe")
    with pytest.raises(FormatError, match="bounded UTF-8"):
        engine_module._capture_seed(binary)

    directories = tmp_path / "directories"
    (directories / "one").mkdir(parents=True)
    monkeypatch.setattr(engine_module, "_MAX_SEED_DIRECTORIES", 0)
    with pytest.raises(FormatError, match="directory limit"):
        engine_module._capture_seed(directories)

    destination = tmp_path / "destination.txt"
    destination.write_text("not a directory", encoding="utf-8")
    snapshot = engine_module._SeedSnapshot.empty()
    with pytest.raises(FormatError, match="real disposable workspace"):
        snapshot.materialize(destination)


def test_seed_materialization_wraps_exclusive_file_creation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "fixture.txt").write_text("safe", encoding="utf-8")
    snapshot = engine_module._capture_seed(seed)
    destination = tmp_path / "destination"
    destination.mkdir()
    monkeypatch.setattr(os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    with pytest.raises(FormatError, match="created exclusively"):
        snapshot.materialize(destination)


def test_runtime_constructor_codec_and_cleanup_guards(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="target, surfaces, and codec"):
        ExecutorEngineRuntime(codec_factories={}, workspace_parent=tmp_path)
    with pytest.raises(FormatError, match="validator must be callable"):
        ExecutorEngineRuntime(
            target_admission=_target_admission(),
            surface_factory=_SurfaceHarness(),
            codec_factories={_CODEC_ID: lambda _observation: _FixtureCodec()},
            workspace_parent=tmp_path,
            control_proof_validator=cast("Any", object()),
        )

    runtime = _runtime(tmp_path, _SurfaceHarness())
    grant = ExecutorChamberGrant(
        identifier="grant:unknown",
        binding_id=_SET_BINDING,
        codec_id="unknown/0.1",
        description="Unknown codec fixture",
        argument_schema={},
    )
    with pytest.raises(FormatError, match="unregistered engine codec"):
        runtime.codec_resolver(grant, cast("Any", object()))

    surfaces = _SurfaceHarness()("primary")

    def fail_close() -> None:
        raise RuntimeError

    bad = replace(surfaces[0], close=fail_close)
    with pytest.raises(FormatError, match="could not be closed"):
        ExecutorEngineRuntime._close_surfaces((bad,))
    with pytest.raises(FormatError, match="phase-owned surfaces"):
        ExecutorEngineRuntime._close_phase_generation((bad,), fail_close)


def test_runtime_rejects_duplicate_surfaces_and_phase_reuse(tmp_path: Path) -> None:
    surfaces = _SurfaceHarness()("primary")
    duplicate_sensor = replace(surfaces[1], sensor_name=surfaces[0].sensor_name)
    runtime = _runtime(tmp_path, _SurfaceHarness())
    with pytest.raises(FormatError, match="identifiers must be unique"):
        runtime._record_surface_generation((surfaces[0], duplicate_sensor))
    with pytest.raises(FormatError, match="phase is unsupported"):
        runtime.environment_factory("unknown")

    environment = runtime.environment_factory("primary")
    try:
        with pytest.raises(FormatError, match="cannot be created twice"):
            runtime.environment_factory("primary")
    finally:
        environment.close()


def test_phase_runtime_rejects_unavailable_workspace_and_undeclared_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codecs = {_CODEC_ID: lambda _observation: _FixtureCodec()}
    missing_parent = tmp_path / "missing"
    runtime = ExecutorEngineRuntime(
        codec_factories=codecs,
        phase_surface_factory=lambda _phase, _workspace: cast("Any", object()),
        workspace_parent=missing_parent,
    )
    with pytest.raises(FormatError, match="parent is unavailable"):
        runtime.environment_factory("primary")

    parent_file = tmp_path / "parent.txt"
    parent_file.write_text("x", encoding="utf-8")
    runtime = ExecutorEngineRuntime(
        codec_factories=codecs,
        phase_surface_factory=lambda _phase, _workspace: cast("Any", object()),
        workspace_parent=parent_file,
    )
    with pytest.raises(FormatError, match="must be one existing directory"):
        runtime.environment_factory("primary")

    runtime = ExecutorEngineRuntime(
        codec_factories=codecs,
        phase_surface_factory=lambda _phase, _workspace: cast("Any", object()),
        workspace_parent=tmp_path,
    )
    with pytest.raises(FormatError, match="undeclared generation"):
        runtime.environment_factory("primary")

    runtime = ExecutorEngineRuntime(
        codec_factories=codecs,
        phase_surface_factory=lambda _phase, _workspace: (_ for _ in ()).throw(RuntimeError()),
        workspace_parent=tmp_path,
    )
    before = set(tmp_path.glob("sova-engine-phase-*"))
    with pytest.raises(RuntimeError):
        runtime.environment_factory("primary")
    assert set(tmp_path.glob("sova-engine-phase-*")) == before

    monkeypatch.setattr(
        tempfile,
        "mkdtemp",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )
    runtime = ExecutorEngineRuntime(
        codec_factories=codecs,
        phase_surface_factory=lambda _phase, _workspace: cast("Any", object()),
        workspace_parent=tmp_path,
    )
    with pytest.raises(FormatError, match="could not be created"):
        runtime.environment_factory("primary")


def test_static_runtime_rejects_non_tuple_surface_generations_and_cleans_them(
    tmp_path: Path,
) -> None:
    closed: list[str] = []
    surface = replace(_SurfaceHarness()("primary")[0], close=lambda: closed.append("closed"))
    runtime = ExecutorEngineRuntime(
        target_admission=_target_admission(),
        surface_factory=lambda _phase: cast("Any", [surface]),
        codec_factories={_CODEC_ID: lambda _observation: _FixtureCodec()},
        workspace_parent=tmp_path,
    )
    with pytest.raises(FormatError, match="non-empty exact generation tuple"):
        runtime.environment_factory("primary")
    assert closed == ["closed"]


def test_runtime_required_target_and_reproduction_attachment_collision_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="target admission is unavailable"):
        ExecutorEngineRuntime._required_target_admission(None)

    runtime = _runtime(tmp_path, _SurfaceHarness())

    def chamber(*_args: Any, **kwargs: Any) -> Any:
        provider = kwargs["capsule_attachment_provider"]
        provider()
        raise AssertionError

    monkeypatch.setattr(engine_module, "run_executor_chamber", chamber)
    with pytest.raises(FormatError, match="attempted to replace"):
        run_executor_engine_document(
            _document(),
            tmp_path / "collision",
            runtime=runtime,
            proof=_proof(),
            approval_prompt=_approve,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            capsule_attachment_provider=lambda: {
                "executor-chamber-reproduction-contract.json": b"replacement"
            },
        )
