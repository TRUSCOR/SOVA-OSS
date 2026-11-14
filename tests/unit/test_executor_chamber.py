# SPDX-License-Identifier: Apache-2.0
"""Adversarial acceptance tests for the unified executor chamber."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.community.executor_chamber as chamber_module
from sova.community.executor_chamber import (
    ChamberAuthorizationController,
    ChamberObservation,
    ChamberOracleResult,
    ChamberVerification,
    ExecutorChamberBudget,
    ExecutorChamberCase,
    ExecutorChamberEnvironment,
    ExecutorChamberGrant,
    ExecutorChamberParticipant,
    OracleAssessment,
    ProjectionFieldOracle,
    build_chamber_authorization_controller,
    run_executor_chamber,
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
from sova.models import ScriptedModel, ScriptedTurn
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
)
from sova.runtime.unified_execution import CapabilityBinding
from sova.safety import ControlProof, ControlProofMethod
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from sova.safety import ActionIntent, ApprovalBatchChallenge

_AUTHORITY_TARGET = "sova:sandbox:executor-chamber-fixture"
_SECRET = "fixture-secret-must-never-reach-models-or-artifacts"  # noqa: S105
_EVIDENCE_ROLE = "state-change"
_CLEANUP_ERROR = "fixture cleanup verification failed"
_AUTHORIZATION_FACTORY_ERROR = "fixture authorization factory failure"


def _digest(value: str | bytes) -> str:
    return sha256_digest(value.encode("utf-8") if isinstance(value, str) else value)


def _capability() -> Capability:
    return Capability(
        name="fixture.set",
        version="0.1",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=(_EVIDENCE_ROLE,),
    )


def _capability_contract_digest() -> str:
    capability = _capability()
    return _digest(
        canonical_json_bytes(
            {
                "name": capability.name,
                "version": capability.version,
                "sideEffect": capability.side_effect.value,
                "idempotent": capability.idempotent,
                "evidence": list(capability.evidence),
            }
        )
    )


class _SecretProvider:
    def resolve(self, reference: str) -> str:
        if reference != "sova-secret:fixture-login":
            raise AssertionError
        return _SECRET


class _FixtureExecutor:
    name = "fixture-session-bound-executor"

    def __init__(self, environment: _FixtureEnvironment, *, include_evidence: bool) -> None:
        self.environment = environment
        self.include_evidence = include_evidence
        self.requests: list[ActionRequest] = []
        self.contexts: list[ExecutionContext] = []

    def capabilities(self) -> tuple[Capability, ...]:
        return (_capability(),)

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                SideEffect.MUTATE,
                {},
            )
        authorization = context.authorization
        if authorization.get("decision") != "allowed" or not isinstance(
            authorization.get("executionGrant"), dict
        ):
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {},
                error_code="FIXTURE-AUTHORIZATION-DENIED",
            )
        value = request.inputs.get("value")
        if not isinstance(value, str):
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.MUTATE,
                {},
                error_code="FIXTURE-INVALID-VALUE",
            )
        self.requests.append(request)
        self.contexts.append(context)
        self.environment.state = value
        payload = canonical_json_bytes({"state": value})
        evidence = (
            (EvidenceReference(_EVIDENCE_ROLE, "application/json", _digest(payload), len(payload)),)
            if self.include_evidence
            else ()
        )
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {"stateDigest": _digest(payload)},
            evidence=evidence,
            verification="fixture-post-action-observation",
        )


class _FixtureEnvironment:
    def __init__(  # noqa: PLR0913 - fixture exposes each trust-bound variant explicitly
        self,
        phase: str,
        generation: int,
        *,
        verification_independence: str = "agent-independent",
        include_evidence: bool = True,
        satisfy_evidence: bool = True,
        fail_close: bool = False,
    ) -> None:
        environment_digest = _digest("fixture-environment")
        containment_digest = _digest("fixture-containment")
        self._target = TargetInstance(
            instance_id=f"fixture-target-{phase}-{generation}",
            target_manifest_digest=_digest("fixture-target-manifest"),
            environment_digest=environment_digest,
            containment_digest=containment_digest,
            generation=generation,
            clock_domain="fixture-clock",
        )
        capability_generation = CapabilityGeneration(
            _capability().identifier,
            1,
            _capability_contract_digest(),
        )
        backend = BackendGeneration(
            backend_id="fixture-backend",
            generation=1,
            target_instance_digest=self._target.digest,
            environment_digest=environment_digest,
            capabilities=(capability_generation,),
        )
        self._session = SessionEnvelope(
            session_id=f"fixture-session-{phase}-{generation}",
            run_id=f"fixture-run-{phase}-{generation}",
            generation=generation,
            target_instance_digest=self._target.digest,
            environment_digest=environment_digest,
            containment_digest=containment_digest,
            identity_digest=_digest(f"fixture-identity-{phase}-{generation}"),
            clock_domain="fixture-clock",
            backend_generations=(backend,),
            affinity_resources=("fixture-state",),
        )
        self._binding = CapabilityBinding(
            binding_id="fixture-binding",
            backend_id=backend.backend_id,
            backend_generation=backend.generation,
            backend_generation_digest=backend.digest,
            capability_name=_capability().name,
            capability_version=_capability().version,
            capability_generation=capability_generation.generation,
            capability_contract_digest=capability_generation.contract_digest,
            session_digest=self._session.digest,
            target_instance_digest=self._target.digest,
            environment_digest=environment_digest,
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            expected_evidence=(_EVIDENCE_ROLE,),
            verifier_id="fixture-verifier",
            affinity_resources=("fixture-state",),
            effect_resources=("fixture-state",),
        )
        self._workspace = Path.cwd()
        self.state = "clean"
        self.verification_independence = verification_independence
        self.satisfy_evidence = satisfy_evidence
        self.fail_close = fail_close
        self.closed = False
        self.close_calls = 0
        self.secret_provider = _SecretProvider()
        self.executor = _FixtureExecutor(self, include_evidence=include_evidence)

    @property
    def target(self) -> TargetInstance:
        return self._target

    @property
    def session(self) -> SessionEnvelope:
        return self._session

    @property
    def bindings(self) -> Mapping[str, CapabilityBinding]:
        return {self._binding.binding_id: self._binding}

    @property
    def executors(self) -> Mapping[str, _FixtureExecutor]:
        return {self._binding.backend_id: self.executor}

    @property
    def workspace(self) -> Path:
        return self._workspace

    def observe(self) -> Mapping[str, Any]:
        return {"state": self.state, "password": _SECRET}

    def verify(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        del request, before, after
        return ChamberVerification(
            verified=outcome.status == OutcomeStatus.SUCCEEDED,
            independence=self.verification_independence,
            method="fixture-independent-state-comparison",
            evidence_digests=tuple(item.digest for item in outcome.evidence),
            satisfied_evidence=(binding.expected_evidence if self.satisfy_evidence else ()),
        )

    def rotate_session_after_observation(self) -> None:
        self._session = replace(self._session, generation=self._session.generation + 1)

    def stale_session_binding(self) -> None:
        self._binding = replace(self._binding, session_digest=_digest("stale-session"))

    def stale_backend_binding(self) -> None:
        self._binding = replace(
            self._binding,
            backend_generation=self._binding.backend_generation + 1,
        )

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError(_CLEANUP_ERROR)
        self.closed = True


class _EnvironmentFactory:
    def __init__(
        self,
        *,
        verification_independence: str = "agent-independent",
        include_evidence: bool = True,
        satisfy_evidence: bool = True,
        fail_close_phase: str | None = None,
        mutators: Mapping[str, Callable[[_FixtureEnvironment], None]] | None = None,
    ) -> None:
        self.verification_independence = verification_independence
        self.include_evidence = include_evidence
        self.satisfy_evidence = satisfy_evidence
        self.fail_close_phase = fail_close_phase
        self.mutators = dict(mutators or {})
        self.environments: list[_FixtureEnvironment] = []

    def __call__(self, phase: str) -> _FixtureEnvironment:
        environment = _FixtureEnvironment(
            phase,
            len(self.environments) + 1,
            verification_independence=self.verification_independence,
            include_evidence=self.include_evidence,
            satisfy_evidence=self.satisfy_evidence,
            fail_close=phase == self.fail_close_phase,
        )
        mutator = self.mutators.get(phase)
        if mutator is not None:
            mutator(environment)
        self.environments.append(environment)
        return environment


class _FixtureCodec:
    codec_id = "fixture-codec"

    def __init__(
        self,
        *,
        substitute: str | None = None,
        hook: Callable[[], None] | None = None,
        observed_timeouts: list[float] | None = None,
    ) -> None:
        self.substitute = substitute
        self.hook = hook
        self.observed_timeouts = observed_timeouts

    def decode(
        self,
        value: Mapping[str, Any],
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> ActionRequest:
        if set(value) != {"value"} or not isinstance(value.get("value"), str):
            raise FormatError(
                "FIXTURE-CODEC-ARGUMENTS",
                "fixture codec requires exactly one string value",
            )
        if self.hook is not None:
            self.hook()
        if self.observed_timeouts is not None:
            self.observed_timeouts.append(timeout_seconds)
        decoded = self.substitute if self.substitute is not None else value["value"]
        return ActionRequest(
            request_id,
            "fixture.set",
            {"value": decoded},
            min(timeout_seconds, 1.0),
        )


@dataclass(frozen=True, slots=True)
class _ApprovalRecord:
    phase: str
    authority_id: str
    challenge_id: str
    challenge_intent_digests: tuple[str, ...]
    supplied_intent_digests: tuple[str, ...]


def _proof() -> ControlProof:
    now = datetime.now(UTC)
    challenge = "sova-control:executor-chamber-fixture"
    return ControlProof(
        ControlProofMethod.SANDBOX,
        _AUTHORITY_TARGET,
        challenge,
        {"challenge": challenge, "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.executor-chamber-test/0.1",
    )


def _case() -> ExecutorChamberCase:
    return ExecutorChamberCase(
        "fixture-case",
        "Owned two-agent fixture",
        "Exercise a typed mutation and reproduce independently verified state.",
        (
            ExecutorChamberParticipant("agent-a", "Explore the state.", ("set-state",)),
            ExecutorChamberParticipant("agent-b", "Confirm the finding.", ("set-state",)),
        ),
    )


def _grant() -> ExecutorChamberGrant:
    return ExecutorChamberGrant(
        "set-state",
        "fixture-binding",
        "fixture-codec",
        "Set the owned fixture state to one bounded string.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["value"],
            "properties": {"value": {"type": "string", "maxLength": 64}},
        },
    )


def _budget() -> ExecutorChamberBudget:
    return ExecutorChamberBudget(
        rounds=1,
        max_total_actions=2,
        max_duration_seconds=30,
        max_output_bytes=4096,
        max_mutations=2,
        max_processes=0,
        max_files=0,
        max_network_requests=0,
        action_timeout_seconds=5,
    )


def _proposal(grant_id: str, value: str) -> dict[str, Any]:
    return {
        "status": "continue",
        "message": "Bounded fixture action proposed.",
        "actions": [{"grantId": grant_id, "arguments": {"value": value}}],
        "coverage": ["fixture-state"],
        "reason": "The current observable state has not yet met the deterministic oracle.",
    }


def _models(
    *,
    first_grant: str = "set-state",
    first_tool_calls: tuple[dict[str, Any], ...] = (),
) -> dict[str, ScriptedModel]:
    expected = "sova.executor-chamber-planner/0.1.0"
    return {
        "agent-a": ScriptedModel(
            [
                ScriptedTurn(
                    expected,
                    "{}",
                    structured=_proposal(first_grant, "scanned"),
                    tool_calls=first_tool_calls,
                    token_count=3,
                )
            ],
            model_id="fixture-agent-a",
        ),
        "agent-b": ScriptedModel(
            [
                ScriptedTurn(
                    expected,
                    "{}",
                    structured=_proposal("set-state", "vulnerable-observed"),
                    token_count=5,
                )
            ],
            model_id="fixture-agent-b",
        ),
    }


def _authorization_factory(
    records: list[_ApprovalRecord],
) -> Callable[[str, ExecutorChamberEnvironment], ChamberAuthorizationController]:
    case = _case()
    budget = _budget()

    def factory(
        phase: str,
        environment: ExecutorChamberEnvironment,
    ) -> ChamberAuthorizationController:
        def approve(
            challenge: ApprovalBatchChallenge,
            intents: tuple[ActionIntent, ...],
        ) -> str:
            records.append(
                _ApprovalRecord(
                    phase,
                    challenge.authority_id,
                    challenge.id,
                    tuple(item.intent_digest for item in challenge.items),
                    tuple(item.digest for item in intents),
                )
            )
            return challenge.exact_phrase

        return build_chamber_authorization_controller(
            phase=phase,
            case=case,
            budget=budget,
            environment=environment,
            proof=_proof(),
            authority_target=_AUTHORITY_TARGET,
            approval_prompt=approve,
        )

    return factory


def _run(  # noqa: PLR0913 - fixture exposes each injected chamber boundary
    destination: Path,
    *,
    environments: _EnvironmentFactory,
    models: Mapping[str, ScriptedModel] | None = None,
    codec_resolver: Callable[[ExecutorChamberGrant, ChamberObservation], _FixtureCodec]
    | None = None,
    approval_records: list[_ApprovalRecord] | None = None,
    authorization_factory: Callable[
        [str, ExecutorChamberEnvironment], ChamberAuthorizationController
    ]
    | None = None,
    coordination_context_provider: Callable[[str], Mapping[str, Any]] | None = None,
    action_admission_hook: Callable[[str, Any, Any], None] | None = None,
) -> Any:
    records = approval_records if approval_records is not None else []
    return run_executor_chamber(
        _case(),
        (_grant(),),
        _models() if models is None else models,
        _budget(),
        destination,
        environment_factory=environments,
        authorization_factory=(
            _authorization_factory(records)
            if authorization_factory is None
            else authorization_factory
        ),
        codec_resolver=(
            (lambda _grant_spec, _observation: _FixtureCodec())
            if codec_resolver is None
            else codec_resolver
        ),
        oracle=ProjectionFieldOracle(("state",), "vulnerable"),
        authority_target=_AUTHORITY_TARGET,
        provider_calls_authorized=False,
        coordination_context_provider=coordination_context_provider,
        action_admission_hook=action_admission_hook,
    )


def test_chamber_static_validation_rejects_every_model_grant_binding_and_backend_drift() -> None:
    case = _case()
    grant = _grant()
    budget = _budget()
    models = _models()
    base = _FixtureEnvironment("validation", 1)

    def environment(
        *,
        bindings: Mapping[str, CapabilityBinding] | None = None,
        executors: Mapping[str, Any] | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            session=base.session,
            target=base.target,
            bindings=base.bindings if bindings is None else bindings,
            executors=base.executors if executors is None else executors,
        )

    with pytest.raises(FormatError, match="model set"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            {"agent-a": models["agent-a"]},
            budget,
            environment(),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="built-in provider"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            {**models, "agent-a": SimpleNamespace()},
            budget,
            environment(),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="empty or duplicated"):
        chamber_module.validate_executor_chamber(
            case, (), models, budget, environment(), provider_calls_authorized=False
        )
    with pytest.raises(FormatError, match="binding set"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            models,
            budget,
            environment(bindings={}),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="absent capability binding"):
        chamber_module.validate_executor_chamber(
            case,
            (replace(grant, binding_id="missing-binding"),),
            models,
            budget,
            environment(),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="multiple grant aliases"):
        chamber_module.validate_executor_chamber(
            case,
            (grant, replace(grant, identifier="set-state-alias")),
            models,
            budget,
            environment(),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="no trusted executor"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            models,
            budget,
            environment(executors={}),
            provider_calls_authorized=False,
        )
    no_capability = SimpleNamespace(capabilities=lambda: ())
    with pytest.raises(FormatError, match="does not advertise"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            models,
            budget,
            environment(executors={"fixture-backend": no_capability}),
            provider_calls_authorized=False,
        )
    substituted = SimpleNamespace(
        capabilities=lambda: (
            Capability(
                name="fixture.set",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=(_EVIDENCE_ROLE,),
            ),
        )
    )
    with pytest.raises(FormatError, match="contract differs"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            models,
            budget,
            environment(executors={"fixture-backend": substituted}),
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="executor set"):
        chamber_module.validate_executor_chamber(
            case,
            (grant,),
            models,
            budget,
            environment(executors={**base.executors, "extra": base.executor}),
            provider_calls_authorized=False,
        )
    unknown_case = replace(
        case,
        participants=(
            replace(case.participants[0], allowed_grants=("unknown",)),
            case.participants[1],
        ),
    )
    with pytest.raises(FormatError, match="unknown grant"):
        chamber_module.validate_executor_chamber(
            unknown_case,
            (grant,),
            models,
            budget,
            environment(),
            provider_calls_authorized=False,
        )


def test_chamber_observation_intent_and_normalized_failure_helpers_fail_closed(
    tmp_path: Path,
) -> None:
    base = _FixtureEnvironment("helpers", 1)
    malformed = SimpleNamespace(
        session=base.session,
        target=base.target,
        observe=list,
    )
    with pytest.raises(FormatError, match="must be an object"):
        chamber_module._capture_observation(malformed)
    first = chamber_module._capture_observation(base)
    rotated = SimpleNamespace(
        session=replace(base.session, generation=base.session.generation + 1),
        target=base.target,
        observe=base.observe,
    )
    with pytest.raises(FormatError, match="generation changed"):
        chamber_module._capture_observation(rotated, first)

    proposal = SimpleNamespace(
        proposal_id="proposal:fixture",
        session_digest=base.session.digest,
        observation_version_digest=first.version.digest,
    )
    with pytest.raises(FormatError, match="escaped"):
        chamber_module._intent(
            ActionRequest("escape", "filesystem.read", {"path": "../escape"}, 1),
            cast("Any", proposal),
            base._binding,
            target=_AUTHORITY_TARGET,
            offensive=False,
            authorization_subject_id="sova:principal:executor-chamber",
            workspace=tmp_path,
        )
    intent = chamber_module._intent(
        ActionRequest(
            "intent",
            "fixture.set",
            {
                "path": "opaque-path",
                "url": "https://owned.example/path",
                "identity": "identity:fixture",
            },
            1,
        ),
        cast("Any", proposal),
        base._binding,
        target=_AUTHORITY_TARGET,
        offensive=False,
        authorization_subject_id="sova:principal:executor-chamber",
        workspace=tmp_path,
    )
    assert intent.path == "opaque-path"
    assert intent.domain == "owned.example"
    assert intent.identity == "identity:fixture"

    request = ActionRequest("failure", "fixture.set", {}, 1)
    normalized = chamber_module._normalize_executor_exception(request, base._binding)
    assert normalized.error_code == "SOVA-EXECUTOR-CHAMBER-ADAPTER-EXCEPTION"
    deadline = chamber_module._deadline_outcome(request, base._binding, normalized)
    assert deadline.status is OutcomeStatus.TIMEOUT
    assert deadline.evidence == normalized.evidence


def test_chamber_controller_refuses_environment_without_capability_bindings() -> None:
    base = _FixtureEnvironment("authorization", 1)
    empty = SimpleNamespace(
        session=base.session,
        target=base.target,
        bindings={},
        workspace=base.workspace,
    )
    with pytest.raises(FormatError, match="at least one capability binding"):
        build_chamber_authorization_controller(
            phase="primary",
            case=_case(),
            budget=_budget(),
            environment=empty,
            proof=_proof(),
            authority_target=_AUTHORITY_TARGET,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        )


def test_two_agent_dynamic_pass_reproduces_with_fresh_approval_and_signed_traces(
    tmp_path: Path,
) -> None:
    environments = _EnvironmentFactory()
    models = _models()
    approvals: list[_ApprovalRecord] = []
    artifacts = _run(
        tmp_path / "pass",
        environments=environments,
        models=models,
        approval_records=approvals,
    )

    assert artifacts.status == "pass"
    assert artifacts.reproduction_trace is not None
    assert artifacts.capsule is not None
    assert all(model.consumed == 1 and model.complete for model in models.values())
    assert len(environments.environments) == 2
    primary, reproduction = environments.environments
    assert primary.target.digest != reproduction.target.digest
    assert primary.session.digest != reproduction.session.digest
    assert primary.closed and reproduction.closed
    assert len(primary.executor.requests) == len(reproduction.executor.requests) == 2
    assert all(
        context.authorization["decision"] == "allowed"
        and isinstance(context.authorization["executionGrant"], dict)
        for environment in environments.environments
        for context in environment.executor.contexts
    )

    assert [record.phase for record in approvals] == [
        "primary",
        "primary",
        "reproduction",
        "reproduction",
    ]
    assert len({record.authority_id for record in approvals}) == 2
    assert len({record.challenge_id for record in approvals}) == 4
    assert all(
        record.challenge_intent_digests == record.supplied_intent_digests for record in approvals
    )
    assert all(
        TraceReader(trace).verify(require_signature=True).signature_valid
        for trace in (artifacts.trace, artifacts.reproduction_trace)
    )
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "trace"]) == 2
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["primary"]["actions"] == 2
    assert report["reproduction"]["freshAuthorizationRequired"] is True
    assert report["reproduction"]["equivalent"] is True


def test_dynamic_coordination_context_is_prompted_and_signed(tmp_path: Path) -> None:
    calls: list[str] = []

    def context(participant_id: str) -> Mapping[str, Any]:
        calls.append(participant_id)
        return {
            "contract": "sova.swarm-peer-context/0.1.0",
            "messages": [{"authorAgentId": "peer", "summary": "tested login"}],
            "executorAuthorityGranted": False,
        }

    artifacts = _run(
        tmp_path / "coordinated",
        environments=_EnvironmentFactory(),
        coordination_context_provider=context,
    )

    assert calls == ["agent-a", "agent-b"]
    snapshots = [
        event
        for event in TraceReader(artifacts.trace).events()
        if event["kind"] == "x.sova.coordination.snapshot"
    ]
    assert len(snapshots) == 2
    assert snapshots[0]["payload"]["contentCaptured"] is True
    assert snapshots[0]["payload"]["context"]["messages"][0]["authorAgentId"] == "peer"
    assert snapshots[0]["payload"]["plannerAuthorityGranted"] is False


def test_external_action_admission_hook_runs_before_executor_dispatch(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()

    def deny(_phase: str, _request: Any, _binding: Any) -> None:
        raise FormatError("SOVA-FIXTURE-AGGREGATE", "aggregate action denied")

    with pytest.raises(FormatError, match="aggregate action denied"):
        _run(
            tmp_path / "aggregate-denied",
            environments=environments,
            action_admission_hook=deny,
        )
    assert environments.environments[0].executor.requests == []


def test_direct_model_tool_call_is_rejected_and_environment_is_closed(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()
    models = _models(first_tool_calls=({"name": "fixture.set", "arguments": {"value": "bypass"}},))
    with pytest.raises(FormatError, match="cannot call tools"):
        _run(tmp_path / "direct-tool", environments=environments, models=models)
    assert len(environments.environments) == 1
    assert environments.environments[0].closed
    assert environments.environments[0].executor.requests == []


def test_model_cannot_select_an_undeclared_grant(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()
    with pytest.raises(FormatError, match="outside its exact participant scope"):
        _run(
            tmp_path / "undeclared-grant",
            environments=environments,
            models=_models(first_grant="not-declared"),
        )
    assert environments.environments[0].executor.requests == []


def test_codec_argument_substitution_is_rejected_before_authorization(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()
    with pytest.raises(FormatError, match="substitution"):
        _run(
            tmp_path / "argument-substitution",
            environments=environments,
            codec_resolver=lambda _grant_spec, _observation: _FixtureCodec(
                substitute="vulnerable-substituted"
            ),
        )


def test_stale_observation_is_rejected_after_session_rotation(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()
    rotated = False

    def resolver(
        _grant_spec: ExecutorChamberGrant,
        _observation: ChamberObservation,
    ) -> _FixtureCodec:
        def rotate_once() -> None:
            nonlocal rotated
            if not rotated:
                environments.environments[-1].rotate_session_after_observation()
                rotated = True

        return _FixtureCodec(hook=rotate_once)

    with pytest.raises(FormatError, match="observation is attached to another"):
        _run(
            tmp_path / "stale-observation",
            environments=environments,
            codec_resolver=resolver,
        )
    assert environments.environments[0].closed
    assert environments.environments[0].executor.requests == []


@pytest.mark.parametrize(
    ("mutator", "message"),
    (
        (lambda environment: environment.stale_session_binding(), "another session"),
        (lambda environment: environment.stale_backend_binding(), "backend generation"),
    ),
)
def test_stale_session_or_backend_generation_is_rejected_before_models(
    tmp_path: Path,
    mutator: Callable[[_FixtureEnvironment], None],
    message: str,
) -> None:
    environments = _EnvironmentFactory(mutators={"primary": mutator})
    models = _models()
    with pytest.raises(FormatError, match=message):
        _run(
            tmp_path / f"stale-{message.split(maxsplit=1)[0]}",
            environments=environments,
            models=models,
        )
    assert all(model.consumed == 0 for model in models.values())
    assert environments.environments[0].closed
    assert environments.environments[0].close_calls == 1
    assert environments.environments[0].executor.requests == []


def test_authorization_factory_failure_closes_environment_before_models(tmp_path: Path) -> None:
    environments = _EnvironmentFactory()
    models = _models()

    def fail_authorization(
        phase: str,
        environment: ExecutorChamberEnvironment,
    ) -> ChamberAuthorizationController:
        del phase, environment
        raise RuntimeError(_AUTHORIZATION_FACTORY_ERROR)

    with pytest.raises(RuntimeError, match="authorization factory failure"):
        _run(
            tmp_path / "authorization-factory-failure",
            environments=environments,
            models=models,
            authorization_factory=fail_authorization,
        )

    assert len(environments.environments) == 1
    assert environments.environments[0].closed
    assert environments.environments[0].close_calls == 1
    assert environments.environments[0].executor.requests == []
    assert all(model.consumed == 0 for model in models.values())


def test_primary_and_reproduction_share_one_global_duration_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    monkeypatch.setattr("sova.community.executor_chamber.time.monotonic", clock)

    def exhaust_global_budget(_environment: _FixtureEnvironment) -> None:
        clock.now = float(_budget().max_duration_seconds) + 0.001

    environments = _EnvironmentFactory(mutators={"reproduction": exhaust_global_budget})
    models = _models()
    with pytest.raises(FormatError, match="duration budget is exhausted"):
        _run(
            tmp_path / "shared-global-deadline",
            environments=environments,
            models=models,
        )

    assert all(model.complete for model in models.values())
    assert len(environments.environments) == 2
    primary, reproduction = environments.environments
    assert primary.closed and primary.close_calls == 1
    assert reproduction.closed and reproduction.close_calls == 1
    assert len(primary.executor.requests) == 2
    assert reproduction.executor.requests == []


def test_codec_action_timeout_is_capped_by_action_budget(tmp_path: Path) -> None:
    observed_timeouts: list[float] = []
    artifacts = _run(
        tmp_path / "action-timeout-cap",
        environments=_EnvironmentFactory(),
        codec_resolver=lambda _grant_spec, _observation: _FixtureCodec(
            observed_timeouts=observed_timeouts
        ),
    )

    assert artifacts.status == "pass"
    assert len(observed_timeouts) == 4
    assert observed_timeouts == pytest.approx(
        [float(_budget().action_timeout_seconds)] * len(observed_timeouts)
    )


def test_provider_only_verification_cannot_pass_or_trigger_reproduction(tmp_path: Path) -> None:
    environments = _EnvironmentFactory(verification_independence="provider-only")
    artifacts = _run(tmp_path / "provider-only", environments=environments)
    assert artifacts.status == "not-observed"
    assert artifacts.reproduction_trace is None
    assert artifacts.capsule is None
    assert len(environments.environments) == 1


def test_missing_required_evidence_cannot_pass(tmp_path: Path) -> None:
    environments = _EnvironmentFactory(include_evidence=True, satisfy_evidence=False)
    artifacts = _run(tmp_path / "missing-evidence", environments=environments)
    assert artifacts.status == "not-observed"
    assert artifacts.reproduction_trace is None
    assert artifacts.capsule is None
    completed = list(TraceReader(artifacts.trace).query(kind_prefix="tool.completed"))
    assert completed
    assert completed[-1]["payload"]["evidence"]
    assert completed[-1]["payload"]["verification"]["evidence_digests"]
    assert completed[-1]["payload"]["verification"]["satisfied_evidence"] == []
    assert completed[-1]["payload"]["verification"]["method"] == "required-evidence-missing"


def test_confirmed_sequence_requires_every_causal_action_and_verification() -> None:
    failed = ActionOutcome(
        "failed",
        OutcomeStatus.FAILED,
        SideEffect.MUTATE,
        {},
        error_code="FIXTURE-FAILED",
    )
    succeeded = ActionOutcome(
        "succeeded",
        OutcomeStatus.SUCCEEDED,
        SideEffect.MUTATE,
        {},
        evidence=(EvidenceReference("fixture", "text/plain", _digest("ok"), 2),),
    )
    verified = ChamberVerification(
        verified=True,
        independence="agent-independent",
        method="fixture",
        evidence_digests=(_digest("evidence"),),
        satisfied_evidence=(_EVIDENCE_ROLE,),
    )
    oracle = ChamberOracleResult(
        OracleAssessment.OBSERVED,
        "fixture-oracle",
        (_digest("oracle"),),
        {},
    )

    assert not chamber_module._independently_confirmed(
        oracle,
        (failed, succeeded),
        (verified, verified),
    )


def test_cleanup_failure_is_terminal_and_seals_a_signed_failed_trace(tmp_path: Path) -> None:
    environments = _EnvironmentFactory(fail_close_phase="primary")
    destination = tmp_path / "cleanup-failure"
    with pytest.raises(RuntimeError, match="cleanup verification failed"):
        _run(destination, environments=environments)
    assert environments.environments[0].close_calls == 2
    trace = destination / "primary.sova-trace"
    verification = TraceReader(trace).verify(require_signature=True)
    assert verification.signature_valid
    assert verification.completion == "failed"


def test_nonempty_destination_is_rejected_before_environment_creation(tmp_path: Path) -> None:
    destination = tmp_path / "nonempty"
    destination.mkdir()
    (destination / "existing.txt").write_text("occupied", encoding="utf-8")
    environments = _EnvironmentFactory()
    with pytest.raises(FormatError, match="empty real directory"):
        _run(destination, environments=environments)
    assert environments.environments == []


def test_symlink_destination_is_rejected_before_environment_creation(tmp_path: Path) -> None:
    real = tmp_path / "real-destination"
    real.mkdir()
    link = tmp_path / "linked-destination"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")
    environments = _EnvironmentFactory()
    # The traversal guard rejects the link itself before the emptiness check runs.
    with pytest.raises(FormatError, match="cannot traverse a link or junction"):
        _run(link, environments=environments)
    assert environments.environments == []
    assert list(real.iterdir()) == []


def test_model_prompts_and_exported_artifacts_withhold_environment_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts: list[str] = []
    original_respond = ScriptedModel.respond

    def capture(model: ScriptedModel, prompt: str) -> ScriptedTurn:
        prompts.append(prompt)
        return original_respond(model, prompt)

    monkeypatch.setattr(ScriptedModel, "respond", capture)
    destination = tmp_path / "secret-withholding"
    artifacts = _run(destination, environments=_EnvironmentFactory())

    assert artifacts.status == "pass"
    assert len(prompts) == 2
    assert all(_SECRET not in prompt for prompt in prompts)
    assert all("sova-secret:fixture-login" not in prompt for prompt in prompts)
    assert any("$redacted" in prompt for prompt in prompts)
    persisted = [path.read_bytes() for path in destination.rglob("*") if path.is_file()]
    assert persisted
    assert all(_SECRET.encode("utf-8") not in value for value in persisted)
