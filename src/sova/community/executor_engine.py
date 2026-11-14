# SPDX-License-Identifier: Apache-2.0
"""Concrete composition layer for the authorization-gated SOVA Engine.

The engine joins heterogeneous trusted executor surfaces behind one fresh
target/session generation.  Planner agents receive only redacted observations
and declarative grants; they never receive executor objects, process handles,
workspaces, profile paths, or secret providers.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.community.executor_chamber import (
    ApprovalPrompt,
    ChamberActionCodec,
    ChamberObservation,
    ExecutorChamberArtifacts,
    ExecutorChamberGrant,
    build_chamber_authorization_controller,
    run_executor_chamber,
)
from sova.community.executor_chamber_config import parse_executor_chamber_document
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import normalize_workspace_relative_path
from sova.runtime.environment_builder import (
    BackendAdmission,
    TargetEnvironmentAdmission,
    build_bound_executor_environment,
    capability_contract_digest,
)
from sova.runtime.managed_surfaces import (
    CompositeObservationSource,
    EvidenceSatisfactionPolicy,
    PolicyEvidenceVerifier,
)
from sova.trace import Redactor

if TYPE_CHECKING:
    from sova.community.executor_chamber import (
        ActionAdmissionHook,
        ChamberAuthorizationController,
        CoordinationContextProvider,
        ExecutorChamberEnvironment,
    )
    from sova.executors import CancellationToken, SecretProvider
    from sova.runtime import RoleModel
    from sova.runtime.bound_environment import (
        BoundExecutorChamberEnvironment,
        EvidenceReader,
    )
    from sova.runtime.target_environment import SessionEnvelope, TargetInstance
    from sova.safety import ControlProof

_MAX_SEED_FILES = 256
_MAX_SEED_DIRECTORIES = 256
_MAX_SEED_BYTES = 16 * 1024 * 1024
_RESERVED_SEED_ROOTS = frozenset({".cache", ".sova"})
_SHA256_DIGEST_LENGTH = 71

SurfaceBind = Callable[["SessionEnvelope", "TargetInstance", Path], None]
SurfaceObserve = Callable[[], Mapping[str, Any]]
SurfaceClose = Callable[[], None]
SurfaceFactory = Callable[[str], tuple["EngineSurfaceGeneration", ...]]
PhaseSurfaceFactory = Callable[[str, Path], "EnginePhaseGeneration"]
CodecFactory = Callable[[ChamberObservation], ChamberActionCodec]
SecretProviderFactory = Callable[[str], "SecretProvider | None"]
ControlProofValidator = Callable[["ControlProof"], None]


def _noop_bind(_session: SessionEnvelope, _target: TargetInstance, _workspace: Path) -> None:
    return


def _noop_close() -> None:
    return


@dataclass(frozen=True, slots=True)
class EngineSurfaceGeneration:
    """One trusted backend generation plus its observation/evidence boundary."""

    sensor_name: str
    backend: BackendAdmission
    observe: SurfaceObserve
    evidence_policies: tuple[EvidenceSatisfactionPolicy, ...]
    bind: SurfaceBind = _noop_bind
    close: SurfaceClose = _noop_close

    def __post_init__(self) -> None:
        if (
            not self.sensor_name
            or not self.sensor_name.replace("-", "_").isidentifier()
            or type(self.backend) is not BackendAdmission
            or not callable(self.observe)
            or not callable(self.bind)
            or not callable(self.close)
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SURFACE",
                "engine surface generation is malformed",
            )
        if not isinstance(self.evidence_policies, tuple) or any(
            type(item) is not EvidenceSatisfactionPolicy for item in self.evidence_policies
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-EVIDENCE",
                "surface evidence policies must use exact immutable policy contracts",
            )
        capabilities = self.backend.executor.capabilities()
        capability_ids = {item.identifier for item in capabilities}
        policy_ids = {item.capability for item in self.evidence_policies}
        if (
            not self.evidence_policies
            or len(policy_ids) != len(self.evidence_policies)
            or policy_ids != capability_ids
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-EVIDENCE",
                "every surface capability requires one exact independent evidence policy",
                details={
                    "missing": sorted(capability_ids - policy_ids),
                    "extra": sorted(policy_ids - capability_ids),
                },
            )

    def contract_mapping(self) -> dict[str, Any]:
        executor_name = self.backend.executor.name
        if not isinstance(executor_name, str) or not executor_name:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SURFACE",
                "surface executor name is invalid",
            )
        capabilities = tuple(
            sorted(self.backend.executor.capabilities(), key=lambda item: item.identifier)
        )
        return {
            "sensor": self.sensor_name,
            "backendId": self.backend.backend_id,
            "executorName": executor_name,
            "backendGeneration": self.backend.generation,
            "capabilityGeneration": self.backend.capability_generation,
            "verifierId": self.backend.verifier_id,
            "affinityResources": list(self.backend.affinity_resources),
            "effectResources": {
                action: list(resources)
                for action, resources in sorted(self.backend.effect_resources.items())
            },
            "capabilities": [
                {
                    "identifier": item.identifier,
                    "contractDigest": capability_contract_digest(item),
                }
                for item in capabilities
            ],
            "evidencePolicies": [
                {
                    "capability": policy.capability,
                    "satisfiedEvidence": list(policy.satisfied_evidence),
                    "requiredProjectionPaths": [
                        list(path) for path in policy.required_projection_paths
                    ],
                    "requiredOutputKeys": list(policy.required_output_keys),
                    "requireObservationChange": policy.require_observation_change,
                    "independence": policy.independence,
                }
                for policy in sorted(
                    self.evidence_policies,
                    key=lambda item: item.capability,
                )
            ],
        }


@dataclass(frozen=True, slots=True)
class EnginePhaseGeneration:
    """One phase-owned target generation launched inside its disposable workspace.

    The stable contract digest excludes ephemeral pid/window/start values and
    therefore must describe the admitted target artifact, launch contract, and
    containment contract. The runtime compares it across discovery and
    reproduction while still binding each phase to its own measured process.
    """

    target_admission: TargetEnvironmentAdmission
    surfaces: tuple[EngineSurfaceGeneration, ...]
    stable_target_contract_digest: str
    close: SurfaceClose

    def __post_init__(self) -> None:
        if (
            type(self.target_admission) is not TargetEnvironmentAdmission
            or not isinstance(self.surfaces, tuple)
            or not self.surfaces
            or any(type(item) is not EngineSurfaceGeneration for item in self.surfaces)
            or not isinstance(self.stable_target_contract_digest, str)
            or len(self.stable_target_contract_digest) != _SHA256_DIGEST_LENGTH
            or not self.stable_target_contract_digest.startswith("sha256:")
            or not callable(self.close)
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-PHASE-GENERATION",
                "phase target, surfaces, stable contract, and cleanup are required",
            )


@dataclass(frozen=True, slots=True)
class _SeedSnapshot:
    directories: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    digest: str

    @classmethod
    def empty(cls) -> _SeedSnapshot:
        return cls((), (), sha256_digest(canonical_json_bytes({"directories": [], "files": []})))

    def materialize(self, workspace: Path) -> None:
        if workspace.is_symlink() or not workspace.is_dir():
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-WORKSPACE",
                "seed destination must be one real disposable workspace",
            )
        root = workspace.resolve(strict=True)
        if any(workspace.iterdir()):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-WORKSPACE",
                "seed destination must be an empty disposable workspace",
            )
        for relative in self.directories:
            target = root.joinpath(*relative.split("/"))
            lexical_parent = target.parent
            parent = lexical_parent.resolve(strict=True)
            if (
                lexical_parent.is_symlink()
                or not parent.is_relative_to(root)
                or parent.is_symlink()
            ):
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED",
                    "workspace seed directory parent escaped or became a link",
                )
            target.mkdir(parents=False, exist_ok=False)
            if target.is_symlink() or not target.is_dir():
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED",
                    "workspace seed directory could not be materialized safely",
                )
        for relative, data in self.files:
            target = root.joinpath(*relative.split("/"))
            lexical_parent = target.parent
            parent = lexical_parent.resolve(strict=True)
            if (
                lexical_parent.is_symlink()
                or not parent.is_relative_to(root)
                or parent.is_symlink()
            ):
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED",
                    "workspace seed file parent escaped or became a link",
                )
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_BINARY", 0))
                | int(getattr(os, "O_NOFOLLOW", 0))
            )
            try:
                descriptor = os.open(target, flags, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED",
                    "workspace seed file could not be created exclusively",
                ) from error
            if (
                target.is_symlink()
                or not target.is_file()
                or _read_seed_file(target, max_bytes=len(data)) != data
            ):
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED",
                    "workspace seed could not be materialized and verified",
                )


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # On Windows, st_ctime means creation time on older Pythons and metadata-change time on
    # newer ones, and a stat by path can report it differently from a stat by handle, so it
    # is left out there. File ID, size and mtime still detect a change; the seed digest binds it.
    change = 0 if os.name == "nt" else value.st_ctime_ns
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        change,
    )


def _read_seed_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED",
            "workspace seed entry could not be inspected without following links",
        ) from error
    if not stat.S_ISREG(before.st_mode):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED",
            "workspace seed contains a non-regular entry",
        )
    if before.st_size > max_bytes:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED-LIMIT",
            "workspace seed file exceeds its remaining byte budget",
        )
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read(max_bytes + 1)
            stable = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED",
            "workspace seed file could not be read through a stable descriptor",
        ) from error
    identity = _stat_identity(before)
    if (
        len(data) > max_bytes
        or len(data) != before.st_size
        or _stat_identity(opened) != identity
        or _stat_identity(stable) != identity
        or _stat_identity(after) != identity
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED",
            "workspace seed file changed while it was admitted",
        )
    return data


def _capture_seed(root: Path | None) -> _SeedSnapshot:
    if root is None:
        return _SeedSnapshot.empty()
    unresolved = root.absolute()
    if unresolved.is_symlink() or not unresolved.is_dir():
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SEED",
            "workspace seed must be a real existing directory",
        )
    resolved = unresolved.resolve(strict=True)
    directories: list[str] = []
    files: list[tuple[str, bytes]] = []
    total_bytes = 0
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED",
                "workspace seed cannot contain links",
            )
        try:
            actual = path.resolve(strict=True)
        except OSError as error:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED",
                "workspace seed entry disappeared during admission",
            ) from error
        if not actual.is_relative_to(resolved):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED",
                "workspace seed entry escaped through a filesystem link",
            )
        relative = normalize_workspace_relative_path(path.relative_to(resolved).as_posix())
        if relative.split("/", 1)[0].casefold() in _RESERVED_SEED_ROOTS:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED",
                "workspace seed cannot pre-populate SOVA runtime directories",
            )
        if path.is_dir():
            directories.append(relative)
            if len(directories) > _MAX_SEED_DIRECTORIES:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SEED-LIMIT",
                    "workspace seed exceeds its directory limit",
                )
            continue
        remaining = _MAX_SEED_BYTES - total_bytes
        data = _read_seed_file(path, max_bytes=remaining)
        total_bytes += len(data)
        if len(files) >= _MAX_SEED_FILES or total_bytes > _MAX_SEED_BYTES:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED-LIMIT",
                "workspace seed exceeds 256 files or 16 MiB",
            )
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED",
                "workspace seed is restricted to bounded UTF-8 research fixtures",
            ) from error
        _redacted, disclosures = Redactor(context_id="sova-executor-engine-seed").redact(
            {"path": relative, "content": text}
        )
        if disclosures:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SEED-SENSITIVE",
                "workspace seed contains credential-shaped material",
            )
        files.append((relative, data))
    document = {
        "directories": directories,
        "files": [
            {"path": relative, "digest": sha256_digest(data), "size": len(data)}
            for relative, data in files
        ],
    }
    return _SeedSnapshot(
        tuple(directories),
        tuple(files),
        sha256_digest(canonical_json_bytes(document)),
    )


def capture_workspace_seed_digest(root: Path | None) -> str:
    """Return the exact bounded seed digest used by fresh engine workspaces."""
    return _capture_seed(root).digest


class ExecutorEngineRuntime:
    """Own fresh heterogeneous surface generations for discovery and reproduction."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        codec_factories: Mapping[str, CodecFactory],
        target_admission: TargetEnvironmentAdmission | None = None,
        surface_factory: SurfaceFactory | None = None,
        phase_surface_factory: PhaseSurfaceFactory | None = None,
        workspace_parent: Path | None = None,
        workspace_seed: Path | None = None,
        evidence_reader: EvidenceReader | None = None,
        secret_provider_factory: SecretProviderFactory | None = None,
        control_proof_validator: ControlProofValidator | None = None,
    ) -> None:
        static_mode = (
            type(target_admission) is TargetEnvironmentAdmission
            and callable(surface_factory)
            and phase_surface_factory is None
        )
        phase_mode = (
            target_admission is None and surface_factory is None and callable(phase_surface_factory)
        )
        if (
            not (static_mode or phase_mode)
            or not codec_factories
            or any(
                not isinstance(key, str) or not key or not callable(value)
                for key, value in codec_factories.items()
            )
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-RUNTIME",
                "engine runtime target, surfaces, and codec registry are required",
            )
        self._target_admission = target_admission
        self._surface_factory = surface_factory
        self._phase_surface_factory = phase_surface_factory
        self._codec_factories = dict(sorted(codec_factories.items()))
        self._workspace_parent = workspace_parent
        self._seed = _capture_seed(workspace_seed)
        self._evidence_reader = evidence_reader
        self._secret_provider_factory = secret_provider_factory
        if control_proof_validator is not None and not callable(control_proof_validator):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CONTROL-PROOF",
                "engine control proof validator must be callable",
            )
        self._control_proof_validator = control_proof_validator
        self._lock = threading.RLock()
        self._phases: set[str] = set()
        self._executor_identities: set[int] = set()
        self._surface_contract_digest: str | None = None
        self._stable_target_contract_digest: str | None = None

    @property
    def seed_digest(self) -> str:
        return self._seed.digest

    @property
    def codec_ids(self) -> tuple[str, ...]:
        return tuple(self._codec_factories)

    def codec_resolver(
        self,
        grant: ExecutorChamberGrant,
        observation: ChamberObservation,
    ) -> ChamberActionCodec:
        factory = self._codec_factories.get(grant.codec_id)
        if factory is None:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CODEC",
                "grant references an unregistered engine codec",
                details={"codecId": grant.codec_id},
            )
        try:
            codec = factory(observation)
            codec_id = codec.codec_id
            decode = codec.decode
        except Exception as error:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CODEC-SUBSTITUTION",
                "engine codec factory did not return a usable declared codec",
            ) from error
        if not isinstance(codec_id, str) or not callable(decode) or codec_id != grant.codec_id:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CODEC-SUBSTITUTION",
                "engine codec factory returned another codec generation",
            )
        return codec

    def assert_control_proof(self, proof: ControlProof) -> None:
        if self._control_proof_validator is not None:
            self._control_proof_validator(proof)

    @staticmethod
    def _close_surfaces(surfaces: Sequence[EngineSurfaceGeneration]) -> None:
        failures = 0
        for surface in reversed(tuple(surfaces)):
            try:
                surface.close()
            except Exception:  # noqa: BLE001 - private cleanup details never escape
                failures += 1
        if failures:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CLEANUP",
                "one or more engine surfaces could not be closed",
            )

    def _record_surface_generation(
        self,
        surfaces: tuple[EngineSurfaceGeneration, ...],
    ) -> None:
        executor_ids = {id(item.backend.executor) for item in surfaces}
        if len(executor_ids) != len(surfaces) or executor_ids & self._executor_identities:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FRESHNESS",
                "every phase requires fresh non-aliased executor generations",
            )
        sensor_names = [item.sensor_name for item in surfaces]
        backend_ids = [item.backend.backend_id for item in surfaces]
        if len(set(sensor_names)) != len(sensor_names) or len(set(backend_ids)) != len(backend_ids):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SURFACE",
                "engine sensor and backend identifiers must be unique",
            )
        contract_digest = sha256_digest(
            canonical_json_bytes(
                [
                    item.contract_mapping()
                    for item in sorted(surfaces, key=lambda value: value.sensor_name)
                ]
            )
        )
        if (
            self._surface_contract_digest is not None
            and contract_digest != self._surface_contract_digest
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-REPRODUCTION-SUBSTITUTION",
                "fresh reproduction surface contracts differ from discovery",
            )
        self._surface_contract_digest = contract_digest
        self._executor_identities.update(executor_ids)

    @staticmethod
    def _close_phase_generation(
        surfaces: Sequence[EngineSurfaceGeneration],
        phase_close: SurfaceClose,
    ) -> None:
        failures = 0
        try:
            ExecutorEngineRuntime._close_surfaces(surfaces)
        except Exception:  # noqa: BLE001 - cleanup details stay inside the boundary
            failures += 1
        try:
            phase_close()
        except Exception:  # noqa: BLE001 - cleanup details stay inside the boundary
            failures += 1
        if failures:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CLEANUP",
                "one or more phase-owned surfaces or target processes could not be closed",
            )

    def _create_phase_workspace(self) -> Path:
        parent = (
            Path(tempfile.gettempdir())
            if self._workspace_parent is None
            else self._workspace_parent
        )
        try:
            resolved_parent = parent.resolve(strict=True)
        except OSError as error:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-WORKSPACE",
                "phase workspace parent is unavailable",
            ) from error
        if not resolved_parent.is_dir():
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-WORKSPACE",
                "phase workspace parent must be one existing directory",
            )
        try:
            workspace = Path(
                tempfile.mkdtemp(prefix="sova-engine-phase-", dir=resolved_parent)
            ).resolve(strict=True)
        except OSError as error:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-WORKSPACE",
                "phase-owned disposable workspace could not be created",
            ) from error
        self._seed.materialize(workspace)
        return workspace

    def _record_stable_target_contract(self, digest: str) -> None:
        if (
            self._stable_target_contract_digest is not None
            and digest != self._stable_target_contract_digest
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-TARGET-SUBSTITUTION",
                "fresh reproduction target contract differs from discovery",
            )
        self._stable_target_contract_digest = digest

    @staticmethod
    def _required_target_admission(
        admission: TargetEnvironmentAdmission | None,
    ) -> TargetEnvironmentAdmission:
        if admission is None:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-RUNTIME",
                "phase target admission is unavailable",
            )
        return admission

    def environment_factory(  # noqa: PLR0912, PLR0915 - explicit lifecycle fail-closes
        self,
        phase: str,
    ) -> BoundExecutorChamberEnvironment:
        if phase not in {"primary", "reproduction"}:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-PHASE",
                "engine environment phase is unsupported",
            )
        with self._lock:
            if phase in self._phases:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-PHASE",
                    "one engine environment phase cannot be created twice",
                )
            precreated_workspace: Path | None = None
            phase_close: SurfaceClose = _noop_close
            target_admission = self._target_admission
            phase_generation: EnginePhaseGeneration | None = None
            if self._phase_surface_factory is not None:
                precreated_workspace = self._create_phase_workspace()
                try:
                    phase_generation = self._phase_surface_factory(phase, precreated_workspace)
                except Exception:
                    shutil.rmtree(precreated_workspace, ignore_errors=True)
                    raise
                if type(phase_generation) is not EnginePhaseGeneration:
                    shutil.rmtree(precreated_workspace, ignore_errors=True)
                    raise FormatError(
                        "SOVA-EXECUTOR-ENGINE-PHASE-GENERATION",
                        "phase surface factory returned an undeclared generation",
                    )
                target_admission = phase_generation.target_admission
                supplied_surfaces = phase_generation.surfaces
                phase_close = phase_generation.close
            else:
                if self._surface_factory is None:  # constructor invariant
                    raise FormatError(
                        "SOVA-EXECUTOR-ENGINE-RUNTIME",
                        "static surface factory is unavailable",
                    )
                supplied_surfaces = self._surface_factory(phase)
            if (
                not isinstance(supplied_surfaces, tuple)
                or not supplied_surfaces
                or any(type(item) is not EngineSurfaceGeneration for item in supplied_surfaces)
            ):
                if isinstance(supplied_surfaces, Sequence) and all(
                    type(item) is EngineSurfaceGeneration for item in supplied_surfaces
                ):
                    self._close_surfaces(supplied_surfaces)
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-SURFACE",
                    "surface factory must return a non-empty exact generation tuple",
                )
            surfaces = supplied_surfaces
            try:
                self._record_surface_generation(surfaces)
                if phase_generation is not None:
                    self._record_stable_target_contract(
                        phase_generation.stable_target_contract_digest
                    )
                self._phases.add(phase)
            except Exception:
                self._close_phase_generation(surfaces, phase_close)
                if precreated_workspace is not None:
                    shutil.rmtree(precreated_workspace, ignore_errors=True)
                raise

        environment: BoundExecutorChamberEnvironment | None = None
        try:
            observer = CompositeObservationSource(
                {item.sensor_name: item.observe for item in surfaces}
            )
            policy_rows = tuple(
                (item.backend.backend_id, policy)
                for item in surfaces
                for policy in item.evidence_policies
            )
            policies = tuple(policy for _backend_id, policy in policy_rows)
            verifier = PolicyEvidenceVerifier(
                policies,
                backend_ids=tuple(backend_id for backend_id, _policy in policy_rows),
            )
            secret_provider = (
                None
                if self._secret_provider_factory is None
                else self._secret_provider_factory(phase)
            )
            environment = build_bound_executor_environment(
                self._required_target_admission(target_admission),
                tuple(item.backend for item in surfaces),
                observe=observer,
                verify=verifier,
                workspace_parent=self._workspace_parent,
                precreated_workspace=precreated_workspace,
                evidence_reader=self._evidence_reader,
                secret_provider=secret_provider,
                cleanup=lambda: self._close_phase_generation(surfaces, phase_close),
            )
            if precreated_workspace is None:
                self._seed.materialize(environment.workspace)
            for surface in surfaces:
                surface.bind(environment.session, environment.target, environment.workspace)
        except Exception as error:
            try:
                if environment is None:
                    self._close_phase_generation(surfaces, phase_close)
                    if precreated_workspace is not None:
                        shutil.rmtree(precreated_workspace, ignore_errors=True)
                else:
                    environment.close()
            except Exception as cleanup_error:
                raise cleanup_error from error
            raise
        else:
            return environment


def run_executor_engine_document(  # noqa: PLR0913
    document: dict[str, Any],
    destination: Path,
    *,
    runtime: ExecutorEngineRuntime,
    proof: ControlProof,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    offensive: bool = False,
    external_models: Mapping[str, RoleModel] | None = None,
    allowed_domains: tuple[str, ...] = (),
    allowed_identities: tuple[str, ...] = (),
    cancellation: CancellationToken | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    capsule_attachment_provider: Callable[[], Mapping[str, bytes]] | None = None,
    coordination_context_provider: CoordinationContextProvider | None = None,
    action_admission_hook: ActionAdmissionHook | None = None,
) -> ExecutorChamberArtifacts:
    """Validate the complete plan before constructing any executor surface."""
    runtime.assert_control_proof(proof)
    plan = parse_executor_chamber_document(
        document,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
        external_models=external_models,
    )
    unknown_codecs = sorted({item.codec_id for item in plan.grants} - set(runtime.codec_ids))
    if unknown_codecs:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CODEC",
            "executor chamber document references an unavailable runtime codec",
            details={"codecIds": unknown_codecs},
        )

    reproduction_contract = canonical_json_bytes(
        {
            "artifactType": "sova.executor-chamber-reproduction-contract",
            "schemaVersion": "0.1.0",
            "sourceDocumentDigest": sha256_digest(canonical_json_bytes(document)),
            "document": document,
        }
    )

    def combined_capsule_attachments() -> Mapping[str, bytes]:
        extra = {} if capsule_attachment_provider is None else dict(capsule_attachment_provider())
        name = "executor-chamber-reproduction-contract.json"
        if name in extra:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-REPRODUCTION-CONTRACT",
                "capsule attachment attempted to replace the engine reproduction contract",
            )
        return {name: reproduction_contract, **extra}

    def authorization_factory(
        phase: str,
        environment: ExecutorChamberEnvironment,
    ) -> ChamberAuthorizationController:
        return build_chamber_authorization_controller(
            phase=phase,
            case=plan.case,
            budget=plan.budget,
            environment=environment,
            proof=proof,
            authority_target=plan.authority.authority_target,
            approval_prompt=approval_prompt,
            allowed_domains=allowed_domains,
            allowed_identities=allowed_identities,
            offensive=plan.authority.offensive,
        )

    return run_executor_chamber(
        plan.case,
        plan.grants,
        plan.models,
        plan.budget,
        destination,
        environment_factory=runtime.environment_factory,
        authorization_factory=authorization_factory,
        codec_resolver=runtime.codec_resolver,
        oracle=plan.oracle,
        authority_target=plan.authority.authority_target,
        provider_calls_authorized=plan.authority.provider_calls,
        offensive=plan.authority.offensive,
        cancellation=cancellation,
        event_observer=event_observer,
        capsule_attachment_provider=combined_capsule_attachments,
        coordination_context_provider=coordination_context_provider,
        action_admission_hook=action_admission_hook,
    )


__all__ = [
    "CodecFactory",
    "EnginePhaseGeneration",
    "EngineSurfaceGeneration",
    "ExecutorEngineRuntime",
    "SurfaceFactory",
    "capture_workspace_seed_digest",
    "run_executor_engine_document",
]
