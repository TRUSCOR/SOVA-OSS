# SPDX-License-Identifier: Apache-2.0
"""Read finding capsules and their recorded runs without executing anything."""

from __future__ import annotations

import hashlib
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sova.audit.agentdojo import episode_from_events
from sova.audit.engine import AuditSpec, Episode, audit_episode, load_spec
from sova.formats import PackageReader, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.rerun.judges import verdict_for_category
from sova.rerun.records import VERDICTS, Verdict, text_digest
from sova.trace import TraceReader

BENCHMARK: Final = "AgentDojo"
CONTEXT_DIMENSIONS: Final[tuple[str, ...]] = (
    "model",
    "benchmarkVersion",
    "attack",
    "defense",
    "toolOutputFormat",
    "systemPrompt",
    "attackName",
    "returnedModel",
)
_REQUIRED_PARAMETERS: Final = ("attack", "suite", "userTask", "injectionTask")
# Condition labels used by the PF v1.1 AgentDojo studies, whose released capsules
# record the label instead of the explicit settings.
_KNOWN_CONDITION_LABELS: Final[Mapping[str, Mapping[str, Any]]] = {
    "baseline": {"defense": None, "toolOutputFormat": "yaml"},
    "N1-rerun": {"defense": None, "toolOutputFormat": "yaml"},
    "N2-json-tool-output": {"defense": None, "toolOutputFormat": "json"},
    "N3-paraphrased-system": {"defense": None, "toolOutputFormat": "yaml"},
    "M1-other-model": {"defense": None, "toolOutputFormat": "yaml"},
    "M2-repeat-user-prompt": {"defense": "repeat_user_prompt", "toolOutputFormat": "yaml"},
    "M3-spotlighting": {"defense": "spotlighting_with_delimiting", "toolOutputFormat": "yaml"},
}
_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def slug(value: str, limit: int = 48) -> str:
    """Return a short filesystem- and package-safe name fragment."""
    cleaned = _SLUG.sub("-", value).strip("-.") or "x"
    return cleaned[:limit]


@dataclass(frozen=True, slots=True)
class RecordedTrace:
    """One trace recorded in a finding capsule, summarized for comparison."""

    name: str
    digest: str
    valid: bool
    problem: str | None
    context: Mapping[str, Any]
    verdict: Verdict


@dataclass(frozen=True, slots=True)
class Finding:
    """A finding capsule that names an AgentDojo episode."""

    path: Path
    digest: str
    capsule_id: str
    title: str
    manifest: Mapping[str, Any]
    scenario: Mapping[str, Any]
    parameters: Mapping[str, Any]
    traces: tuple[RecordedTrace, ...]

    @property
    def label(self) -> str:
        """Return a short human label for tables and file names."""
        return self.path.stem

    @property
    def suite(self) -> str:
        """Return the AgentDojo suite."""
        return str(self.parameters["suite"])

    @property
    def user_task(self) -> str:
        """Return the AgentDojo user task identifier."""
        return str(self.parameters["userTask"])

    @property
    def injection_task(self) -> str:
        """Return the AgentDojo injection task identifier."""
        return str(self.parameters["injectionTask"])

    @property
    def attack(self) -> str:
        """Return the AgentDojo attack name."""
        return str(self.parameters["attack"])

    @property
    def benchmark_version(self) -> str | None:
        """Return the benchmark version from the scenario or the recorded runs."""
        value = self.parameters.get("benchmarkVersion")
        if value is not None:
            return str(value)
        recorded = {
            str(t.context["benchmarkVersion"])
            for t in self.traces
            if t.valid and t.context.get("benchmarkVersion")
        }
        return recorded.pop() if len(recorded) == 1 else None

    def episode_key(self, benchmark_version: str) -> str:
        """Return the identity of the episode, independent of the capsule's bytes."""
        parts = (
            BENCHMARK,
            benchmark_version,
            self.attack,
            self.suite,
            self.user_task,
            self.injection_task,
        )
        return "/".join(parts)


def file_digest(path: Path) -> str:
    """Return the SHA-256 digest of a file's bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _first(events: Sequence[Mapping[str, Any]], kind: str) -> Mapping[str, Any] | None:
    return next((event for event in events if event.get("kind") == kind), None)


def _payload(event: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if event is None:
        return {}
    payload = event.get("payload")
    return payload if isinstance(payload, Mapping) else {}


def _normalized_format(value: Any) -> Any:
    return "yaml" if value is None else value


def context_from_events(
    events: Sequence[Mapping[str, Any]],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the comparison context of one run from its trace events.

    Values the trace does not record are taken from the scenario parameters;
    values neither records are left out, so that comparison reports them as
    not recorded instead of guessing.
    """
    started = _payload(_first(events, "run.started"))
    context: dict[str, Any] = {}
    for key in ("model", "benchmarkVersion", "attack"):
        value = started.get(key, parameters.get(key))
        if value is not None:
            context[key] = value
    label = started.get("condition")
    label_settings = _KNOWN_CONDITION_LABELS.get(label) if isinstance(label, str) else None
    for key in ("defense", "toolOutputFormat"):
        if key in started:
            value = started[key]
        elif label_settings is not None:
            value = label_settings[key]
        elif key in parameters:
            value = parameters[key]
        else:
            continue
        context[key] = _normalized_format(value) if key == "toolOutputFormat" else value
    attack_name = started.get("attackName", started.get("attackModelName"))
    if attack_name is not None:
        context["attackName"] = attack_name
    system = _payload(_first(events, "prompt.system")).get("text")
    if isinstance(system, str):
        context["systemPrompt"] = text_digest(system)
    returned = sorted(
        {
            str(_payload(event).get("returned"))
            for event in events
            if event.get("kind") == "environment.model.returned" and _payload(event).get("returned")
        }
    )
    if not returned and isinstance(started.get("returnedModels"), list):
        returned = sorted(str(item) for item in started["returnedModels"])
    if returned:
        context["returnedModel"] = returned
    return context


def verdict_from_events(events: Sequence[Mapping[str, Any]]) -> Verdict:
    """Return the recorded run's verdict, judged the same way as fresh runs.

    A ``judge.completed`` event wins. Otherwise the recorded trace is audited with the
    same rules as fresh runs (the attacker's decisive call, executed). Only when the
    audit cannot read the decisive evidence (it was redacted, or no rule covers the
    goal) does the benchmark's own verdict decide.
    """
    judged = _payload(_first(events, "judge.completed")).get("verdict")
    for verdict in VERDICTS:
        if judged == verdict:
            return verdict
    episode = episode_from_events([dict(event) for event in events], source="recorded run")
    if isinstance(episode, Episode):
        category = audit_episode(episode, _audit_spec()).category
        if category not in {"evidence-redacted", "no-spec"}:
            return verdict_for_category(category)
    succeeded = _payload(_first(events, "oracle.completed")).get("attackSucceeded")
    if isinstance(succeeded, bool):
        return "attack" if succeeded else "no-attack"
    return "cant-tell"


_SPEC: list[AuditSpec] = []


def _audit_spec() -> AuditSpec:
    if not _SPEC:
        _SPEC.append(load_spec())
    return _SPEC[0]


def read_trace_events(path: Path) -> list[dict[str, Any]]:
    """Verify a trace offline and return its events."""
    reader = TraceReader(path)
    reader.verify()
    return reader.events()


def _recorded_trace(
    reader: PackageReader,
    descriptor: Any,
    parameters: Mapping[str, Any],
    local: Path,
) -> RecordedTrace:
    name = str(descriptor.path).removeprefix("traces/")
    local.write_bytes(reader.read_object(descriptor))
    try:
        events = read_trace_events(local)
    except FormatError as error:
        return RecordedTrace(
            name=name,
            digest=str(descriptor.digest),
            valid=False,
            problem=f"{error.issue.code}: {error.issue.message}",
            context={},
            verdict="cant-tell",
        )
    return RecordedTrace(
        name=name,
        digest=str(descriptor.digest),
        valid=True,
        problem=None,
        context=context_from_events(events, parameters),
        verdict=verdict_from_events(events),
    )


def load_finding(path: Path) -> Finding:
    """Verify a capsule and read the AgentDojo episode it records. Runs nothing."""
    reader = PackageReader(path)
    descriptors = reader.verify("sova.capsule")
    manifest = reader.manifest("sova.capsule")
    scenario_descriptor = next((item for item in descriptors if item.role == "scenario"), None)
    if scenario_descriptor is None:
        raise FormatError("SOVA-RERUN-NO-SCENARIO", "capsule has no scenario to re-run")
    scenario = strict_json_loads(reader.read_object(scenario_descriptor))
    if not isinstance(scenario, dict):
        raise FormatError("SOVA-RERUN-SCENARIO-TYPE", "scenario root must be an object")
    validate_document(scenario, "sova.scenario")
    parameters = scenario.get("parameters") or {}
    if parameters.get("benchmark") != BENCHMARK:
        raise FormatError(
            "SOVA-RERUN-UNSUPPORTED",
            "only findings whose scenario names the AgentDojo benchmark can be re-run",
            path="$.parameters.benchmark",
        )
    missing = [key for key in _REQUIRED_PARAMETERS if not isinstance(parameters.get(key), str)]
    if missing:
        raise FormatError(
            "SOVA-RERUN-PARAMETERS",
            "scenario parameters are missing AgentDojo keys",
            path="$.parameters",
            details={"missing": missing},
        )
    trace_descriptors = sorted(
        (item for item in descriptors if item.role == "trace"), key=lambda item: item.path
    )
    with tempfile.TemporaryDirectory(prefix="sova-rerun-capsule-") as temporary:
        workspace = Path(temporary)
        traces = [
            _recorded_trace(reader, descriptor, parameters, workspace / f"{index:04d}.sova-trace")
            for index, descriptor in enumerate(trace_descriptors)
        ]
    return Finding(
        path=path.resolve(),
        digest=file_digest(path),
        capsule_id=str(manifest["id"]),
        title=str(manifest["title"]),
        manifest=manifest,
        scenario=scenario,
        parameters=parameters,
        traces=tuple(traces),
    )


def discover_capsules(paths: Iterable[Path]) -> list[Path]:
    """Expand files and directories into a sorted, de-duplicated list of `.sova` files."""
    found: dict[Path, None] = {}
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.glob("*.sova")):
                found.setdefault(candidate.resolve(), None)
        elif path.is_file():
            found.setdefault(path.resolve(), None)
        else:
            raise FormatError("SOVA-RERUN-INPUT", f"no such capsule or folder: {path}")
    if not found:
        raise FormatError("SOVA-RERUN-INPUT", "no .sova capsules were found")
    return sorted(found)


__all__ = [
    "BENCHMARK",
    "CONTEXT_DIMENSIONS",
    "Finding",
    "RecordedTrace",
    "context_from_events",
    "discover_capsules",
    "file_digest",
    "load_finding",
    "read_trace_events",
    "slug",
    "verdict_from_events",
]
