# SPDX-License-Identifier: Apache-2.0
"""Local, inert-by-default command line for SOVA artifacts."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import threading
import webbrowser
from contextlib import contextmanager, suppress
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any

from sova import __version__
from sova.acceptance import (
    acceptance_receipt_template,
    default_release_gates,
    evaluate_release_readiness,
    load_receipts,
    run_offline_acceptance_lab,
)
from sova.adapters.security_catalog import get_security_adapter, security_adapter_catalog
from sova.adapters.security_contracts import AdapterInvocation
from sova.adapters.security_parsers import normalize_security_output
from sova.assessment import (
    build_assessment_plan,
    create_browser_test_kit,
    run_reference_assessment,
    target_template,
)
from sova.audit import DEFAULT_SPEC, run_audit
from sova.capsule import (
    analyze_migration,
    build_capsule,
    capsule_manifest_template,
    lint_capsule,
    migrate_capsule,
    render_capsule,
    scenario_template,
)
from sova.community import (
    build_ctf_document,
    build_leaderboard_document,
    issue_probe_document,
    render_replay_clip_document,
    run_agent_arena_document,
    run_arena_chamber_document,
    run_arena_document,
    run_browser_swarm_document,
    validate_agent_arena_document,
    validate_browser_swarm_document,
    verify_probe_response,
)
from sova.community.executor_capsule_reproduction import (
    build_executor_capsule_reproduction_document,
)
from sova.community.executor_chamber_config import validate_executor_chamber_document
from sova.community.executor_engine import run_executor_engine_document
from sova.community.executor_engine_full import (
    ComputerBackendSpec,
    LocalComputerAuthorization,
    MelraComputerBackendSpec,
    NativeWindowsComputerBackendSpec,
    run_full_capability_web_engine,
)
from sova.community.executor_engine_runtime_config import (
    build_executor_engine_runtime_surfaces,
    parse_executor_engine_runtime_document,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.community.live_executor_engine import run_live_web_executor_engine
from sova.community.software_executor_engine import (
    SoftwareLaunchSpec,
    build_authorized_software_runtime,
    create_local_software_control_proof,
    melra_software_computer_surface_factory,
)
from sova.community.swarm import run_software_swarm, run_stress_profile, run_web_swarm
from sova.composition import (
    CompositionBudget,
    CompositionObservation,
    CompositionSearchEngine,
    CompositionStrategy,
    graph_from_mapping,
)
from sova.conformance import export_conformance_kit, verify_conformance_kit
from sova.evidence import (
    ExecutionObservation,
    ObservationState,
    ScannerFinding,
    adjudicate_findings,
    build_evidence_bundle,
    construct_safe_test_plan,
    default_disclosure_clock,
    discover_maintainer_contacts,
    evidence_to_sarif,
    prepare_disclosure_package,
    render_evidence_report,
)
from sova.executors import GVisorOciExecutor, attest_docker_desktop, attest_gvisor
from sova.extensions import (
    ExtensionApproval,
    ExtensionManifest,
    discover_extension_metadata,
    extension_launch_from_mapping,
    prepare_extension_launch,
    run_extension_workflow,
)
from sova.forensics import (
    CausalLayer,
    CounterfactualTrial,
    assess_counterfactuals,
    blinded_study_from_mapping,
    browser_counterfactual_from_mapping,
    create_blinded_reviewer_keypair,
    create_stochastic_blinded_fixture,
    reconstruct_events,
    reconstruct_trace,
    run_attribution_ground_truth_fixture,
    run_blinded_attribution_study,
    run_browser_counterfactual_study,
    score_blinded_attribution_study,
    sign_blinded_answer_key,
)
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.front_door import front_door_description, show_artifact
from sova.intake import (
    EntryPoint,
    EntryPointKind,
    InputDescriptor,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    describe_material,
    read_target_profile,
    run_universal_intake,
    target_profile_template,
    validate_target_profile,
)
from sova.interoperability.record import (
    record_agentdojo,
    record_inspect,
    record_inspect_logs,
    record_trace_attestation,
)
from sova.live import (
    adaptive_browser_policy_from_mapping,
    adversarial_tactic_ids,
    browser_campaign_from_mapping,
    challenge_from_mapping,
    collect_website_control_proof,
    control_proof_from_mapping,
    create_website_control_challenge,
    run_adaptive_agent_browser_campaign,
    run_agent_browser_campaign,
    run_browser_campaign,
    run_browser_profile_handoff,
    run_live_browser_assessment,
    run_live_semantic_browser_workflow,
    run_live_software_assessment,
    run_owned_action_lab_vertical_slice,
    run_owned_software_vertical_slice,
    run_owned_web_campaign,
    run_owned_web_vertical_slice,
    semantic_browser_mission_from_mapping,
)
from sova.local_mcp import (
    LocalApprovalStore,
    LocalToolContext,
    create_control_key,
    load_control_key,
    manifest_self_check,
    serve_stdio,
    tool_manifest,
)
from sova.mapping import build_capability_map, write_capability_map, write_tool_snapshot
from sova.mcp import MELRA_AUDIT_RECEIPT, PLAYWRIGHT_MCP_RECEIPT, WINDOWS_MCP_RECEIPT
from sova.methodology import (
    EffectClass,
    MethodologyObservationSet,
    SchedulerKind,
    compile_methodology,
    load_builtin_library,
    methodology_policy_from_mapping,
    methodology_policy_template,
    observation_set_from_mapping,
    prepare_playbook_contribution,
    read_playbook,
    replan_methodology,
    validate_methodology_plan,
)
from sova.monitoring import (
    ContinuousMonitorService,
    WebhookAlertNotifier,
    build_behavior_snapshot,
    build_integrity_manifest,
    compare_behavior_snapshots,
    evaluate_ci,
    monitoring_jobs_from_document,
    record_local_process,
    run_sentinel,
    verify_integrity_manifest,
)
from sova.onboarding import delete_instance_data, diagnose_instance, initialize_instance
from sova.providers import provider_model_router, provider_runtime_from_mapping
from sova.registry import (
    CommunityHTTPService,
    CommunityServiceConfig,
    RegistryClient,
    RegistryEndpoint,
    auto_contribute_after_run,
    check_community_service_health,
    create_community_service_token,
    prepare_community_submission,
    prepare_contribution,
    resolve_registry_capsule,
    serialize_community_submission,
    sync_registry,
    verify_community_service_index,
    verify_registry,
)
from sova.rehearsal import (
    export_approved_changes,
    prepare_rehearsal_environment,
    provider_rehearsal_request_from_mapping,
    run_provider_rehearsal,
    run_rehearsal,
    specification_from_mapping,
)
from sova.release import (
    verify_checksums,
    write_cargo_cyclonedx_sbom,
    write_checksums,
    write_cyclonedx_sbom,
)
from sova.replay import (
    CapsuleReplaySelection,
    ReplayHTTPService,
    ReplayMode,
    ReplayServiceConfig,
    VerificationState,
    render_capsule_timeline,
    render_timeline_html,
    semantic_reproduction_study,
    verify_artifact,
)
from sova.reproduction import compare_observable_outcomes
from sova.rerun.command import (
    add_calibrate_arguments,
    add_matrix_arguments,
    add_rerun_arguments,
    run_calibrate_command,
    run_matrix_command,
    run_rerun_command,
)
from sova.runtime import (
    BrowserProfileLease,
    BrowserProfileVault,
    ModelRouter,
    OciAgentApproval,
    ProfileKind,
    RoleKind,
    RunProfile,
    authorize_oci_agent_adapter,
    oci_agent_runtime_from_mapping,
    run_oci_agent_conformance,
    standard_profile,
)
from sova.runtime.native_windows_computer import (
    native_window_targets_from_mapping,
    native_windows_computer_surface_factory,
    native_windows_discovery_surface_factory,
)
from sova.runtime.software_target import attest_software_target
from sova.runtime.window_recording import SoftwareWindowRecordingCoordinator
from sova.safety import (
    DisclosureRequest,
    VulnerabilityState,
    known_backend_descriptors,
)
from sova.search import run_trigger_search_demo
from sova.targets import TargetKind, target_manifest_from_mapping, validate_target_manifest
from sova.trace import Redactor, TraceReader, generate_ed25519_keypair, recover_trace
from sova.trace.otel import export_event
from sova.validation import (
    assemble_launch_bundle,
    evaluate_launch_bundle,
    read_launch_bundle,
    sign_launch_evidence,
)
from sova.workflows import build_case_workspace, run_browser_check, run_check, run_complete_demo

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from sova.targets import TargetManifest

_MIN_REPLAY_SERVICE_DURATION = 0.1
_MAX_REPLAY_SERVICE_DURATION = 86_400
_INTAKE_SPEC_PARTS = 4


def _path(value: str) -> Path:
    return Path(value)


_POSITIVE_COUNT_MESSAGE = "must be a positive integer"


def _positive_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(_POSITIVE_COUNT_MESSAGE) from error
    if count < 1:
        raise argparse.ArgumentTypeError(_POSITIVE_COUNT_MESSAGE)
    return count


def _add_browser_profile_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--browser-profile-vault",
        type=_path,
        help="local BrowserProfileVault root; must be paired with --browser-profile-handle",
    )
    parser.add_argument(
        "--browser-profile-handle",
        help="opaque handle provisioned for the exact target digest",
    )


def _add_contribution_arguments(parser: argparse.ArgumentParser) -> None:
    """Registry contribution is on by default; every run gets exactly one opt-out flag."""
    parser.add_argument(
        "--no-contribute",
        action="store_true",
        help="opt out of the default-on registry contribution of this run's capsule and trace",
    )
    parser.add_argument(
        "--registry-url",
        help="loopback registry service origin, e.g. http://127.0.0.1:8787; omit for the "
        "local git-PR-instructions fallback (nothing is ever pushed automatically)",
    )
    parser.add_argument("--registry-token", help="operator bearer token for --registry-url")
    parser.add_argument("--contributor-name", default="SOVA operator")
    parser.add_argument("--contributor-identity", default="unknown")


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    """Build the public command-line parser without performing side effects."""
    parser = argparse.ArgumentParser(
        prog="sova",
        description=front_door_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Front-door commands (record, show, audit). Handlers below delegate to
    # sova.interoperability.record, sova.front_door, and sova.audit.
    record_parser = commands.add_parser(
        "record", help="turn an external run log into SOVA artifacts without re-running it"
    )
    record_commands = record_parser.add_subparsers(dest="record_command")
    record_agentdojo_parser = record_commands.add_parser(
        "agentdojo",
        help="write a .sova-trace and a .sova capsule for each AgentDojo run log",
    )
    record_agentdojo_parser.add_argument(
        "source", type=_path, help="one AgentDojo log, or a directory searched recursively"
    )
    record_agentdojo_parser.add_argument("--out", type=_path, required=True)
    record_agentdojo_parser.add_argument("--author", default="Unknown author")
    record_agentdojo_parser.add_argument(
        "--bundle",
        action="store_true",
        help="write one capsule that nests one capsule per episode",
    )
    record_agentdojo_parser.add_argument("--name", help="bundle file name (default: DIR-bundle)")
    record_agentdojo_parser.set_defaults(handler=_record_agentdojo)
    record_inspect_log_parser = record_commands.add_parser(
        "inspect-log",
        help="write a .sova-trace per sample and a .sova capsule per Inspect AI eval log",
        description=(
            "Convert Inspect AI eval logs (.json, or .eval archives) into one .sova-trace per "
            "sample and epoch, sealed in one .sova capsule per log. Reads the log as data; "
            "imports no Inspect code and runs nothing."
        ),
    )
    record_inspect_log_parser.add_argument(
        "source", type=_path, help="one eval log, or a directory searched recursively"
    )
    record_inspect_log_parser.add_argument("--out", type=_path, required=True)
    record_inspect_log_parser.add_argument("--author", default="Unknown author")
    record_inspect_log_parser.set_defaults(handler=_record_inspect_log)
    for record_name, record_help, record_handler in (
        (
            "inspect",
            "import an Inspect AI sample dataset (JSON/JSONL) as an inert scenario set",
            _record_inspect,
        ),
        (
            "trace",
            "import TRACE trust records as declared trust inputs, not observations",
            _record_trace,
        ),
    ):
        record_import = record_commands.add_parser(record_name, help=record_help)
        record_import.add_argument("source", type=_path)
        record_import.add_argument("--license", required=True, help="SPDX licence of the source")
        record_import.add_argument("--source-url", required=True)
        record_import.add_argument("--out", type=_path, help="JSON destination; default stdout")
        record_import.set_defaults(handler=record_handler)

    show_parser = commands.add_parser(
        "show", help="print a capsule summary or a trace timeline without running anything"
    )
    show_parser.add_argument("path", type=_path)
    show_parser.set_defaults(handler=_show)

    audit_parser = commands.add_parser(
        "audit",
        help="check benchmark attack verdicts against the tool calls in each episode",
        description=(
            "For each AgentDojo episode, compare the benchmark's security verdict with the "
            "recorded messages: did the agent request the attacker's decisive tool call, and "
            "did it run without error? Reads logs and traces only; calls no model."
        ),
    )
    audit_parser.add_argument(
        "path",
        type=_path,
        help="an AgentDojo log, a .sova-trace, or a directory searched recursively",
    )
    audit_parser.add_argument(
        "--spec",
        default=DEFAULT_SPEC,
        help=f"packaged rule set name or a rule-set JSON file (default: {DEFAULT_SPEC})",
    )
    audit_parser.add_argument("--json", type=_path, help="write per-episode results here")
    audit_parser.add_argument("--limit", type=_positive_count, help="audit at most N episodes")
    audit_parser.set_defaults(handler=_audit)

    init_parser = commands.add_parser(
        "init", help="create an account-free local SOVA data directory"
    )
    init_parser.add_argument("root", type=_path)
    init_parser.add_argument(
        "--provider",
        choices=("none", "openai", "anthropic", "google", "openrouter", "ollama", "custom"),
        default="none",
    )
    init_parser.add_argument("--registry", type=_path)
    init_parser.set_defaults(handler=_init)

    doctor_parser = commands.add_parser(
        "doctor", help="diagnose one local SOVA instance without exposing credentials"
    )
    doctor_parser.add_argument("root", type=_path)
    doctor_parser.set_defaults(handler=_doctor)

    data_parser = commands.add_parser("data", help="preview or remove managed local SOVA data")
    data_commands = data_parser.add_subparsers(dest="data_command")
    data_delete = data_commands.add_parser(
        "delete", help="remove one exactly identified managed instance"
    )
    data_delete.add_argument("root", type=_path)
    data_delete.add_argument("--instance-id", required=True)
    data_delete.add_argument("--yes", action="store_true")
    data_delete.set_defaults(handler=_data_delete)

    release_parser = commands.add_parser(
        "release", help="build and verify deterministic local release metadata"
    )
    release_commands = release_parser.add_subparsers(dest="release_command")
    release_sbom = release_commands.add_parser(
        "sbom", help="generate a timestamp-free CycloneDX SBOM from uv.lock"
    )
    release_sbom.add_argument("lock", type=_path)
    release_sbom.add_argument("destination", type=_path)
    release_sbom.add_argument("--scope", choices=("runtime", "all"), default="runtime")
    release_sbom.set_defaults(handler=_release_sbom)
    release_cargo_sbom = release_commands.add_parser(
        "cargo-sbom", help="generate a timestamp-free CycloneDX SBOM from Cargo.lock"
    )
    release_cargo_sbom.add_argument("lock", type=_path)
    release_cargo_sbom.add_argument("destination", type=_path)
    release_cargo_sbom.add_argument("--root", required=True)
    release_cargo_sbom.set_defaults(handler=_release_cargo_sbom)
    release_checksums = release_commands.add_parser(
        "checksums", help="write a stable SHA-256 manifest for a release directory"
    )
    release_checksums.add_argument("root", type=_path)
    release_checksums.add_argument("destination", type=_path)
    release_checksums.set_defaults(handler=_release_checksums)
    release_verify = release_commands.add_parser(
        "verify-checksums", help="verify checksums and undeclared-file absence offline"
    )
    release_verify.add_argument("root", type=_path)
    release_verify.add_argument("manifest", type=_path)
    release_verify.set_defaults(handler=_release_verify_checksums)
    release_keygen = release_commands.add_parser(
        "keygen", help="create a raw Ed25519 keypair for signed launch evidence"
    )
    release_keygen.add_argument("private_key", type=_path)
    release_keygen.add_argument("public_key", type=_path)
    release_keygen.set_defaults(handler=_release_keygen)
    release_sign = release_commands.add_parser(
        "sign-evidence", help="validate and sign one canonical P6 launch-evidence document"
    )
    release_sign.add_argument("document", type=_path)
    release_sign.add_argument("private_key", type=_path)
    release_sign.add_argument("public_key", type=_path)
    release_sign.add_argument("destination", type=_path)
    release_sign.set_defaults(handler=_release_sign_evidence)
    release_assemble = release_commands.add_parser(
        "assemble-evidence",
        help="assemble strict signed P6 evidence into one deterministic launch bundle",
    )
    release_assemble.add_argument("trust_policy", type=_path)
    release_assemble.add_argument("protocol", type=_path)
    release_assemble.add_argument("observation_ledger", type=_path)
    release_assemble.add_argument("registry_policy", type=_path)
    release_assemble.add_argument("candidate", type=_path)
    release_assemble.add_argument("destination", type=_path)
    release_assemble.add_argument("--operational-receipt", type=_path, action="append", default=[])
    release_assemble.add_argument("--review-receipt", type=_path, action="append", default=[])
    release_assemble.add_argument("--gate-receipt", type=_path, action="append", default=[])
    release_assemble.set_defaults(handler=_release_assemble_evidence)
    release_dossier = release_commands.add_parser(
        "dossier", help="recompute an exact-candidate launch verdict from signed P6 evidence"
    )
    release_dossier.add_argument("bundle", type=_path)
    release_dossier.add_argument("artifact_manifest", type=_path)
    release_dossier.add_argument("claims_register", type=_path)
    release_dossier.add_argument("public_claims_snapshot", type=_path)
    release_dossier.add_argument("destination", type=_path)
    release_dossier.add_argument("--expected-commit", required=True)
    release_dossier.add_argument("--expected-trust-policy-digest", required=True)
    release_dossier.set_defaults(handler=_release_dossier)

    acceptance_parser = commands.add_parser(
        "acceptance", help="run core acceptance and evaluate stable-release evidence gates"
    )
    acceptance_commands = acceptance_parser.add_subparsers(dest="acceptance_command")
    acceptance_run = acceptance_commands.add_parser(
        "run", help="run the credential-free offline acceptance lab"
    )
    acceptance_run.add_argument("destination", type=_path)
    acceptance_run.add_argument(
        "--receipts",
        type=_path,
        help="optional directory of strict external acceptance receipts",
    )
    acceptance_run.set_defaults(handler=_acceptance_run)
    acceptance_evaluate = acceptance_commands.add_parser(
        "evaluate", help="evaluate strict receipts against every stable-1.0 gate"
    )
    acceptance_evaluate.add_argument("receipts", type=_path)
    acceptance_evaluate.set_defaults(handler=_acceptance_evaluate)
    acceptance_template = acceptance_commands.add_parser(
        "template", help="write an inconclusive receipt template for one gate"
    )
    acceptance_template.add_argument(
        "gate",
        choices=tuple(gate.id for gate in default_release_gates()),
    )
    acceptance_template.add_argument("destination", type=_path)
    acceptance_template.set_defaults(handler=_acceptance_template)

    conformance_parser = commands.add_parser(
        "conformance", help="export or verify the neutral SOVA compatibility kit"
    )
    conformance_commands = conformance_parser.add_subparsers(dest="conformance_command")
    conformance_export = conformance_commands.add_parser(
        "export", help="export deterministic schemas and golden vectors"
    )
    conformance_export.add_argument("destination", type=_path)
    conformance_export.set_defaults(handler=_conformance_export)
    conformance_verify = conformance_commands.add_parser(
        "verify", help="verify a compatibility kit entirely offline"
    )
    conformance_verify.add_argument("path", type=_path)
    conformance_verify.set_defaults(handler=_conformance_verify)

    target_parser = commands.add_parser(
        "target", help="author, validate, plan, or fixture-test an authorized target"
    )
    target_commands = target_parser.add_subparsers(dest="target_command")
    target_template_parser = target_commands.add_parser(
        "template", help="write a secret-free portable target manifest"
    )
    target_template_parser.add_argument("kind", choices=tuple(kind.value for kind in TargetKind))
    target_template_parser.add_argument("destination", type=_path)
    target_template_parser.set_defaults(handler=_target_template)
    target_validate = target_commands.add_parser(
        "validate", help="validate a target manifest without connecting to it"
    )
    target_validate.add_argument("manifest", type=_path)
    target_validate.set_defaults(handler=_target_validate)
    target_plan = target_commands.add_parser(
        "plan", help="write an inert authorization and execution plan"
    )
    target_plan.add_argument("manifest", type=_path)
    target_plan.add_argument("destination", type=_path)
    target_plan.set_defaults(handler=_target_plan)
    target_fixture = target_commands.add_parser(
        "fixture", help="prove the target-to-capsule pipeline on an owned deterministic fixture"
    )
    target_fixture.add_argument("kind", choices=("website", "software"))
    target_fixture.add_argument("destination", type=_path)
    target_fixture.set_defaults(handler=_target_fixture)
    target_challenge = target_commands.add_parser(
        "challenge", help="create a short-lived external website control challenge"
    )
    target_challenge.add_argument("manifest", type=_path)
    target_challenge.add_argument("destination", type=_path)
    target_challenge.set_defaults(handler=_target_challenge)
    target_prove = target_commands.add_parser(
        "prove", help="verify a hosted website-control challenge without redirects"
    )
    target_prove.add_argument("manifest", type=_path)
    target_prove.add_argument("challenge", type=_path)
    target_prove.add_argument("destination", type=_path)
    target_prove.set_defaults(handler=_target_prove)
    target_prove_software = target_commands.add_parser(
        "prove-software",
        help="create a short-lived proof bound to an exact local executable and workspace",
    )
    target_prove_software.add_argument("manifest", type=_path)
    target_prove_software.add_argument("executable", type=_path)
    target_prove_software.add_argument("destination", type=_path)
    target_prove_software.add_argument("--workspace-seed", type=_path)
    target_prove_software.set_defaults(handler=_target_prove_software)
    target_browser_kit = target_commands.add_parser(
        "browser-kit",
        help="write an inert authorized-browser target, campaign, plan, and instructions",
    )
    target_browser_kit.add_argument("origin")
    target_browser_kit.add_argument("destination", type=_path)
    target_browser_kit.set_defaults(handler=_target_browser_kit)
    target_profile_create = target_commands.add_parser(
        "profile-create",
        help="write a composite content-addressed universal target profile",
    )
    target_profile_create.add_argument("identifier")
    target_profile_create.add_argument("destination", type=_path)
    target_profile_create.add_argument("--title")
    target_profile_create.add_argument(
        "--kind",
        action="append",
        required=True,
        choices=tuple(kind.value for kind in ProfileTargetKind),
    )
    target_profile_create.add_argument("--authorization-scope", required=True)
    target_profile_create.add_argument(
        "--material",
        action="append",
        default=[],
        metavar="ID=KIND=SOURCE=PATH",
        help="bind and digest a required supplied material; may be repeated",
    )
    target_profile_create.add_argument(
        "--optional-material",
        action="append",
        default=[],
        metavar="ID=KIND=SOURCE=PATH",
        help="bind and digest an optional supplied material; may be repeated",
    )
    target_profile_create.add_argument(
        "--entrypoint",
        action="append",
        default=[],
        metavar="ID=KIND=TARGET_KINDS=LOCATOR",
        help="add an inert seed; TARGET_KINDS is a comma-separated list",
    )
    target_profile_create.set_defaults(handler=_target_profile_create)
    target_profile_validate = target_commands.add_parser(
        "profile-validate",
        help="validate a universal target profile without loading its materials",
    )
    target_profile_validate.add_argument("profile", type=_path)
    target_profile_validate.set_defaults(handler=_target_profile_validate)
    target_intake = target_commands.add_parser(
        "intake",
        help="create provenance-separated workflow and attack-surface intake evidence",
    )
    target_intake.add_argument("profile", type=_path)
    target_intake.add_argument("destination", type=_path)
    target_intake.add_argument(
        "--material",
        action="append",
        default=[],
        metavar="ID=PATH",
        help="override a material path; otherwise use the profile-adjacent logical name",
    )
    target_intake.add_argument("--authorize-active-observations", action="store_true")
    target_intake.set_defaults(handler=_target_intake)

    detonate_parser = commands.add_parser(
        "detonate",
        help="run authorization-gated dynamic behavior assessments",
    )
    detonate_commands = detonate_parser.add_subparsers(dest="detonate_command")
    detonate_fixture = detonate_commands.add_parser(
        "owned-web-fixture",
        help="prove the real browser-to-evidence pipeline on SOVA's loopback fixture",
    )
    detonate_fixture.add_argument("destination", type=_path)
    detonate_fixture.add_argument("--package-runner", type=_path)
    detonate_fixture.add_argument("--browser-executable", type=_path)
    detonate_fixture.add_argument("--playwright-browser-cache", type=_path)
    detonate_fixture.add_argument("--headed", action="store_true")
    detonate_fixture.add_argument("--record-video", action="store_true")
    detonate_fixture.set_defaults(handler=_detonate_owned_web_fixture)
    detonate_action_lab = detonate_commands.add_parser(
        "action-lab",
        help=(
            "prove confined file, loopback email/message, settings, browser evidence, "
            "reproduction, replay, and registry packaging"
        ),
    )
    detonate_action_lab.add_argument("destination", type=_path)
    detonate_action_lab.add_argument("--package-runner", type=_path)
    detonate_action_lab.add_argument("--browser-executable", type=_path)
    detonate_action_lab.add_argument("--playwright-browser-cache", type=_path)
    detonate_action_lab.add_argument("--headed", action="store_true")
    detonate_action_lab.add_argument("--record-video", action="store_true")
    detonate_action_lab.set_defaults(handler=_detonate_action_lab)
    detonate_software_fixture = detonate_commands.add_parser(
        "owned-software-fixture",
        help="prove the real local-process-to-evidence pipeline on SOVA's inert fixture",
    )
    detonate_software_fixture.add_argument("destination", type=_path)
    detonate_software_fixture.set_defaults(handler=_detonate_owned_software_fixture)
    detonate_browser = detonate_commands.add_parser(
        "browser",
        help="execute one capsule on one exactly authorized browser target",
    )
    detonate_browser.add_argument("manifest", type=_path)
    detonate_browser.add_argument("capsule", type=_path)
    detonate_browser.add_argument("destination", type=_path)
    detonate_browser.add_argument("--control-proof", type=_path)
    detonate_browser.add_argument("--package-runner", type=_path)
    detonate_browser.add_argument("--browser-executable", type=_path)
    detonate_browser.add_argument("--playwright-browser-cache", type=_path)
    detonate_browser.add_argument("--headed", action="store_true")
    detonate_browser.add_argument("--record-video", action="store_true")
    _add_browser_profile_arguments(detonate_browser)
    detonate_browser.set_defaults(handler=_detonate_browser)
    detonate_software = detonate_commands.add_parser(
        "software",
        help="execute one capsule on credential-stripped copies of trusted local software",
    )
    detonate_software.add_argument("manifest", type=_path)
    detonate_software.add_argument("capsule", type=_path)
    detonate_software.add_argument("workspace", type=_path)
    detonate_software.add_argument("destination", type=_path)
    detonate_software.add_argument("--executable", type=_path, required=True)
    detonate_software.set_defaults(handler=_detonate_software)

    inspect_parser = commands.add_parser("inspect", help="render an inert capsule summary")
    inspect_parser.add_argument("path", type=_path)
    inspect_parser.set_defaults(handler=_inspect)

    validate_parser = commands.add_parser(
        "validate",
        help="validate a capsule, trace, or JSON object",
    )
    validate_parser.add_argument("path", type=_path)
    validate_parser.set_defaults(handler=_validate)

    lint_parser = commands.add_parser("lint", help="report capsule semantic warnings")
    lint_parser.add_argument("path", type=_path)
    lint_parser.set_defaults(handler=_lint)

    verify_parser = commands.add_parser("verify", help="verify a capsule or trace offline")
    verify_parser.add_argument("path", type=_path)
    verify_parser.add_argument("--require-signature", action="store_true")
    verify_parser.add_argument("--key-id")
    verify_parser.set_defaults(handler=_verify)

    migrate_parser = commands.add_parser(
        "migrate",
        help="migrate a capsule without overwriting it",
    )
    migrate_parser.add_argument("source", type=_path)
    migrate_parser.add_argument("destination", type=_path)
    migrate_parser.add_argument("--to", default="0.1.0")
    migrate_parser.set_defaults(handler=_migrate)

    compat_parser = commands.add_parser(
        "compat",
        help="explain capsule migration compatibility without writing",
    )
    compat_parser.add_argument("source", type=_path)
    compat_parser.add_argument("--to", default="0.1.0")
    compat_parser.set_defaults(handler=_compat)

    format_parser = commands.add_parser("format", help="emit canonical JSON")
    format_parser.add_argument("path", type=_path)
    format_parser.set_defaults(handler=_format)

    hash_parser = commands.add_parser("hash", help="hash exact artifact bytes")
    hash_parser.add_argument("path", type=_path)
    hash_parser.add_argument(
        "--content",
        action="store_true",
        help="hash the canonical manifest/root instead of ZIP transport bytes",
    )
    hash_parser.set_defaults(handler=_hash)

    template_parser = commands.add_parser("template", help="write a safe authoring template")
    template_parser.add_argument("kind", choices=("capsule", "scenario"))
    template_parser.add_argument("destination", type=_path)
    template_parser.add_argument("--title", default="Untitled SOVA behavior")
    template_parser.add_argument(
        "--summary",
        default="Describe the observed or hypothesized behavior.",
    )
    template_parser.add_argument("--author", default="Unknown author")
    template_parser.set_defaults(handler=_template)

    pack_parser = commands.add_parser(
        "pack",
        help="build a capsule from manifest and scenario JSON",
    )
    pack_parser.add_argument("manifest", type=_path)
    pack_parser.add_argument("scenario", type=_path)
    pack_parser.add_argument("destination", type=_path)
    pack_parser.set_defaults(handler=_pack)

    playback_parser = commands.add_parser(
        "playback",
        help="print an inert trace timeline",
    )
    playback_parser.add_argument("path", type=_path)
    playback_parser.set_defaults(handler=_playback)

    replay_parser = commands.add_parser(
        "replay",
        help="open a finding at its decisive recording or use an explicit replay mode",
        description=(
            "Open a verified .sova finding with `sova replay FINDING.sova`, or choose one "
            "of the explicit replay operations below."
        ),
    )
    replay_commands = replay_parser.add_subparsers(dest="replay_command")
    replay_parser.set_defaults(handler=_replay_help, replay_parser=replay_parser)
    replay_open = replay_commands.add_parser(
        "open",
        help="render a .sova finding and open its decisive local replay",
    )
    replay_open.add_argument("source", type=_path)
    replay_open.add_argument(
        "--output",
        type=_path,
        help="HTML destination; defaults to FINDING-replay.html beside the capsule",
    )
    replay_open.add_argument(
        "--nested-capsule",
        help="exact internal nested finding path; defaults to the first verified finding",
    )
    replay_open.add_argument(
        "--no-open",
        action="store_true",
        help="render and report the replay without launching the local browser",
    )
    replay_open.add_argument(
        "--primary-trace", help="exact internal package path shown by sova inspect"
    )
    open_comparison_group = replay_open.add_mutually_exclusive_group()
    open_comparison_group.add_argument(
        "--comparison-trace", help="exact internal package path shown by sova inspect"
    )
    open_comparison_group.add_argument("--no-comparison", action="store_true")
    open_media_group = replay_open.add_mutually_exclusive_group()
    open_media_group.add_argument(
        "--media-object", help="exact internal visual-replay path shown by sova inspect"
    )
    open_media_group.add_argument(
        "--surface",
        choices=("browser", "computer"),
        help="select the cue-bound browser or computer recording",
    )
    open_media_group.add_argument("--no-media", action="store_true")
    replay_open.set_defaults(handler=_replay_open)
    replay_modes = replay_commands.add_parser(
        "modes", help="describe the three non-interchangeable replay operations"
    )
    replay_modes.set_defaults(handler=_replay_modes)
    replay_timeline = replay_commands.add_parser(
        "timeline", help="render a self-contained inert visual timeline"
    )
    replay_timeline.add_argument("source", type=_path)
    replay_timeline.add_argument("destination", type=_path)
    replay_timeline.add_argument("--comparison", type=_path)
    replay_timeline.add_argument("--counterfactual")
    replay_timeline.add_argument(
        "--media",
        type=_path,
        help="optional reviewed local WebM/MP4 session recording to embed in the replay",
    )
    replay_timeline.set_defaults(handler=_replay_timeline)
    replay_capsule = replay_commands.add_parser(
        "capsule", help="render verified trace and video evidence directly from a .sova capsule"
    )
    replay_capsule.add_argument("source", type=_path)
    replay_capsule.add_argument("destination", type=_path)
    replay_capsule.add_argument(
        "--primary-trace", help="exact internal package path shown by sova inspect"
    )
    replay_capsule.add_argument(
        "--nested-capsule",
        help="exact internal nested finding path; defaults to the first verified finding",
    )
    comparison_group = replay_capsule.add_mutually_exclusive_group()
    comparison_group.add_argument(
        "--comparison-trace", help="exact internal package path shown by sova inspect"
    )
    comparison_group.add_argument("--no-comparison", action="store_true")
    media_group = replay_capsule.add_mutually_exclusive_group()
    media_group.add_argument(
        "--media-object", help="exact internal visual-replay path shown by sova inspect"
    )
    media_group.add_argument(
        "--surface",
        choices=("browser", "computer"),
        help="select the cue-bound browser or computer recording",
    )
    media_group.add_argument("--no-media", action="store_true")
    replay_capsule.set_defaults(handler=_replay_capsule)
    replay_serve = replay_commands.add_parser(
        "serve", help="serve the inert replay application and a live trace tail on loopback"
    )
    replay_serve.add_argument("source", type=_path)
    replay_serve.add_argument("--port", type=int, default=0)
    replay_serve.add_argument(
        "--duration-seconds",
        type=float,
        help="optional bounded service duration; otherwise stop with Ctrl-C",
    )
    replay_serve.set_defaults(handler=_replay_serve)
    replay_study = replay_commands.add_parser(
        "study", help="measure observable-outcome reproduction across fresh traces"
    )
    replay_study.add_argument("reference", type=_path)
    replay_study.add_argument("trials", nargs="+", type=_path)
    replay_study.add_argument(
        "--condition",
        action="append",
        help="one condition label per trial; defaults to declared-baseline",
    )
    replay_study.set_defaults(handler=_replay_study)
    replay_clip = replay_commands.add_parser(
        "clip", help="render a redaction-first metadata-only local replay clip"
    )
    replay_clip.add_argument("specification", type=_path)
    replay_clip.add_argument("destination", type=_path)
    replay_clip.set_defaults(handler=_replay_clip)

    query_parser = commands.add_parser("query", help="query trace events offline")
    query_parser.add_argument("path", type=_path)
    query_parser.add_argument("--kind-prefix")
    query_parser.add_argument("--actor-id")
    query_parser.add_argument("--start", type=int, default=0)
    query_parser.add_argument("--stop", type=int)
    query_parser.set_defaults(handler=_query)

    compare_parser = commands.add_parser(
        "compare",
        help="compare declared observable outcomes from two traces without re-execution",
    )
    compare_parser.add_argument("left", type=_path)
    compare_parser.add_argument("right", type=_path)
    compare_parser.add_argument(
        "--kind",
        action="append",
        help="event kind to compare; repeat to select multiple kinds",
    )
    compare_parser.set_defaults(handler=_compare)

    rerun_parser = commands.add_parser(
        "rerun",
        help="re-run a recorded AgentDojo finding on a model (model calls need --authorize)",
    )
    add_rerun_arguments(rerun_parser)
    rerun_parser.set_defaults(handler=_rerun)
    matrix_parser = commands.add_parser(
        "matrix",
        help="re-run findings x models x trials, or check a model upgrade (needs --authorize)",
    )
    add_matrix_arguments(matrix_parser)
    matrix_parser.set_defaults(handler=_matrix)
    calibrate_parser = commands.add_parser(
        "calibrate",
        help="measure which setup changes affect recurrence on a model (needs --authorize)",
    )
    add_calibrate_arguments(calibrate_parser)
    calibrate_parser.set_defaults(handler=_calibrate)

    export_parser = commands.add_parser(
        "export",
        help="write a local machine-readable trace projection to stdout",
    )
    export_parser.add_argument("path", type=_path)
    export_parser.add_argument(
        "--format",
        choices=("native-jsonl", "otel-jsonl", "disclosure-json"),
        default="native-jsonl",
    )
    export_parser.add_argument("--sequence", action="append", type=int)
    export_parser.add_argument("--include-payload", action="store_true")
    export_parser.set_defaults(handler=_export)

    recover_parser = commands.add_parser(
        "recover-trace",
        help="recover a force-interrupted trace as an explicit observable prefix",
    )
    recover_parser.add_argument("destination", type=_path)
    recover_parser.set_defaults(handler=_recover_trace)

    safety_parser = commands.add_parser(
        "safety",
        help="inspect local containment capability without starting a backend",
    )
    safety_commands = safety_parser.add_subparsers(dest="safety_command")
    backends_parser = safety_commands.add_parser(
        "backends",
        help="report known containment backends and explicit limitations",
    )
    backends_parser.set_defaults(handler=_safety_backends)
    docker_attest_parser = safety_commands.add_parser(
        "attest-docker",
        help="attest a cached digest-pinned image on Docker Desktop without executing it",
    )
    docker_attest_parser.add_argument(
        "--docker",
        type=_path,
        help="exact Docker CLI path; otherwise resolve docker from PATH",
    )
    docker_attest_parser.add_argument(
        "--image",
        required=True,
        help="exact cached repository@sha256 image reference",
    )
    docker_attest_parser.set_defaults(handler=_safety_attest_docker)
    gvisor_attest_parser = safety_commands.add_parser(
        "attest-gvisor",
        help=(
            "attest a registered gVisor runsc runtime and cached digest-pinned image "
            "without executing it"
        ),
    )
    gvisor_attest_parser.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path; auto-detected when omitted",
    )
    gvisor_attest_parser.add_argument(
        "--image",
        required=True,
        help="exact cached repository@sha256 image reference",
    )
    gvisor_attest_parser.add_argument(
        "--runtime",
        default="runsc",
        help="registered OCI runtime name (default: runsc)",
    )
    gvisor_attest_parser.set_defaults(handler=_safety_attest_gvisor)

    demo_parser = commands.add_parser(
        "demo",
        help="run a safe no-native-code synthetic demonstration",
    )
    demo_parser.add_argument("kind", choices=("sleeper",))
    demo_parser.add_argument("destination", type=_path)
    demo_parser.set_defaults(handler=_demo)

    check_parser = commands.add_parser(
        "check",
        help="run a bounded local check and return an explicit assurance state",
    )
    check_parser.add_argument("target", nargs="?")
    check_parser.add_argument("destination", nargs="?", type=_path)
    check_parser.add_argument(
        "--self",
        action="store_true",
        dest="check_self",
        help="verify the local SOVA MCP tool manifest and authorization posture",
    )
    check_parser.add_argument(
        "--custom-profile",
        type=_path,
        help="canonical JSON customization; marks the run non-standard",
    )
    check_parser.add_argument(
        "--browser-campaign",
        type=_path,
        help="execute a non-offensive campaign on a controlled browser target manifest",
    )
    check_parser.add_argument("--control-proof", type=_path)
    check_parser.add_argument("--package-runner", type=_path)
    check_parser.add_argument("--browser-executable", type=_path)
    check_parser.set_defaults(handler=_check)

    map_parser = commands.add_parser(
        "map",
        help="map local declared capability reach without executing target code",
    )
    map_parser.add_argument("root", nargs="?", type=_path, default=Path())
    map_parser.add_argument("--output", "-o", type=_path)
    map_parser.add_argument("--inventory", action="append", type=_path, default=[])
    map_parser.add_argument("--observed-inventory", action="append", type=_path, default=[])
    map_parser.add_argument(
        "--authorize-runtime-inventory",
        action="store_true",
        help="confirm imported observed inventory was collected under authorization",
    )
    map_parser.add_argument("--baseline", type=_path)
    map_parser.add_argument("--write-tool-snapshot", type=_path)
    map_parser.set_defaults(handler=_map)

    executors_parser = commands.add_parser(
        "executors", help="inspect external executor receipts and limitations"
    )
    executors_commands = executors_parser.add_subparsers(dest="executors_command")
    executor_receipts = executors_commands.add_parser(
        "receipts", help="print pinned MELRA and open-source fallback receipts"
    )
    executor_receipts.set_defaults(handler=_executor_receipts)

    session_parser = commands.add_parser(
        "session", help="provision and inspect local opaque browser profiles"
    )
    session_commands = session_parser.add_subparsers(dest="session_command")
    session_create = session_commands.add_parser(
        "browser-create",
        help="provision a profile bound to one exact target-manifest digest",
    )
    session_create.add_argument("vault", type=_path)
    session_create.add_argument("identity")
    session_create.add_argument("target_digest")
    session_create.set_defaults(handler=_session_browser_create)
    session_inspect = session_commands.add_parser(
        "browser-inspect", help="print trace-safe profile metadata"
    )
    session_inspect.add_argument("vault", type=_path)
    session_inspect.add_argument("handle")
    session_inspect.set_defaults(handler=_session_browser_inspect)
    session_handoff = session_commands.add_parser(
        "browser-handoff",
        help="open a target-bound profile for manual login or CAPTCHA completion",
    )
    session_handoff.add_argument("manifest", type=_path)
    session_handoff.add_argument("entry_url")
    session_handoff.add_argument("browser_profile_vault", type=_path)
    session_handoff.add_argument("browser_profile_handle")
    session_handoff.add_argument("destination", type=_path)
    session_handoff.add_argument("--control-proof", type=_path)
    session_handoff.add_argument("--package-runner", type=_path)
    session_handoff.add_argument("--browser-executable", type=_path)
    session_handoff.set_defaults(handler=_session_browser_handoff)

    hunt_parser = commands.add_parser(
        "hunt",
        help="run an authorization-gated bounded behavior search",
    )
    hunt_commands = hunt_parser.add_subparsers(dest="hunt_command")
    hunt_fixture = hunt_commands.add_parser(
        "owned-web-fixture",
        help="discover and reproduce the planted behavior through a real browser",
    )
    hunt_fixture.add_argument("destination", type=_path)
    hunt_fixture.add_argument("--package-runner", type=_path)
    hunt_fixture.add_argument("--browser-executable", type=_path)
    hunt_fixture.add_argument("--playwright-browser-cache", type=_path)
    hunt_fixture.add_argument("--headed", action="store_true")
    hunt_fixture.add_argument("--record-video", action="store_true")
    hunt_fixture.set_defaults(handler=_hunt_owned_web_fixture)
    hunt_browser = hunt_commands.add_parser(
        "browser",
        help="search a declared candidate set on one exactly authorized website",
    )
    hunt_browser.add_argument("manifest", type=_path)
    hunt_browser.add_argument("campaign", type=_path)
    hunt_browser.add_argument("destination", type=_path)
    hunt_browser.add_argument("--control-proof", type=_path)
    hunt_browser.add_argument("--package-runner", type=_path)
    hunt_browser.add_argument("--browser-executable", type=_path)
    hunt_browser.add_argument("--playwright-browser-cache", type=_path)
    hunt_browser.add_argument("--headed", action="store_true")
    hunt_browser.add_argument("--record-video", action="store_true")
    _add_browser_profile_arguments(hunt_browser)
    hunt_browser.set_defaults(handler=_hunt_browser)
    hunt_agent_browser = hunt_commands.add_parser(
        "agent-browser",
        help=(
            "use isolated provider roles to propose a bounded campaign, then require "
            "exact human review before running it on an authorized website"
        ),
    )
    hunt_agent_browser.add_argument("manifest", type=_path)
    hunt_agent_browser.add_argument("campaign", type=_path)
    hunt_agent_browser.add_argument("provider_runtime", type=_path)
    hunt_agent_browser.add_argument("destination", type=_path)
    hunt_agent_browser.add_argument("--control-proof", type=_path)
    hunt_agent_browser.add_argument("--package-runner", type=_path)
    hunt_agent_browser.add_argument("--browser-executable", type=_path)
    hunt_agent_browser.add_argument("--playwright-browser-cache", type=_path)
    hunt_agent_browser.add_argument("--headed", action="store_true")
    hunt_agent_browser.add_argument("--record-video", action="store_true")
    _add_browser_profile_arguments(hunt_agent_browser)
    hunt_agent_browser.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    hunt_agent_browser.set_defaults(handler=_hunt_agent_browser)
    hunt_adaptive_browser = hunt_commands.add_parser(
        "adaptive-browser",
        help=(
            "adapt provider-proposed candidate batches between independently approved "
            "rounds on one authorized website"
        ),
    )
    hunt_adaptive_browser.add_argument("manifest", type=_path)
    hunt_adaptive_browser.add_argument("campaign", type=_path)
    hunt_adaptive_browser.add_argument("policy", type=_path)
    hunt_adaptive_browser.add_argument("provider_runtime", type=_path)
    hunt_adaptive_browser.add_argument("destination", type=_path)
    hunt_adaptive_browser.add_argument("--control-proof", type=_path)
    hunt_adaptive_browser.add_argument("--package-runner", type=_path)
    hunt_adaptive_browser.add_argument("--browser-executable", type=_path)
    _add_browser_profile_arguments(hunt_adaptive_browser)
    hunt_adaptive_browser.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    hunt_adaptive_browser.set_defaults(handler=_hunt_adaptive_browser)

    hunt_demo_parser = commands.add_parser(
        "hunt-demo",
        help="run an owned inert trigger-search comparison without native code",
    )
    hunt_demo_parser.set_defaults(handler=_hunt_demo)

    forensics_parser = commands.add_parser(
        "forensics", help="reconstruct evidence or assess declared counterfactual trials"
    )
    forensics_commands = forensics_parser.add_subparsers(dest="forensics_command")
    reconstruct_parser = forensics_commands.add_parser(
        "reconstruct", help="build an uncertainty-preserving evidence timeline"
    )
    reconstruct_parser.add_argument("source", type=_path)
    reconstruct_parser.set_defaults(handler=_forensics_reconstruct)
    attribute_parser = forensics_commands.add_parser(
        "attribute", help="assess paired intervention records without claiming causal proof"
    )
    attribute_parser.add_argument("study", type=_path)
    attribute_parser.set_defaults(handler=_forensics_attribute)
    benchmark_parser = forensics_commands.add_parser(
        "benchmark", help="run the safe deterministic attribution acceptance fixture"
    )
    benchmark_parser.set_defaults(handler=_forensics_benchmark)
    browser_cf_parser = forensics_commands.add_parser(
        "browser-counterfactual",
        help="run repeated message-removal interventions on a controlled browser target",
    )
    browser_cf_parser.add_argument("manifest", type=_path)
    browser_cf_parser.add_argument("study", type=_path)
    browser_cf_parser.add_argument("destination", type=_path)
    browser_cf_parser.add_argument("--control-proof", type=_path)
    browser_cf_parser.add_argument("--package-runner", type=_path)
    browser_cf_parser.add_argument("--browser-executable", type=_path)
    browser_cf_parser.set_defaults(handler=_forensics_browser_counterfactual)
    blind_fixture = forensics_commands.add_parser(
        "blind-fixture",
        help="create a reproducible stochastic fixture and separate committed answer key",
    )
    blind_fixture.add_argument("task", type=_path)
    blind_fixture.add_argument("answer_key", type=_path)
    blind_fixture.add_argument("--seed", type=int, default=20260809)
    blind_fixture.add_argument("--cases", type=int, default=16)
    blind_fixture.add_argument("--trials-per-layer", type=int, default=16)
    blind_fixture.set_defaults(handler=_forensics_blind_fixture)
    blind_run = forensics_commands.add_parser(
        "blind-run", help="run attribution without loading the committed answer key"
    )
    blind_run.add_argument("task", type=_path)
    blind_run.add_argument("predictions", type=_path)
    blind_run.set_defaults(handler=_forensics_blind_run)
    blind_score = forensics_commands.add_parser(
        "blind-score", help="verify the answer commitment and score frozen predictions"
    )
    blind_score.add_argument("task", type=_path)
    blind_score.add_argument("predictions", type=_path)
    blind_score.add_argument("answer_key", type=_path)
    blind_score.add_argument("output", type=_path)
    blind_score.add_argument("--reviewer-public-key", type=_path)
    blind_score.add_argument("--required-reviewer-key-id")
    blind_score.set_defaults(handler=_forensics_blind_score)
    blind_keygen = forensics_commands.add_parser(
        "blind-keygen", help="create separate raw Ed25519 reviewer key files"
    )
    blind_keygen.add_argument("private_key", type=_path)
    blind_keygen.add_argument("public_key", type=_path)
    blind_keygen.set_defaults(handler=_forensics_blind_keygen)
    blind_sign = forensics_commands.add_parser(
        "blind-sign-key", help="DSSE-sign a frozen answer key with reviewer-held key files"
    )
    blind_sign.add_argument("answer_key", type=_path)
    blind_sign.add_argument("private_key", type=_path)
    blind_sign.add_argument("public_key", type=_path)
    blind_sign.add_argument("output", type=_path)
    blind_sign.set_defaults(handler=_forensics_blind_sign_key)

    evidence_parser = commands.add_parser(
        "evidence", help="build a bounded, watermarked self-assessment evidence bundle"
    )
    evidence_parser.add_argument("specification", type=_path)
    evidence_parser.add_argument(
        "--format",
        choices=("json", "sarif", "technical", "executive", "reproduction", "methodology"),
        default="json",
    )
    evidence_parser.set_defaults(handler=_evidence)

    case_parser = commands.add_parser(
        "case", help="build a complete offline review workspace from linked evidence"
    )
    case_commands = case_parser.add_subparsers(dest="case_command")
    case_build = case_commands.add_parser(
        "build", help="verify a capsule and its signed trace, then render a local case workspace"
    )
    case_build.add_argument("trace", type=_path)
    case_build.add_argument("capsule", type=_path)
    case_build.add_argument("destination", type=_path)
    case_build.add_argument("--title", default="SOVA behavior case")
    case_build.add_argument(
        "--classification",
        choices=("simulation", "bundled-target", "real-disclosed-finding"),
        default="bundled-target",
    )
    case_build.add_argument("--component", default="operator-controlled target")
    case_build.add_argument("--component-version", default="not-recorded")
    case_build.add_argument("--disclosure-cleared", action="store_true")
    case_build.add_argument("--reviewed-for-export", action="store_true")
    case_build.set_defaults(handler=_case_build)

    adjudicate_parser = commands.add_parser(
        "adjudicate", help="bound scanner disagreement using reviewed execution observations"
    )
    adjudicate_commands = adjudicate_parser.add_subparsers(dest="adjudicate_command")
    adjudicate_plan = adjudicate_commands.add_parser(
        "plan", help="construct an inert authorized test plan"
    )
    adjudicate_plan.add_argument("study", type=_path)
    adjudicate_plan.set_defaults(handler=_adjudicate_plan)
    adjudicate_evaluate = adjudicate_commands.add_parser(
        "evaluate", help="adjudicate already-recorded observations"
    )
    adjudicate_evaluate.add_argument("study", type=_path)
    adjudicate_evaluate.set_defaults(handler=_adjudicate_evaluate)

    disclose_parser = commands.add_parser(
        "disclose", help="prepare a local disclosure package without sending or publishing"
    )
    disclose_parser.add_argument("specification", type=_path)
    disclose_parser.set_defaults(handler=_disclose)

    compose_parser = commands.add_parser(
        "compose", help="plan or evaluate bounded multi-component interaction searches"
    )
    compose_commands = compose_parser.add_subparsers(dest="compose_command")
    compose_plan = compose_commands.add_parser(
        "plan", help="list deterministic candidates without executing them"
    )
    compose_plan.add_argument("graph", type=_path)
    compose_plan.add_argument("--strategy", choices=tuple(CompositionStrategy), default="pairwise")
    compose_plan.add_argument("--limit", type=int, default=100)
    compose_plan.add_argument("--t", type=int, default=3)
    compose_plan.set_defaults(handler=_compose_plan)
    compose_evaluate = compose_commands.add_parser(
        "evaluate", help="evaluate declared observations; never execute target actions"
    )
    compose_evaluate.add_argument("study", type=_path)
    compose_evaluate.add_argument(
        "--strategy", choices=tuple(CompositionStrategy), default="trigger-aware-sequence"
    )
    compose_evaluate.set_defaults(handler=_compose_evaluate)

    rehearse_parser = commands.add_parser(
        "rehearse", help="run a user-agent task only in a prepared substitute workspace"
    )
    rehearse_commands = rehearse_parser.add_subparsers(dest="rehearse_command")
    rehearse_prepare = rehearse_commands.add_parser(
        "prepare", help="create a credential-stripped disposable workspace"
    )
    rehearse_prepare.add_argument("source", type=_path)
    rehearse_prepare.add_argument("workspace", type=_path)
    rehearse_prepare.add_argument("--substitute", action="append")
    rehearse_prepare.set_defaults(handler=_rehearse_prepare)
    rehearse_run = rehearse_commands.add_parser(
        "run", help="execute a reviewed user-agent plan against substitutes"
    )
    rehearse_run.add_argument("specification", type=_path)
    rehearse_run.add_argument("workspace", type=_path)
    rehearse_run.add_argument("trace", type=_path)
    rehearse_run.add_argument("report", type=_path)
    rehearse_run.set_defaults(handler=_rehearse_run)
    rehearse_agent_run = rehearse_commands.add_parser(
        "agent-run",
        help="ask a tool-free provider to propose, review, and rehearse a substitute-only plan",
    )
    rehearse_agent_run.add_argument("request", type=_path)
    rehearse_agent_run.add_argument("provider_runtime", type=_path)
    rehearse_agent_run.add_argument("workspace", type=_path)
    rehearse_agent_run.add_argument("destination", type=_path)
    rehearse_agent_run.add_argument("--allow-provider-calls", action="store_true")
    rehearse_agent_run.set_defaults(handler=_rehearse_agent_run)
    rehearse_export = rehearse_commands.add_parser(
        "export", help="stage only explicitly approved file changes"
    )
    rehearse_export.add_argument("report", type=_path)
    rehearse_export.add_argument("workspace", type=_path)
    rehearse_export.add_argument("destination", type=_path)
    rehearse_export.add_argument("--approve", action="append", required=True)
    rehearse_export.set_defaults(handler=_rehearse_export)

    trace_parser = commands.add_parser(
        "trace", help="record an allowlisted local agent process or freeze a behavior snapshot"
    )
    trace_commands = trace_parser.add_subparsers(dest="trace_command")
    trace_run = trace_commands.add_parser(
        "run", help="record one shell-free allowlisted process into a signed trace"
    )
    trace_run.add_argument("specification", type=_path)
    trace_run.add_argument("destination", type=_path)
    trace_run.set_defaults(handler=_trace_run)
    trace_command = trace_commands.add_parser(
        "command",
        help="record one exact shell-free local command after interactive human approval",
    )
    trace_command.add_argument("destination", type=_path)
    trace_command.add_argument("--working-directory", type=_path, required=True)
    trace_command.add_argument("--timeout-seconds", type=float, default=60.0)
    trace_command.add_argument(
        "--capture-profile",
        choices=("lite", "standard", "forensic", "interpretability"),
        default="standard",
    )
    trace_command.add_argument("argv", nargs="+")
    trace_command.set_defaults(handler=_trace_command)
    trace_snapshot = trace_commands.add_parser(
        "snapshot", help="canonicalize declared behavior, environment, and methodology axes"
    )
    trace_snapshot.add_argument("specification", type=_path)
    trace_snapshot.add_argument("--output", type=_path)
    trace_snapshot.set_defaults(handler=_trace_snapshot)

    diff_parser = commands.add_parser(
        "diff", help="separate behavior drift from environment and methodology drift"
    )
    diff_parser.add_argument("left", type=_path)
    diff_parser.add_argument("right", type=_path)
    diff_parser.set_defaults(handler=_behavior_diff)

    sentinel_parser = commands.add_parser(
        "sentinel", help="run one local regression check and append local history"
    )
    sentinel_parser.add_argument("baseline", type=_path)
    sentinel_parser.add_argument("current", type=_path)
    sentinel_parser.add_argument("history", type=_path)
    sentinel_parser.add_argument("--policy", type=_path)
    sentinel_parser.set_defaults(handler=_sentinel)

    ci_parser = commands.add_parser("ci", help="apply a deterministic behavioral regression gate")
    ci_parser.add_argument("baseline", type=_path)
    ci_parser.add_argument("current", type=_path)
    ci_parser.add_argument("--policy", type=_path)
    ci_parser.add_argument("--sarif", type=_path)
    ci_parser.set_defaults(handler=_ci)

    methodology_parser = commands.add_parser(
        "methodology",
        help="compile bounded security methodology plans from native playbook contracts",
    )
    methodology_commands = methodology_parser.add_subparsers(dest="methodology_command")
    methodology_library = methodology_commands.add_parser(
        "library-export", help="export the pinned SOVA-native playbook library"
    )
    methodology_library.add_argument("destination", type=_path)
    methodology_library.set_defaults(handler=_methodology_library_export)
    methodology_validate = methodology_commands.add_parser(
        "playbook-validate", help="schema- and semantic-validate one playbook"
    )
    methodology_validate.add_argument("playbook", type=_path)
    methodology_validate.set_defaults(handler=_methodology_playbook_validate)
    methodology_policy = methodology_commands.add_parser(
        "policy-create", help="create a non-authorizing methodology policy for one profile"
    )
    methodology_policy.add_argument("profile", type=_path)
    methodology_policy.add_argument("destination", type=_path)
    methodology_policy.add_argument("--budget", type=int, default=100_000)
    methodology_policy.add_argument(
        "--scheduler",
        choices=tuple(item.value for item in SchedulerKind),
        default=SchedulerKind.EVIDENCE_GAP_BALANCED.value,
    )
    methodology_policy.add_argument(
        "--allow-effect",
        action="append",
        choices=tuple(item.value for item in EffectClass),
    )
    methodology_policy.set_defaults(handler=_methodology_policy_create)
    methodology_compile = methodology_commands.add_parser(
        "compile", help="compile a deterministic dependency- and budget-aware plan"
    )
    methodology_compile.add_argument("profile", type=_path)
    methodology_compile.add_argument("policy", type=_path)
    methodology_compile.add_argument("destination", type=_path)
    methodology_compile.add_argument("--intake-report", type=_path)
    methodology_compile.set_defaults(handler=_methodology_compile)
    methodology_observations = methodology_commands.add_parser(
        "observations-template",
        help="create an empty evidence-bound observation set for one compiled plan",
    )
    methodology_observations.add_argument("plan", type=_path)
    methodology_observations.add_argument("destination", type=_path)
    methodology_observations.add_argument(
        "--source-artifact-digest", action="append", required=True
    )
    methodology_observations.set_defaults(handler=_methodology_observations_template)
    methodology_replan = methodology_commands.add_parser(
        "replan", help="re-score plan status from observations without widening authority"
    )
    methodology_replan.add_argument("profile", type=_path)
    methodology_replan.add_argument("policy", type=_path)
    methodology_replan.add_argument("previous_plan", type=_path)
    methodology_replan.add_argument("observations", type=_path)
    methodology_replan.add_argument("destination", type=_path)
    methodology_replan.add_argument("--intake-report", type=_path)
    methodology_replan.set_defaults(handler=_methodology_replan)
    methodology_keygen = methodology_commands.add_parser(
        "keygen", help="create separate raw Ed25519 playbook contributor keys"
    )
    methodology_keygen.add_argument("private_key", type=_path)
    methodology_keygen.add_argument("public_key", type=_path)
    methodology_keygen.set_defaults(handler=_methodology_keygen)
    methodology_contribute = methodology_commands.add_parser(
        "contribute", help="sign and locally stage one playbook through Registry review gates"
    )
    methodology_contribute.add_argument("playbook", type=_path)
    methodology_contribute.add_argument("specification", type=_path)
    methodology_contribute.add_argument("private_key", type=_path)
    methodology_contribute.add_argument("public_key", type=_path)
    methodology_contribute.add_argument("destination", type=_path)
    methodology_contribute.add_argument("--confirm", action="store_true")
    methodology_contribute.set_defaults(handler=_methodology_contribute)

    adapter_parser = commands.add_parser(
        "adapter",
        help="inspect and offline-normalize curated external security-tool contracts",
    )
    adapter_commands = adapter_parser.add_subparsers(dest="adapter_command")
    adapter_catalog = adapter_commands.add_parser(
        "catalog", help="export the deterministic version-pinned adapter catalog"
    )
    adapter_catalog.add_argument("destination", type=_path)
    adapter_catalog.set_defaults(handler=_adapter_catalog_export)
    adapter_describe = adapter_commands.add_parser(
        "describe", help="export one exact adapter descriptor"
    )
    adapter_describe.add_argument("identifier")
    adapter_describe.add_argument("destination", type=_path)
    adapter_describe.set_defaults(handler=_adapter_describe)
    adapter_plan = adapter_commands.add_parser(
        "plan", help="create an inert operator-input template; never execute a tool"
    )
    adapter_plan.add_argument("identifier")
    adapter_plan.add_argument("destination", type=_path)
    adapter_plan.set_defaults(handler=_adapter_plan)
    adapter_normalize = adapter_commands.add_parser(
        "normalize", help="offline-normalize captured raw output; never create a finding"
    )
    adapter_normalize.add_argument("identifier")
    adapter_normalize.add_argument("invocation", type=_path)
    adapter_normalize.add_argument("raw", type=_path)
    adapter_normalize.add_argument("destination", type=_path)
    adapter_normalize.add_argument("--media-type")
    adapter_normalize.add_argument("--executable-digest", required=True)
    adapter_normalize.set_defaults(handler=_adapter_normalize)

    registry_parser = commands.add_parser(
        "registry", help="verify a repository-of-files registry entirely offline"
    )
    registry_commands = registry_parser.add_subparsers(dest="registry_command")
    registry_init = registry_commands.add_parser(
        "init-service", help="create a private local token for the community service"
    )
    registry_init.add_argument("token_file", type=_path)
    registry_init.set_defaults(handler=_registry_init_service)
    registry_prepare = registry_commands.add_parser(
        "prepare-upload", help="build a bounded local upload document without networking"
    )
    registry_prepare.add_argument("metadata", type=_path)
    registry_prepare.add_argument("capsule", type=_path)
    registry_prepare.add_argument("trace", type=_path)
    registry_prepare.add_argument("output", type=_path)
    registry_prepare.add_argument("--kind", choices=("registry", "leaderboard"), required=True)
    registry_prepare.set_defaults(handler=_registry_prepare_upload)
    registry_verify = registry_commands.add_parser("verify", help="verify index and objects")
    registry_verify.add_argument("root", type=_path)
    registry_verify.add_argument("--trusted-key-id", action="append")
    registry_verify.set_defaults(handler=_registry_verify)
    registry_replay = registry_commands.add_parser(
        "replay",
        help="verify and open one exact trusted registry capsule, including nested findings",
    )
    registry_replay.add_argument("root", type=_path)
    registry_replay.add_argument("entry_id")
    registry_replay.add_argument("version")
    registry_replay.add_argument("destination", type=_path)
    registry_replay.add_argument("--trusted-key-id", action="append", required=True)
    registry_replay.add_argument("--nested-capsule")
    registry_replay.add_argument(
        "--surface",
        choices=("browser", "computer"),
        help="select the exact digest-bound visual proof surface",
    )
    registry_replay.set_defaults(handler=_registry_replay)
    registry_serve = registry_commands.add_parser(
        "serve",
        help="serve a loopback-only staged registry and verified standard leaderboard",
    )
    registry_serve.add_argument("root", type=_path)
    registry_serve.add_argument("--token-file", type=_path, required=True)
    registry_serve.add_argument("--trusted-key-id", action="append", required=True)
    registry_serve.add_argument("--methodology", type=_path, required=True)
    registry_serve.add_argument("--host", default="127.0.0.1")
    registry_serve.add_argument("--port", type=int, default=8736)
    registry_serve.set_defaults(handler=_registry_serve)
    registry_verify_live = registry_commands.add_parser(
        "verify-live-index",
        help="verify a downloaded live index against an out-of-band service-key pin",
    )
    registry_verify_live.add_argument("index", type=_path)
    registry_verify_live.add_argument("--trusted-service-key-id", action="append", required=True)
    registry_verify_live.add_argument("--minimum-sequence", type=int, default=0)
    registry_verify_live.set_defaults(handler=_registry_verify_live_index)
    registry_health = registry_commands.add_parser(
        "healthcheck",
        help="verify the exact loopback readiness contract used by hardened deployments",
    )
    registry_health.add_argument(
        "--url",
        default="http://127.0.0.1:8736/v1/health",
        help="exact literal-loopback health URL",
    )
    registry_health.set_defaults(handler=_registry_healthcheck)

    monitor_parser = commands.add_parser(
        "monitor", help="run or inspect the durable local behavioral monitoring service"
    )
    monitor_commands = monitor_parser.add_subparsers(dest="monitor_command")
    monitor_serve = monitor_commands.add_parser(
        "serve", help="run declarative snapshot checks in one foreground scheduler"
    )
    monitor_serve.add_argument("specification", type=_path)
    monitor_serve.add_argument("state", type=_path)
    monitor_serve.add_argument("--workspace", type=_path, required=True)
    monitor_serve.add_argument("--once", action="store_true")
    monitor_serve.add_argument("--poll-seconds", type=float, default=0.25)
    monitor_serve.add_argument(
        "--alert-webhook",
        help="deliver failed runs to one HTTPS webhook (loopback HTTP allowed for fixtures)",
    )
    monitor_serve.add_argument(
        "--alert-secret-env",
        help="environment-variable name containing at least 32 bytes of webhook secret",
    )
    monitor_serve.set_defaults(handler=_monitor_serve)
    monitor_status = monitor_commands.add_parser(
        "status", help="inspect durable monitor state without starting the scheduler"
    )
    monitor_status.add_argument("specification", type=_path)
    monitor_status.add_argument("state", type=_path)
    monitor_status.add_argument("--workspace", type=_path, required=True)
    monitor_status.set_defaults(handler=_monitor_status)

    sync_parser = commands.add_parser(
        "sync", help="pull and atomically cache a verified local registry mirror"
    )
    sync_parser.add_argument("sources", nargs="+", type=_path)
    sync_parser.add_argument("--cache", required=True, type=_path)
    sync_parser.set_defaults(handler=_sync)

    contribute_parser = commands.add_parser(
        "contribute", help="preview and locally stage an explicit public contribution"
    )
    contribute_parser.add_argument("specification", type=_path)
    contribute_parser.add_argument("destination", type=_path)
    contribute_parser.add_argument("--confirm", action="store_true")
    contribute_parser.set_defaults(handler=_contribute)

    self_check_parser = commands.add_parser(
        "self-check", help="create or verify a local versionable file-integrity baseline"
    )
    self_check_commands = self_check_parser.add_subparsers(dest="self_check_command")
    self_check_create = self_check_commands.add_parser(
        "create", help="create a hash baseline for explicitly listed files"
    )
    self_check_create.add_argument("root", type=_path)
    self_check_create.add_argument("manifest", type=_path)
    self_check_create.add_argument("--include", action="append", required=True)
    self_check_create.set_defaults(handler=_self_check_create)
    self_check_verify = self_check_commands.add_parser(
        "verify", help="verify files against a protected baseline"
    )
    self_check_verify.add_argument("root", type=_path)
    self_check_verify.add_argument("manifest", type=_path)
    self_check_verify.set_defaults(handler=_self_check_verify)

    probe_parser = commands.add_parser(
        "probe", help="verify signed, nonce-bound local probe evidence"
    )
    probe_commands = probe_parser.add_subparsers(dest="probe_command")
    probe_issue = probe_commands.add_parser(
        "issue", help="sign one secret-free local probe response with an ephemeral key"
    )
    probe_issue.add_argument("request", type=_path)
    probe_issue.add_argument("destination", type=_path)
    probe_issue.set_defaults(handler=_probe_issue)
    probe_verify = probe_commands.add_parser(
        "verify", help="verify a signed probe response offline"
    )
    probe_verify.add_argument("response", type=_path)
    probe_verify.add_argument("--nonce", required=True)
    probe_verify.add_argument("--scope", action="append", required=True)
    probe_verify.add_argument("--key-id")
    probe_verify.add_argument("--revoked-key-id", action="append", default=[])
    probe_verify.set_defaults(handler=_probe_verify)

    engine_parser = commands.add_parser(
        "engine",
        help=("validate or run SOVA's authorization-gated heterogeneous multi-agent engine"),
    )
    engine_commands = engine_parser.add_subparsers(dest="engine_command")
    engine_validate = engine_commands.add_parser(
        "validate",
        help="effect-free validation of a strict multi-agent executor-chamber document",
    )
    engine_validate.add_argument("specification", type=_path)
    engine_validate.add_argument("--allow-provider-calls", action="store_true")
    engine_validate.add_argument("--allow-offensive-actions", action="store_true")
    engine_validate.set_defaults(handler=_engine_validate)
    engine_reproduce_plan = engine_commands.add_parser(
        "reproduce-plan",
        help=(
            "compile an engine finding capsule into a provider-free exact-action chamber "
            "document for a fresh authorized runtime"
        ),
    )
    engine_reproduce_plan.add_argument("capsule", type=_path)
    engine_reproduce_plan.add_argument("destination", type=_path)
    engine_reproduce_plan.set_defaults(handler=_engine_reproduce_plan)
    engine_run_web = engine_commands.add_parser(
        "run-web",
        help=("run 2-8 agents over an authorized browser and disposable file workspace"),
    )
    engine_run_web.add_argument("manifest", type=_path)
    engine_run_web.add_argument("mission", type=_path)
    engine_run_web.add_argument("specification", type=_path)
    engine_run_web.add_argument("destination", type=_path)
    engine_run_web.add_argument("--control-proof", type=_path)
    engine_run_web.add_argument("--package-runner", type=_path)
    engine_run_web.add_argument("--browser-executable", type=_path)
    engine_run_web.add_argument("--playwright-package-cache", type=_path)
    engine_run_web.add_argument("--playwright-browser-cache", type=_path)
    engine_run_web.add_argument("--workspace-seed", type=_path)
    engine_run_web.add_argument(
        "--runtime-surfaces",
        type=_path,
        help=(
            "strict sova.executor-engine-runtime document for disposable files and "
            "explicitly acknowledged shell-free host process templates"
        ),
    )
    engine_run_web.add_argument("--headed", action="store_true")
    engine_run_web.add_argument(
        "--record-video",
        action="store_true",
        help=(
            "request signed decisive video evidence; fails closed until the engine "
            "recorder lifecycle is available"
        ),
    )
    engine_run_web.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path for declared digest-pinned OCI planner participants",
    )
    _add_browser_profile_arguments(engine_run_web)
    engine_run_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured provider calls, which may incur cost",
    )
    engine_run_web.add_argument(
        "--allow-sandboxed-agent-code",
        action="store_true",
        help=("permit declared planner images only through separately approved attested gVisor"),
    )
    engine_run_web.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help="send only bounded secret-redacted target observations to declared planners",
    )
    engine_run_web.add_argument(
        "--allow-offensive-actions",
        action="store_true",
        help="exactly match an offensive=true mission and chamber authority declaration",
    )
    engine_run_web.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="stream each already-redacted event with its signed trace channel",
    )
    _add_contribution_arguments(engine_run_web)
    engine_run_web.set_defaults(handler=_engine_run_web)
    engine_run_software = engine_commands.add_parser(
        "run-software",
        help=(
            "launch and measure an authorized local application separately for discovery "
            "and reproduction, with disposable files, reviewed processes, and optional "
            "MELRA computer use"
        ),
    )
    engine_run_software.add_argument("manifest", type=_path)
    engine_run_software.add_argument("specification", type=_path)
    engine_run_software.add_argument("destination", type=_path)
    engine_run_software.add_argument("--executable", type=_path, required=True)
    engine_run_software.add_argument(
        "--launch-arg",
        action="append",
        default=[],
        help="one fixed target launch argv item; repeat for more (never interpreted by a shell)",
    )
    engine_run_software.add_argument("--workspace-seed", type=_path)
    engine_run_software.add_argument("--workspace-parent", type=_path)
    engine_run_software.add_argument(
        "--runtime-surfaces",
        type=_path,
        help=(
            "portable runtime document declaring multiple exact shell-free process "
            "templates; workspace.enabled must be false because software runs already "
            "include one disposable workspace"
        ),
    )
    engine_run_software.add_argument("--control-proof", type=_path, required=True)
    engine_run_software.add_argument("--window-title-contains")
    engine_run_software.add_argument(
        "--record-screen",
        action="store_true",
        help=(
            "record only the exact OS-attested target window and bind decisive frames "
            "to the signed finding replay"
        ),
    )
    engine_run_software.add_argument(
        "--recording-interval-seconds",
        type=float,
        default=0.5,
        help="bounded exact-window frame interval (0.1 to 5.0 seconds)",
    )
    engine_run_software.add_argument("--melra-node", type=_path)
    engine_run_software.add_argument("--melra-cli", type=_path)
    engine_run_software.add_argument("--melra-policy", type=_path)
    engine_run_software.add_argument(
        "--native-window-map",
        type=_path,
        help=(
            "operator-reviewed exact-window target map for dependency-free Windows "
            "click/type computer use; mutually exclusive with MELRA"
        ),
    )
    engine_run_software.add_argument(
        "--discover-native-window",
        action="store_true",
        help=(
            "dynamically discover visible enabled controls inside only the exact "
            "OS-attested target HWND on every planner observation"
        ),
    )
    engine_run_software.add_argument(
        "--melra-mutations",
        default="computer.click,computer.type",
        help="comma-separated reviewed computer mutation ceiling",
    )
    engine_run_software.add_argument("--process-template-id")
    engine_run_software.add_argument("--process-executable", type=_path)
    engine_run_software.add_argument("--process-argv-prefix", action="append", default=[])
    engine_run_software.add_argument("--trusted-host-process", action="store_true")
    engine_run_software.add_argument("--allow-provider-calls", action="store_true")
    engine_run_software.add_argument("--allow-offensive-actions", action="store_true")
    engine_run_software.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help="send only bounded secret-redacted target observations to declared planners",
    )
    engine_run_software.add_argument("--stream-jsonl", action="store_true")
    _add_contribution_arguments(engine_run_software)
    engine_run_software.set_defaults(handler=_engine_run_software)
    engine_swarm_software = engine_commands.add_parser(
        "swarm-software",
        help=(
            "run concurrent isolated agents over separately launched/measured software "
            "targets with a signed adaptive blackboard and aggregate effect budget"
        ),
    )
    engine_swarm_software.add_argument("manifest", type=_path)
    engine_swarm_software.add_argument(
        "specification",
        type=_path,
        help="one-active-participant sova.executor-chamber document template",
    )
    engine_swarm_software.add_argument("destination", type=_path)
    engine_swarm_software.add_argument("--agents", type=int, required=True)
    engine_swarm_software.add_argument("--persona", action="append", default=[])
    engine_swarm_software.add_argument("--max-concurrency", type=int, default=8)
    engine_swarm_software.add_argument("--executable", type=_path, required=True)
    engine_swarm_software.add_argument("--launch-arg", action="append", default=[])
    engine_swarm_software.add_argument("--workspace-seed", type=_path)
    engine_swarm_software.add_argument(
        "--runtime-surfaces",
        type=_path,
        help="portable multi-process runtime document (workspace.enabled must be false)",
    )
    engine_swarm_software.add_argument("--control-proof", type=_path, required=True)
    engine_swarm_software.add_argument("--window-title-contains")
    engine_swarm_software.add_argument("--record-screen", action="store_true")
    engine_swarm_software.add_argument("--recording-interval-seconds", type=float, default=0.5)
    engine_swarm_software.add_argument("--melra-node", type=_path)
    engine_swarm_software.add_argument("--melra-cli", type=_path)
    engine_swarm_software.add_argument("--melra-policy", type=_path)
    engine_swarm_software.add_argument("--native-window-map", type=_path)
    engine_swarm_software.add_argument("--discover-native-window", action="store_true")
    engine_swarm_software.add_argument("--melra-mutations", default="computer.click,computer.type")
    engine_swarm_software.add_argument("--process-template-id")
    engine_swarm_software.add_argument("--process-executable", type=_path)
    engine_swarm_software.add_argument("--process-argv-prefix", action="append", default=[])
    engine_swarm_software.add_argument("--trusted-host-process", action="store_true")
    engine_swarm_software.add_argument("--allow-provider-calls", action="store_true")
    engine_swarm_software.add_argument("--allow-offensive-actions", action="store_true")
    engine_swarm_software.add_argument("--allow-target-observation-disclosure", action="store_true")
    engine_swarm_software.add_argument("--stream-jsonl", action="store_true")
    _add_contribution_arguments(engine_swarm_software)
    engine_swarm_software.set_defaults(handler=_engine_swarm_software)
    engine_swarm_web = engine_commands.add_parser(
        "swarm-web",
        help=(
            "run N concurrent isolated agents, each its own browser context and "
            "workspace, over one authorized target, sharing a redacted blackboard"
        ),
    )
    engine_swarm_web.add_argument("manifest", type=_path)
    engine_swarm_web.add_argument("mission", type=_path)
    engine_swarm_web.add_argument(
        "specification",
        type=_path,
        help="one-participant sova.executor-chamber document template",
    )
    engine_swarm_web.add_argument("destination", type=_path)
    engine_swarm_web.add_argument(
        "--agents",
        type=int,
        help="number of concurrent agents; prompted interactively if omitted",
    )
    engine_swarm_web.add_argument("--persona", action="append", default=[])
    engine_swarm_web.add_argument("--allow-large-swarm", action="store_true")
    engine_swarm_web.add_argument("--max-concurrency", type=int, default=8)
    engine_swarm_web.add_argument("--control-proof", type=_path)
    engine_swarm_web.add_argument("--package-runner", type=_path)
    engine_swarm_web.add_argument("--browser-executable", type=_path)
    engine_swarm_web.add_argument("--playwright-package-cache", type=_path)
    engine_swarm_web.add_argument("--playwright-browser-cache", type=_path)
    engine_swarm_web.add_argument("--workspace-seed", type=_path)
    engine_swarm_web.add_argument(
        "--runtime-surfaces",
        type=_path,
        help=(
            "strict sova.executor-engine-runtime document applied independently to "
            "every worker for disposable files and reviewed shell-free processes"
        ),
    )
    engine_swarm_web.add_argument("--headed", action="store_true")
    engine_swarm_web.add_argument("--record-video", action="store_true")
    engine_swarm_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured provider calls, which may incur cost",
    )
    engine_swarm_web.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help="send only bounded secret-redacted target observations to declared planners",
    )
    engine_swarm_web.add_argument(
        "--allow-offensive-actions",
        action="store_true",
        help="exactly match an offensive=true mission and chamber authority declaration",
    )
    engine_swarm_web.add_argument("--stream-jsonl", action="store_true")
    _add_contribution_arguments(engine_swarm_web)
    engine_swarm_web.set_defaults(handler=_engine_swarm_web)
    engine_full_web = engine_commands.add_parser(
        "full-web",
        help=(
            "run one authorized agent over browser + workspace, plus an optional "
            "independently authorized MELRA/native Windows computer surface and/or "
            "one reviewed host process"
        ),
    )
    engine_full_web.add_argument("manifest", type=_path)
    engine_full_web.add_argument("mission", type=_path)
    engine_full_web.add_argument("specification", type=_path)
    engine_full_web.add_argument("destination", type=_path)
    engine_full_web.add_argument("--control-proof", type=_path)
    engine_full_web.add_argument("--package-runner", type=_path)
    engine_full_web.add_argument("--browser-executable", type=_path)
    engine_full_web.add_argument("--playwright-package-cache", type=_path)
    engine_full_web.add_argument("--playwright-browser-cache", type=_path)
    engine_full_web.add_argument("--workspace-seed", type=_path)
    engine_full_web.add_argument("--headed", action="store_true")
    engine_full_web.add_argument(
        "--record-video",
        action="store_true",
        help="record signed primary and reproduction videos with decisive oracle cues",
    )
    engine_full_web.add_argument(
        "--record-computer-screen",
        action="store_true",
        help="record the exact authorized computer HWND in both execution phases",
    )
    engine_full_web.add_argument(
        "--computer-recording-interval-seconds",
        type=float,
        default=0.5,
        help="bounded exact-window capture interval (0.1 to 5.0 seconds)",
    )
    engine_full_web.add_argument(
        "--melra-node",
        type=_path,
        help="MELRA Node.js executable; supplying this adds a computer surface",
    )
    engine_full_web.add_argument(
        "--melra-cli",
        type=_path,
        help="MELRA CLI entrypoint; required together with --melra-node",
    )
    engine_full_web.add_argument(
        "--melra-policy",
        type=_path,
        help="existing MELRA policy file copied into this run's disposable workspace",
    )
    engine_full_web.add_argument(
        "--melra-target-executable",
        "--computer-target-executable",
        dest="melra_target_executable",
        type=_path,
        help="exact executable image for OS measurement of the composed computer target",
    )
    engine_full_web.add_argument(
        "--melra-pid",
        "--computer-pid",
        dest="melra_pid",
        type=int,
        help="live computer-target pid; SOVA verifies its executable and process generation",
    )
    engine_full_web.add_argument(
        "--melra-window-id",
        "--computer-window-id",
        dest="melra_window_id",
        type=int,
        help="live target window handle; SOVA verifies ownership by the measured pid",
    )
    engine_full_web.add_argument(
        "--computer-target-manifest",
        type=_path,
        help=(
            "local-process target manifest independently authorizing the composed window; "
            "required for any computer backend"
        ),
    )
    engine_full_web.add_argument(
        "--computer-control-proof",
        type=_path,
        help=(
            "optional fresh local-possession proof for the computer target; when omitted "
            "SOVA captures one from the exact local executable and workspace seed"
        ),
    )
    engine_full_web.add_argument(
        "--native-window-map",
        type=_path,
        help="operator-reviewed exact-HWND coordinate map; mutually exclusive with MELRA",
    )
    engine_full_web.add_argument(
        "--discover-native-window",
        action="store_true",
        help=(
            "discover only visible enabled controls owned by the exact attested HWND; "
            "mutually exclusive with MELRA and --native-window-map"
        ),
    )
    engine_full_web.add_argument(
        "--melra-mutations",
        default="computer.click,computer.type",
        help="comma-separated reviewed computer mutation ceiling",
    )
    engine_full_web.add_argument(
        "--process-template-id",
        help="identifier for the one reviewed host-process template; adds a process surface",
    )
    engine_full_web.add_argument("--process-executable", type=_path)
    engine_full_web.add_argument(
        "--process-argv-prefix",
        action="append",
        default=[],
        help="one fixed reviewed argv-prefix item; repeat for more",
    )
    engine_full_web.add_argument(
        "--trusted-host-process",
        action="store_true",
        help="explicit operator acknowledgement required to admit a host-process template",
    )
    engine_full_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured provider calls, which may incur cost",
    )
    engine_full_web.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help="send only bounded secret-redacted target observations to declared planners",
    )
    engine_full_web.add_argument(
        "--allow-offensive-actions",
        action="store_true",
        help="exactly match an offensive=true mission and chamber authority declaration",
    )
    engine_full_web.add_argument("--stream-jsonl", action="store_true")
    _add_contribution_arguments(engine_full_web)
    engine_full_web.set_defaults(handler=_engine_full_web)
    engine_stress_web = engine_commands.add_parser(
        "stress-web",
        help=(
            "run a bounded authorized robustness ('stress') profile: the curated "
            "adversarial-tactic battery fanned across concurrent agents with "
            "bounded repetition, never raw request flooding"
        ),
    )
    engine_stress_web.add_argument("manifest", type=_path)
    engine_stress_web.add_argument(
        "specification",
        type=_path,
        help="one-participant sova.executor-chamber document template",
    )
    engine_stress_web.add_argument("destination", type=_path)
    engine_stress_web.add_argument("--entry-url", required=True)
    engine_stress_web.add_argument(
        "--agents",
        type=int,
        help="number of concurrent agents; prompted interactively if omitted",
    )
    engine_stress_web.add_argument(
        "--repetitions",
        type=int,
        default=1,
        help="bounded per-agent repeat passes over the tactic battery (max 25)",
    )
    engine_stress_web.add_argument(
        "--tactics",
        help=(
            "comma-separated adversarial tactic ids; defaults to the full curated "
            f"library ({', '.join(adversarial_tactic_ids())})"
        ),
    )
    engine_stress_web.add_argument("--control-proof", type=_path)
    engine_stress_web.add_argument("--package-runner", type=_path)
    engine_stress_web.add_argument("--browser-executable", type=_path)
    engine_stress_web.add_argument("--playwright-package-cache", type=_path)
    engine_stress_web.add_argument("--playwright-browser-cache", type=_path)
    engine_stress_web.add_argument("--headed", action="store_true")
    engine_stress_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured provider calls, which may incur cost",
    )
    engine_stress_web.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help="send only bounded secret-redacted target observations to declared planners",
    )
    engine_stress_web.add_argument("--stream-jsonl", action="store_true")
    _add_contribution_arguments(engine_stress_web)
    engine_stress_web.set_defaults(handler=_engine_stress_web)

    arena_parser = commands.add_parser(
        "arena", help="run deterministic local evidence-first Arena fixtures"
    )
    arena_commands = arena_parser.add_subparsers(dest="arena_command")
    arena_run = arena_commands.add_parser("run", help="run a strict local Arena document")
    arena_run.add_argument("specification", type=_path)
    arena_run.add_argument("destination", type=_path)
    arena_run.set_defaults(handler=_arena_run)
    arena_agent_run = arena_commands.add_parser(
        "agent-run",
        help="run provider-capable agents in a fully observed synthetic message environment",
    )
    arena_agent_run.add_argument("specification", type=_path)
    arena_agent_run.add_argument("destination", type=_path)
    arena_agent_run.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    arena_agent_run.add_argument(
        "--allow-sandboxed-agent-code",
        action="store_true",
        help="permit declared digest-pinned OCI participants through attested gVisor only",
    )
    arena_agent_run.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path when OCI participants are declared",
    )
    arena_agent_run.set_defaults(handler=_arena_agent_run)
    arena_chamber = arena_commands.add_parser(
        "chamber",
        help="run an authorized real-time multi-agent chamber with signed evidence",
    )
    arena_chamber.add_argument("specification", type=_path)
    arena_chamber.add_argument("destination", type=_path)
    arena_chamber.add_argument(
        "--authorize-contained-fixture",
        action="store_true",
        help="confirm the exact self-owned, inert, sink-only built-in environment",
    )
    arena_chamber.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="permit configured model-provider calls, which may incur operator cost",
    )
    arena_chamber.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="stream each already-redacted hash-chained event to stdout as it is persisted",
    )
    arena_chamber.set_defaults(handler=_arena_chamber)
    arena_web = arena_commands.add_parser(
        "web",
        help=(
            "run provider-backed Arena roles against one exactly authorized website "
            "with live signed-event streaming"
        ),
    )
    arena_web.add_argument("manifest", type=_path)
    arena_web.add_argument("campaign", type=_path)
    arena_web.add_argument("provider_runtime", type=_path)
    arena_web.add_argument("destination", type=_path)
    arena_web.add_argument("--control-proof", type=_path)
    arena_web.add_argument("--package-runner", type=_path)
    arena_web.add_argument("--browser-executable", type=_path)
    arena_web.add_argument("--playwright-browser-cache", type=_path)
    arena_web.add_argument("--headed", action="store_true")
    arena_web.add_argument("--record-video", action="store_true")
    _add_browser_profile_arguments(arena_web)
    arena_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    arena_web.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="stream each already-redacted hash-chained event with its trace channel",
    )
    arena_web.set_defaults(handler=_arena_web)
    arena_explore_web = arena_commands.add_parser(
        "explore-web",
        help=(
            "autonomously explore one exactly authorized website through SOVA's "
            "typed browser policy with signed traces and fresh reproduction"
        ),
    )
    arena_explore_web.add_argument("manifest", type=_path)
    arena_explore_web.add_argument("mission", type=_path)
    arena_explore_web.add_argument("provider_runtime", type=_path)
    arena_explore_web.add_argument("destination", type=_path)
    arena_explore_web.add_argument("--control-proof", type=_path)
    arena_explore_web.add_argument("--package-runner", type=_path)
    arena_explore_web.add_argument("--browser-executable", type=_path)
    arena_explore_web.add_argument("--playwright-browser-cache", type=_path)
    arena_explore_web.add_argument("--headed", action="store_true")
    arena_explore_web.add_argument("--record-video", action="store_true")
    arena_explore_web.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path when provider_runtime is a sova.oci-agent-runtime document",
    )
    _add_browser_profile_arguments(arena_explore_web)
    arena_explore_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    arena_explore_web.add_argument(
        "--allow-sandboxed-agent-code",
        action="store_true",
        help=(
            "permit a digest-pinned external agent image only through the required "
            "attested gVisor profile and an additional exact approval"
        ),
    )
    arena_explore_web.add_argument(
        "--allow-target-observation-disclosure",
        action="store_true",
        help=(
            "permit secret-redacted bounded accessibility snapshots from the controlled "
            "target to be sent to the configured planning provider"
        ),
    )
    arena_explore_web.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="stream each already-redacted signed event with its trace channel",
    )
    arena_explore_web.set_defaults(handler=_arena_explore_web)
    arena_swarm_web = arena_commands.add_parser(
        "swarm-web",
        help=(
            "run bounded model roles sequentially over one authorized, target-bound "
            "persistent browser identity"
        ),
    )
    arena_swarm_web.add_argument("manifest", type=_path)
    arena_swarm_web.add_argument("campaign", type=_path)
    arena_swarm_web.add_argument("specification", type=_path)
    arena_swarm_web.add_argument("destination", type=_path)
    arena_swarm_web.add_argument("--control-proof", type=_path)
    arena_swarm_web.add_argument("--package-runner", type=_path)
    arena_swarm_web.add_argument("--browser-executable", type=_path)
    arena_swarm_web.add_argument(
        "--playwright-browser-cache",
        type=_path,
        help="optional preinstalled Playwright browser cache used by trusted browser subruns",
    )
    arena_swarm_web.add_argument(
        "--headed",
        action="store_true",
        help="show the trusted browser during each sequential participant subrun",
    )
    arena_swarm_web.add_argument(
        "--record-video",
        action="store_true",
        help="record each browser subrun and emit decisive replay proof for a reproduced pass",
    )
    arena_swarm_web.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path for declared sova.oci-agent-runtime swarm participants",
    )
    _add_browser_profile_arguments(arena_swarm_web)
    arena_swarm_web.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help="explicitly permit configured model-provider calls, which may incur cost",
    )
    arena_swarm_web.add_argument(
        "--allow-sandboxed-agent-code",
        action="store_true",
        help=(
            "permit digest-pinned external swarm agents only through attested gVisor "
            "with no browser, network, credential, or host-mount authority"
        ),
    )
    arena_swarm_web.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="stream each redacted event with its coordinator or participant channel",
    )
    arena_swarm_web.set_defaults(handler=_arena_swarm_web)
    arena_run_software = arena_commands.add_parser(
        "run-software",
        parents=[engine_run_software],
        add_help=False,
        help=(
            "run the authorization-gated SOVA Engine against one phase-owned local "
            "application and preserve complete Arena evidence"
        ),
    )
    arena_run_software.set_defaults(handler=_arena_run_software_engine, arena_mode=True)
    arena_swarm_software = arena_commands.add_parser(
        "swarm-software",
        parents=[engine_swarm_software],
        add_help=False,
        help=(
            "run isolated adaptive SOVA Engine workers against separately launched "
            "software targets and merge their replayable findings"
        ),
    )
    arena_swarm_software.set_defaults(
        handler=_arena_swarm_software_engine,
        arena_mode=True,
    )
    arena_full_web = arena_commands.add_parser(
        "full-web",
        parents=[engine_full_web],
        add_help=False,
        help=(
            "run the complete authorization-gated browser, computer, workspace, and "
            "reviewed-process engine while preserving Arena evidence"
        ),
    )
    arena_full_web.set_defaults(handler=_arena_full_web_engine, arena_mode=True)

    leaderboard_parser = commands.add_parser(
        "leaderboard", help="build a verified static local leaderboard"
    )
    leaderboard_commands = leaderboard_parser.add_subparsers(dest="leaderboard_command")
    leaderboard_build = leaderboard_commands.add_parser(
        "build", help="build JSON and HTML from signed standard-profile evidence"
    )
    leaderboard_build.add_argument("specification", type=_path)
    leaderboard_build.add_argument("destination", type=_path)
    leaderboard_build.set_defaults(handler=_leaderboard_build)

    ctf_parser = commands.add_parser("ctf", help="build an inert local CTF catalog")
    ctf_commands = ctf_parser.add_subparsers(dest="ctf_command")
    ctf_build = ctf_commands.add_parser(
        "build", help="build a provenance-preserving reference-only CTF catalog"
    )
    ctf_build.add_argument("specification", type=_path)
    ctf_build.add_argument("destination", type=_path)
    ctf_build.set_defaults(handler=_ctf_build)

    extension_parser = commands.add_parser(
        "extension",
        help="inspect metadata or run one digest-pinned local subprocess extension",
    )
    extension_commands = extension_parser.add_subparsers(dest="extension_command")
    extension_discover = extension_commands.add_parser(
        "discover",
        help="list installed PyPA extension metadata without importing extension code",
    )
    extension_discover.set_defaults(handler=_extension_discover)
    extension_prepare = extension_commands.add_parser(
        "prepare",
        help="create a digest-pinned launch document without executing extension code",
    )
    extension_prepare.add_argument("manifest", type=_path)
    extension_prepare.add_argument("output", type=_path)
    extension_prepare.add_argument(
        "--operation", choices=("describe", "self-test", "invoke", "conform"), default="conform"
    )
    extension_prepare.add_argument("--executable", type=_path, required=True)
    extension_prepare.add_argument("--working-directory", type=_path, required=True)
    extension_prepare.add_argument("--argument", action="append", default=[])
    extension_prepare.add_argument("--payload", type=_path)
    extension_prepare.add_argument("--timeout", type=int, default=30)
    extension_prepare.set_defaults(handler=_extension_prepare)
    extension_run = extension_commands.add_parser(
        "run",
        help="interactively run one exact extension launch and capture signed evidence",
    )
    extension_run.add_argument("manifest", type=_path)
    extension_run.add_argument("launch", type=_path)
    extension_run.add_argument("destination", type=_path)
    extension_run.set_defaults(handler=_extension_run)

    agent_parser = commands.add_parser(
        "agent",
        help="attest and conform external agent images without granting host or target authority",
    )
    agent_commands = agent_parser.add_subparsers(dest="agent_command")
    agent_conform = agent_commands.add_parser(
        "conform-oci",
        help="run digest-pinned external-agent conformance through an attested gVisor runtime",
    )
    agent_conform.add_argument("runtime", type=_path)
    agent_conform.add_argument("destination", type=_path)
    agent_conform.add_argument(
        "--docker",
        type=_path,
        help="Docker CLI path; auto-detected when omitted",
    )
    agent_conform.set_defaults(handler=_agent_conform_oci)

    mcp_parser = commands.add_parser(
        "mcp", help="run or administer the local account-free SOVA MCP server"
    )
    mcp_commands = mcp_parser.add_subparsers(dest="mcp_command")
    mcp_manifest = mcp_commands.add_parser(
        "manifest", help="print the stable versioned local MCP tool manifest"
    )
    mcp_manifest.set_defaults(handler=_mcp_manifest)
    mcp_init = mcp_commands.add_parser(
        "init-control", help="create a local out-of-band control key"
    )
    mcp_init.add_argument("key_file", type=_path)
    mcp_init.set_defaults(handler=_mcp_init_control)
    mcp_approve = mcp_commands.add_parser(
        "approve", help="interactively approve one exact pending invocation"
    )
    mcp_approve.add_argument("challenge_id")
    mcp_approve.add_argument("--control-dir", type=_path, required=True)
    mcp_approve.add_argument("--key-file", type=_path, required=True)
    mcp_approve.add_argument("--workspace", type=_path, required=True)
    mcp_approve.set_defaults(handler=_mcp_approve)
    mcp_serve = mcp_commands.add_parser("serve", help="serve local SOVA MCP over stdio")
    mcp_serve.add_argument("--workspace", type=_path, required=True)
    mcp_serve.add_argument("--evidence-dir", type=_path, required=True)
    mcp_serve.add_argument("--control-dir", type=_path, required=True)
    mcp_serve.add_argument("--key-file", type=_path, required=True)
    mcp_serve.add_argument("--allow-sensitive-map", action="store_true")
    mcp_serve.set_defaults(handler=_mcp_serve)
    return parser


def _load_object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-ROOT-TYPE", "JSON root must be an object")
    return value


def _methodology_library_export(args: argparse.Namespace) -> int:
    library = load_builtin_library()
    document = library.to_mapping()
    validate_document(document, "sova.playbook-library")
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.playbook-library-export",
                "libraryDigest": library.digest,
                "playbookCount": len(library.playbooks),
                "destination": str(args.destination),
            }
        )
        + b"\n"
    )
    return 0


def _methodology_playbook_validate(args: argparse.Namespace) -> int:
    playbook = read_playbook(args.playbook)
    result = {
        "artifactType": "sova.playbook-validation",
        "schemaVersion": "0.1.0",
        "playbookId": playbook.identifier,
        "playbookVersion": playbook.version,
        "playbookDigest": playbook.digest,
        "accepted": True,
        "oracleCalibrationStatus": playbook.oracle_proposal.calibration_status,
        "externalProseEmbedded": False,
        "thirdPartyDatasetEmbedded": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


def _methodology_policy_create(args: argparse.Namespace) -> int:
    profile = read_target_profile(args.profile)
    effects = (
        tuple(EffectClass(item) for item in args.allow_effect)
        if args.allow_effect
        else (
            EffectClass.OBSERVE,
            EffectClass.READ_TARGET,
            EffectClass.AUTHENTICATE,
            EffectClass.MUTATE_REVERSIBLE,
            EffectClass.CONSUME_BOUNDED_RESOURCE,
            EffectClass.EXECUTE_CONTAINED_CODE,
        )
    )
    policy = methodology_policy_template(
        profile.digest,
        max_budget_units=args.budget,
        scheduler=SchedulerKind(args.scheduler),
        allowed_effects=effects,
    )
    document = policy.to_mapping()
    validate_document(document, "sova.methodology-policy")
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _methodology_compile(args: argparse.Namespace) -> int:
    profile = read_target_profile(args.profile)
    policy_document = _load_object(args.policy)
    validate_document(policy_document, "sova.methodology-policy")
    policy = methodology_policy_from_mapping(policy_document)
    intake_report = None if args.intake_report is None else _load_object(args.intake_report)
    plan = compile_methodology(profile, policy, intake_report=intake_report)
    _write_new_document(args.destination, plan)
    sys.stdout.buffer.write(canonical_json_bytes(plan) + b"\n")
    return 0


def _methodology_observations_template(args: argparse.Namespace) -> int:
    plan = _load_object(args.plan)
    validate_methodology_plan(plan)
    observations = MethodologyObservationSet(
        target_profile_digest=plan["targetProfileDigest"],
        previous_plan_digest=plan["contentDigest"],
        source_artifact_digests=tuple(args.source_artifact_digest),
        observations=(),
    )
    document = observations.to_mapping()
    validate_document(document, "sova.methodology-observations")
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _methodology_replan(args: argparse.Namespace) -> int:
    profile = read_target_profile(args.profile)
    policy_document = _load_object(args.policy)
    validate_document(policy_document, "sova.methodology-policy")
    policy = methodology_policy_from_mapping(policy_document)
    previous_plan = _load_object(args.previous_plan)
    observation_document = _load_object(args.observations)
    validate_document(observation_document, "sova.methodology-observations")
    observations = observation_set_from_mapping(observation_document)
    intake_report = None if args.intake_report is None else _load_object(args.intake_report)
    plan = replan_methodology(
        profile,
        policy,
        previous_plan,
        observations,
        intake_report=intake_report,
    )
    _write_new_document(args.destination, plan)
    sys.stdout.buffer.write(canonical_json_bytes(plan) + b"\n")
    return 0


def _methodology_keygen(args: argparse.Namespace) -> int:
    keypair = generate_ed25519_keypair()
    _write_new_bytes(args.private_key, keypair.private_key, mode=0o600)
    try:
        _write_new_bytes(args.public_key, keypair.public_key, mode=0o644)
    except BaseException:
        args.private_key.unlink(missing_ok=True)
        raise
    result = {
        "artifactType": "sova.playbook-contributor-keypair",
        "schemaVersion": "0.1.0",
        "keyid": keypair.key_id,
        "privateKeyPrinted": False,
        "publisherIdentityEstablished": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


def _methodology_contribute(args: argparse.Namespace) -> int:
    playbook = read_playbook(args.playbook)
    receipt = prepare_playbook_contribution(
        playbook,
        _load_object(args.specification),
        args.private_key.read_bytes(),
        args.public_key.read_bytes(),
        args.destination,
        confirmed=args.confirm,
    )
    sys.stdout.buffer.write(canonical_json_bytes(receipt) + b"\n")
    return 0


def _adapter_catalog_export(args: argparse.Namespace) -> int:
    descriptors = [item.to_mapping() for item in security_adapter_catalog()]
    for descriptor in descriptors:
        validate_document(descriptor, "sova.adapter-descriptor")
    document = {
        "artifactType": "sova.adapter-catalog",
        "schemaVersion": "0.1.0",
        "descriptorCount": len(descriptors),
        "descriptors": descriptors,
        "catalogDigest": sha256_digest(canonical_json_bytes(descriptors)),
        "installationPerformed": False,
        "executionAuthorized": False,
    }
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _adapter_describe(args: argparse.Namespace) -> int:
    document = get_security_adapter(str(args.identifier)).to_mapping()
    validate_document(document, "sova.adapter-descriptor")
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _adapter_plan(args: argparse.Namespace) -> int:
    descriptor = get_security_adapter(str(args.identifier))
    document = {
        "artifactType": "sova.adapter-execution-plan-template",
        "schemaVersion": "0.1.0",
        "adapterId": descriptor.identifier,
        "descriptorDigest": descriptor.digest,
        "admission": descriptor.admission.value,
        "tool": {
            "name": descriptor.tool_name,
            "version": descriptor.tool_version,
            "executableNames": list(descriptor.executable_names),
            "executableDigestPolicy": descriptor.executable_digest_policy,
        },
        "requiredBindings": [
            "targetId",
            "targetProfileDigest",
            "targetGeneration",
            "exactExecutablePathAndDigest",
            "capturedVersionEvidenceDigest",
            "configurationDigestWhenRequired",
            "rulesetDigestWhenRequired",
            "disclosureGateForExternalTransfer",
            "freshAuthorizationDecision",
            "requiredContainmentAttestation",
        ],
        "requirements": descriptor.to_mapping()["requirements"],
        "bounds": descriptor.to_mapping()["execution"]["bounds"],
        "privacyDefaults": descriptor.to_mapping()["privacyDefaults"],
        "commandMaterialized": False,
        "executionPerformed": False,
        "executionAuthorized": False,
        "findingConfirmed": False,
    }
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _adapter_invocation_from_mapping(document: dict[str, Any]) -> AdapterInvocation:
    required = {
        "id",
        "descriptorId",
        "targetId",
        "target",
        "targetPredicate",
        "targetProfileDigest",
        "targetGeneration",
        "executablePath",
        "observedToolVersion",
        "versionEvidenceDigest",
    }
    missing = sorted(required - set(document))
    if missing:
        raise FormatError(
            "SOVA-CLI-ADAPTER-INVOCATION",
            "adapter invocation is missing required fields",
            details={"missing": missing},
        )
    return AdapterInvocation(
        identifier=str(document["id"]),
        descriptor_id=str(document["descriptorId"]),
        target_id=str(document["targetId"]),
        target=str(document["target"]),
        target_predicate=str(document["targetPredicate"]),
        target_profile_digest=str(document["targetProfileDigest"]),
        target_generation=str(document["targetGeneration"]),
        executable_path=str(document["executablePath"]),
        observed_tool_version=str(document["observedToolVersion"]),
        version_evidence_digest=str(document["versionEvidenceDigest"]),
        output_path=(
            str(document["outputPath"]) if document.get("outputPath") is not None else None
        ),
        config_path=(
            str(document["configPath"]) if document.get("configPath") is not None else None
        ),
        config_digest=(
            str(document["configDigest"]) if document.get("configDigest") is not None else None
        ),
        ruleset_path=(
            str(document["rulesetPath"]) if document.get("rulesetPath") is not None else None
        ),
        ruleset_digest=(
            str(document["rulesetDigest"]) if document.get("rulesetDigest") is not None else None
        ),
        disclosure_gate_id=(
            str(document["disclosureGateId"])
            if document.get("disclosureGateId") is not None
            else None
        ),
        disclosure_gate_digest=(
            str(document["disclosureGateDigest"])
            if document.get("disclosureGateDigest") is not None
            else None
        ),
    )


def _adapter_normalize(args: argparse.Namespace) -> int:
    descriptor = get_security_adapter(str(args.identifier))
    invocation = _adapter_invocation_from_mapping(_load_object(args.invocation))
    media_type = str(args.media_type or descriptor.output_media_types[0])
    observations = normalize_security_output(
        descriptor,
        invocation,
        executable_digest=str(args.executable_digest),
        raw=args.raw.read_bytes(),
        media_type=media_type,
    )
    for observation in observations:
        validate_document(observation.to_mapping(), "sova.normalized-observation")
    document = {
        "artifactType": "sova.normalized-observation-set",
        "schemaVersion": "0.1.0",
        "adapterId": descriptor.identifier,
        "descriptorDigest": descriptor.digest,
        "observationCount": len(observations),
        "observations": [item.to_mapping() for item in observations],
        "executionPerformed": False,
        "findingConfirmed": False,
    }
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _init(args: argparse.Namespace) -> int:
    report = initialize_instance(args.root, provider=args.provider, registry=args.registry)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _doctor(args: argparse.Namespace) -> int:
    report = diagnose_instance(args.root)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["status"] == "pass" else 1


def _data_delete(args: argparse.Namespace) -> int:
    report = delete_instance_data(
        args.root,
        instance_id=str(args.instance_id),
        confirmed=bool(args.yes),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _release_sbom(args: argparse.Namespace) -> int:
    report = write_cyclonedx_sbom(args.lock, args.destination, scope=str(args.scope))
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _release_cargo_sbom(args: argparse.Namespace) -> int:
    report = write_cargo_cyclonedx_sbom(args.lock, args.destination, root=str(args.root))
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _release_checksums(args: argparse.Namespace) -> int:
    report = write_checksums(args.root, args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _release_verify_checksums(args: argparse.Namespace) -> int:
    report = verify_checksums(args.root, args.manifest)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["accepted"] else 1


def _release_keygen(args: argparse.Namespace) -> int:
    if args.private_key.resolve() == args.public_key.resolve():
        raise FormatError("SOVA-P6-LAUNCH-KEY", "private and public key paths must differ")
    keypair = generate_ed25519_keypair()
    _write_new_bytes(args.private_key, keypair.private_key, mode=0o600)
    try:
        _write_new_bytes(args.public_key, keypair.public_key, mode=0o644)
    except BaseException:
        args.private_key.unlink(missing_ok=True)
        raise
    report = {
        "artifactType": "sova.launch-evidence-keypair",
        "schemaVersion": "0.1.0",
        "keyId": keypair.key_id,
        "privateKeyPrinted": False,
        "identityEstablished": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _release_sign_evidence(args: argparse.Namespace) -> int:
    envelope = sign_launch_evidence(
        _load_object(args.document),
        args.private_key.read_bytes(),
        args.public_key.read_bytes(),
    )
    _write_new_document(args.destination, envelope)
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.launch-evidence-signed",
                "schemaVersion": "0.1.0",
                "keyId": envelope["signatures"][0]["keyid"],
                "destination": str(args.destination.resolve()),
                "identityEstablished": False,
            }
        )
        + b"\n"
    )
    return 0


def _release_dossier_input(path: Path, role: str, *, maximum_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FormatError("SOVA-P6-LAUNCH-FILE", f"{role} must be a regular non-symlink file")
    if path.stat().st_size > maximum_bytes:
        raise FormatError("SOVA-P6-LAUNCH-FILE", f"{role} exceeds its byte limit")
    return path.read_bytes()


def _release_evidence_object(path: Path, role: str) -> dict[str, Any]:
    value = strict_json_loads(
        _release_dossier_input(path, role, maximum_bytes=8 * 1024 * 1024),
        max_bytes=8 * 1024 * 1024,
        max_items=100_000,
        max_depth=64,
    )
    if not isinstance(value, dict):
        raise FormatError("SOVA-P6-LAUNCH-FILE", f"{role} root must be an object")
    return value


def _release_assemble_evidence(args: argparse.Namespace) -> int:
    document = assemble_launch_bundle(
        trust_policy=_release_evidence_object(args.trust_policy, "trust policy"),
        protocol=_release_evidence_object(args.protocol, "evaluation protocol"),
        observation_envelope=_release_evidence_object(
            args.observation_ledger, "signed observation ledger"
        ),
        registry_policy=_release_evidence_object(args.registry_policy, "Registry policy"),
        operational_envelopes=tuple(
            _release_evidence_object(path, "signed operational receipt")
            for path in args.operational_receipt
        ),
        candidate=_release_evidence_object(args.candidate, "release candidate"),
        review_envelopes=tuple(
            _release_evidence_object(path, "signed review receipt") for path in args.review_receipt
        ),
        gate_envelopes=tuple(
            _release_evidence_object(path, "signed launch-gate receipt")
            for path in args.gate_receipt
        ),
    )
    _write_new_document(args.destination, document)
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.launch-evidence-assembled",
                "schemaVersion": "0.1.0",
                "bundleDigest": document["contentDigest"],
                "operationalReceiptCount": len(args.operational_receipt),
                "reviewReceiptCount": len(args.review_receipt),
                "launchGateReceiptCount": len(args.gate_receipt),
                "destination": str(args.destination.resolve()),
                "signaturesVerified": False,
                "publicationPerformed": False,
            }
        )
        + b"\n"
    )
    return 0


def _release_dossier(args: argparse.Namespace) -> int:
    bundle = read_launch_bundle(
        _release_dossier_input(args.bundle, "launch bundle", maximum_bytes=32 * 1024 * 1024)
    )
    dossier = evaluate_launch_bundle(
        bundle,
        artifact_manifest=_release_dossier_input(
            args.artifact_manifest, "artifact manifest", maximum_bytes=16 * 1024 * 1024
        ),
        claims_register=_release_dossier_input(
            args.claims_register, "claims register", maximum_bytes=16 * 1024 * 1024
        ),
        public_claims_snapshot=_release_dossier_input(
            args.public_claims_snapshot,
            "public claims snapshot",
            maximum_bytes=4 * 1024 * 1024,
        ),
        expected_commit=str(args.expected_commit),
        expected_trust_policy_digest=str(args.expected_trust_policy_digest),
    )
    _write_new_document(args.destination, dossier)
    sys.stdout.buffer.write(canonical_json_bytes(dossier) + b"\n")
    return 0 if dossier["tagOrPublishAllowed"] else 3


def _acceptance_run(args: argparse.Namespace) -> int:
    receipts = load_receipts(args.receipts) if args.receipts is not None else ()
    artifacts = run_offline_acceptance_lab(args.destination, receipts=receipts)
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 1


def _acceptance_evaluate(args: argparse.Namespace) -> int:
    report = evaluate_release_readiness(load_receipts(args.receipts)).to_mapping()
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["readyForStable1"] else 3


def _acceptance_template(args: argparse.Namespace) -> int:
    document = acceptance_receipt_template(str(args.gate))
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "status": "template-only",
                "gateId": document["gateId"],
                "destination": str(args.destination.resolve()),
            }
        )
        + b"\n"
    )
    return 0


def _conformance_export(args: argparse.Namespace) -> int:
    report = export_conformance_kit(args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _conformance_verify(args: argparse.Namespace) -> int:
    report = verify_conformance_kit(args.path)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["accepted"] else 1


def _target_template(args: argparse.Namespace) -> int:
    document = target_template(TargetKind(str(args.kind)))
    args.destination.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.write(f"WROTE {args.destination}\n")
    return 0


def _target_validate(args: argparse.Namespace) -> int:
    target = target_manifest_from_mapping(_load_object(args.manifest))
    report = validate_target_manifest(target)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["accepted"] else 1


def _target_plan(args: argparse.Namespace) -> int:
    target = target_manifest_from_mapping(_load_object(args.manifest))
    plan = build_assessment_plan(target)
    args.destination.write_bytes(canonical_json_bytes(plan) + b"\n")
    sys.stdout.write(f"{plan['planDigest']}  {args.destination}\n")
    return 0


def _target_fixture(args: argparse.Namespace) -> int:
    artifacts = run_reference_assessment(str(args.kind), args.destination)
    report = _load_object(artifacts.report)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["status"] == "pass" else 1


def _target_challenge(args: argparse.Namespace) -> int:
    target = target_manifest_from_mapping(_load_object(args.manifest))
    challenge = create_website_control_challenge(target)
    args.destination.write_bytes(canonical_json_bytes(challenge.to_mapping()) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(challenge.to_mapping()) + b"\n")
    return 0


def _target_prove(args: argparse.Namespace) -> int:
    target = target_manifest_from_mapping(_load_object(args.manifest))
    challenge = challenge_from_mapping(_load_object(args.challenge))
    expected_origin = target.configuration.get("allowedOrigins")
    if expected_origin != [challenge.origin]:
        raise FormatError(
            "SOVA-CONTROL-TARGET-MISMATCH",
            "challenge does not match the target manifest's exact origin",
        )
    proof = collect_website_control_proof(challenge)
    args.destination.write_bytes(canonical_json_bytes(proof.to_mapping()) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(proof.to_mapping()) + b"\n")
    return 0


def _target_prove_software(args: argparse.Namespace) -> int:
    target = target_manifest_from_mapping(_load_object(args.manifest))
    proof = create_local_software_control_proof(
        target,
        args.executable,
        workspace_seed=args.workspace_seed,
    )
    args.destination.write_bytes(canonical_json_bytes(proof.to_mapping()) + b"\n")
    report = {
        "artifactType": "sova.local-software-control-proof-result",
        "schemaVersion": "0.1.0",
        "proof": str(args.destination),
        "authorityTarget": proof.subject,
        "expiresAt": proof.to_mapping()["expiresAt"],
        "executableDigest": proof.evidence["executableDigest"],
        "workspaceFingerprint": proof.evidence["workspaceFingerprint"],
        "targetDigest": proof.evidence["targetDigest"],
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _target_browser_kit(args: argparse.Namespace) -> int:
    report = create_browser_test_kit(str(args.origin), args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _target_profile_create(args: argparse.Namespace) -> int:
    target_kinds = tuple(ProfileTargetKind(value) for value in dict.fromkeys(args.kind))
    base = target_profile_template(
        identifier=str(args.identifier),
        title=str(args.title or args.identifier),
        target_kinds=target_kinds,
        authorization_scope=str(args.authorization_scope),
    )
    inputs = tuple(
        _target_profile_material(value, required=required)
        for required, values in ((True, args.material), (False, args.optional_material))
        for value in values
    )
    entrypoints = tuple(_target_profile_entrypoint(value) for value in args.entrypoint)
    profile = TargetProfile(
        identifier=base.identifier,
        version=base.version,
        title=base.title,
        target_kinds=base.target_kinds,
        authorization_scope=base.authorization_scope,
        entrypoints=entrypoints,
        inputs=inputs,
        constraints=base.constraints,
        provenance=base.provenance,
    )
    _write_new_document(args.destination, profile.to_mapping())
    report = validate_target_profile(profile)
    report["profile"] = str(args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _target_profile_material(value: str, *, required: bool) -> InputDescriptor:
    parts = value.split("=", maxsplit=3)
    if len(parts) != _INTAKE_SPEC_PARTS or not all(parts):
        raise FormatError(
            "SOVA-CLI-INTAKE-MATERIAL",
            "material must use ID=KIND=SOURCE=PATH",
        )
    identifier, kind_value, source_value, raw_path = parts
    try:
        kind = InputKind(kind_value)
        source = SourceClass(source_value)
    except ValueError as error:
        raise FormatError(
            "SOVA-CLI-INTAKE-MATERIAL", "material kind or source class is unsupported"
        ) from error
    return describe_material(
        Path(raw_path),
        identifier=identifier,
        kind=kind,
        source_class=source,
        required=required,
    )


def _target_profile_entrypoint(value: str) -> EntryPoint:
    parts = value.split("=", maxsplit=3)
    if len(parts) != _INTAKE_SPEC_PARTS or not all(parts):
        raise FormatError(
            "SOVA-CLI-INTAKE-ENTRYPOINT",
            "entrypoint must use ID=KIND=TARGET_KINDS=LOCATOR",
        )
    identifier, kind_value, target_values, locator = parts
    try:
        return EntryPoint(
            id=identifier,
            kind=EntryPointKind(kind_value),
            locator=locator,
            target_kinds=tuple(ProfileTargetKind(item) for item in target_values.split(",")),
        )
    except ValueError as error:
        raise FormatError("SOVA-CLI-INTAKE-ENTRYPOINT", "entrypoint kind is unsupported") from error


def _target_profile_validate(args: argparse.Namespace) -> int:
    profile = read_target_profile(args.profile)
    report = validate_target_profile(profile)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0 if report["accepted"] else 1


def _target_intake(args: argparse.Namespace) -> int:
    profile = read_target_profile(args.profile)
    bindings = {
        descriptor.id: candidate
        for descriptor in profile.inputs
        if (candidate := args.profile.parent / descriptor.logical_locator).exists()
    }
    for value in args.material:
        identifier, separator, raw_path = value.partition("=")
        if not separator or not identifier or not raw_path:
            raise FormatError("SOVA-CLI-INTAKE-MATERIAL", "material override must use ID=PATH")
        bindings[identifier] = Path(raw_path)
    artifacts = run_universal_intake(
        profile,
        bindings,
        args.destination,
        active_observations_authorized=bool(args.authorize_active_observations),
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 2 if artifacts.status == "inconclusive" else 0


def _inspect(args: argparse.Namespace) -> int:
    sys.stdout.write(render_capsule(args.path))
    return 0


def _record_agentdojo(args: argparse.Namespace) -> int:
    return record_agentdojo(
        args.source,
        args.out,
        author=args.author,
        bundle=args.bundle,
        bundle_name=args.name,
        stdout=sys.stdout,
    )


def _record_inspect_log(args: argparse.Namespace) -> int:
    return record_inspect_logs(
        args.source, args.out, author=args.author, stdout=sys.stdout, stderr=sys.stderr
    )


def _record_inspect(args: argparse.Namespace) -> int:
    return record_inspect(
        args.source,
        license_expression=args.license,
        source_url=args.source_url,
        destination=args.out,
        stdout=sys.stdout,
    )


def _record_trace(args: argparse.Namespace) -> int:
    return record_trace_attestation(
        args.source,
        license_expression=args.license,
        source_url=args.source_url,
        destination=args.out,
        stdout=sys.stdout,
    )


def _show(args: argparse.Namespace) -> int:
    return show_artifact(args.path, sys.stdout)


def _audit(args: argparse.Namespace) -> int:
    return run_audit(
        args.path,
        spec_reference=args.spec,
        json_destination=args.json,
        limit=args.limit,
        stdout=sys.stdout,
    )


def _detected_path(explicit: Path | None, candidates: tuple[str, ...], role: str) -> Path:
    if explicit is not None:
        value = explicit.resolve()
        if value.is_file():
            return value
        raise FormatError("SOVA-LIVE-EXECUTABLE", f"{role} does not exist")
    for candidate in candidates:
        discovered = shutil.which(candidate)
        if discovered:
            return Path(discovered).resolve()
        local = Path(candidate)
        if local.is_file():
            return local.resolve()
    raise FormatError(
        "SOVA-LIVE-EXECUTABLE",
        f"{role} was not detected; pass its exact path explicitly",
    )


def _detonate_owned_web_fixture(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-LIVE-INTERACTIVE-APPROVAL",
            "live detonation requires a human-operated interactive terminal",
        )
    package_runner = _detected_path(
        args.package_runner,
        ("npx.cmd", "npx"),
        "Node package runner",
    )
    browser = _detected_path(
        args.browser_executable,
        (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "chrome.exe",
            "msedge.exe",
        ),
        "Chromium browser executable",
    )

    def prompt(challenge: Any, intents: Any) -> str:
        review = [
            {
                "target": intent.target,
                "action": intent.action,
                "effect": intent.effect.name.lower(),
                "domain": intent.domain,
                "offensive": intent.offensive,
                "irreversible": intent.irreversible,
                "requiredEvidence": sorted(intent.required_evidence),
            }
            for intent in intents
        ]
        sys.stderr.write(json.dumps({"approvedIntents": review}, indent=2) + "\n")
        sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
        return input("approval> ")

    artifacts = run_owned_web_vertical_slice(
        args.destination,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=prompt,
        headless=not args.headed,
        record_video=args.record_video,
        browser_cache=args.playwright_browser_cache,
    )
    sys.stdout.write(
        json.dumps(
            {
                "status": artifacts.status,
                "destination": str(args.destination.resolve()),
                "trace": str(artifacts.trace),
                "reproductionTrace": str(artifacts.reproduction_trace),
                "evidenceCapsule": str(artifacts.evidence_capsule),
                "report": str(artifacts.report),
                "visualReplays": [str(path) for path in artifacts.visual_replays],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0 if artifacts.status == "pass" else 1


def _detonate_action_lab(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-LIVE-INTERACTIVE-APPROVAL",
            "consequential-action lab requires a human-operated interactive terminal",
        )
    package_runner = _detected_path(
        args.package_runner,
        ("npx.cmd", "npx"),
        "Node package runner",
    )
    browser = _detected_path(
        args.browser_executable,
        (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "chrome.exe",
            "msedge.exe",
        ),
        "Chromium browser executable",
    )

    def prompt(challenge: Any, intents: Any) -> str:
        review = [
            {
                "target": intent.target,
                "action": intent.action,
                "effect": intent.effect.name.lower(),
                "domain": intent.domain,
                "offensive": intent.offensive,
                "irreversible": intent.irreversible,
                "requiredEvidence": sorted(intent.required_evidence),
            }
            for intent in intents
        ]
        sys.stderr.write(json.dumps({"approvedIntents": review}, indent=2) + "\n")
        sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
        return input("approval> ")

    artifacts = run_owned_action_lab_vertical_slice(
        args.destination,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=prompt,
        headless=not args.headed,
        record_video=args.record_video,
        browser_cache=args.playwright_browser_cache,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 1


def _detonate_browser(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-LIVE-INTERACTIVE-APPROVAL",
            "live detonation requires a human-operated interactive terminal",
        )
    target = target_manifest_from_mapping(_load_object(args.manifest))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner = _detected_path(
        args.package_runner,
        ("npx.cmd", "npx"),
        "Node package runner",
    )
    browser = _detected_path(
        args.browser_executable,
        (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "chrome.exe",
            "msedge.exe",
        ),
        "Chromium browser executable",
    )

    def prompt(challenge: Any, intents: Any) -> str:
        sys.stderr.write(
            json.dumps(
                {
                    "approvedIntents": [
                        {
                            "target": intent.target,
                            "action": intent.action,
                            "effect": intent.effect.name.lower(),
                            "domain": intent.domain,
                            "offensive": intent.offensive,
                            "irreversible": intent.irreversible,
                            "requiredEvidence": sorted(intent.required_evidence),
                        }
                        for intent in intents
                    ]
                },
                indent=2,
            )
            + "\n"
        )
        sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
        return input("approval> ")

    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_live_browser_assessment(
            target,
            args.capsule,
            args.destination,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=prompt,
            control_proof=proof,
            profile_lease=profile_lease,
            headless=not args.headed,
            record_video=args.record_video,
            browser_cache=args.playwright_browser_cache,
        )
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "status": artifacts.status,
                "trace": str(artifacts.trace),
                "reproductionTrace": str(artifacts.reproduction_trace),
                "evidenceCapsule": str(artifacts.evidence_capsule),
                "report": str(artifacts.report),
                "visualReplays": [str(path) for path in artifacts.visual_replays],
            }
        )
        + b"\n"
    )
    return 0 if artifacts.status == "pass" else 1


def _software_approval_prompt(challenge: Any, intents: Any) -> str:
    sys.stderr.write(
        json.dumps(
            {
                "approvedIntents": [
                    {
                        "id": intent.id,
                        "target": intent.target,
                        "action": intent.action,
                        "effect": intent.effect.name.lower(),
                        "offensive": intent.offensive,
                        "irreversible": intent.irreversible,
                        "requiredEvidence": sorted(intent.required_evidence),
                    }
                    for intent in intents
                ],
                "hostProcessWarning": (
                    "The admitted executable is trusted by the operator. This is restricted "
                    "host-process execution, not a security sandbox; network and writes outside "
                    "the disposable workspace are not independently blocked or observed."
                ),
            },
            indent=2,
        )
        + "\n"
    )
    sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
    return input("approval> ")


def _require_live_software_terminal() -> None:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-SOFTWARE-INTERACTIVE-APPROVAL",
            "live software detonation requires a human-operated interactive terminal",
        )


def _detonate_owned_software_fixture(args: argparse.Namespace) -> int:
    _require_live_software_terminal()
    artifacts = run_owned_software_vertical_slice(
        args.destination,
        approval_prompt=_software_approval_prompt,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 3


def _detonate_software(args: argparse.Namespace) -> int:
    _require_live_software_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    artifacts = run_live_software_assessment(
        target,
        args.capsule,
        args.workspace,
        args.destination,
        executable=args.executable,
        approval_prompt=_software_approval_prompt,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 3


def _live_campaign_prompt(challenge: Any, intents: Any) -> str:
    sys.stderr.write(
        json.dumps(
            {
                "approvedIntents": [
                    {
                        "id": intent.id,
                        "target": intent.target,
                        "action": intent.action,
                        "effect": intent.effect.name.lower(),
                        "domain": intent.domain,
                        "offensive": intent.offensive,
                        "irreversible": intent.irreversible,
                        "requiredEvidence": sorted(intent.required_evidence),
                    }
                    for intent in intents
                ]
            },
            indent=2,
        )
        + "\n"
    )
    sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
    return input("approval> ")


def _require_live_campaign_terminal() -> None:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-LIVE-INTERACTIVE-APPROVAL",
            "live browser search requires a human-operated interactive terminal",
        )


def _campaign_executables(args: argparse.Namespace) -> tuple[Path, Path]:
    package_runner = _detected_path(
        args.package_runner,
        ("npx.cmd", "npx"),
        "Node package runner",
    )
    browser = _detected_path(
        args.browser_executable,
        (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "chrome.exe",
            "msedge.exe",
        ),
        "Chromium browser executable",
    )
    return package_runner, browser


@contextmanager
def _browser_profile_lease(
    args: argparse.Namespace,
    target: TargetManifest,
) -> Iterator[BrowserProfileLease | None]:
    vault_path = getattr(args, "browser_profile_vault", None)
    handle = getattr(args, "browser_profile_handle", None)
    if (vault_path is None) != (handle is None):
        raise FormatError(
            "SOVA-PROFILE-CLI-PAIR",
            "--browser-profile-vault and --browser-profile-handle must be supplied together",
        )
    if vault_path is None:
        yield None
        return
    vault = BrowserProfileVault(vault_path)
    with vault.acquire(
        str(handle),
        owner_id=f"sova-cli:{os.getpid()}",
        ttl_seconds=3600,
    ) as lease:
        lease.require_target(target.digest)
        yield lease


def _campaign_output(artifacts: Any) -> dict[str, Any]:
    return {
        "status": artifacts.status,
        "traces": [str(path) for path in artifacts.traces],
        "reproductionTrace": (
            None if artifacts.reproduction_trace is None else str(artifacts.reproduction_trace)
        ),
        "discoveryCapsule": (
            None if artifacts.discovery_capsule is None else str(artifacts.discovery_capsule)
        ),
        "visualReplays": [str(path) for path in getattr(artifacts, "visual_replays", ())],
        "replayCues": (
            None if getattr(artifacts, "replay_cues", None) is None else str(artifacts.replay_cues)
        ),
        "report": str(artifacts.report),
    }


def _hunt_owned_web_fixture(args: argparse.Namespace) -> int:
    _require_live_campaign_terminal()
    package_runner, browser = _campaign_executables(args)
    artifacts = run_owned_web_campaign(
        args.destination,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=_live_campaign_prompt,
        headless=not getattr(args, "headed", False),
        record_video=getattr(args, "record_video", False),
        browser_cache=getattr(args, "playwright_browser_cache", None),
    )
    sys.stdout.buffer.write(canonical_json_bytes(_campaign_output(artifacts)) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _hunt_browser(args: argparse.Namespace) -> int:
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    campaign = browser_campaign_from_mapping(_load_object(args.campaign))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_browser_campaign(
            target,
            campaign,
            args.destination,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
            profile_lease=profile_lease,
            headless=not getattr(args, "headed", False),
            record_video=getattr(args, "record_video", False),
            browser_cache=getattr(args, "playwright_browser_cache", None),
        )
    sys.stdout.buffer.write(canonical_json_bytes(_campaign_output(artifacts)) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _hunt_agent_browser(args: argparse.Namespace) -> int:
    if not args.allow_provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "agent browser planning requires the explicit --allow-provider-calls flag",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    campaign = browser_campaign_from_mapping(_load_object(args.campaign))
    runtime = provider_runtime_from_mapping(_load_object(args.provider_runtime))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_agent_browser_campaign(
            target,
            campaign,
            args.destination,
            router=provider_model_router(runtime, secret_resolver=os.getenv),
            max_model_turns=runtime.max_model_turns,
            max_total_tokens=runtime.max_total_tokens,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
            profile_lease=profile_lease,
            headless=not getattr(args, "headed", False),
            record_video=getattr(args, "record_video", False),
            browser_cache=getattr(args, "playwright_browser_cache", None),
        )
    output = _campaign_output(artifacts.browser)
    output.update(
        {
            "agentReport": str(artifacts.report),
            "agentOrchestrationTrace": str(artifacts.orchestration_trace),
        }
    )
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _hunt_adaptive_browser(args: argparse.Namespace) -> int:
    if not args.allow_provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "adaptive browser planning requires the explicit --allow-provider-calls flag",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    campaign = browser_campaign_from_mapping(_load_object(args.campaign))
    policy = adaptive_browser_policy_from_mapping(_load_object(args.policy))
    runtime = provider_runtime_from_mapping(_load_object(args.provider_runtime))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_adaptive_agent_browser_campaign(
            target,
            campaign,
            policy,
            args.destination,
            router=provider_model_router(runtime, secret_resolver=os.getenv),
            max_model_turns=runtime.max_model_turns,
            max_total_tokens=runtime.max_total_tokens,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
            profile_lease=profile_lease,
        )
    output = {
        "status": artifacts.status,
        "rounds": len(artifacts.rounds),
        "report": str(artifacts.report),
        "coordinatorTrace": str(artifacts.coordinator_trace),
        "discoveryCapsule": (
            None if artifacts.discovery_capsule is None else str(artifacts.discovery_capsule)
        ),
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _validate(args: argparse.Namespace) -> int:
    path: Path = args.path
    if path.suffix == ".sova":
        PackageReader(path).verify("sova.capsule")
    elif path.name.endswith(".sova-trace"):
        TraceReader(path).events()
    else:
        validate_document(_load_object(path))
    sys.stdout.write("VALID\n")
    return 0


def _lint(args: argparse.Namespace) -> int:
    issues = lint_capsule(args.path)
    if not issues:
        sys.stdout.write("CLEAN\n")
        return 0
    for issue in issues:
        sys.stdout.write(f"{issue.code} {issue.path}: {issue.message}\n")
    return 1


def _verify(args: argparse.Namespace) -> int:
    path: Path = args.path
    report = verify_artifact(
        path,
        require_signature=args.require_signature,
        required_key_id=args.key_id,
    )
    value = report.to_mapping()
    if report.accepted and path.name.endswith(".sova-trace"):
        trace = TraceReader(path).verify()
        value.update(
            {
                "traceId": trace.trace_id,
                "eventCount": trace.event_count,
                "completion": trace.completion,
                "signaturePresent": trace.signature_present,
                "signatureValid": trace.signature_valid,
                "trustPolicy": trace.trust_policy,
            }
        )
    elif report.accepted and path.suffix == ".sova":
        value["objectCount"] = len(PackageReader(path).verify("sova.capsule"))
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    if report.state == VerificationState.INVALID:
        return 2
    if report.state == VerificationState.UNSUPPORTED:
        return 4
    return 0


def _migrate(args: argparse.Namespace) -> int:
    digest = migrate_capsule(args.source, args.destination, destination_version=args.to)
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _compat(args: argparse.Namespace) -> int:
    source = PackageReader(args.source).raw_manifest()
    report = analyze_migration(source, destination_version=args.to)
    sys.stdout.write(json.dumps(report.to_mapping(), sort_keys=True) + "\n")
    return 0 if not report.blockers else 1


def _format(args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(_load_object(args.path)) + b"\n")
    return 0


def _hash(args: argparse.Namespace) -> int:
    digest = (
        PackageReader(args.path).content_digest()
        if args.content
        else sha256_digest(args.path.read_bytes())
    )
    label = "content" if args.content else "package"
    sys.stdout.write(f"{digest}  {label}:{args.path}\n")
    return 0


def _template(args: argparse.Namespace) -> int:
    if args.kind == "capsule":
        document = capsule_manifest_template(
            title=args.title,
            summary=args.summary,
            author=args.author,
        )
    else:
        document = scenario_template(title=args.title, purpose=args.summary)
    args.destination.write_bytes(canonical_json_bytes(document) + b"\n")
    return 0


def _pack(args: argparse.Namespace) -> int:
    digest = build_capsule(
        args.destination,
        _load_object(args.manifest),
        scenario=_load_object(args.scenario),
    )
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _playback(args: argparse.Namespace) -> int:
    sys.stdout.write("\n".join(TraceReader(args.path).playback()) + "\n")
    return 0


def _replay_modes(_args: argparse.Namespace) -> int:
    value = {
        "tracePlayback": {
            "mode": ReplayMode.PLAYBACK.value,
            "executesActions": False,
            "claim": "deterministic inspection of recorded evidence",
        },
        "controlledReexecution": {
            "mode": ReplayMode.CONTROLLED_REEXECUTION.value,
            "executesActions": True,
            "claim": "fresh authorized run with condition drift",
        },
        "semanticReproduction": {
            "mode": ReplayMode.SEMANTIC_REPRODUCTION.value,
            "executesActions": "outside-study",
            "claim": "repeated observable-outcome measurement with uncertainty",
        },
        "bitForBitHostedInferenceClaim": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _replay_help(args: argparse.Namespace) -> int:
    parser = args.replay_parser
    if not isinstance(parser, argparse.ArgumentParser):  # pragma: no cover - parser invariant
        raise TypeError
    parser.print_help()
    return 0


def _capsule_replay_selection(args: argparse.Namespace) -> CapsuleReplaySelection:
    return CapsuleReplaySelection(
        primary_trace=args.primary_trace,
        comparison_trace=args.comparison_trace,
        media_object=args.media_object,
        surface=getattr(args, "surface", None),
        no_comparison=args.no_comparison,
        no_media=args.no_media,
        nested_capsule=getattr(args, "nested_capsule", None),
    )


def _derived_replay_destination(source: Path) -> Path:
    return source.with_name(f"{source.stem}-replay.html")


def _local_replay_uri(destination: Path) -> str:
    try:
        resolved = destination.resolve(strict=True)
    except OSError as error:
        raise FormatError(
            "SOVA-REPLAY-LOCAL-FILE",
            "generated replay must be one real local HTML file",
        ) from error
    if not resolved.is_file() or resolved.suffix.casefold() not in {".htm", ".html"}:
        raise FormatError(
            "SOVA-REPLAY-LOCAL-FILE",
            "generated replay must be one real local HTML file",
        )
    return resolved.as_uri()


def _replay_open(args: argparse.Namespace) -> int:
    destination = args.output or _derived_replay_destination(args.source)
    report = render_capsule_timeline(
        args.source,
        destination,
        selection=_capsule_replay_selection(args),
    )
    local_uri = _local_replay_uri(destination)
    opened: bool | None = None
    open_error: str | None = None
    if not args.no_open:
        try:
            opened = bool(webbrowser.open(local_uri, new=2, autoraise=True))
            if not opened:
                open_error = "default-browser-refused-local-file"
        except (OSError, webbrowser.Error):
            opened = False
            open_error = "default-browser-launch-failed"
    report.update(
        {
            "destination": str(destination.resolve()),
            "localUri": local_uri,
            "openRequested": not args.no_open,
            "opened": opened,
            "openError": open_error,
        }
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _replay_timeline(args: argparse.Namespace) -> int:
    render_timeline_html(
        args.source,
        args.destination,
        comparison=args.comparison,
        counterfactual=args.counterfactual,
        media=args.media,
    )
    sys.stdout.write(f"{args.destination}\n")
    return 0


def _replay_capsule(args: argparse.Namespace) -> int:
    report = render_capsule_timeline(
        args.source,
        args.destination,
        selection=_capsule_replay_selection(args),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _replay_serve(args: argparse.Namespace) -> int:
    duration = args.duration_seconds
    if duration is not None and not (
        _MIN_REPLAY_SERVICE_DURATION <= duration <= _MAX_REPLAY_SERVICE_DURATION
    ):
        raise FormatError(
            "SOVA-REPLAY-SERVICE-DURATION",
            "replay service duration must be between 0.1 seconds and one day",
        )
    service = ReplayHTTPService(ReplayServiceConfig(source=args.source, port=args.port)).start()
    report = {
        "artifactType": "sova.replay-service-started",
        "schemaVersion": "0.1.0",
        "url": service.url,
        "loopbackOnly": True,
        "executesRecordedActions": False,
        "productionHttpServer": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    sys.stdout.flush()
    try:
        if duration is None:
            while True:
                threading.Event().wait(1)
        else:
            threading.Event().wait(duration)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
    return 0


def _replay_study(args: argparse.Namespace) -> int:
    conditions = tuple(args.condition) if args.condition else None
    report = semantic_reproduction_study(
        args.reference,
        tuple(args.trials),
        conditions=conditions,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0 if report.eligible else 3


def _query(args: argparse.Namespace) -> int:
    reader = TraceReader(args.path)
    for event in reader.query(
        kind_prefix=args.kind_prefix,
        actor_id=args.actor_id,
        start_sequence=args.start,
        stop_sequence=args.stop,
    ):
        sys.stdout.buffer.write(canonical_json_bytes(event) + b"\n")
    return 0


def _replay_clip(args: argparse.Namespace) -> int:
    report = render_replay_clip_document(_load_object(args.specification), args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _probe_verify(args: argparse.Namespace) -> int:
    report = verify_probe_response(
        _load_object(args.response),
        expected_nonce=args.nonce,
        expected_scope=tuple(args.scope),
        now=datetime.now(UTC),
        required_key_id=args.key_id,
        revoked_key_ids=tuple(args.revoked_key_id),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _probe_issue(args: argparse.Namespace) -> int:
    response = issue_probe_document(_load_object(args.request), now=datetime.now(UTC))
    args.destination.write_bytes(canonical_json_bytes(response) + b"\n")
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.probe-issuance-report",
                "schemaVersion": "0.1.0",
                "response": str(args.destination.resolve()),
                "keyId": response["publicKey"]["keyid"],
                "trustPolicy": response["trustPolicy"],
                "identityTrustEstablished": False,
                "networkUsed": False,
            }
        )
        + b"\n"
    )
    return 0


def _engine_validate(args: argparse.Namespace) -> int:
    document = _load_object(args.specification)
    validated = validate_executor_chamber_document(
        document,
        provider_calls_authorized=bool(args.allow_provider_calls),
        offensive=bool(args.allow_offensive_actions),
    )
    report = {
        "artifactType": "sova.executor-engine-validation",
        "schemaVersion": "0.1.0",
        "status": "accepted",
        "documentDigest": validated.document_digest,
        "authorityTarget": validated.authority.authority_target,
        "providerCalls": validated.authority.provider_calls,
        "offensive": validated.authority.offensive,
        "participants": [item.identifier for item in validated.case.participants],
        "models": [
            {
                "participant": item.participant_id,
                "adapter": item.adapter,
                "runtimeDigest": item.runtime_digest,
            }
            for item in validated.models
        ],
        "grants": [
            {
                "id": item.identifier,
                "bindingId": item.binding_id,
                "codecId": item.codec_id,
                "argumentSchemaDigest": item.argument_schema_digest,
            }
            for item in validated.grants
        ],
        "budget": validated.budget.to_mapping(),
        "runtimeMaterialized": False,
        "executorsStarted": False,
        "providerCallsMade": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _engine_reproduce_plan(args: argparse.Namespace) -> int:
    document = build_executor_capsule_reproduction_document(args.capsule)
    encoded = canonical_json_bytes(document)
    args.destination.write_bytes(encoded + b"\n")
    report = {
        "artifactType": "sova.executor-capsule-reproduction-plan-result",
        "schemaVersion": "0.1.0",
        "sourceCapsule": str(args.capsule),
        "sourceCapsuleDigest": sha256_digest(args.capsule.read_bytes()),
        "destination": str(args.destination),
        "documentDigest": sha256_digest(encoded),
        "authorityTarget": document["authorization"]["authorityTarget"],
        "actionCount": document["budget"]["maxTotalActions"],
        "providerCalls": False,
        "freshTargetAndAuthorizationRequired": True,
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _engine_run_web(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the executor engine requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    mission = semantic_browser_mission_from_mapping(_load_object(args.mission))
    chamber_document = _load_object(args.specification)
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)

    additional_surface_factory = None
    additional_codec_factories = None
    additional_surface_contract_digest = None
    runtime_surfaces_path = getattr(args, "runtime_surfaces", None)
    if runtime_surfaces_path is not None:
        # Host-process and workspace surfaces only today; a declarative MELRA
        # computer-use surface is not yet wired through this document (compose
        # `sova.community.executor_surfaces.melra_computer_surface_generation`
        # directly at the Python API level in the meantime).
        config = parse_executor_engine_runtime_document(_load_object(runtime_surfaces_path))
        builder = build_executor_engine_runtime_surfaces(config)
        preview = builder("primary")
        try:
            additional_surface_contract_digest = sha256_digest(
                canonical_json_bytes(
                    [
                        item.contract_mapping()
                        for item in sorted(preview, key=lambda item: item.sensor_name)
                    ]
                )
            )
        finally:
            for surface in reversed(preview):
                surface.close()
        additional_surface_factory = builder
        additional_codec_factories = builder.codec_factories

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.executor-engine-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_live_web_executor_engine(
            target,
            mission,
            chamber_document,
            args.destination,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            secret_resolver=os.getenv,
            provider_calls_authorized=args.allow_provider_calls,
            target_observation_disclosure_authorized=args.allow_target_observation_disclosure,
            control_proof=proof,
            profile_lease=profile_lease,
            offensive=args.allow_offensive_actions,
            headless=not getattr(args, "headed", False),
            record_video=getattr(args, "record_video", False),
            package_cache=getattr(args, "playwright_package_cache", None),
            browser_cache=getattr(args, "playwright_browser_cache", None),
            workspace_seed=getattr(args, "workspace_seed", None),
            additional_surface_factory=additional_surface_factory,
            additional_codec_factories=additional_codec_factories,
            additional_surface_contract_digest=additional_surface_contract_digest,
            event_observer=observe if args.stream_jsonl else None,
        )
    contribution = _contribute_run_evidence(
        args,
        capsule=artifacts.capsule,
        trace=artifacts.trace,
        destination=args.destination,
    )
    output = {
        "artifactType": "sova.executor-engine-cli-result",
        "schemaVersion": "0.1.0",
        "status": artifacts.status,
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
        "reproductionTrace": (
            None if artifacts.reproduction_trace is None else str(artifacts.reproduction_trace)
        ),
        "capsule": None if artifacts.capsule is None else str(artifacts.capsule),
        "liveEvents": str(artifacts.live_events),
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _contribute_run_evidence(
    args: argparse.Namespace,
    *,
    capsule: Path | None,
    trace: Path,
    destination: Path,
) -> dict[str, Any]:
    """Contribute this run's capsule and trace; never mask the primary run's own result.

    Registry contribution is on by default (the founder's decision); this
    only ever runs after the primary engine/swarm result already succeeded,
    and a contribution-side failure (a failed gate, an unreachable service)
    is reported alongside the run output rather than raised, so it can never
    turn an otherwise-successful run into a CLI failure.
    """
    if capsule is None:
        return {
            "artifactType": "sova.auto-contribution-result",
            "schemaVersion": "0.1.0",
            "contributed": False,
            "reason": "no-capsule-produced",
        }
    registry_client = None
    if getattr(args, "registry_url", None) is not None:
        if not getattr(args, "registry_token", None):
            return {
                "artifactType": "sova.auto-contribution-result",
                "schemaVersion": "0.1.0",
                "contributed": False,
                "reason": "registry-url-without-token",
            }
        registry_client = RegistryClient(RegistryEndpoint(args.registry_url, args.registry_token))
    try:
        return auto_contribute_after_run(
            capsule=capsule,
            trace=trace,
            staging_destination=destination / "contribution",
            contributor={
                "name": args.contributor_name,
                "identity": args.contributor_identity,
            },
            enabled=not getattr(args, "no_contribute", False),
            registry_client=registry_client,
        )
    except FormatError as error:
        return {
            "artifactType": "sova.auto-contribution-result",
            "schemaVersion": "0.1.0",
            "contributed": False,
            "reason": "contribution-failed",
            "error": {"code": error.issue.code, "message": str(error)},
        }


def _prompt_agent_count(args: argparse.Namespace) -> int:
    """Always ask the operator how many agents; never silently default."""
    if getattr(args, "agents", None) is not None:
        count = args.agents
        if not isinstance(count, int) or count < 1:
            raise FormatError(
                "SOVA-SWARM-CLI-AGENTS",
                "--agents must be a positive integer",
            )
        return count
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-SWARM-CLI-AGENTS",
            "swarm-web requires --agents in a non-interactive environment",
        )
    hard_cap = "any positive number" if args.allow_large_swarm else "2-8"
    response = input(f"How many agents should join the swarm? [{hard_cap}]: ")
    try:
        count = int(response.strip())
    except ValueError as error:
        raise FormatError(
            "SOVA-SWARM-CLI-AGENTS",
            "agent count must be an integer",
        ) from error
    if count < 1:
        raise FormatError("SOVA-SWARM-CLI-AGENTS", "agent count must be at least one")
    return count


def _engine_swarm_web(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the swarm engine requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    agent_count = _prompt_agent_count(args)
    target = target_manifest_from_mapping(_load_object(args.manifest))
    mission = semantic_browser_mission_from_mapping(_load_object(args.mission))
    base_document = _load_object(args.specification)
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    personas = tuple(args.persona) if args.persona else None
    additional_surface_factory = None
    additional_codec_factories = None
    additional_surface_contract_digest = None
    runtime_surfaces_path = getattr(args, "runtime_surfaces", None)
    if runtime_surfaces_path is not None:
        config = parse_executor_engine_runtime_document(_load_object(runtime_surfaces_path))
        builder = build_executor_engine_runtime_surfaces(config)
        preview = builder("primary")
        try:
            additional_surface_contract_digest = sha256_digest(
                canonical_json_bytes(
                    [
                        item.contract_mapping()
                        for item in sorted(preview, key=lambda item: item.sensor_name)
                    ]
                )
            )
        finally:
            for surface in reversed(preview):
                surface.close()
        additional_surface_factory = builder
        additional_codec_factories = builder.codec_factories

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.swarm-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    artifacts = run_web_swarm(
        target,
        mission,
        base_document,
        args.destination,
        agent_count=agent_count,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=_live_campaign_prompt,
        secret_resolver=os.getenv,
        provider_calls_authorized=args.allow_provider_calls,
        target_observation_disclosure_authorized=args.allow_target_observation_disclosure,
        personas=personas,
        control_proof=proof,
        offensive=args.allow_offensive_actions,
        headless=not getattr(args, "headed", False),
        record_video=getattr(args, "record_video", False),
        package_cache=getattr(args, "playwright_package_cache", None),
        browser_cache=getattr(args, "playwright_browser_cache", None),
        workspace_seed=getattr(args, "workspace_seed", None),
        max_concurrency=args.max_concurrency,
        allow_large_swarm=args.allow_large_swarm,
        event_observer=observe if args.stream_jsonl else None,
        additional_surface_factory=additional_surface_factory,
        additional_codec_factories=additional_codec_factories,
        additional_surface_contract_digest=additional_surface_contract_digest,
    )
    contribution = _contribute_run_evidence(
        args,
        capsule=artifacts.swarm_capsule,
        trace=artifacts.coordinator_trace,
        destination=artifacts.destination,
    )
    output = {
        "artifactType": "sova.swarm-cli-result",
        "schemaVersion": "0.1.0",
        "agentCount": artifacts.agent_count,
        "destination": str(artifacts.destination),
        "swarmCapsule": str(artifacts.swarm_capsule),
        "coordinatorTrace": str(artifacts.coordinator_trace),
        "report": artifacts.report,
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    per_agent = artifacts.report.get("perAgentSummaries", [])
    failed = sum(1 for item in per_agent if item.get("status") != "pass")
    return 0 if failed == 0 else 2


def _arena_run_software_engine(args: argparse.Namespace) -> int:
    """Route Arena software execution through the same authorization/evidence engine."""
    args.arena_mode = True
    return _engine_run_software(args)


def _arena_swarm_software_engine(args: argparse.Namespace) -> int:
    """Route Arena software swarms through the same isolated engine workers."""
    args.arena_mode = True
    return _engine_swarm_software(args)


def _arena_full_web_engine(args: argparse.Namespace) -> int:
    """Route Arena full-capability execution through the exact SOVA Engine path."""
    args.arena_mode = True
    return _engine_full_web(args)


def _full_capability_computer_spec(args: argparse.Namespace) -> ComputerBackendSpec | None:
    melra_fields = (args.melra_node, args.melra_cli, args.melra_policy)
    target_fields = (
        args.computer_target_manifest,
        args.melra_target_executable,
        args.melra_pid,
        args.melra_window_id,
    )
    native_map = args.native_window_map
    discover_native = args.discover_native_window
    melra_requested = any(value is not None for value in melra_fields)
    native_requested = native_map is not None or discover_native
    if (
        not melra_requested
        and not native_requested
        and all(value is None for value in target_fields)
    ):
        return None
    if melra_requested == native_requested:
        raise FormatError(
            "SOVA-ENGINE-CLI-COMPUTER",
            "select exactly one MELRA or native Windows computer backend",
        )
    if native_map is not None and discover_native:
        raise FormatError(
            "SOVA-ENGINE-CLI-COMPUTER",
            "--native-window-map and --discover-native-window are mutually exclusive",
        )
    if any(value is None for value in target_fields):
        raise FormatError(
            "SOVA-ENGINE-CLI-COMPUTER",
            "--computer-target-manifest, --computer-target-executable, --computer-pid, "
            "and --computer-window-id must all be supplied for computer use",
        )
    software_target = target_manifest_from_mapping(_load_object(args.computer_target_manifest))
    proof = (
        create_local_software_control_proof(
            software_target,
            args.melra_target_executable,
            workspace_seed=args.workspace_seed,
        )
        if args.computer_control_proof is None
        else control_proof_from_mapping(_load_object(args.computer_control_proof))
    )
    authorization = LocalComputerAuthorization(
        software_target,
        proof,
        attest_software_target(
            args.melra_target_executable,
            pid=args.melra_pid,
            window_id=args.melra_window_id,
        ),
    )
    if native_requested:
        return NativeWindowsComputerBackendSpec(
            authorization,
            reviewed_targets=(
                None
                if native_map is None
                else native_window_targets_from_mapping(_load_object(native_map))
            ),
            discover_controls=discover_native,
        )
    if any(value is None for value in melra_fields):
        raise FormatError(
            "SOVA-ENGINE-CLI-MELRA",
            "--melra-node, --melra-cli, and --melra-policy must all be supplied together",
        )
    policy_source: Path = args.melra_policy

    def policy_factory(workspace: Path) -> Path:
        target_policy = workspace / "melra-policy.json"
        target_policy.write_bytes(policy_source.read_bytes())
        return target_policy

    mutations = tuple(item.strip() for item in args.melra_mutations.split(",") if item.strip())
    return MelraComputerBackendSpec(
        node_executable=args.melra_node,
        cli_entrypoint=args.melra_cli,
        policy_factory=policy_factory,
        authorization=authorization,
        mutations=mutations,
    )


def _full_capability_process_spec(args: argparse.Namespace) -> ExactProcessSurfaceSpec | None:
    if args.process_template_id is None and args.process_executable is None:
        return None
    if args.process_template_id is None or args.process_executable is None:
        raise FormatError(
            "SOVA-ENGINE-CLI-PROCESS",
            "--process-template-id and --process-executable must be supplied together",
        )
    return ExactProcessSurfaceSpec(
        args.process_template_id,
        args.process_executable,
        tuple(args.process_argv_prefix),
        trusted_host_process_acknowledged=args.trusted_host_process,
    )


def _software_computer_surface_factory(args: argparse.Namespace) -> Any:
    fields = (args.melra_node, args.melra_cli, args.melra_policy)
    native_map = getattr(args, "native_window_map", None)
    discover_native = getattr(args, "discover_native_window", False)
    if native_map is not None and discover_native:
        raise FormatError(
            "SOVA-ENGINE-CLI-SOFTWARE-COMPUTER",
            "--native-window-map and --discover-native-window are mutually exclusive",
        )
    if native_map is not None:
        if any(value is not None for value in fields):
            raise FormatError(
                "SOVA-ENGINE-CLI-SOFTWARE-COMPUTER",
                "--native-window-map and the MELRA computer backend are mutually exclusive",
            )
        return native_windows_computer_surface_factory(
            native_window_targets_from_mapping(_load_object(native_map))
        )
    if discover_native:
        if any(value is not None for value in fields):
            raise FormatError(
                "SOVA-ENGINE-CLI-SOFTWARE-COMPUTER",
                "--discover-native-window and the MELRA computer backend are mutually exclusive",
            )
        return native_windows_discovery_surface_factory()
    if all(value is None for value in fields):
        if args.window_title_contains is not None and not getattr(args, "record_screen", False):
            raise FormatError(
                "SOVA-ENGINE-CLI-SOFTWARE-COMPUTER",
                "--window-title-contains requires MELRA computer use or --record-screen",
            )
        return None
    if any(value is None for value in fields):
        raise FormatError(
            "SOVA-ENGINE-CLI-SOFTWARE-COMPUTER",
            "--melra-node, --melra-cli, and --melra-policy must be supplied together",
        )
    policy_source: Path = args.melra_policy

    def policy_factory(workspace: Path) -> Path:
        target = workspace / "melra-policy.json"
        target.write_bytes(policy_source.read_bytes())
        return target

    mutations = tuple(item.strip() for item in args.melra_mutations.split(",") if item.strip())
    return melra_software_computer_surface_factory(
        node_executable=args.melra_node,
        cli_entrypoint=args.melra_cli,
        policy_factory=policy_factory,
        mutations=mutations,
    )


def _software_runtime_surfaces(
    args: argparse.Namespace,
    *,
    direct_process_template: ExactProcessSurfaceSpec | None,
) -> tuple[Any | None, dict[str, Any] | None, str | None]:
    path = getattr(args, "runtime_surfaces", None)
    if path is None:
        return None, None, None
    if direct_process_template is not None:
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-RUNTIME-SURFACES",
            "--runtime-surfaces and the legacy single process template are mutually exclusive",
        )
    config = parse_executor_engine_runtime_document(_load_object(path))
    if config.workspace.enabled or not config.host_processes:
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-RUNTIME-SURFACES",
            "software runtime surfaces require workspace.enabled=false and at least one process",
        )
    builder = build_executor_engine_runtime_surfaces(config)
    preview = builder("primary")
    try:
        digest = sha256_digest(
            canonical_json_bytes(
                [
                    item.contract_mapping()
                    for item in sorted(preview, key=lambda item: item.sensor_name)
                ]
            )
        )
    finally:
        for surface in reversed(preview):
            surface.close()
    return builder, dict(builder.codec_factories), digest


def _engine_run_software(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the software engine requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    chamber_document = _load_object(args.specification)
    proof = control_proof_from_mapping(_load_object(args.control_proof))
    process_template = _full_capability_process_spec(args)
    computer_factory = _software_computer_surface_factory(args)
    runtime_surface_factory, runtime_codecs, runtime_contract_digest = _software_runtime_surfaces(
        args, direct_process_template=process_template
    )
    recording = (
        SoftwareWindowRecordingCoordinator(
            args.destination / "recordings",
            interval_seconds=args.recording_interval_seconds,
        )
        if args.record_screen
        else None
    )

    def observe(channel: str, event: dict[str, Any]) -> None:
        if recording is not None:
            recording.observe(channel, event)
        if not args.stream_jsonl:
            return
        envelope = {
            "artifactType": "sova.executor-engine-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    with TemporaryDirectory(prefix="sova-software-engine-parent-") as temporary_parent:
        workspace_parent = (
            Path(temporary_parent) if args.workspace_parent is None else args.workspace_parent
        )
        runtime = build_authorized_software_runtime(
            target,
            SoftwareLaunchSpec(
                args.executable,
                tuple(args.launch_arg),
                window_required=computer_factory is not None or recording is not None,
                window_title_contains=args.window_title_contains,
            ),
            workspace_parent=workspace_parent,
            workspace_seed=args.workspace_seed,
            process_templates=(() if process_template is None else (process_template,)),
            computer_surface_factory=computer_factory,
            window_recording=recording,
            additional_surface_factory=runtime_surface_factory,
            additional_codec_factories=runtime_codecs,
            additional_surface_contract_digest=runtime_contract_digest,
        )
        artifacts = run_executor_engine_document(
            chamber_document,
            args.destination,
            runtime=runtime,
            proof=proof,
            approval_prompt=_live_campaign_prompt,
            secret_resolver=os.getenv,
            provider_calls_authorized=args.allow_provider_calls,
            offensive=args.allow_offensive_actions,
            event_observer=observe if args.stream_jsonl or recording is not None else None,
            capsule_attachment_provider=(None if recording is None else recording.attachments),
        )
    contribution = _contribute_run_evidence(
        args,
        capsule=artifacts.capsule,
        trace=artifacts.trace,
        destination=args.destination,
    )
    output = {
        "artifactType": (
            "sova.arena-executor-engine-cli-result"
            if getattr(args, "arena_mode", False)
            else "sova.executor-engine-cli-result"
        ),
        "schemaVersion": "0.1.0",
        "surface": "software",
        "status": artifacts.status,
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
        "reproductionTrace": (
            None if artifacts.reproduction_trace is None else str(artifacts.reproduction_trace)
        ),
        "capsule": None if artifacts.capsule is None else str(artifacts.capsule),
        "liveEvents": str(artifacts.live_events),
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _engine_swarm_software(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the software swarm requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    chamber_document = _load_object(args.specification)
    proof = control_proof_from_mapping(_load_object(args.control_proof))
    process_template = _full_capability_process_spec(args)
    computer_factory = _software_computer_surface_factory(args)
    runtime_surface_factory, runtime_codecs, runtime_contract_digest = _software_runtime_surfaces(
        args, direct_process_template=process_template
    )

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.executor-engine-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    artifacts = run_software_swarm(
        target,
        SoftwareLaunchSpec(
            args.executable,
            tuple(args.launch_arg),
            window_required=computer_factory is not None or args.record_screen,
            window_title_contains=args.window_title_contains,
        ),
        chamber_document,
        args.destination,
        agent_count=_prompt_agent_count(args),
        personas=tuple(args.persona) or None,
        max_concurrency=args.max_concurrency,
        approval_prompt=_live_campaign_prompt,
        secret_resolver=os.getenv,
        provider_calls_authorized=args.allow_provider_calls,
        target_observation_disclosure_authorized=True,
        proof=proof,
        workspace_seed=args.workspace_seed,
        process_templates=(() if process_template is None else (process_template,)),
        computer_surface_factory=computer_factory,
        offensive=args.allow_offensive_actions,
        event_observer=observe if args.stream_jsonl else None,
        record_window=args.record_screen,
        recording_interval_seconds=args.recording_interval_seconds,
        additional_surface_factory=runtime_surface_factory,
        additional_codec_factories=runtime_codecs,
        additional_surface_contract_digest=runtime_contract_digest,
    )
    contribution = _contribute_run_evidence(
        args,
        capsule=artifacts.swarm_capsule,
        trace=artifacts.coordinator_trace,
        destination=args.destination,
    )
    output = {
        "artifactType": (
            "sova.arena-software-swarm-cli-result"
            if getattr(args, "arena_mode", False)
            else "sova.swarm-cli-result"
        ),
        "schemaVersion": "0.1.0",
        "surface": "software",
        "agentCount": artifacts.agent_count,
        "destination": str(artifacts.destination),
        "swarmCapsule": str(artifacts.swarm_capsule),
        "coordinatorTrace": str(artifacts.coordinator_trace),
        "report": artifacts.report,
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    failed = sum(
        1 for item in artifacts.report.get("perAgentSummaries", []) if item.get("status") != "pass"
    )
    return 0 if failed == 0 else 2


def _engine_full_web(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the executor engine requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    mission = semantic_browser_mission_from_mapping(_load_object(args.mission))
    chamber_document = _load_object(args.specification)
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    computer = _full_capability_computer_spec(args)
    process_template = _full_capability_process_spec(args)

    arena_mode = bool(getattr(args, "arena_mode", False))

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": (
                "sova.arena-full-web-live-event"
                if arena_mode
                else "sova.executor-engine-live-event"
            ),
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    artifacts = run_full_capability_web_engine(
        target,
        mission,
        chamber_document,
        args.destination,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=_live_campaign_prompt,
        secret_resolver=os.getenv,
        provider_calls_authorized=args.allow_provider_calls,
        target_observation_disclosure_authorized=args.allow_target_observation_disclosure,
        control_proof=proof,
        computer=computer,
        process_template=process_template,
        offensive=args.allow_offensive_actions,
        headless=not getattr(args, "headed", False),
        record_video=getattr(args, "record_video", False),
        record_computer_screen=getattr(args, "record_computer_screen", False),
        computer_recording_interval_seconds=getattr(
            args, "computer_recording_interval_seconds", 0.5
        ),
        package_cache=getattr(args, "playwright_package_cache", None),
        browser_cache=getattr(args, "playwright_browser_cache", None),
        workspace_seed=getattr(args, "workspace_seed", None),
        event_observer=observe if args.stream_jsonl else None,
    )
    contribution = _contribute_run_evidence(
        args,
        capsule=artifacts.capsule,
        trace=artifacts.trace,
        destination=args.destination,
    )
    output = {
        "artifactType": (
            "sova.arena-full-web-cli-result" if arena_mode else "sova.executor-engine-cli-result"
        ),
        "schemaVersion": "0.1.0",
        "status": artifacts.status,
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
        "reproductionTrace": (
            None if artifacts.reproduction_trace is None else str(artifacts.reproduction_trace)
        ),
        "capsule": None if artifacts.capsule is None else str(artifacts.capsule),
        "liveEvents": str(artifacts.live_events),
        "visualReplays": [str(path) for path in artifacts.visual_replays],
        "replayCues": [str(path) for path in artifacts.replay_cues],
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _engine_stress_web(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "the stress profile requires explicit redacted target observation disclosure",
        )
    _require_live_campaign_terminal()
    args.allow_large_swarm = False  # the stress agent ceiling is never operator-raised
    agent_count = _prompt_agent_count(args)
    target = target_manifest_from_mapping(_load_object(args.manifest))
    base_document = _load_object(args.specification)
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    tactic_ids = (
        tuple(item.strip() for item in args.tactics.split(",") if item.strip())
        if args.tactics
        else None
    )

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.stress-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    report = run_stress_profile(
        target,
        base_document,
        args.destination,
        entry_url=args.entry_url,
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=_live_campaign_prompt,
        secret_resolver=os.getenv,
        provider_calls_authorized=args.allow_provider_calls,
        target_observation_disclosure_authorized=args.allow_target_observation_disclosure,
        agent_count=agent_count,
        repetitions=args.repetitions,
        tactic_ids=tactic_ids,
        control_proof=proof,
        headless=not getattr(args, "headed", False),
        package_cache=getattr(args, "playwright_package_cache", None),
        browser_cache=getattr(args, "playwright_browser_cache", None),
        event_observer=observe if args.stream_jsonl else None,
    )
    contribution = _contribute_run_evidence(
        args,
        capsule=report.swarm.swarm_capsule,
        trace=report.swarm.coordinator_trace,
        destination=report.destination,
    )
    output = {
        "artifactType": "sova.stress-cli-result",
        "schemaVersion": "0.1.0",
        "agentCount": report.agent_count,
        "repetitions": report.repetitions,
        "tacticIds": list(report.tactic_ids),
        "destination": str(report.destination),
        "swarmCapsule": str(report.swarm.swarm_capsule),
        "coordinatorTrace": str(report.swarm.coordinator_trace),
        "report": report.swarm.report,
        "contribution": contribution,
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    per_agent = report.swarm.report.get("perAgentSummaries", [])
    failed = sum(1 for item in per_agent if item.get("status") != "pass")
    return 0 if failed == 0 else 2


def _arena_run(args: argparse.Namespace) -> int:
    report = run_arena_document(_load_object(args.specification), args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _arena_agent_run(args: argparse.Namespace) -> int:
    if not args.allow_provider_calls and not getattr(args, "allow_sandboxed_agent_code", False):
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "agent Arena requires explicit participant execution authorization",
        )
    document = _load_object(args.specification)
    provider_participants = document.get("participants")
    oci_participants = document.get("ociParticipants", [])
    if not isinstance(provider_participants, list) or not isinstance(oci_participants, list):
        raise FormatError(
            "SOVA-AGENT-ARENA-PARTICIPANT",
            "Arena participants and ociParticipants must be arrays",
        )
    if provider_participants and not args.allow_provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "provider-backed agent Arena participants require --allow-provider-calls",
        )
    if oci_participants and not getattr(args, "allow_sandboxed_agent_code", False):
        raise FormatError(
            "SOVA-OCI-AGENT-CODE-NOT-ALLOWED",
            "OCI Arena participants require --allow-sandboxed-agent-code",
        )
    if oci_participants and not sys.stdin.isatty():
        raise FormatError(
            "SOVA-OCI-AGENT-INTERACTIVE",
            "OCI Arena participants require a human-operated interactive terminal",
        )
    # Validate the complete profile, budgets, participant/runtime identities,
    # matches, and references before attesting or executing any external image.
    validate_agent_arena_document(
        document,
        provider_calls_authorized=args.allow_provider_calls,
    )
    external_models: dict[str, Any] = {}
    if oci_participants:
        if args.destination.exists() and (
            args.destination.is_symlink()
            or not args.destination.is_dir()
            or any(args.destination.iterdir())
        ):
            raise FormatError(
                "SOVA-AGENT-ARENA-EXISTS",
                "agent Arena destination must be an empty real directory",
            )
        args.destination.resolve().mkdir(parents=True, exist_ok=True)
        docker = _detected_path(
            getattr(args, "docker", None),
            ("docker", "docker.exe"),
            "Docker CLI",
        )
        document_digest = sha256_digest(canonical_json_bytes(document))
        for row in oci_participants:
            if not isinstance(row, dict) or set(row) != {"id", "runtime"}:
                raise FormatError(
                    "SOVA-AGENT-ARENA-EXTERNAL",
                    "OCI Arena participant fields are invalid",
                )
            identifier = row.get("id")
            runtime_value = row.get("runtime")
            if not isinstance(identifier, str) or not isinstance(runtime_value, dict):
                raise FormatError(
                    "SOVA-AGENT-ARENA-EXTERNAL",
                    "OCI Arena participant values are invalid",
                )
            runtime = oci_agent_runtime_from_mapping(runtime_value)
            if runtime.identifier != identifier:
                raise FormatError(
                    "SOVA-AGENT-ARENA-EXTERNAL",
                    "OCI participant id must match its runtime id",
                )
            executor = GVisorOciExecutor(
                docker,
                runtime.image,
                runtime=runtime.runtime,
            )
            adapter = authorize_oci_agent_adapter(
                runtime,
                executor,
                args.destination,
                use_scope={
                    "purpose": "synthetic-agent-arena",
                    "arenaDocumentDigest": document_digest,
                    "participant": identifier,
                    "targetToolsAvailable": False,
                },
                approval_prompt=_oci_agent_approval_prompt,
            )
            adapter.conform()
            external_models[identifier] = adapter
    artifacts = run_agent_arena_document(
        document,
        args.destination,
        secret_resolver=os.getenv,
        provider_calls_authorized=args.allow_provider_calls,
        external_models=external_models,
    )
    output = {
        "status": artifacts.status,
        "report": str(artifacts.report),
        "traces": [str(path) for path in artifacts.traces],
        "capsules": [str(path) for path in artifacts.capsules],
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _arena_chamber(args: argparse.Namespace) -> int:
    if not args.authorize_contained_fixture:
        raise FormatError(
            "SOVA-CHAMBER-NOT-AUTHORIZED",
            "Arena chamber requires the explicit --authorize-contained-fixture flag",
        )

    def observe(event: dict[str, Any]) -> None:
        sys.stdout.buffer.write(canonical_json_bytes(event) + b"\n")
        sys.stdout.buffer.flush()

    artifacts = run_arena_chamber_document(
        _load_object(args.specification),
        args.destination,
        secret_resolver=os.getenv,
        contained_fixture_authorized=True,
        provider_calls_authorized=args.allow_provider_calls,
        event_observer=observe if args.stream_jsonl else None,
    )
    output = {
        "artifactType": "sova.arena-chamber-cli-result",
        "schemaVersion": "0.1.0",
        "status": artifacts.status,
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
        "capsule": str(artifacts.capsule),
        "liveEvents": str(artifacts.live_events),
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status in {"pass", "not-observed"} else 2


def _arena_web(args: argparse.Namespace) -> int:
    if not args.allow_provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "website Arena planning requires the explicit --allow-provider-calls flag",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    campaign = browser_campaign_from_mapping(_load_object(args.campaign))
    runtime = provider_runtime_from_mapping(_load_object(args.provider_runtime))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.arena-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_agent_browser_campaign(
            target,
            campaign,
            args.destination,
            router=provider_model_router(runtime, secret_resolver=os.getenv),
            max_model_turns=runtime.max_model_turns,
            max_total_tokens=runtime.max_total_tokens,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
            event_observer=observe if args.stream_jsonl else None,
            profile_lease=profile_lease,
            headless=not getattr(args, "headed", False),
            record_video=getattr(args, "record_video", False),
            browser_cache=getattr(args, "playwright_browser_cache", None),
        )
    output = _campaign_output(artifacts.browser)
    output.update(
        {
            "artifactType": "sova.arena-web-cli-result",
            "schemaVersion": "0.1.0",
            "agentReport": str(artifacts.report),
            "agentOrchestrationTrace": str(artifacts.orchestration_trace),
        }
    )
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _arena_explore_web(args: argparse.Namespace) -> int:
    if not args.allow_target_observation_disclosure:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "semantic website exploration requires explicit disclosure authorization",
        )
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    mission = semantic_browser_mission_from_mapping(_load_object(args.mission))
    runtime_document = _load_object(args.provider_runtime)
    runtime_type = runtime_document.get("artifactType")
    if runtime_type == "sova.provider-runtime":
        if not args.allow_provider_calls:
            raise FormatError(
                "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
                "provider-backed semantic exploration requires --allow-provider-calls",
            )
        runtime = provider_runtime_from_mapping(runtime_document)
        if mission.max_planner_turns > runtime.max_model_turns:
            raise FormatError(
                "SOVA-SEMANTIC-BROWSER-RUNTIME-BUDGET",
                "mission planner-turn budget exceeds the provider runtime budget",
            )
        if runtime.max_total_tokens is not None and (
            mission.max_total_tokens is None or mission.max_total_tokens > runtime.max_total_tokens
        ):
            raise FormatError(
                "SOVA-SEMANTIC-BROWSER-RUNTIME-BUDGET",
                (
                    "mission token budget must be present and no larger than the provider "
                    "runtime budget"
                ),
            )
        router = provider_model_router(runtime, secret_resolver=os.getenv)
    elif runtime_type == "sova.oci-agent-runtime":
        if not getattr(args, "allow_sandboxed_agent_code", False):
            raise FormatError(
                "SOVA-OCI-AGENT-CODE-NOT-ALLOWED",
                "OCI agent exploration requires --allow-sandboxed-agent-code",
            )
        oci_runtime = oci_agent_runtime_from_mapping(runtime_document)
        docker = _detected_path(
            getattr(args, "docker", None),
            ("docker", "docker.exe"),
            "Docker CLI",
        )
        executor = GVisorOciExecutor(
            docker,
            oci_runtime.image,
            runtime=oci_runtime.runtime,
        )
        args.destination.resolve().mkdir(parents=True, exist_ok=True)
        adapter = authorize_oci_agent_adapter(
            oci_runtime,
            executor,
            args.destination,
            use_scope={
                "purpose": "semantic-browser-planning",
                "targetDigest": target.digest,
                "missionDigest": mission.digest,
                "browserAuthorityInherited": False,
            },
            approval_prompt=_oci_agent_approval_prompt,
        )
        adapter.conform()
        router = ModelRouter({RoleKind.EXPLORER: (adapter,)})
    else:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-RUNTIME",
            "planning runtime must be a provider or OCI agent runtime document",
        )
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)

    def observe(channel: str, event: dict[str, Any]) -> None:
        envelope = {
            "artifactType": "sova.arena-semantic-browser-live-event",
            "schemaVersion": "0.1.0",
            "channel": channel,
            "event": event,
        }
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        sys.stdout.buffer.flush()

    with _browser_profile_lease(args, target) as profile_lease:
        artifacts = run_live_semantic_browser_workflow(
            target,
            mission,
            args.destination,
            router=router,
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
            browser_cache=getattr(args, "playwright_browser_cache", None),
            profile_lease=profile_lease,
            event_observer=observe if args.stream_jsonl else None,
            headless=not getattr(args, "headed", False),
            record_video=getattr(args, "record_video", False),
        )
    output = _campaign_output(artifacts)
    output.update(
        {
            "artifactType": "sova.arena-semantic-browser-cli-result",
            "schemaVersion": "0.1.0",
            "mission": str(artifacts.mission),
            "target": str(artifacts.target),
        }
    )
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _arena_swarm_web(args: argparse.Namespace) -> int:
    _require_live_campaign_terminal()
    document = _load_object(args.specification)
    oci_rows = document.get("ociParticipants", [])
    if not isinstance(oci_rows, list):
        raise FormatError(
            "SOVA-BROWSER-SWARM-EXTERNAL",
            "browser swarm ociParticipants must be an array",
        )
    if oci_rows and not getattr(args, "allow_sandboxed_agent_code", False):
        raise FormatError(
            "SOVA-OCI-AGENT-CODE-NOT-ALLOWED",
            "OCI browser-swarm participants require --allow-sandboxed-agent-code",
        )
    target = target_manifest_from_mapping(_load_object(args.manifest))
    campaign = browser_campaign_from_mapping(_load_object(args.campaign))
    if oci_rows:
        # Validate participant/runtime identities, campaign grants, and the aggregate
        # turn budget before Docker attestation or native-code setup.
        validate_browser_swarm_document(
            document,
            campaign,
            provider_calls_authorized=args.allow_provider_calls,
        )
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    if args.browser_profile_vault is None or args.browser_profile_handle is None:
        raise FormatError(
            "SOVA-BROWSER-SWARM-PROFILE",
            "browser swarm requires an explicit target-bound profile vault and handle",
        )
    external_models: dict[str, Any] = {}
    with TemporaryDirectory(prefix="sova-browser-swarm-oci-") as temporary_root:
        if oci_rows:
            if args.destination.exists() and (
                args.destination.is_symlink()
                or not args.destination.is_dir()
                or any(args.destination.iterdir())
            ):
                raise FormatError(
                    "SOVA-BROWSER-SWARM-EXISTS",
                    "browser swarm destination must be an empty real directory",
                )
            docker = _detected_path(
                getattr(args, "docker", None),
                ("docker", "docker.exe"),
                "Docker CLI",
            )
            document_digest = sha256_digest(canonical_json_bytes(document))
            workspace_root = Path(temporary_root)
            for row in oci_rows:
                if not isinstance(row, dict):  # validated above; narrows the type
                    raise FormatError(
                        "SOVA-BROWSER-SWARM-EXTERNAL",
                        "OCI browser-swarm participant must be an object",
                    )
                identifier = row["id"]
                runtime = oci_agent_runtime_from_mapping(row["runtime"])
                workspace = workspace_root / identifier
                workspace.mkdir()
                executor = GVisorOciExecutor(
                    docker,
                    runtime.image,
                    runtime=runtime.runtime,
                )
                adapter = authorize_oci_agent_adapter(
                    runtime,
                    executor,
                    workspace,
                    use_scope={
                        "purpose": "bounded-browser-swarm-planning",
                        "swarmDocumentDigest": document_digest,
                        "targetDigest": target.digest,
                        "campaignDigest": campaign.digest,
                        "participant": identifier,
                        "browserAuthorityInherited": False,
                        "targetToolsAvailable": False,
                    },
                    approval_prompt=_oci_agent_approval_prompt,
                )
                adapter.conform()
                external_models[identifier] = adapter

        def observe(channel: str, event: dict[str, Any]) -> None:
            envelope = {
                "artifactType": "sova.browser-swarm-live-event",
                "schemaVersion": "0.1.0",
                "channel": channel,
                "event": event,
            }
            sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
            sys.stdout.buffer.flush()

        with _browser_profile_lease(args, target) as profile_lease:
            if profile_lease is None:  # pragma: no cover - rejected above, narrows the type
                raise AssertionError
            artifacts = run_browser_swarm_document(
                document,
                target,
                campaign,
                args.destination,
                package_runner=package_runner,
                browser_executable=browser,
                approval_prompt=_live_campaign_prompt,
                profile_lease=profile_lease,
                secret_resolver=os.getenv,
                control_proof=proof,
                provider_calls_authorized=args.allow_provider_calls,
                headless=not getattr(args, "headed", False),
                record_video=getattr(args, "record_video", False),
                browser_cache=getattr(args, "playwright_browser_cache", None),
                event_observer=observe if args.stream_jsonl else None,
                external_models=external_models,
            )
    output = {
        "artifactType": "sova.browser-swarm-cli-result",
        "schemaVersion": "0.1.0",
        "status": artifacts.status,
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
        "capsule": str(artifacts.capsule),
        "decisiveReplayCapsule": (
            None
            if artifacts.decisive_replay_capsule is None
            else str(artifacts.decisive_replay_capsule)
        ),
        "liveEvents": str(artifacts.live_events),
        "participantRuns": [str(path) for path in artifacts.participant_runs],
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _leaderboard_build(args: argparse.Namespace) -> int:
    specification: Path = args.specification
    report = build_leaderboard_document(
        _load_object(specification),
        args.destination,
        base=specification.resolve().parent,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _ctf_build(args: argparse.Namespace) -> int:
    specification: Path = args.specification
    report = build_ctf_document(
        _load_object(specification),
        args.destination,
        base=specification.resolve().parent,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _extension_discover(_args: argparse.Namespace) -> int:
    document = {
        "artifactType": "sova.extension-discovery",
        "schemaVersion": "0.1.0",
        "extensions": [asdict(item) for item in discover_extension_metadata()],
        "importsExtensionCode": False,
        "establishesTrust": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _extension_approval_prompt(challenge: ExtensionApproval) -> str:
    sys.stderr.write(json.dumps(challenge.summary, indent=2) + "\n")
    sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
    return input("approval> ")


def _extension_prepare(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise FormatError("SOVA-EXTENSION-OUTPUT", "launch output already exists")
    manifest = ExtensionManifest.from_mapping(_load_object(args.manifest))
    payload = {} if args.payload is None else _load_object(args.payload)
    launch = prepare_extension_launch(
        manifest,
        operation=args.operation,
        executable=args.executable,
        arguments=tuple(args.argument),
        working_directory=args.working_directory,
        timeout_seconds=args.timeout,
        payload=payload,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json_bytes(launch.to_mapping()) + b"\n")
    sys.stdout.write(f"{launch.digest}  {args.output}\n")
    return 0


def _extension_run(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-EXTENSION-INTERACTIVE",
            "extension execution requires a human-operated interactive terminal",
        )
    manifest = ExtensionManifest.from_mapping(_load_object(args.manifest))
    launch = extension_launch_from_mapping(_load_object(args.launch))
    artifacts = run_extension_workflow(
        manifest,
        launch,
        args.destination,
        approval_prompt=_extension_approval_prompt,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 3


def _oci_agent_approval_prompt(challenge: OciAgentApproval) -> str:
    sys.stderr.write(json.dumps(challenge.summary, indent=2) + "\n")
    sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
    return input("approval> ")


def _agent_conform_oci(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-OCI-AGENT-INTERACTIVE",
            "external-agent execution requires a human-operated interactive terminal",
        )
    runtime = oci_agent_runtime_from_mapping(_load_object(args.runtime))
    docker = _detected_path(args.docker, ("docker", "docker.exe"), "Docker CLI")
    artifacts = run_oci_agent_conformance(
        runtime,
        docker,
        args.destination,
        approval_prompt=_oci_agent_approval_prompt,
    )
    output = {
        "artifactType": "sova.oci-agent-cli-result",
        "schemaVersion": "0.1.0",
        "status": artifacts.status,
        "runtime": str(artifacts.runtime),
        "report": str(artifacts.report),
        "trace": str(artifacts.trace),
    }
    sys.stdout.buffer.write(canonical_json_bytes(output) + b"\n")
    return 0 if artifacts.status == "pass" else 3


def _compare(args: argparse.Namespace) -> int:
    kinds = tuple(args.kind) if args.kind else ("model.response", "oracle.completed")
    result = compare_observable_outcomes(args.left, args.right, kinds=kinds)
    sys.stdout.buffer.write(canonical_json_bytes(asdict(result)) + b"\n")
    return 0 if result.equivalent else 1


def _rerun(args: argparse.Namespace) -> int:
    return run_rerun_command(args)


def _matrix(args: argparse.Namespace) -> int:
    return run_matrix_command(args)


def _calibrate(args: argparse.Namespace) -> int:
    return run_calibrate_command(args)


def _export(args: argparse.Namespace) -> int:
    reader = TraceReader(args.path)
    if args.format == "native-jsonl":
        for event in reader.events():
            sys.stdout.buffer.write(canonical_json_bytes(event) + b"\n")
        return 0
    if args.format == "otel-jsonl":
        for event in reader.events():
            span, fidelity = export_event(event)
            sys.stdout.buffer.write(
                canonical_json_bytes({"span": span, "fidelity": asdict(fidelity)}) + b"\n"
            )
        return 0
    selected = set(args.sequence) if args.sequence is not None else None
    view = reader.disclosure_view(
        sequences=selected,
        include_payload=args.include_payload,
    )
    sys.stdout.buffer.write(canonical_json_bytes(view) + b"\n")
    return 0


def _recover_trace(args: argparse.Namespace) -> int:
    digest = recover_trace(args.destination)
    sys.stdout.write(f"{digest}  {args.destination}\n")
    return 0


def _safety_backends(_args: argparse.Namespace) -> int:
    value = [backend.to_mapping() for backend in known_backend_descriptors()]
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _safety_attest_docker(args: argparse.Namespace) -> int:
    docker = _detected_path(args.docker, ("docker", "docker.exe"), "Docker CLI")
    attestation = attest_docker_desktop(docker, args.image)
    sys.stdout.buffer.write(canonical_json_bytes(attestation.to_mapping()) + b"\n")
    return 0 if attestation.ready else 3


def _safety_attest_gvisor(args: argparse.Namespace) -> int:
    docker = _detected_path(args.docker, ("docker", "docker.exe"), "Docker CLI")
    attestation = attest_gvisor(docker, args.image, runtime=args.runtime)
    sys.stdout.buffer.write(canonical_json_bytes(attestation.to_mapping()) + b"\n")
    return 0 if attestation.ready else 3


def _demo(args: argparse.Namespace) -> int:
    if args.kind != "sleeper":  # pragma: no cover - argparse constrains this
        raise FormatError("SOVA-DEMO-KIND", "unsupported demo kind")
    artifacts = run_complete_demo(args.destination, profile=standard_profile())
    rendered = {
        "capsule": str(artifacts.capsule),
        "trace": str(artifacts.trace),
        "reproductionTrace": str(artifacts.reproduction_trace),
        "orchestrationTrace": str(artifacts.orchestration_trace),
        "mapReport": str(artifacts.map_report),
        "report": str(artifacts.report),
        "summary": str(artifacts.summary),
        "oracleStatus": artifacts.oracle_status,
        "evidenceClosure": artifacts.evidence_closure,
        "cleanupVerified": artifacts.cleanup_verified,
        "reproduced": artifacts.reproduced,
    }
    sys.stdout.buffer.write(canonical_json_bytes(rendered) + b"\n")
    return 0


def _run_profile(custom_profile: Path | None) -> RunProfile:
    if custom_profile is None:
        return standard_profile()
    configuration = _load_object(custom_profile)
    return RunProfile(
        ProfileKind.CUSTOM,
        "0.1.0",
        customization_digest=sha256_digest(canonical_json_bytes(configuration)),
    )


def _check(args: argparse.Namespace) -> int:
    if args.check_self:
        if args.target is not None or args.destination is not None:
            raise FormatError(
                "SOVA-CHECK-SELF-ARGS",
                "sova check --self does not accept a target or destination",
            )
        self_result = manifest_self_check()
        sys.stdout.buffer.write(canonical_json_bytes(self_result) + b"\n")
        return 0 if self_result["accepted"] else 2
    if args.target is None or args.destination is None:
        raise FormatError(
            "SOVA-CHECK-ARGS", "check requires target and destination unless --self is used"
        )
    live_options = (
        args.control_proof,
        args.package_runner,
        args.browser_executable,
    )
    if args.browser_campaign is None and any(value is not None for value in live_options):
        raise FormatError(
            "SOVA-CHECK-BROWSER-ARGS",
            "browser execution options require --browser-campaign",
        )
    if args.browser_campaign is None:
        local_result = run_check(
            args.target,
            args.destination,
            profile=_run_profile(args.custom_profile),
        )
        result_mapping = local_result.to_mapping()
        result_exit_code = local_result.exit_code
    else:
        if args.custom_profile is not None:
            raise FormatError(
                "SOVA-CHECK-BROWSER-PROFILE",
                "live browser check currently requires the pinned standard profile",
            )
        _require_live_campaign_terminal()
        target = target_manifest_from_mapping(_load_object(Path(args.target)))
        campaign = browser_campaign_from_mapping(_load_object(args.browser_campaign))
        proof = (
            control_proof_from_mapping(_load_object(args.control_proof))
            if args.control_proof is not None
            else None
        )
        package_runner, browser = _campaign_executables(args)
        browser_result = run_browser_check(
            target,
            campaign,
            args.destination,
            profile=standard_profile(),
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=_live_campaign_prompt,
            control_proof=proof,
        )
        result_mapping = browser_result.to_mapping()
        result_exit_code = browser_result.exit_code
    sys.stdout.buffer.write(canonical_json_bytes(result_mapping) + b"\n")
    return result_exit_code


def _mcp_manifest(_args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(tool_manifest()) + b"\n")
    return 0


def _mcp_init_control(args: argparse.Namespace) -> int:
    create_control_key(args.key_file)
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.mcp-control-key-created",
                "schemaVersion": "0.1.0",
                "path": str(args.key_file),
                "secretPrinted": False,
            }
        )
        + b"\n"
    )
    return 0


def _mcp_store(args: argparse.Namespace) -> LocalApprovalStore:
    return LocalApprovalStore(
        args.control_dir,
        load_control_key(args.key_file),
        workspace=args.workspace,
    )


def _mcp_approve(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-LOCAL-MCP-INTERACTIVE",
            "approval requires a human-operated interactive terminal",
        )
    store = _mcp_store(args)
    challenge = store.challenge_record(args.challenge_id)
    review = challenge.get("invocation")
    if not isinstance(review, dict):
        raise FormatError("SOVA-LOCAL-MCP-CHALLENGE", "challenge invocation is malformed")
    sys.stderr.write(canonical_json_bytes(review).decode("utf-8") + "\n")
    exact_phrase = input("Type the exact approval phrase displayed in the challenge: ")
    reviewed = input("Have you reviewed every effect and risk? Type YES: ") == "YES"
    token = store.approve(
        args.challenge_id,
        exact_phrase=exact_phrase,
        reviewed_effects=reviewed,
        human_confirmed=True,
    )
    sys.stdout.buffer.write(canonical_json_bytes(token) + b"\n")
    return 0


def _mcp_serve(args: argparse.Namespace) -> int:
    context = LocalToolContext(
        args.workspace.resolve(),
        args.evidence_dir.resolve(),
        _mcp_store(args),
        sensitive_mapping_allowed=bool(args.allow_sensitive_map),
    )
    serve_stdio(context)
    return 0


def _map(args: argparse.Namespace) -> int:
    report = build_capability_map(
        args.root,
        inventories=tuple(args.inventory),
        observed_inventories=tuple(args.observed_inventory),
        runtime_authorized=bool(args.authorize_runtime_inventory),
        baseline=args.baseline,
    )
    if args.write_tool_snapshot is not None:
        write_tool_snapshot(args.write_tool_snapshot, report.graph)
    if args.output is None:
        sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    else:
        digest = write_capability_map(args.output, report)
        sys.stdout.write(f"{digest}  {args.output}\n")
    return 0


def _executor_receipts(_args: argparse.Namespace) -> int:
    value = {
        "artifactType": "sova.external-executor-receipts",
        "schemaVersion": "0.1.0",
        "receipts": [
            MELRA_AUDIT_RECEIPT.to_mapping(),
            PLAYWRIGHT_MCP_RECEIPT.to_mapping(),
            WINDOWS_MCP_RECEIPT.to_mapping(),
        ],
        "sovaRemainsAuthority": True,
        "noMelraOperationPreserved": True,
    }
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _session_browser_create(args: argparse.Namespace) -> int:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(args.target_digest)) is None:
        raise FormatError(
            "SOVA-PROFILE-TARGET-DIGEST",
            "browser profile target must be an exact sha256 target-manifest digest",
        )
    vault = BrowserProfileVault(args.vault)
    record = vault.create(identity_id=str(args.identity), target=str(args.target_digest))
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.browser-profile-provisioning-result",
                "schemaVersion": "0.1.0",
                "handle": record.handle,
                "identityId": record.identity_id,
                "targetDigest": record.target,
                "profilePathIncluded": False,
                "profileMaterialIncluded": False,
                "operatorAction": (
                    "Keep this vault local. Use the handle only with the exact target digest."
                ),
            }
        )
        + b"\n"
    )
    return 0


def _session_browser_inspect(args: argparse.Namespace) -> int:
    value = BrowserProfileVault(args.vault).inspect(str(args.handle))
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    return 0


def _session_browser_handoff(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-PROFILE-HANDOFF-INTERACTIVE",
            "browser profile handoff requires a human-operated interactive terminal",
        )
    target = target_manifest_from_mapping(_load_object(args.manifest))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)

    def prompt(phrase: str, summary: str) -> str:
        sys.stderr.write(summary + "\n")
        sys.stderr.write(f"Type exactly: {phrase}\n")
        return input("handoff> ")

    with _browser_profile_lease(args, target) as profile_lease:
        if profile_lease is None:  # pragma: no cover - parser requires both values
            raise FormatError("SOVA-PROFILE-HANDOFF", "browser profile lease is required")
        artifacts = run_browser_profile_handoff(
            target,
            str(args.entry_url),
            args.destination,
            profile_lease=profile_lease,
            package_runner=package_runner,
            browser_executable=browser,
            handoff_prompt=prompt,
            control_proof=proof,
        )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 2


def _hunt_demo(_args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(run_trigger_search_demo()) + b"\n")
    return 0


def _object_member(value: dict[str, Any], name: str) -> dict[str, Any]:
    member = value.get(name)
    if not isinstance(member, dict):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an object", path=f"$.{name}")
    return member


def _array_member(value: dict[str, Any], name: str) -> list[Any]:
    member = value.get(name)
    if not isinstance(member, list):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an array", path=f"$.{name}")
    return member


def _string_member(value: dict[str, Any], name: str) -> str:
    member = value.get(name)
    if not isinstance(member, str) or not member:
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a string", path=f"$.{name}")
    return member


def _boolean_member(value: dict[str, Any], name: str) -> bool:
    member = value.get(name)
    if not isinstance(member, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a boolean", path=f"$.{name}")
    return member


def _optional_boolean_member(value: dict[str, Any], name: str) -> bool | None:
    member = value.get(name)
    if member is not None and not isinstance(member, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be a boolean or null", path=f"$.{name}")
    return member


def _integer_value(value: Any, name: str, *, default: int) -> int:
    selected = default if value is None else value
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise FormatError("SOVA-CLI-FIELD", f"{name} must be an integer", path=f"$.{name}")
    return selected


def _scanner_finding(value: Any) -> ScannerFinding:
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-SCANNER-FINDING", "scanner finding must be an object")
    return ScannerFinding(
        scanner=_string_member(value, "scanner"),
        scanner_version=_string_member(value, "scannerVersion"),
        rule_id=_string_member(value, "ruleId"),
        target_id=_string_member(value, "targetId"),
        location=_string_member(value, "location"),
        message=_string_member(value, "message"),
        evidence_reference=_string_member(value, "evidenceReference"),
        mechanism=_string_member(value, "mechanism"),
    )


def _forensics_reconstruct(args: argparse.Namespace) -> int:
    path: Path = args.source
    if path.name.endswith(".sova-trace"):
        report = reconstruct_trace(path)
    else:
        specification = _load_object(path)
        raw_events = _array_member(specification, "events")
        if any(not isinstance(event, dict) for event in raw_events):
            raise FormatError("SOVA-FORENSICS-EVENT", "events must contain objects")
        report = reconstruct_events(
            raw_events,
            source_type=str(specification.get("sourceType", "external.normalized-events")),
            source_id=str(specification.get("sourceId", path.name)),
            source_digest=(
                str(specification["sourceDigest"])
                if specification.get("sourceDigest") is not None
                else None
            ),
            integrity_state=str(specification.get("integrityState", "not-independently-verified")),
            dropped_event_count=_integer_value(
                specification.get("droppedEventCount"), "droppedEventCount", default=0
            ),
        )
    document = report.to_mapping()
    validate_document(document, "sova.forensic-reconstruction")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _counterfactual_trial(value: Any) -> CounterfactualTrial:
    if not isinstance(value, dict):
        raise FormatError("SOVA-FORENSICS-TRIAL", "counterfactual trial must be an object")
    try:
        layer = CausalLayer(_string_member(value, "layer"))
        changed = tuple(CausalLayer(str(item)) for item in _array_member(value, "changedLayers"))
    except ValueError as error:
        raise FormatError("SOVA-FORENSICS-LAYER", "unsupported causal layer") from error
    return CounterfactualTrial(
        trial_id=_string_member(value, "trialId"),
        layer=layer,
        changed_layers=changed,
        baseline_outcome=_optional_boolean_member(value, "baselineOutcome"),
        intervention_outcome=_optional_boolean_member(value, "interventionOutcome"),
        context_equivalent=_boolean_member(value, "contextEquivalent"),
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        original_trace=(
            str(value["originalTrace"]) if value.get("originalTrace") is not None else None
        ),
        counterfactual_trace=(
            str(value["counterfactualTrace"])
            if value.get("counterfactualTrace") is not None
            else None
        ),
        execution_status=str(value.get("executionStatus", "completed")),
        limitation=str(value["limitation"]) if value.get("limitation") is not None else None,
    )


def _forensics_attribute(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    trials = tuple(_counterfactual_trial(item) for item in _array_member(study, "trials"))
    report = assess_counterfactuals(_string_member(study, "originalTrace"), trials)
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _forensics_benchmark(_args: argparse.Namespace) -> int:
    result = run_attribution_ground_truth_fixture()
    sys.stdout.buffer.write(canonical_json_bytes(result.to_mapping()) + b"\n")
    return 0


def _forensics_browser_counterfactual(args: argparse.Namespace) -> int:
    _require_live_campaign_terminal()
    target = target_manifest_from_mapping(_load_object(args.manifest))
    study = browser_counterfactual_from_mapping(_load_object(args.study))
    proof = (
        control_proof_from_mapping(_load_object(args.control_proof))
        if args.control_proof is not None
        else None
    )
    package_runner, browser = _campaign_executables(args)
    artifacts = run_browser_counterfactual_study(
        target,
        study,
        args.destination,
        profile=standard_profile(),
        package_runner=package_runner,
        browser_executable=browser,
        approval_prompt=_live_campaign_prompt,
        control_proof=proof,
    )
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "status": artifacts.status,
                "report": str(artifacts.report),
                "capsule": str(artifacts.capsule),
                "traces": [str(path) for path in artifacts.traces],
            }
        )
        + b"\n"
    )
    return 0


def _write_all_descriptor(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError
        offset += written
    os.fsync(descriptor)


def _write_new_bytes(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, mode)
        created = True
        _write_all_descriptor(descriptor, content)
    except FileExistsError as error:
        raise FormatError("SOVA-CLI-DESTINATION", "destination already exists") from error
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_new_document(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o644)
        created = True
        _write_all_descriptor(descriptor, canonical_json_bytes(value) + b"\n")
    except FileExistsError as error:
        raise FormatError("SOVA-CLI-DESTINATION", "destination already exists") from error
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _forensics_blind_fixture(args: argparse.Namespace) -> int:
    task, key = create_stochastic_blinded_fixture(
        seed=args.seed,
        case_count=args.cases,
        trials_per_layer=args.trials_per_layer,
    )
    if args.task.resolve() == args.answer_key.resolve():
        raise FormatError(
            "SOVA-BLIND-SEPARATION", "task and answer key require separate destinations"
        )
    task_written = False
    try:
        _write_new_document(args.task, task)
        task_written = True
        _write_new_document(args.answer_key, key)
    except BaseException:
        if task_written:
            args.task.unlink(missing_ok=True)
        raise
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.blinded-causal-fixture-created",
                "task": str(args.task),
                "answerKey": str(args.answer_key),
                "answerKeyLoadedDuringPrediction": False,
                "realAgentEvidence": False,
            }
        )
        + b"\n"
    )
    return 0


def _forensics_blind_run(args: argparse.Namespace) -> int:
    study = blinded_study_from_mapping(_load_object(args.task))
    predictions = run_blinded_attribution_study(study)
    _write_new_document(args.predictions, predictions)
    sys.stdout.buffer.write(canonical_json_bytes(predictions) + b"\n")
    return 0


def _forensics_blind_score(args: argparse.Namespace) -> int:
    study = blinded_study_from_mapping(_load_object(args.task))
    result = score_blinded_attribution_study(
        study,
        _load_object(args.predictions),
        _load_object(args.answer_key),
        reviewer_public_key=(
            args.reviewer_public_key.read_bytes() if args.reviewer_public_key is not None else None
        ),
        required_reviewer_key_id=args.required_reviewer_key_id,
    )
    _write_new_document(args.output, result)
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0 if result["passed"] else 3


def _forensics_blind_keygen(args: argparse.Namespace) -> int:
    result = create_blinded_reviewer_keypair(args.private_key, args.public_key)
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


def _forensics_blind_sign_key(args: argparse.Namespace) -> int:
    signed = sign_blinded_answer_key(
        _load_object(args.answer_key),
        args.private_key.read_bytes(),
        args.public_key.read_bytes(),
    )
    _write_new_document(args.output, signed)
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.blinded-causal-answer-key-signed",
                "output": str(args.output),
                "privateKeyPrinted": False,
            }
        )
        + b"\n"
    )
    return 0


def _evidence(args: argparse.Namespace) -> int:
    bundle = build_evidence_bundle(_load_object(args.specification))
    if args.format == "json":
        document = bundle.to_mapping()
        validate_document(document, "sova.evidence")
        sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    elif args.format == "sarif":
        sys.stdout.buffer.write(canonical_json_bytes(evidence_to_sarif(bundle)) + b"\n")
    else:
        sys.stdout.write(render_evidence_report(bundle, audience=args.format))
    return 0


def _case_build(args: argparse.Namespace) -> int:
    artifacts = build_case_workspace(
        args.trace,
        args.capsule,
        args.destination,
        title=args.title,
        classification=args.classification,
        component=args.component,
        component_version=args.component_version,
        disclosure_cleared=args.disclosure_cleared,
        reviewed_for_export=args.reviewed_for_export,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0


def _execution_observation(value: Any) -> ExecutionObservation:
    if not isinstance(value, dict):
        raise FormatError("SOVA-CLI-OBSERVATION", "execution observation must be an object")
    try:
        state = ObservationState(_string_member(value, "state"))
    except ValueError as error:
        raise FormatError("SOVA-CLI-OBSERVATION-STATE", "unsupported observation state") from error
    raw_limitations = value.get("limitations", [])
    if not isinstance(raw_limitations, list) or any(
        not isinstance(item, str) for item in raw_limitations
    ):
        raise FormatError("SOVA-CLI-LIMITATIONS", "limitations must be a string array")
    return ExecutionObservation(
        claim_key=_string_member(value, "claimKey"),
        state=state,
        trace_reference=(
            str(value["traceReference"]) if value.get("traceReference") is not None else None
        ),
        oracle_method=_string_member(value, "oracleMethod"),
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        safe_and_authorized=_boolean_member(value, "safeAndAuthorized"),
        limitations=tuple(raw_limitations),
    )


def _adjudicate_plan(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    findings = tuple(_scanner_finding(item) for item in _array_member(study, "findings"))
    raw_actions = _array_member(study, "allowedActionFamilies")
    if any(not isinstance(item, str) for item in raw_actions):
        raise FormatError("SOVA-CLI-ACTIONS", "allowedActionFamilies must contain strings")
    plan = construct_safe_test_plan(
        findings,
        target_owned_or_authorized=study.get("targetOwnedOrAuthorized") is True,
        allowed_action_families=tuple(raw_actions),
    )
    sys.stdout.buffer.write(canonical_json_bytes(plan) + b"\n")
    return 0


def _adjudicate_evaluate(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    findings = tuple(_scanner_finding(item) for item in _array_member(study, "findings"))
    observations = tuple(
        _execution_observation(item) for item in _array_member(study, "observations")
    )
    report = adjudicate_findings(findings, observations)
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _disclose(args: argparse.Namespace) -> int:
    specification = _load_object(args.specification)
    bundle = build_evidence_bundle(_object_member(specification, "evidence"))
    raw_request = _object_member(specification, "request")
    try:
        vulnerability_state = VulnerabilityState(_string_member(raw_request, "vulnerabilityState"))
    except ValueError as error:
        raise FormatError("SOVA-DISCLOSE-STATE", "unsupported vulnerability state") from error
    request = DisclosureRequest(
        target_kind=_string_member(raw_request, "targetKind"),
        vulnerability_state=vulnerability_state,
        contains_working_payload=_boolean_member(raw_request, "containsWorkingPayload"),
        authorization_redacted=_boolean_member(raw_request, "authorizationRedacted"),
        secrets_scan_clean=_boolean_member(raw_request, "secretsScanClean"),
        human_reviewed=_boolean_member(raw_request, "humanReviewed"),
        limitations_present=_boolean_member(raw_request, "limitationsPresent"),
        coordinated_disclosure_reference=(
            str(raw_request["coordinatedDisclosureReference"])
            if raw_request.get("coordinatedDisclosureReference") is not None
            else None
        ),
    )
    contacts = specification.get("contacts", [])
    if not isinstance(contacts, list):
        raise FormatError("SOVA-DISCLOSE-CONTACTS", "contacts must be an array")
    if any(not isinstance(item, dict) for item in contacts):
        raise FormatError("SOVA-DISCLOSE-CONTACTS", "contacts must contain objects")
    contact_root = specification.get("contactRoot")
    if contact_root is not None:
        if not isinstance(contact_root, str) or not contact_root:
            raise FormatError("SOVA-DISCLOSE-CONTACTS", "contactRoot must be a path string")
        discovered = discover_maintainer_contacts(Path(contact_root))
        contacts = [*contacts, *discovered]
    if not contacts:
        raise FormatError(
            "SOVA-DISCLOSE-CONTACTS",
            "at least one reviewed or locally discovered contact is required",
        )
    vendor_responses = specification.get("vendorResponses", [])
    if not isinstance(vendor_responses, list) or any(
        not isinstance(item, dict) for item in vendor_responses
    ):
        raise FormatError("SOVA-DISCLOSE-RESPONSES", "vendorResponses must contain objects")
    if "clock" in specification:
        clock = _object_member(specification, "clock")
    else:
        clock = default_disclosure_clock(_string_member(specification, "reportedAt"))
    package = prepare_disclosure_package(
        bundle,
        request,
        contacts=contacts,
        clock=clock,
        vendor_responses=vendor_responses,
        remediation=(
            _object_member(specification, "remediation") if "remediation" in specification else None
        ),
    )
    sys.stdout.buffer.write(canonical_json_bytes(package.to_mapping()) + b"\n")
    return 0 if package.release_allowed else 3


def _composition_budget(
    value: dict[str, Any], *, default_candidates: int = 100
) -> CompositionBudget:
    return CompositionBudget(
        max_attempts=_integer_value(value.get("maxAttempts"), "maxAttempts", default=100),
        max_duration_ms=_integer_value(value.get("maxDurationMs"), "maxDurationMs", default=30_000),
        max_t=_integer_value(value.get("maxT"), "maxT", default=3),
        max_path_nodes=_integer_value(value.get("maxPathNodes"), "maxPathNodes", default=5),
        max_candidates=_integer_value(
            value.get("maxCandidates"), "maxCandidates", default=default_candidates
        ),
    )


def _compose_plan(args: argparse.Namespace) -> int:
    graph = graph_from_mapping(_load_object(args.graph))
    budget = CompositionBudget(max_attempts=args.limit, max_t=args.t, max_candidates=args.limit)
    engine = CompositionSearchEngine(graph, budget)
    candidates = engine.candidates(CompositionStrategy(args.strategy))
    sys.stdout.buffer.write(
        canonical_json_bytes(
            {
                "artifactType": "sova.composition-plan",
                "schemaVersion": "0.1.0",
                "strategy": args.strategy,
                "candidateCount": len(candidates),
                "candidates": [candidate.to_mapping() for candidate in candidates],
                "executesActions": False,
            }
        )
        + b"\n"
    )
    return 0


def _composition_observation(value: Any) -> CompositionObservation:
    if not isinstance(value, dict):
        raise FormatError("SOVA-COMPOSE-OBSERVATION", "observation must be an object")
    traces = value.get("traceReferences", [])
    outcomes = value.get("individualOutcomes", {})
    limitations = value.get("limitations", [])
    if not isinstance(traces, list) or any(not isinstance(item, str) for item in traces):
        raise FormatError("SOVA-COMPOSE-TRACES", "traceReferences must contain strings")
    if not isinstance(outcomes, dict) or any(
        not isinstance(key, str) or not (isinstance(result, bool) or result is None)
        for key, result in outcomes.items()
    ):
        raise FormatError("SOVA-COMPOSE-OUTCOMES", "individualOutcomes is invalid")
    if not isinstance(limitations, list) or any(not isinstance(item, str) for item in limitations):
        raise FormatError("SOVA-COMPOSE-LIMITATIONS", "limitations must contain strings")
    triggered = value.get("triggered")
    if not (isinstance(triggered, bool) or triggered is None):
        raise FormatError("SOVA-COMPOSE-TRIGGERED", "triggered must be boolean or null")
    return CompositionObservation(
        triggered=triggered,
        evidence_complete=_boolean_member(value, "evidenceComplete"),
        oracle_state=_string_member(value, "oracleState"),
        trace_references=tuple(traces),
        individual_outcomes=tuple(sorted(outcomes.items())),
        limitations=tuple(limitations),
    )


def _compose_evaluate(args: argparse.Namespace) -> int:
    study = _load_object(args.study)
    graph = graph_from_mapping(_object_member(study, "graph"))
    observation_rows = _array_member(study, "observations")
    observations: dict[str, CompositionObservation] = {}
    for row in observation_rows:
        if not isinstance(row, dict):
            raise FormatError("SOVA-COMPOSE-OBSERVATION", "observation row must be an object")
        digest = _string_member(row, "candidateDigest")
        if digest in observations:
            raise FormatError("SOVA-COMPOSE-DUPLICATE", "candidate observation is duplicated")
        observations[digest] = _composition_observation(row)

    def evaluator(candidate: Any) -> CompositionObservation:
        return observations.get(
            candidate.digest,
            CompositionObservation(
                triggered=None,
                evidence_complete=False,
                oracle_state="not-observed",
                trace_references=(),
                individual_outcomes=(),
                limitations=("No reviewed observation was supplied for this candidate digest.",),
            ),
        )

    report = CompositionSearchEngine(
        graph, _composition_budget(_object_member(study, "budget"))
    ).search(CompositionStrategy(args.strategy), evaluator)
    document = report.to_mapping()
    validate_document(document, "sova.composition-report")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0 if report.successful is not None else 3


def _rehearse_prepare(args: argparse.Namespace) -> int:
    substitutes = (
        tuple(args.substitute)
        if args.substitute
        else ("process", "database", "api", "network", "browser", "computer")
    )
    report = prepare_rehearsal_environment(
        args.source,
        args.workspace,
        substitutes=substitutes,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 0


def _rehearse_run(args: argparse.Namespace) -> int:
    specification = specification_from_mapping(_load_object(args.specification))
    report = run_rehearsal(specification, args.workspace, args.trace)
    document = report.to_mapping()
    args.report.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    return 0


def _provider_rehearsal_approval_prompt(challenge: Any) -> str:
    sys.stderr.write(
        json.dumps(
            {
                "phase": challenge.phase,
                "scopeDigest": challenge.scope_digest,
                "summary": challenge.summary,
                "warning": (
                    "The provider has no tools. Approved file actions affect only the prepared "
                    "workspace; non-file actions use inert substitutes. The built-in backend "
                    "is not a security sandbox."
                ),
            },
            indent=2,
        )
        + "\n"
    )
    sys.stderr.write(f"Type exactly: {challenge.exact_phrase}\n")
    return input("approval> ")


def _require_provider_rehearsal_terminal() -> None:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-REHEARSE-PROVIDER-INTERACTIVE",
            "provider rehearsal requires a human-operated interactive terminal",
        )


def _rehearse_agent_run(args: argparse.Namespace) -> int:
    if not args.allow_provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "provider rehearsal requires the explicit --allow-provider-calls flag",
        )
    _require_provider_rehearsal_terminal()
    request = provider_rehearsal_request_from_mapping(_load_object(args.request))
    runtime = provider_runtime_from_mapping(_load_object(args.provider_runtime))
    artifacts = run_provider_rehearsal(
        request,
        args.workspace,
        args.destination,
        router=provider_model_router(runtime, secret_resolver=os.getenv),
        max_model_turns=runtime.max_model_turns,
        max_total_tokens=runtime.max_total_tokens,
        provider_calls_authorized=True,
        approval_prompt=_provider_rehearsal_approval_prompt,
    )
    sys.stdout.buffer.write(canonical_json_bytes(artifacts.to_mapping()) + b"\n")
    return 0 if artifacts.status == "pass" else 3


def _rehearse_export(args: argparse.Namespace) -> int:
    result = export_approved_changes(
        _load_object(args.report),
        args.workspace,
        args.destination,
        frozenset(args.approve),
    )
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


def _trace_run(args: argparse.Namespace) -> int:
    result = record_local_process(_load_object(args.specification), args.destination)
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0 if result["processStatus"] == "succeeded" else 3


_SENSITIVE_COMMAND_ARGUMENT = re.compile(
    r"^--?(?:api[-_]?key|authorization|cookie|credential|password|secret|session|token)(?:=|$)",
    re.IGNORECASE,
)


def _trace_command(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise FormatError(
            "SOVA-TRACE-INTERACTIVE-APPROVAL",
            "direct command capture requires a human-operated interactive terminal",
        )
    argv = tuple(str(item) for item in args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise FormatError("SOVA-TRACE-ARGV", "provide an executable after `--`")
    if any(_SENSITIVE_COMMAND_ARGUMENT.search(item) for item in argv):
        raise FormatError(
            "SOVA-TRACE-SENSITIVE-ARGV",
            "direct command arguments cannot contain credential-bearing option names",
        )
    _, sensitive = Redactor(context_id="sova-trace-command-review").redact({"argv": list(argv)})
    if sensitive:
        raise FormatError(
            "SOVA-TRACE-SENSITIVE-ARGV",
            "direct command arguments cannot contain credential-shaped values",
        )
    discovered = shutil.which(argv[0])
    executable = (Path(discovered) if discovered else Path(argv[0])).resolve()
    if not executable.is_file():
        raise FormatError("SOVA-TRACE-EXECUTABLE", "command executable does not exist")
    cwd = args.working_directory.resolve()
    if not cwd.is_dir():
        raise FormatError("SOVA-TRACE-CWD", "working directory does not exist")
    review = {
        "executable": str(executable),
        "argv": [str(executable), *argv[1:]],
        "workingDirectory": str(cwd),
        "timeoutSeconds": str(args.timeout_seconds),
        "captureProfile": str(args.capture_profile),
        "shell": False,
        "nativeSandbox": False,
    }
    review_digest = sha256_digest(canonical_json_bytes(review))
    exact_phrase = f"APPROVE TRACE {review_digest[-16:]}"
    sys.stderr.write(canonical_json_bytes(review).decode("utf-8") + "\n")
    sys.stderr.write(
        "This command runs with restricted environment inheritance but ordinary host authority; "
        "it is not a security sandbox.\n"
    )
    supplied = input(f"Type exactly `{exact_phrase}`: ")
    if supplied != exact_phrase:
        raise FormatError("SOVA-TRACE-APPROVAL", "direct command approval phrase did not match")
    result = record_local_process(
        {
            "argv": review["argv"],
            "workingDirectory": str(cwd),
            "timeoutSeconds": args.timeout_seconds,
            "captureProfile": args.capture_profile,
            "authorizationConfirmed": True,
            "executableAllowlist": [str(executable)],
            "observedEvents": [
                {
                    "kind": "authorization.decision",
                    "payload": {
                        "decision": "allowed",
                        "method": "exact-interactive-command-review",
                        "reviewDigest": review_digest,
                    },
                }
            ],
        },
        args.destination,
    )
    result["directCommandFrontDoor"] = True
    result["reviewDigest"] = review_digest
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0 if result["processStatus"] == "succeeded" else 3


def _trace_snapshot(args: argparse.Namespace) -> int:
    document = build_behavior_snapshot(_load_object(args.specification)).to_mapping()
    if args.output is None:
        sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")
    else:
        args.output.write_bytes(canonical_json_bytes(document) + b"\n")
        sys.stdout.write(f"{document['snapshotDigest']}  {args.output}\n")
    return 0


def _snapshot_from_file(path: Path) -> Any:
    value = _load_object(path)
    if value.get("artifactType") == "sova.behavior-snapshot":
        axes = _object_member(value, "axes")
        axes["id"] = _string_member(value, "id")
        trace_reference = value.get("traceReference")
        if trace_reference is not None:
            if not isinstance(trace_reference, str):
                raise FormatError("SOVA-DIFF-TRACE", "traceReference must be a string or null")
            axes["traceReference"] = trace_reference
        return build_behavior_snapshot(axes)
    return build_behavior_snapshot(value)


def _behavior_diff(args: argparse.Namespace) -> int:
    report = compare_behavior_snapshots(
        _snapshot_from_file(args.left),
        _snapshot_from_file(args.right),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report.to_mapping()) + b"\n")
    return 1 if report.behavioral_drift else 0


def _monitor_policy(path: Path | None) -> dict[str, Any]:
    return (
        _load_object(path)
        if path is not None
        else {
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "maxMethodologyChanges": 0,
            "allowedFlakyReproductions": 0,
            "observedFlakyReproductions": 0,
            "profile": "standard",
            "retention": "operator-controlled",
        }
    )


def _sentinel(args: argparse.Namespace) -> int:
    report = run_sentinel(
        _snapshot_from_file(args.baseline),
        _snapshot_from_file(args.current),
        policy=_monitor_policy(args.policy),
        history_path=args.history,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 1 if report["status"] == "failed" else 0


def _ci(args: argparse.Namespace) -> int:
    diff = compare_behavior_snapshots(
        _snapshot_from_file(args.baseline),
        _snapshot_from_file(args.current),
    )
    report = evaluate_ci(diff, _monitor_policy(args.policy))
    if args.sarif is not None:
        args.sarif.write_bytes(canonical_json_bytes(report["sarif"]) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return int(report["exitCode"])


def _registry_verify(args: argparse.Namespace) -> int:
    trusted = frozenset(args.trusted_key_id or [])
    report = verify_registry(args.root, trusted_key_ids=trusted)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _registry_replay(args: argparse.Namespace) -> int:
    capsule, resolution = resolve_registry_capsule(
        args.root,
        entry_id=args.entry_id,
        version=args.version,
        trusted_key_ids=frozenset(args.trusted_key_id),
    )
    replay = render_capsule_timeline(
        capsule,
        args.destination,
        selection=CapsuleReplaySelection(
            nested_capsule=args.nested_capsule,
            surface=getattr(args, "surface", None),
        ),
    )
    report = {
        "artifactType": "sova.registry-capsule-replay",
        "schemaVersion": "0.1.0",
        "resolution": resolution,
        "replay": replay,
    }
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _registry_init_service(args: argparse.Namespace) -> int:
    report = create_community_service_token(args.token_file)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _registry_prepare_upload(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise FormatError("SOVA-SERVICE-UPLOAD", "upload output already exists")
    document = prepare_community_submission(
        kind=args.kind,
        metadata=_load_object(args.metadata),
        capsule=args.capsule,
        trace=args.trace,
    )
    payload = serialize_community_submission(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    summary = {
        "artifactType": "sova.community-upload-prepared",
        "schemaVersion": "0.1.0",
        "output": str(args.output.resolve()),
        "submissionDigest": sha256_digest(payload),
        "uploadPerformed": False,
    }
    sys.stdout.buffer.write(canonical_json_bytes(summary) + b"\n")
    return 0


def _registry_verify_live_index(args: argparse.Namespace) -> int:
    report = verify_community_service_index(
        _load_object(args.index),
        trusted_service_key_ids=frozenset(args.trusted_service_key_id),
        minimum_sequence=args.minimum_sequence,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _registry_healthcheck(args: argparse.Namespace) -> int:
    report = check_community_service_health(args.url)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _registry_serve(args: argparse.Namespace) -> int:
    token = args.token_file.read_text(encoding="utf-8").strip()
    methodology = args.methodology.read_text(encoding="utf-8")
    config = CommunityServiceConfig(
        args.root,
        token,
        frozenset(args.trusted_key_id),
        methodology,
        host=args.host,
        port=args.port,
    )
    service = CommunityHTTPService(config)
    host, port = service.address
    sys.stderr.write(
        f"SOVA community service listening on http://{host}:{port}; "
        "submitted content is verified but never executed.\n"
    )
    with suppress(KeyboardInterrupt):
        service.serve_forever()
    return 0


def _monitor_service(args: argparse.Namespace) -> ContinuousMonitorService:
    jobs = monitoring_jobs_from_document(
        _load_object(args.specification),
        workspace=args.workspace,
    )
    endpoint = getattr(args, "alert_webhook", None)
    secret_name = getattr(args, "alert_secret_env", None)
    if (endpoint is None) != (secret_name is None):
        raise FormatError(
            "SOVA-ALERT-CONFIG",
            "alert webhook and secret environment variable must be supplied together",
        )
    notifier = None
    if endpoint is not None and secret_name is not None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", secret_name) is None:
            raise FormatError("SOVA-ALERT-CONFIG", "alert secret environment name is invalid")
        secret = os.environ.get(secret_name)
        if secret is None:
            raise FormatError("SOVA-ALERT-SECRET", "alert webhook secret is unavailable")
        notifier = WebhookAlertNotifier(endpoint, secret.encode())
    return ContinuousMonitorService(jobs, args.state, notifier=notifier)


def _monitor_serve(args: argparse.Namespace) -> int:
    service = _monitor_service(args)
    stop = threading.Event()
    try:
        runs = service.serve(
            stop,
            max_cycles=1 if args.once else None,
            poll_seconds=args.poll_seconds,
        )
    except KeyboardInterrupt:
        stop.set()
        runs = ()
    for run in runs:
        sys.stdout.buffer.write(canonical_json_bytes(run) + b"\n")
    sys.stdout.buffer.write(canonical_json_bytes(service.status()) + b"\n")
    return 1 if any(run["status"] == "failed" for run in runs) else 0


def _monitor_status(args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(canonical_json_bytes(_monitor_service(args).status()) + b"\n")
    return 0


def _sync(args: argparse.Namespace) -> int:
    report = sync_registry(tuple(args.sources), args.cache)
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _contribute(args: argparse.Namespace) -> int:
    report = prepare_contribution(
        _load_object(args.specification),
        args.destination,
        confirmed=bool(args.confirm),
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


def _self_check_create(args: argparse.Namespace) -> int:
    document = build_integrity_manifest(args.root, tuple(args.include))
    args.manifest.write_bytes(canonical_json_bytes(document) + b"\n")
    sys.stdout.write(f"{document['manifestDigest']}  {args.manifest}\n")
    return 0


def _self_check_verify(args: argparse.Namespace) -> int:
    report = verify_integrity_manifest(args.root, _load_object(args.manifest))
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 1 if report["status"] == "failed" else 0


_REPLAY_SUBCOMMANDS = frozenset({"open", "modes", "timeline", "capsule", "serve", "study", "clip"})
_REPLAY_SHORTCUT_MINIMUM_ARGUMENTS = 2


def _rewrite_replay_shortcut(argv: Sequence[str] | None) -> list[str]:
    values = list(sys.argv[1:] if argv is None else argv)
    if (
        len(values) >= _REPLAY_SHORTCUT_MINIMUM_ARGUMENTS
        and values[0] == "replay"
        and values[1] not in _REPLAY_SUBCOMMANDS
        and not values[1].startswith("-")
        and Path(values[1]).suffix.casefold() == ".sova"
    ):
        return ["replay", "open", *values[1:]]
    return values


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(_rewrite_replay_shortcut(argv))
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return int(handler(args))
    except (FormatError, OSError) as error:
        if isinstance(error, FormatError):
            issue = error.issue
            sys.stderr.write(f"{issue.code} {issue.path}: {issue.message}\n")
        else:
            sys.stderr.write(f"SOVA-IO-ERROR: {error}\n")
        return 2
