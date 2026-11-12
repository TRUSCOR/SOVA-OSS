# SPDX-License-Identifier: Apache-2.0
"""Loss-reporting bridge for TRACE Trust Records (v0.2 developer preview).

TRACE records attest *what executed, where, and under which policy*. They do not
report an observable event stream, an outcome predicate, or whether retained
evidence supports a named claim. This bridge therefore imports a record as a
declared trust input to a ``.sova-trace`` and refuses to let it stand in for
observation, sufficiency, or a reproduction decision.

Specification: https://github.com/agentrust-io/trace-spec (v0.2, Developer
Preview, Community Specification License 1.0).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_RECORD_BYTES = 1 * 1024 * 1024
_MAX_RECORDS = 10_000

# Only profiles whose semantics have been reviewed are admitted. An unknown
# profile fails closed rather than being imported on a best-effort basis.
_ADMITTED_PROFILES = frozenset({"tag:agentrust-io.com,2026:trace-v0.2"})

# Platforms that carry no hardware root of trust. v0.2 has no hardware
# attestation at all, but the distinction is recorded for forward compatibility
# with the proposed v0.3 runtime-evidence profile.
_UNATTESTED_PLATFORMS = frozenset({"software-only", "none", "unknown"})

# An appraisal that has not been performed, or was performed and did not pass,
# must never be imported as a satisfied trust condition.
_NON_AFFIRMING_APPRAISALS = frozenset({"none", "pending", "failed", "error"})

# The six completeness meanings a .sova-trace separates (specification 3.2). A
# TRACE record speaks to none of them; it describes the environment, not the
# observation. Recording this explicitly is what stops environment attestation
# from being silently promoted to evidence.
_COMPLETENESS_MEANINGS_NOT_ADDRESSED = (
    "package-continuity",
    "local-event-chain-continuity",
    "recorder-reported-dropped-data",
    "sensor-coverage",
    "source-completeness",
    "semantic-sufficiency-for-claim",
)


def _require_mapping(value: Any, code: str, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatError(code, message)
    return value


def _record(value: Any, index: int) -> dict[str, Any]:
    record = _require_mapping(value, "SOVA-INTEROP-TRACE-RECORD", "TRACE record must be an object")

    profile = record.get("eat_profile")
    if not isinstance(profile, str) or not profile:
        raise FormatError("SOVA-INTEROP-TRACE-PROFILE", "TRACE record requires eat_profile")
    if profile not in _ADMITTED_PROFILES:
        raise FormatError(
            "SOVA-INTEROP-TRACE-PROFILE-UNKNOWN",
            f"TRACE profile is not admitted for import: {profile}",
        )

    subject = record.get("subject")
    if not isinstance(subject, str) or not subject:
        raise FormatError("SOVA-INTEROP-TRACE-SUBJECT", "TRACE record requires a subject")

    runtime = _require_mapping(
        record.get("runtime", {}), "SOVA-INTEROP-TRACE-RUNTIME", "runtime must be an object"
    )
    policy = _require_mapping(
        record.get("policy", {}), "SOVA-INTEROP-TRACE-POLICY", "policy must be an object"
    )
    model = _require_mapping(
        record.get("model", {}), "SOVA-INTEROP-TRACE-MODEL", "model must be an object"
    )
    appraisal = _require_mapping(
        record.get("appraisal", {}), "SOVA-INTEROP-TRACE-APPRAISAL", "appraisal must be an object"
    )

    appraisal_status = str(appraisal.get("status", "none"))
    platform = str(runtime.get("platform", "unknown"))

    reproducibility = record.get("reproducibility")
    if reproducibility is not None:
        _require_mapping(
            reproducibility,
            "SOVA-INTEROP-TRACE-REPRODUCIBILITY",
            "reproducibility must be an object",
        )
    re_execution = appraisal.get("re_execution")
    if re_execution is not None:
        _require_mapping(
            re_execution,
            "SOVA-INTEROP-TRACE-RE-EXECUTION",
            "appraisal.re_execution must be an object",
        )

    return {
        "originalIndex": index,
        "profile": profile,
        "subject": subject,
        "issuedAt": record.get("iat"),
        # Everything below is what the record ASSERTS. None of it is observed by
        # SOVA, and the naming keeps that distinction visible at every call site.
        "assertedModel": {
            "provider": model.get("provider"),
            "modelId": model.get("model_id"),
            "weightsDigest": model.get("weights_digest"),
        },
        "assertedRuntime": {
            "platform": platform,
            "measurement": runtime.get("measurement"),
            "hardwareRootOfTrust": platform not in _UNATTESTED_PLATFORMS,
        },
        "assertedPolicy": {
            "bundleHash": policy.get("bundle_hash"),
            "enforcementMode": policy.get("enforcement_mode"),
        },
        "assertedDataClass": record.get("data_class"),
        "assertedBuildProvenance": record.get("build_provenance"),
        "appraisal": {
            "status": appraisal_status,
            "verifier": appraisal.get("verifier"),
            "affirming": appraisal_status not in _NON_AFFIRMING_APPRAISALS,
            "method": appraisal.get("method"),
            # A re-execution outcome inside a producer-signed record is the
            # producer's report of what a verifier found (TRACE v0.2 section
            # 3.1.4), so it is carried as asserted and never as observed.
            "assertedReExecution": re_execution,
        },
        # TRACE v0.2 section 3.1.4: deterministic re-execution of the producer's
        # coordination logic over a pinned input closure, with model calls
        # recorded as inputs. It is byte-level re-derivation of decisions, not
        # semantic reproduction of an observable behavior under another model.
        "assertedDeterministicReproducibility": reproducibility,
        "transparency": record.get("transparency"),
        "toolTranscript": record.get("tool_transcript"),
        "unknownFields": {
            key: child
            for key, child in record.items()
            if key
            not in {
                "eat_profile",
                "iat",
                "subject",
                "model",
                "runtime",
                "policy",
                "data_class",
                "build_provenance",
                "appraisal",
                "transparency",
                "tool_transcript",
                "reproducibility",
            }
        },
    }


def _rows(path: Path) -> list[Any]:
    size = path.stat().st_size
    if size > _MAX_RECORD_BYTES * _MAX_RECORDS:
        raise FormatError("SOVA-INTEROP-TRACE-LIMIT", "TRACE record set exceeds size limit")
    raw = path.read_bytes()
    if path.suffix.lower() == ".jsonl":
        parsed: list[Any] = [strict_json_loads(line) for line in raw.splitlines() if line.strip()]
    else:
        value = strict_json_loads(raw, max_bytes=_MAX_RECORD_BYTES * _MAX_RECORDS)
        parsed = value if isinstance(value, list) else [value]
    if len(parsed) > _MAX_RECORDS:
        raise FormatError("SOVA-INTEROP-TRACE-COUNT", "TRACE record set has too many records")
    return parsed


def import_trace_records(
    source: Path,
    *,
    license_expression: str,
    source_url: str,
) -> dict[str, Any]:
    """Import TRACE Trust Records as declared trust inputs, never as observations.

    The returned document is deliberately not a ``.sova-trace``. It carries no
    events, supports no outcome predicate, and cannot satisfy any evidence
    requirement on its own.
    """
    if not license_expression or not source_url:
        raise FormatError("SOVA-INTEROP-PROVENANCE", "source URL and licence are required")

    records = [_record(row, index) for index, row in enumerate(_rows(source))]
    source_digest = sha256_digest(source.read_bytes())

    losses: list[str] = [
        # These are unconditional: they are properties of the TRACE format, not
        # of any particular record.
        "trace-record-carries-no-observable-event-stream",
        "trace-record-carries-no-outcome-predicate",
        "trace-record-carries-no-claim-conditioned-evidence-sufficiency",
        # TRACE v0.2 may carry a deterministic reproducibility claim (section
        # 3.1.4), but it never decides whether an observable behavior recurred
        # under a different model or runtime.
        "trace-record-carries-no-semantic-reproduction-state",
    ]
    if any(item["assertedDeterministicReproducibility"] is not None for item in records):
        losses.append(
            "trace-reproducibility-is-deterministic-re-execution-not-semantic-reproduction"
        )
    if any(item["appraisal"]["assertedReExecution"] is not None for item in records):
        losses.append("trace-re-execution-outcome-is-producer-asserted-not-observed")
    if any(not item["assertedRuntime"]["hardwareRootOfTrust"] for item in records):
        losses.append("trace-runtime-measurement-not-hardware-rooted")
    if any(not item["appraisal"]["affirming"] for item in records):
        losses.append("trace-appraisal-not-affirming-trust-condition-unsatisfied")
    if any(item["toolTranscript"] is not None for item in records):
        # A transcript digest proves a transcript existed with that hash. It does
        # not supply the transcript, so no predicate can be evaluated over it.
        losses.append("trace-tool-transcript-digest-only-contents-unavailable")
    if any(item["unknownFields"] for item in records):
        losses.append("trace-unknown-fields-retained-uninterpreted")

    return {
        "artifactType": "sova.external-attestation-set",
        "schemaVersion": "0.1.0",
        "sourceFormat": "trace-trust-record-v0.2",
        "source": {
            "url": source_url,
            "license": license_expression,
            "digest": source_digest,
        },
        "records": records,
        "trustContribution": {
            # The central semantic. A TRACE signature is evidence about the
            # record, not about the world the record describes -- as the TRACE
            # project's own README states for v0.2.
            "establishes": "declared-execution-environment-and-policy-context",
            "doesNotEstablish": "observation-truth-evidence-sufficiency-or-reproduction",
            "completenessMeaningsNotAddressed": list(_COMPLETENESS_MEANINGS_NOT_ADDRESSED),
            "admissibleAs": "trust-input-to-context-equivalence-envelope",
            "inadmissibleAs": "evidence-for-an-outcome-predicate",
        },
        "conversion": {
            "lossless": False,
            "semanticLoss": sorted(losses),
            "executionPolicy": "inert-import-fresh-authorization-required",
        },
    }
