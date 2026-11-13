# SPDX-License-Identifier: Apache-2.0
"""Offline artifact verification with explicit partial and unsupported states."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader
from sova.formats.errors import FormatError
from sova.replay.model import (
    ArtifactVerification,
    CheckState,
    VerificationCheck,
    VerificationState,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

_SUPPORTED_CAPSULE_FEATURES = {
    "capsule.core/0.1",
    "scenario.core/0.1",
    "trace.core/0.1",
    "detonation.synthetic/0.1",
    "arena.chamber/0.1",
}
_SUPPORTED_TRACE_FEATURES = {"trace.core/0.1"}


def _check(name: str, state: CheckState, detail: str) -> VerificationCheck:
    return VerificationCheck(name, state, detail)


def _required_features(
    features: list[str], supported: set[str]
) -> tuple[VerificationCheck, tuple[str, ...]]:
    missing = tuple(sorted(set(features) - supported))
    if missing:
        return (
            _check(
                "required-features",
                CheckState.UNSUPPORTED,
                f"unsupported required features: {', '.join(missing)}",
            ),
            missing,
        )
    return _check("required-features", CheckState.PASSED, "all required features supported"), ()


def _capsule_checks(path: Path) -> ArtifactVerification:
    reader = PackageReader(path)
    descriptors = reader.verify("sova.capsule")
    manifest = reader.manifest("sova.capsule")
    feature_check, missing = _required_features(
        manifest["requiredFeatures"], _SUPPORTED_CAPSULE_FEATURES
    )
    checks = [
        _check("schema", CheckState.PASSED, f"capsule schema {manifest['schemaVersion']}"),
        _check(
            "canonical-package-and-objects",
            CheckState.PASSED,
            f"verified {len(descriptors)} content-addressed object(s)",
        ),
        feature_check,
    ]
    limitations: list[str] = []
    partial = False
    for name in ("methodology", "taxonomy"):
        context = manifest[name]
        if context["digest"] is None:
            checks.append(
                _check(
                    name,
                    CheckState.PARTIAL,
                    f"{context['id']} {context['version']} is named but not digest-pinned",
                )
            )
            limitations.append(f"{name} identity is not content-pinned")
            partial = True
        else:
            checks.append(
                _check(
                    name,
                    CheckState.PASSED,
                    f"{context['id']} {context['version']} is digest-pinned",
                )
            )
    checks.extend(
        (
            _check(
                "authorization",
                CheckState.PASSED,
                "fresh authorization is required before re-execution",
            ),
            _check(
                "safety-and-disclosure",
                CheckState.PASSED,
                "declared safety, disclosure, license, and limitations are structurally valid",
            ),
        )
    )
    if missing:
        state = VerificationState.UNSUPPORTED
        limitations.append("Artifact integrity is valid but required behavior is unsupported.")
    elif partial:
        state = VerificationState.PARTIAL
    else:
        state = VerificationState.VERIFIED
    limitations.append("Verification does not establish that the capsule's claims are true.")
    return ArtifactVerification("sova.capsule", state, tuple(checks), tuple(limitations))


def _fingerprint_check(manifest: dict[str, Any]) -> VerificationCheck:
    values = manifest["fingerprints"]
    absent = sorted(
        name
        for name, value in values.items()
        if value["status"] not in {"recorded", "not-applicable"}
    )
    if absent:
        return _check(
            "environment-and-component-fingerprints",
            CheckState.PARTIAL,
            f"not fully recorded: {', '.join(absent)}",
        )
    return _check(
        "environment-and-component-fingerprints",
        CheckState.PASSED,
        "all applicable fingerprints are recorded",
    )


def _trace_checks(
    path: Path,
    *,
    require_signature: bool,
    required_key_id: str | None,
) -> ArtifactVerification:
    reader = TraceReader(path)
    report = reader.verify(
        require_signature=require_signature,
        required_key_id=required_key_id,
    )
    manifest = reader.manifest()
    feature_check, missing = _required_features(
        manifest["requiredFeatures"], _SUPPORTED_TRACE_FEATURES
    )
    checks = [
        _check("schema", CheckState.PASSED, f"trace schema {manifest['schemaVersion']}"),
        _check("package-hashes", CheckState.PASSED, "package object digests verified"),
        _check("event-order-and-chain", CheckState.PASSED, "sequence and hash chain verified"),
        _check("causal-links", CheckState.PASSED, "causal parents reference earlier events"),
        _check("redaction-structure", CheckState.PASSED, "typed redaction placeholders verified"),
        _fingerprint_check(manifest),
        feature_check,
    ]
    limitations = list(report.limitations)
    partial = any(check.state == CheckState.PARTIAL for check in checks)
    if report.signature_present:
        checks.append(_check("signature", CheckState.PASSED, report.trust_policy))
    else:
        checks.append(_check("signature", CheckState.NOT_PRESENT, "trace is unsigned"))
        limitations.append("No recorder signature is present.")
        partial = True
    signature = manifest["integrity"]["signature"]
    material = signature.get("verificationMaterial") if isinstance(signature, dict) else None
    if material is None:
        checks.append(
            _check(
                "timestamp-and-transparency",
                CheckState.NOT_PRESENT,
                "no timestamp or transparency material is carried",
            )
        )
    else:
        checks.append(
            _check(
                "timestamp-and-transparency",
                CheckState.PARTIAL,
                "material is digest-bound but external trust-root verification "
                "is unavailable offline",
            )
        )
        limitations.append(
            "Timestamp/transparency material requires a pinned external-root verifier."
        )
        partial = True
    if manifest["capturePolicy"]["droppedEventCount"] or manifest["completion"] in {
        "partial",
        "crashed",
        "recovered",
    }:
        checks.append(
            _check(
                "evidence-completeness",
                CheckState.PARTIAL,
                "trace is an integrity-valid observable prefix, not a complete run",
            )
        )
        partial = True
    else:
        checks.append(
            _check("evidence-completeness", CheckState.PASSED, "no recorder loss is declared")
        )
    checks.append(
        _check(
            "threat-model",
            CheckState.PASSED,
            "tamper evidence and recorder provenance only; recorder honesty is out of scope",
        )
    )
    if missing:
        state = VerificationState.UNSUPPORTED
    elif partial:
        state = VerificationState.PARTIAL
    else:
        state = VerificationState.VERIFIED
    return ArtifactVerification("sova.trace", state, tuple(checks), tuple(limitations))


def verify_artifact(
    path: Path,
    *,
    require_signature: bool = False,
    required_key_id: str | None = None,
) -> ArtifactVerification:
    """Verify a capsule or trace without executing content or using a network."""
    if path.name.endswith(".sova-trace"):
        artifact_type = "sova.trace"
    elif path.suffix == ".sova":
        artifact_type = "sova.capsule"
    else:
        artifact_type = "unknown"
    if artifact_type == "unknown":
        return ArtifactVerification(
            artifact_type,
            VerificationState.UNSUPPORTED,
            (
                _check(
                    "artifact-type",
                    CheckState.UNSUPPORTED,
                    "only .sova and .sova-trace artifacts are supported",
                ),
            ),
            (),
            "SOVA-VERIFY-UNSUPPORTED-TYPE",
        )
    try:
        if artifact_type == "sova.trace":
            return _trace_checks(
                path,
                require_signature=require_signature,
                required_key_id=required_key_id,
            )
        if require_signature or required_key_id is not None:
            # Capsules carry no signature of their own; a signature policy must
            # fail closed rather than pass silently (matches the Node verifier).
            return ArtifactVerification(
                artifact_type,
                VerificationState.UNSUPPORTED,
                (
                    _check(
                        "signature-policy",
                        CheckState.UNSUPPORTED,
                        "signature policy is supported only for sova.trace; "
                        "verify each embedded trace with the policy instead",
                    ),
                ),
                (),
                "SOVA-VERIFY-CAPSULE-SIGNATURE-POLICY",
            )
        return _capsule_checks(path)
    except (FormatError, OSError) as error:
        code = error.issue.code if isinstance(error, FormatError) else "SOVA-IO-ERROR"
        return ArtifactVerification(
            artifact_type,
            VerificationState.INVALID,
            (_check("integrity", CheckState.FAILED, "artifact verification failed"),),
            (
                "The error message is omitted because hostile paths or payloads "
                "may contain secrets.",
            ),
            code,
        )


__all__ = ["verify_artifact"]
