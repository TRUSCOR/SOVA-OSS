# SPDX-License-Identifier: Apache-2.0
"""Evidence-bundle construction and bounded interoperability projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sova.evidence.model import EvidenceBundle, EvidenceReference, ScannerFinding, Severity
from sova.formats.errors import FormatError

_MAX_SARIF_RESULTS = 10_000
_SHA256_IDENTIFIER_LENGTH = 71


def _required_text(mapping: Mapping[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value.strip():
        raise FormatError("SOVA-EVIDENCE-FIELD", f"{name} must be a non-empty string")
    return value.strip()


def _string_tuple(value: Any, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise FormatError("SOVA-EVIDENCE-FIELD", f"{name} must be an array")
    result = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
    if len(result) != len(value):
        raise FormatError("SOVA-EVIDENCE-FIELD", f"{name} must contain only non-empty strings")
    return result


def _reference(value: Mapping[str, Any]) -> EvidenceReference:
    digest = value.get("digest")
    if digest is not None and (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != _SHA256_IDENTIFIER_LENGTH
    ):
        raise FormatError("SOVA-EVIDENCE-DIGEST", "evidence digest must be a SHA-256 identifier")
    verified = value.get("verified", False)
    if not isinstance(verified, bool):
        raise FormatError("SOVA-EVIDENCE-VERIFIED", "evidence verified must be a boolean")
    return EvidenceReference(
        role=_required_text(value, "role"),
        uri=_required_text(value, "uri"),
        digest=digest,
        media_type=_required_text(value, "mediaType"),
        verified=verified,
    )


def _references(value: Any, *, name: str) -> tuple[EvidenceReference, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise FormatError("SOVA-EVIDENCE-FIELD", f"{name} must be an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise FormatError("SOVA-EVIDENCE-FIELD", f"{name} must contain objects")
    return tuple(_reference(item) for item in value)


def build_evidence_bundle(specification: Mapping[str, Any]) -> EvidenceBundle:  # noqa: PLR0912
    """Build a strict local evidence bundle from reviewed, already-redacted input."""
    finding = specification.get("finding")
    if not isinstance(finding, Mapping):
        raise FormatError("SOVA-EVIDENCE-FINDING", "finding object is required")
    affected = finding.get("affected")
    if not isinstance(affected, Mapping):
        raise FormatError("SOVA-EVIDENCE-AFFECTED", "affected component object is required")
    coverage = specification.get("coverage")
    if not isinstance(coverage, Mapping):
        raise FormatError("SOVA-EVIDENCE-COVERAGE", "coverage object is required")
    tested = coverage.get("testedCount")
    denominator = coverage.get("denominator")
    if not isinstance(tested, int) or isinstance(tested, bool) or tested < 0:
        raise FormatError("SOVA-EVIDENCE-COVERAGE", "testedCount must be a non-negative integer")
    if denominator is not None and (
        not isinstance(denominator, int) or isinstance(denominator, bool) or denominator < tested
    ):
        raise FormatError(
            "SOVA-EVIDENCE-COVERAGE",
            "coverage denominator must be null or an integer not below testedCount",
        )
    try:
        severity = Severity(_required_text(finding, "technicalSeverity"))
    except ValueError as error:
        raise FormatError("SOVA-EVIDENCE-SEVERITY", "unsupported technical severity") from error
    reproduction = specification.get("reproduction")
    if not isinstance(reproduction, Mapping):
        raise FormatError("SOVA-EVIDENCE-REPRODUCTION", "reproduction object is required")
    methodology = specification.get("methodology")
    if not isinstance(methodology, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in methodology.items()
    ):
        raise FormatError("SOVA-EVIDENCE-METHODOLOGY", "methodology must be a string map")
    taxonomy = specification.get("taxonomyMappings", ())
    if not isinstance(taxonomy, Sequence) or isinstance(taxonomy, (str, bytes)):
        raise FormatError("SOVA-EVIDENCE-TAXONOMY", "taxonomyMappings must be an array")
    taxonomy_rows: list[dict[str, str]] = []
    for row in taxonomy:
        if not isinstance(row, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in row.items()
        ):
            raise FormatError("SOVA-EVIDENCE-TAXONOMY", "taxonomy mapping must be a string map")
        taxonomy_rows.append(dict(row))
    lifecycle = specification.get("lifecycle", {"state": "draft", "supersedes": None})
    if not isinstance(lifecycle, Mapping):
        raise FormatError("SOVA-EVIDENCE-LIFECYCLE", "lifecycle must be an object")
    limitations = _string_tuple(specification.get("limitations", ()), name="limitations")
    if not limitations:
        raise FormatError("SOVA-EVIDENCE-LIMITATIONS", "at least one limitation is required")
    references = _references(specification.get("evidence", ()), name="evidence")
    if not any(item.role == "capsule" for item in references):
        raise FormatError("SOVA-EVIDENCE-CAPSULE", "a `.sova` capsule reference is required")
    if not any(item.role == "trace" for item in references):
        raise FormatError("SOVA-EVIDENCE-TRACE", "a `.sova-trace` reference is required")
    return EvidenceBundle(
        finding_id=_required_text(finding, "id"),
        title=_required_text(finding, "title"),
        summary=_required_text(finding, "summary"),
        component=_required_text(affected, "component"),
        version=_required_text(affected, "version"),
        component_identifiers=_string_tuple(affected.get("identifiers", ()), name="identifiers"),
        severity=severity,
        harm_category=_required_text(finding, "harmCategory"),
        references=references,
        conditions_tested=_string_tuple(
            specification.get("conditionsTested", ()), name="conditionsTested"
        ),
        tested_count=tested,
        coverage_denominator=denominator,
        detection_floor=_required_text(coverage, "detectionFloor"),
        reproduction=dict(reproduction),
        taxonomy_mappings=tuple(taxonomy_rows),
        methodology=dict(methodology),
        mitigations=_string_tuple(
            specification.get("suggestedMitigations", ()), name="suggestedMitigations"
        ),
        regression_evidence=_references(
            specification.get("regressionEvidence", ()), name="regressionEvidence"
        ),
        attachments=_references(specification.get("attachments", ()), name="attachments"),
        limitations=limitations,
        lifecycle=dict(lifecycle),
    )


def evidence_to_sarif(bundle: EvidenceBundle) -> dict[str, Any]:
    """Project one SOVA finding to SARIF without claiming SARIF carries full evidence."""
    evidence = bundle.to_mapping()
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SOVA OSS",
                        "informationUri": "https://github.com/TRUSCOR/SOVA-OSS",
                        "rules": [
                            {
                                "id": bundle.finding_id,
                                "name": bundle.title,
                                "shortDescription": {"text": bundle.summary},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": bundle.finding_id,
                        "level": {
                            Severity.CRITICAL: "error",
                            Severity.HIGH: "error",
                            Severity.MEDIUM: "warning",
                            Severity.LOW: "note",
                            Severity.INFORMATIONAL: "note",
                            Severity.UNKNOWN: "none",
                        }[bundle.severity],
                        "message": {"text": bundle.summary},
                        "properties": {
                            "sovaEvidenceReferences": [
                                item.to_mapping() for item in bundle.references
                            ],
                            "sovaSelfGeneratedEvidence": True,
                            "sovaIndependentAttestation": False,
                            "sovaDetectionFloor": evidence["coverage"]["detectionFloor"],
                        },
                    }
                ],
            }
        ],
    }


def import_sarif(document: Mapping[str, Any]) -> tuple[ScannerFinding, ...]:
    """Import a bounded SARIF result surface while retaining scanner identity."""
    runs = document.get("runs")
    if not isinstance(runs, Sequence) or isinstance(runs, (str, bytes)):
        raise FormatError("SOVA-SARIF-RUNS", "SARIF runs must be an array")
    findings: list[ScannerFinding] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise FormatError("SOVA-SARIF-RUN", "SARIF run must be an object")
        driver = run.get("tool", {})
        driver = driver.get("driver", {}) if isinstance(driver, Mapping) else {}
        scanner = _required_text(driver, "name") if isinstance(driver, Mapping) else "unknown"
        scanner_version = (
            str(driver.get("version", "unknown")) if isinstance(driver, Mapping) else "unknown"
        )
        results = run.get("results", ())
        if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
            raise FormatError("SOVA-SARIF-RESULTS", "SARIF results must be an array")
        for result_index, result in enumerate(results):
            if len(findings) >= _MAX_SARIF_RESULTS:
                raise FormatError("SOVA-SARIF-LIMIT", "SARIF result limit exceeded")
            if not isinstance(result, Mapping):
                raise FormatError("SOVA-SARIF-RESULT", "SARIF result must be an object")
            message = result.get("message", {})
            message_text = (
                str(message.get("text", "no message"))
                if isinstance(message, Mapping)
                else "no message"
            )
            locations = result.get("locations", ())
            location = f"sarif-run-{run_index}-result-{result_index}"
            if isinstance(locations, Sequence) and locations and isinstance(locations[0], Mapping):
                physical = locations[0].get("physicalLocation", {})
                artifact = (
                    physical.get("artifactLocation", {}) if isinstance(physical, Mapping) else {}
                )
                if isinstance(artifact, Mapping) and isinstance(artifact.get("uri"), str):
                    location = str(artifact["uri"])
            fingerprints = result.get("fingerprints")
            target_id = (
                str(fingerprints.get("sovaTarget", location))
                if isinstance(fingerprints, Mapping)
                else location
            )
            findings.append(
                ScannerFinding(
                    scanner=scanner,
                    scanner_version=scanner_version,
                    rule_id=str(result.get("ruleId", "unknown-rule")),
                    target_id=target_id,
                    location=location,
                    message=message_text,
                    evidence_reference=f"sarif:{run_index}:{result_index}",
                    mechanism="external-static-or-dynamic-scanner",
                )
            )
    return tuple(findings)


__all__ = ["build_evidence_bundle", "evidence_to_sarif", "import_sarif"]
