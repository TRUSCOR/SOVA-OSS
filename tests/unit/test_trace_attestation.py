# SPDX-License-Identifier: Apache-2.0
"""TRACE Trust Record import must never promote attestation to observation."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.formats.errors import FormatError
from sova.interoperability import import_trace_records

if TYPE_CHECKING:
    from pathlib import Path

_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

# Adapted from the TRACE README quick-start record (v0.2 profile, CC BY 4.0,
# trace-spec commit d618244), with ``iat`` fixed instead of ``int(time.time())``
# so the fixture is deterministic. It is an unsigned quick-start record, not the
# normative JWT example in spec/trace-v0.2.md section 3.2.
_SPEC_EXAMPLE = {
    "eat_profile": _PROFILE,
    "iat": 1234567890,
    "subject": "spiffe://trust.example.org/agent/payments-processor",
    "model": {"provider": "example-provider", "model_id": "example-model-1"},
    "runtime": {
        "platform": "software-only",
        "measurement": "sha256:" + "0" * 64,
    },
    "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
    "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
}

_PROVENANCE = {
    "license_expression": "CC-BY-4.0",
    "source_url": (
        "https://github.com/agentrust-io/trace-spec/blob/"
        "d618244daa8202c11bf8797ab25c41af5d4bd8ff/README.md"
    ),
}

# Shape of TRACE v0.2 section 3.1.4 (deterministic re-execution claim) and of a
# re-execution appraisal result, with synthetic digests.
_REPRODUCIBILITY = {
    "function": "coordinate",
    "code_identity": "sha256:" + "1" * 64,
    "input_closure": [{"id": "config", "digest": "sha256:" + "2" * 64, "resolver": "producer"}],
    "transcript_digest": "sha256:" + "3" * 64,
}


def _write(tmp_path: Path, payload: object, name: str = "record.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_spec_example_imports_as_trust_input_not_evidence(tmp_path: Path) -> None:
    document = import_trace_records(_write(tmp_path, _SPEC_EXAMPLE), **_PROVENANCE)

    assert document["artifactType"] == "sova.external-attestation-set"
    assert document["sourceFormat"] == "trace-trust-record-v0.2"

    contribution = document["trustContribution"]
    assert contribution["admissibleAs"] == "trust-input-to-context-equivalence-envelope"
    assert contribution["inadmissibleAs"] == "evidence-for-an-outcome-predicate"
    # A TRACE record addresses none of the six completeness meanings.
    assert len(contribution["completenessMeaningsNotAddressed"]) == 6
    assert "semantic-sufficiency-for-claim" in contribution["completenessMeaningsNotAddressed"]


def test_import_is_never_lossless(tmp_path: Path) -> None:
    """The four format-level losses are unconditional, so lossless is unreachable."""
    document = import_trace_records(_write(tmp_path, _SPEC_EXAMPLE), **_PROVENANCE)

    conversion = document["conversion"]
    assert conversion["lossless"] is False
    assert conversion["executionPolicy"] == "inert-import-fresh-authorization-required"
    for expected in (
        "trace-record-carries-no-observable-event-stream",
        "trace-record-carries-no-outcome-predicate",
        "trace-record-carries-no-claim-conditioned-evidence-sufficiency",
        "trace-record-carries-no-semantic-reproduction-state",
    ):
        assert expected in conversion["semanticLoss"]


def test_deterministic_reproducibility_claim_is_not_semantic_reproduction(
    tmp_path: Path,
) -> None:
    """A section 3.1.4 claim is retained as asserted re-derivation, never as reproduction."""
    record = {
        **_SPEC_EXAMPLE,
        "reproducibility": _REPRODUCIBILITY,
        "appraisal": {
            "status": "affirming",
            "method": "re-execution",
            "re_execution": {"outcome": "reproduced"},
        },
    }
    document = import_trace_records(_write(tmp_path, record), **_PROVENANCE)
    item = document["records"][0]
    losses = document["conversion"]["semanticLoss"]

    assert item["assertedDeterministicReproducibility"] == _REPRODUCIBILITY
    assert item["appraisal"]["assertedReExecution"] == {"outcome": "reproduced"}
    assert "reproducibility" not in item["unknownFields"]
    assert "trace-reproducibility-is-deterministic-re-execution-not-semantic-reproduction" in losses
    assert "trace-re-execution-outcome-is-producer-asserted-not-observed" in losses
    assert "trace-record-carries-no-semantic-reproduction-state" in losses
    assert document["trustContribution"]["inadmissibleAs"] == "evidence-for-an-outcome-predicate"
    assert document["conversion"]["lossless"] is False


@pytest.mark.parametrize(
    ("record", "code"),
    [
        ({"reproducibility": ["not", "an", "object"]}, "SOVA-INTEROP-TRACE-REPRODUCIBILITY"),
        (
            {"appraisal": {"status": "affirming", "re_execution": "reproduced"}},
            "SOVA-INTEROP-TRACE-RE-EXECUTION",
        ),
    ],
)
def test_malformed_reproducibility_fails_closed(
    tmp_path: Path, record: dict[str, object], code: str
) -> None:
    with pytest.raises(FormatError) as excinfo:
        import_trace_records(_write(tmp_path, {**_SPEC_EXAMPLE, **record}), **_PROVENANCE)

    assert excinfo.value.issue.code == code


def test_software_only_platform_is_not_hardware_rooted(tmp_path: Path) -> None:
    document = import_trace_records(_write(tmp_path, _SPEC_EXAMPLE), **_PROVENANCE)

    assert document["records"][0]["assertedRuntime"]["hardwareRootOfTrust"] is False
    assert "trace-runtime-measurement-not-hardware-rooted" in document["conversion"]["semanticLoss"]


@pytest.mark.parametrize("status", ["none", "pending", "failed", "error"])
def test_non_affirming_appraisal_never_satisfies_a_trust_condition(
    tmp_path: Path, status: str
) -> None:
    record = {**_SPEC_EXAMPLE, "appraisal": {"status": status}}
    document = import_trace_records(_write(tmp_path, record), **_PROVENANCE)

    assert document["records"][0]["appraisal"]["affirming"] is False
    assert (
        "trace-appraisal-not-affirming-trust-condition-unsatisfied"
        in document["conversion"]["semanticLoss"]
    )


def test_affirming_appraisal_is_recorded_without_upgrading_evidence(tmp_path: Path) -> None:
    """Even an affirming appraisal leaves the record inadmissible as outcome evidence."""
    record = {**_SPEC_EXAMPLE, "appraisal": {"status": "affirming"}}
    document = import_trace_records(_write(tmp_path, record), **_PROVENANCE)

    assert document["records"][0]["appraisal"]["affirming"] is True
    assert document["trustContribution"]["inadmissibleAs"] == "evidence-for-an-outcome-predicate"
    assert document["conversion"]["lossless"] is False


def test_tool_transcript_digest_does_not_supply_transcript(tmp_path: Path) -> None:
    record = {**_SPEC_EXAMPLE, "tool_transcript": {"hash": "sha256:" + "c" * 64, "call_count": 7}}
    document = import_trace_records(_write(tmp_path, record), **_PROVENANCE)

    assert (
        "trace-tool-transcript-digest-only-contents-unavailable"
        in document["conversion"]["semanticLoss"]
    )


def test_unknown_profile_fails_closed(tmp_path: Path) -> None:
    record = {**_SPEC_EXAMPLE, "eat_profile": "tag:example.com,2027:trace-v0.9"}

    with pytest.raises(FormatError) as excinfo:
        import_trace_records(_write(tmp_path, record), **_PROVENANCE)

    assert excinfo.value.issue.code == "SOVA-INTEROP-TRACE-PROFILE-UNKNOWN"


def test_missing_provenance_is_refused(tmp_path: Path) -> None:
    with pytest.raises(FormatError):
        import_trace_records(
            _write(tmp_path, _SPEC_EXAMPLE),
            license_expression="",
            source_url=_PROVENANCE["source_url"],
        )


def test_unknown_fields_are_retained_uninterpreted(tmp_path: Path) -> None:
    record = {**_SPEC_EXAMPLE, "vendor_extension": {"arbitrary": True}}
    document = import_trace_records(_write(tmp_path, record), **_PROVENANCE)

    assert document["records"][0]["unknownFields"] == {"vendor_extension": {"arbitrary": True}}
    assert "trace-unknown-fields-retained-uninterpreted" in document["conversion"]["semanticLoss"]


def test_jsonl_record_set_imports(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_text(
        "\n".join(json.dumps(_SPEC_EXAMPLE) for _ in range(3)),
        encoding="utf-8",
    )

    document = import_trace_records(path, **_PROVENANCE)

    assert len(document["records"]) == 3
    assert [item["originalIndex"] for item in document["records"]] == [0, 1, 2]
