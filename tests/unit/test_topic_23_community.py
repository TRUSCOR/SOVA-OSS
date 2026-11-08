# SPDX-License-Identifier: Apache-2.0
"""Topic 23 probe, Arena, leaderboard, CTF, and replay-media acceptance tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sova.community import (
    STANDARD_ARENA_PROFILE,
    ArenaCase,
    ArenaMatch,
    ArenaProfile,
    CTFScenario,
    LeaderboardSubmission,
    ReplayClipSpec,
    ReplayFrame,
    build_ctf_catalog,
    build_static_leaderboard,
    issue_probe_document,
    issue_probe_response,
    render_replay_clip,
    run_local_arena,
    verify_probe_response,
)
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.local_mcp import LocalApprovalStore, LocalToolContext, dispatch_local_tool
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import verify_artifact
from sova.trace import TraceReader, generate_ed25519_keypair


def _probe(now: datetime) -> tuple[dict[str, Any], str]:
    key = generate_ed25519_keypair()
    document = issue_probe_response(
        key,
        subject="component:fixture/1",
        nonce="nonce-123",
        scope=("mcp.initialize", "mcp.tools.list"),
        assertions=({"claim": "supports-tools"},),
        observations=({"event": "initialize-observed", "evidenceDigest": "sha256:" + "1" * 64},),
        conformance_status="passed",
        now=now,
        revocation_list_digest="sha256:" + "2" * 64,
    )
    return document, key.key_id


def test_probe_signature_freshness_scope_revocation_and_evidence_separation() -> None:
    now = datetime(2026, 8, 4, 12, tzinfo=UTC)
    document, key_id = _probe(now)
    result = verify_probe_response(
        document,
        expected_nonce="nonce-123",
        expected_scope=("mcp.tools.list", "mcp.initialize"),
        now=now + timedelta(minutes=1),
        required_key_id=key_id,
    )
    assert result["verified"] is True
    assert result["identityTrust"] == "pinned-key"
    assert result["assertionCount"] == 1
    assert result["observationCount"] == 1
    assert result["observationsIndependentOfAssertions"] is True

    with pytest.raises(FormatError, match="nonce"):
        verify_probe_response(
            document,
            expected_nonce="substituted",
            expected_scope=("mcp.initialize", "mcp.tools.list"),
            now=now,
        )
    with pytest.raises(FormatError, match="fresh"):
        verify_probe_response(
            document,
            expected_nonce="nonce-123",
            expected_scope=("mcp.initialize", "mcp.tools.list"),
            now=now + timedelta(minutes=5),
        )
    with pytest.raises(FormatError, match="revoked"):
        verify_probe_response(
            document,
            expected_nonce="nonce-123",
            expected_scope=("mcp.initialize", "mcp.tools.list"),
            now=now,
            revoked_key_ids=(key_id,),
        )

    tampered = {**document, "envelope": {**document["envelope"], "payload": "AAAA"}}
    with pytest.raises(FormatError, match="signature"):
        verify_probe_response(
            tampered,
            expected_nonce="nonce-123",
            expected_scope=("mcp.initialize", "mcp.tools.list"),
            now=now,
        )


def test_probe_issuance_document_is_strict_secret_free_and_offline() -> None:
    now = datetime(2026, 8, 7, 12, tzinfo=UTC)
    request = {
        "artifactType": "sova.probe-issuance",
        "schemaVersion": "0.1.0",
        "subject": "component:fixture/1",
        "nonce": "operator-nonce-123",
        "scope": ["mcp.tools.list", "mcp.initialize"],
        "assertions": [{"claim": "supports-tools"}],
        "observations": [{"event": "initialize-observed", "evidenceDigest": "sha256:" + "1" * 64}],
        "conformanceStatus": "passed",
        "ttlSeconds": 300,
    }
    document = issue_probe_document(request, now=now)
    result = verify_probe_response(
        document,
        expected_nonce="operator-nonce-123",
        expected_scope=("mcp.initialize", "mcp.tools.list"),
        now=now + timedelta(minutes=1),
        required_key_id=document["publicKey"]["keyid"],
    )
    assert result["verified"] is True
    assert document["trustPolicy"] == "included-key-integrity-only"

    for mutation, message in (
        ({**request, "unknown": True}, "missing or unknown"),
        ({**request, "ttlSeconds": True}, "ttlSeconds"),
        ({**request, "observations": [{"api_key": "sk-not-allowed-123456"}]}, "credential"),
    ):
        with pytest.raises(FormatError, match=message):
            issue_probe_document(mutation, now=now)


def test_probe_through_mcp_requires_exact_out_of_band_approval(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = LocalApprovalStore(tmp_path / "control", b"z" * 32, workspace=workspace)
    context = LocalToolContext(workspace, workspace / "evidence", store)
    now = datetime.now(UTC)
    document, key_id = _probe(now)
    (workspace / "probe.json").write_bytes(canonical_json_bytes(document))
    arguments = {
        "response": "probe.json",
        "mode": "conformance",
        "expectedNonce": "nonce-123",
        "expectedScope": ["mcp.initialize", "mcp.tools.list"],
        "requiredKeyId": key_id,
    }
    challenged = dispatch_local_tool(context, "sova.probe", arguments)
    assert challenged["executed"] is False
    challenge = challenged["challenge"]
    store.approve(
        challenge["challengeId"],
        exact_phrase=challenge["exactPhrase"],
        reviewed_effects=True,
        human_confirmed=True,
    )
    executed = dispatch_local_tool(
        context,
        "sova.probe",
        {**arguments, "approvalChallengeId": challenge["challengeId"]},
    )
    assert executed["executed"] is True
    assert executed["result"]["networkUsed"] is False
    assert executed["result"]["conformanceBoundary"] == "signed-response-contract-only"
    assert TraceReader(Path(executed["trace"])).verify().completion == "completed"


def _arena(tmp_path: Path) -> tuple[dict[str, Any], ArenaProfile]:
    profile = STANDARD_ARENA_PROFILE
    case = ArenaCase(
        "conditional-marker",
        "produce the safe fixture attack",
        "evaluate the observable marker",
        "MARKER-OBSERVED",
    )
    attacker = ScriptedModel(
        [ScriptedTurn("safe fixture attack", "fixture-payload")], model_id="attacker/1"
    )
    defender = ScriptedModel(
        [ScriptedTurn("ATTACK:\nfixture-payload", "MARKER-OBSERVED")], model_id="defender/1"
    )
    report = run_local_arena(
        profile,
        (ArenaMatch("attacker/1", "defender/1", case),),
        {"attacker/1": attacker, "defender/1": defender},
        tmp_path / "arena",
    )
    return report, profile


def test_arena_creates_trace_and_capsule_then_static_leaderboard_and_ctf(
    tmp_path: Path,
) -> None:
    report, profile = _arena(tmp_path)
    attempt = report["attempts"][0]
    trace = Path(attempt["trace"])
    artifact = Path(attempt["artifact"])
    assert TraceReader(trace).verify(require_signature=True).completion == "completed"
    assert verify_artifact(artifact).artifact_type == "sova.capsule"
    assert report["telemetry"] == "none"

    submission = LeaderboardSubmission(
        "model",
        "defender",
        "1.0.0",
        profile.identifier,
        profile.digest,
        report["score"],
        report["possibleScore"],
        artifact,
        trace,
        report["signingKeyId"],
    )
    leaderboard = build_static_leaderboard(
        (submission,), tmp_path / "leaderboard", methodology_snapshot="fixture-method/0.1"
    )
    assert leaderboard["entries"][0]["rank"] == 1
    assert leaderboard["entries"][0]["gamingChecks"]["minimumSampleWarning"] is True
    assert (tmp_path / "leaderboard" / "index.html").exists()
    with pytest.raises(FormatError, match="duplicate"):
        build_static_leaderboard(
            (submission, submission),
            tmp_path / "duplicate",
            methodology_snapshot="fixture-method/0.1",
        )

    catalog = build_ctf_catalog(
        (
            CTFScenario(
                "ctf.conditional-marker",
                "Conditional marker",
                "beginner",
                "SOVA bundled synthetic target",
                "https://github.com/TRUSCOR/SOVA-OSS",
                "Apache-2.0",
                "bundled-synthetic",
                artifact,
                "Inspect the trigger evidence, replay it, and explain the bounded observation.",
            ),
        ),
        tmp_path / "ctf.json",
    )
    assert catalog["execution"] == "inert-catalog-only"
    assert catalog["scenarios"][0]["artifact"]["verified"] is True


def test_arena_refuses_a_forged_standard_profile(tmp_path: Path) -> None:
    forged = ArenaProfile(
        STANDARD_ARENA_PROFILE.identifier,
        STANDARD_ARENA_PROFILE.version,
        standard=True,
        sensor_policy="weaker-sensor-policy/1",
    )
    with pytest.raises(FormatError, match="exact pinned standard profile"):
        run_local_arena(
            forged,
            (
                ArenaMatch(
                    "a",
                    "b",
                    ArenaCase("case", "seed", "inspect", "marker"),
                ),
            ),
            {
                "a": ScriptedModel([ScriptedTurn("seed", "attack")]),
                "b": ScriptedModel([ScriptedTurn("attack", "marker")]),
            },
            tmp_path,
        )


def test_captioned_replay_video_is_bounded_redacted_and_disclosure_gated(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "replay.y4m"
    clip = render_replay_clip(
        ReplayClipSpec(
            "bundled-target",
            "artifact.sova",
            "verify.json",
            (
                ReplayFrame("prompt.received", "safe trigger"),
                ReplayFrame("model.response", "Authorization: Bearer secret-secret-secret"),
                ReplayFrame("oracle.result", "marker observed"),
            ),
        ),
        destination,
    )
    video = destination.read_bytes()
    assert video.startswith(b"YUV4MPEG2 W320 H180 F5:1")
    assert video.count(b"FRAME\n") == 15
    assert b"secret-secret-secret" not in video
    assert clip["redactedCaptionCount"] == 1
    assert clip["artifactLink"] == "artifact.sova"

    with pytest.raises(FormatError, match="clearance"):
        ReplayClipSpec(
            "real-disclosed-finding",
            "artifact.sova",
            "verify.json",
            (ReplayFrame("finding.created", "component issue"),),
            component_name="Uncleared product",
        )
