# SPDX-License-Identifier: Apache-2.0
"""User-facing CLI coverage for the Topic 21-23 community surfaces."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sova.cli import main
from sova.community import STANDARD_ARENA_PROFILE, issue_probe_response
from sova.trace import generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _arena_specification() -> dict[str, Any]:
    return {
        "profile": {
            "id": STANDARD_ARENA_PROFILE.identifier,
            "version": STANDARD_ARENA_PROFILE.version,
            "standard": True,
            "sensorPolicy": STANDARD_ARENA_PROFILE.sensor_policy,
        },
        "participants": [
            {
                "id": "attacker/1",
                "modelId": "scripted/attacker",
                "turns": [{"expectedContains": "seed", "responseText": "TOKEN-OBSERVED"}],
            },
            {
                "id": "defender/1",
                "modelId": "scripted/defender",
                "turns": [{"expectedContains": "TOKEN-OBSERVED", "responseText": "MARKER"}],
            },
        ],
        "matches": [
            {
                "attacker": "attacker/1",
                "defender": "defender/1",
                "case": {
                    "id": "safe-synthetic-case",
                    "attackerPrompt": "seed",
                    "defenderPrompt": "inspect",
                    "successMarker": "MARKER",
                    "points": 1,
                },
            }
        ],
    }


def test_arena_leaderboard_ctf_and_replay_clip_cli(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    arena_spec = tmp_path / "arena.json"
    _write(arena_spec, _arena_specification())
    arena_dir = tmp_path / "arena"
    assert main(["arena", "run", str(arena_spec), str(arena_dir)]) == 0
    report = json.loads(capfd.readouterr().out)
    assert report["score"] == 1

    leaderboard_spec = tmp_path / "leaderboard.json"
    _write(
        leaderboard_spec,
        {
            "methodologySnapshot": "standard synthetic CLI fixture",
            "submissions": [
                {
                    "category": "model",
                    "component": "scripted-defender",
                    "version": "1",
                    "profileId": STANDARD_ARENA_PROFILE.identifier,
                    "profileDigest": STANDARD_ARENA_PROFILE.digest,
                    "score": 1,
                    "possibleScore": 1,
                    "artifact": "arena/attempt-0000.sova",
                    "trace": "arena/attempt-0000.sova-trace",
                    "requiredKeyId": report["signingKeyId"],
                }
            ],
        },
    )
    leaderboard_dir = tmp_path / "leaderboard"
    assert main(["leaderboard", "build", str(leaderboard_spec), str(leaderboard_dir)]) == 0
    leaderboard = json.loads(capfd.readouterr().out)
    assert leaderboard["entries"][0]["gamingChecks"]["minimumSampleWarning"] is True
    assert (leaderboard_dir / "index.html").is_file()

    ctf_spec = tmp_path / "ctf.json"
    _write(
        ctf_spec,
        {
            "scenarios": [
                {
                    "id": "safe-1",
                    "title": "Safe deterministic fixture",
                    "difficulty": "beginner",
                    "sourceProject": "SOVA OSS",
                    "sourceUrl": "https://github.com/TRUSCOR/SOVA-OSS",
                    "sourceLicense": "Apache-2.0",
                    "setupMode": "bundled-synthetic",
                    "artifact": "arena/attempt-0000.sova",
                    "explanation": "Inspect a synthetic observable marker without live targets.",
                }
            ]
        },
    )
    catalog = tmp_path / "ctf-catalog.json"
    assert main(["ctf", "build", str(ctf_spec), str(catalog)]) == 0
    assert json.loads(capfd.readouterr().out)["execution"] == "inert-catalog-only"

    clip_spec = tmp_path / "clip.json"
    _write(
        clip_spec,
        {
            "findingClass": "simulation",
            "artifactLink": "attempt-0000.sova",
            "verificationLink": "leaderboard/leaderboard.json",
            "frames": [
                {"eventKind": "attempt.started", "caption": "fixture begins"},
                {"eventKind": "oracle.result", "caption": "marker observed"},
            ],
        },
    )
    clip = tmp_path / "replay.y4m"
    assert main(["replay", "clip", str(clip_spec), str(clip)]) == 0
    assert json.loads(capfd.readouterr().out)["mediaDigest"].startswith("sha256:")
    assert clip.read_bytes().startswith(b"YUV4MPEG2")


def test_probe_verify_and_unknown_cli_field_rejection(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    keypair = generate_ed25519_keypair()
    response = issue_probe_response(
        keypair,
        subject="fixture/component",
        nonce="nonce-1",
        scope=("manifest",),
        assertions=({"claim": "supported"},),
        observations=({"check": "manifest", "status": "passed"},),
        conformance_status="passed",
        now=datetime.now(UTC),
    )
    response_path = tmp_path / "probe.json"
    _write(response_path, response)
    assert (
        main(
            [
                "probe",
                "verify",
                str(response_path),
                "--nonce",
                "nonce-1",
                "--scope",
                "manifest",
                "--key-id",
                keypair.key_id,
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["identityTrust"] == "pinned-key"

    invalid = _arena_specification()
    invalid["executeShell"] = True
    invalid_path = tmp_path / "invalid-arena.json"
    _write(invalid_path, invalid)
    assert main(["arena", "run", str(invalid_path), str(tmp_path / "bad")]) == 2
    captured = capfd.readouterr()
    assert "SOVA-COMMUNITY-FIELD" in captured.err
    assert not (tmp_path / "bad").exists()

    escaped = tmp_path / "escaped-ctf.json"
    _write(
        escaped,
        {
            "scenarios": [
                {
                    "id": "bad",
                    "title": "bad path",
                    "difficulty": "beginner",
                    "sourceProject": "fixture",
                    "sourceUrl": "https://example.invalid",
                    "sourceLicense": "Apache-2.0",
                    "setupMode": "bundled-synthetic",
                    "artifact": "../outside.sova",
                    "explanation": "must not escape",
                }
            ]
        },
    )
    assert main(["ctf", "build", str(escaped), str(tmp_path / "catalog.json")]) == 2
    assert "SOVA-COMMUNITY-PATH" in capfd.readouterr().err
