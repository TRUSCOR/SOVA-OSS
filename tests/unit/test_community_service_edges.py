# SPDX-License-Identifier: Apache-2.0
"""Adversarial state, transport, and scheduler edges for local services."""

from __future__ import annotations

import base64
import copy
import http.client
import io
import json
import os
import shutil
import socket
import threading
import time
import zipfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

import sova.monitoring.service as monitor_module
import sova.registry.service as registry_module
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.monitoring import ContinuousMonitorService, MonitoringJob, monitoring_jobs_from_document
from sova.registry import (
    CommunityHTTPService,
    CommunityRegistryStore,
    CommunityServiceConfig,
    CommunityServiceLimits,
    create_community_service_token,
    prepare_community_submission,
    serialize_community_submission,
    verify_community_service_index,
)
from sova.trace import sign_dsse_payload
from tests.unit.test_community_services import _arena, _monitor_jobs, _service_config, _upload

if TYPE_CHECKING:
    from pathlib import Path


def _raw_upload() -> dict[str, Any]:
    rows = []
    for name, data in (("case.sova", b"capsule"), ("case.sova-trace", b"trace")):
        rows.append(
            {
                "name": name,
                "digest": sha256_digest(data),
                "size": len(data),
                "data": base64.b64encode(data).decode(),
            }
        )
    return {
        "artifactType": "sova.community-submission",
        "schemaVersion": "0.1.0",
        "kind": "registry",
        "metadata": {"requiredKeyId": "sha256:" + "1" * 64},
        "files": rows,
    }


@pytest.mark.parametrize("value", (None, "", 1))
def test_registry_required_scalar_helpers_reject_wrong_types(value: Any) -> None:
    with pytest.raises(FormatError):
        registry_module._required_string({"value": value}, "value")
    if value != 1:
        with pytest.raises(FormatError):
            registry_module._required_integer({"value": value}, "value")


def test_registry_path_cursor_and_object_helpers_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="JSON object"):
        registry_module._object_document([])
    with pytest.raises(FormatError, match="integer"):
        registry_module._event_cursor("no")
    for value in ("", "../escape", "a\\b", "/absolute"):
        with pytest.raises(FormatError, match="path"):
            registry_module._inside(tmp_path.resolve(), value)
    outside = tmp_path.parent / "outside"
    with pytest.raises(FormatError, match="escapes"):
        registry_module._inside(tmp_path.resolve(), f"../{outside.name}")


def test_registry_short_write_and_event_retention_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_write = os.write
    monkeypatch.setattr(os, "write", lambda *_args: 0)
    with pytest.raises(OSError):
        registry_module._write_all(1, b"x")
    monkeypatch.setattr(os, "write", original_write)
    store = CommunityRegistryStore(_service_config(tmp_path / "service", "sha256:" + "0" * 64))
    monkeypatch.setattr(registry_module, "_MAX_EVENTS", 1)
    store._event("one", "sova-sub-one", "queued")
    store._event("two", "sova-sub-two", "queued")
    assert [row["kind"] for row in store.events_after(0)] == ["two"]


def test_archive_and_service_key_preflights(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.zip"
    invalid.write_bytes(b"not-a-zip")
    with pytest.raises(FormatError, match="valid archive"):
        registry_module._archive_preflight(invalid)
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(FormatError, match="entry count"):
        registry_module._archive_preflight(empty)
    compressed = tmp_path / "compressed.zip"
    with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros", b"0" * (2 * 1024 * 1024))
    with pytest.raises(FormatError, match="compression ratio"):
        registry_module._archive_preflight(compressed)
    expanded = tmp_path / "expanded.zip"
    with zipfile.ZipFile(expanded, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("content", b"x" * 1024)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(registry_module, "_MAX_SERVICE_UNCOMPRESSED_BYTES", 100)
    try:
        with pytest.raises(FormatError, match="expands beyond"):
            registry_module._archive_preflight(expanded)
    finally:
        monkeypatch.undo()

    root = tmp_path / "keys"
    root.mkdir()
    (root / "service-signing-key.raw").write_bytes(b"short")
    with pytest.raises(FormatError, match="invalid length"):
        registry_module._load_or_create_key(root)

    clean = tmp_path / "clean-keys"
    clean.mkdir()
    key = registry_module._load_or_create_key(clean)
    (clean / "service-signing-key.pub").write_bytes(b"x" * 32)
    with pytest.raises(FormatError, match="do not match"):
        registry_module._load_or_create_key(clean)
    (clean / "service-signing-key.pub").unlink()
    assert registry_module._load_or_create_key(clean).key_id == key.key_id
    assert (clean / "service-signing-key.pub").is_file()


def test_archive_preflight_rejects_compressed_nested_and_prefixed_secrets(tmp_path: Path) -> None:
    secret_value = b'api_key="synthetic-credential-value"'
    compressed_secret = tmp_path / "compressed-secret.zip"
    with zipfile.ZipFile(compressed_secret, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.json", secret_value)
    with pytest.raises(FormatError, match="credential-shaped archive content"):
        registry_module._archive_preflight(compressed_secret)

    nested_buffer = io.BytesIO()
    with zipfile.ZipFile(nested_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.json", secret_value)
    for name, prefix in (
        ("nested-secret.zip", b""),
        ("self-extracting-nested-secret.zip", b"MZ-synthetic-stub"),
    ):
        outer = tmp_path / name
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("attachment.bin", prefix + nested_buffer.getvalue())
        with pytest.raises(FormatError, match="credential-shaped archive content"):
            registry_module._archive_preflight(outer)

    boundary_secret = tmp_path / "boundary-secret.zip"
    split_payload = (
        b"x" * (registry_module._ARCHIVE_SCAN_CHUNK_BYTES - 4)
        + b'api_key="synthetic-credential-value"'
    )
    with zipfile.ZipFile(boundary_secret, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.json", split_payload)
    with pytest.raises(FormatError, match="credential-shaped archive content"):
        registry_module._archive_preflight(boundary_secret)


def test_archive_preflight_allows_namespaced_authorization_identifiers(tmp_path: Path) -> None:
    trace = tmp_path / "namespaced-authorization.sova-trace"
    with zipfile.ZipFile(trace, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "events/000000.jsonl",
            b'{"authorityTarget":"sova:authorization:synthetic-demo"}\n',
        )

    registry_module._archive_preflight(trace)

    credential = tmp_path / "authorization-secret.sova-trace"
    with zipfile.ZipFile(credential, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events/000000.jsonl", b"authorization=synthetic-secret-value\n")
    with pytest.raises(FormatError, match="credential-shaped archive content"):
        registry_module._archive_preflight(credential)


def test_archive_preflight_bounds_nested_size_and_depth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean = io.BytesIO()
    with zipfile.ZipFile(clean, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.json", b'{"value":"safe"}')
    outer = tmp_path / "nested-size.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("attachment.bin", clean.getvalue())
    with monkeypatch.context() as patcher:
        patcher.setattr(registry_module, "_MAX_NESTED_ARCHIVE_BYTES", len(clean.getvalue()) - 1)
        with pytest.raises(FormatError, match="nested archive exceeds"):
            registry_module._archive_preflight(outer)

    nested = clean.getvalue()
    for _index in range(registry_module._MAX_NESTED_ARCHIVE_DEPTH + 1):
        wrapper = io.BytesIO()
        with zipfile.ZipFile(wrapper, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("attachment.bin", nested)
        nested = wrapper.getvalue()
    excessive_depth = tmp_path / "nested-depth.zip"
    excessive_depth.write_bytes(nested)
    with pytest.raises(FormatError, match="nested archive depth"):
        registry_module._archive_preflight(excessive_depth)


def test_registry_rejects_compressed_secret_and_discards_staging(tmp_path: Path) -> None:
    secret_archive = io.BytesIO()
    with zipfile.ZipFile(secret_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.json", b'api_key="synthetic-credential-value"')
    clean_archive = io.BytesIO()
    with zipfile.ZipFile(clean_archive, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.json", b'{"value":"safe"}')
    document = _raw_upload()
    for row, data in zip(
        document["files"],
        (secret_archive.getvalue(), clean_archive.getvalue()),
        strict=True,
    ):
        row.update(
            data=base64.b64encode(data).decode("ascii"),
            size=len(data),
            digest=sha256_digest(data),
        )

    root = tmp_path / "service"
    store = CommunityRegistryStore(_service_config(root, "sha256:" + "1" * 64))
    queued = store.submit(document)
    staging = root / "staging" / queued["id"]
    assert staging.is_dir()
    rejected = store.process_next()
    assert rejected is not None
    assert rejected["status"] == "rejected"
    assert rejected["error"]["code"] == "SOVA-SERVICE-SECRET"
    assert rejected["error"]["stagingCleanupFailed"] is False
    assert not staging.exists()


def test_token_limits_and_config_validation(tmp_path: Path) -> None:
    token = tmp_path / "token"
    create_community_service_token(token)
    with pytest.raises(FormatError, match="already exists"):
        create_community_service_token(token)
    for values in (
        {"max_body_bytes": 0},
        {"max_files": 1},
        {"max_files": 33},
        {"max_body_bytes": 4, "max_file_bytes": 5},
    ):
        with pytest.raises(FormatError):
            CommunityServiceLimits(**values)
    base: dict[str, Any] = {
        "root": tmp_path / "service",
        "token": "x" * 24,
        "trusted_key_ids": frozenset({"sha256:" + "0" * 64}),
        "methodology_snapshot": "method",
    }
    changes: tuple[dict[str, Any], ...] = (
        {"host": "localhost"},
        {"port": 70_000},
        {"token": "short"},
        {"trusted_key_ids": frozenset()},
        {"trusted_key_ids": frozenset({"bad-key"})},
        {"methodology_snapshot": ""},
    )
    for change in changes:
        with pytest.raises(FormatError):
            CommunityServiceConfig(**{**base, **change})


def test_prepare_and_parse_upload_edge_matrix(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sova"
    trace = tmp_path / "trace.sova-trace"
    trace.write_bytes(b"trace")
    with pytest.raises(FormatError, match="missing or unsafe"):
        prepare_community_submission(
            kind="registry",
            metadata={"requiredKeyId": "sha256:" + "1" * 64},
            capsule=missing,
            trace=trace,
        )

    valid = _raw_upload()
    cases = []
    extra = copy.deepcopy(valid)
    extra["extra"] = True
    cases.append(extra)
    version = copy.deepcopy(valid)
    version["schemaVersion"] = "9"
    cases.append(version)
    kind = copy.deepcopy(valid)
    kind["kind"] = "unknown"
    cases.append(kind)
    rows = copy.deepcopy(valid)
    rows["files"] = []
    cases.append(rows)
    row_shape = copy.deepcopy(valid)
    row_shape["files"][0]["extra"] = True
    cases.append(row_shape)
    bad_base64 = copy.deepcopy(valid)
    bad_base64["files"][0]["data"] = "%%%"
    cases.append(bad_base64)
    for document in cases:
        with pytest.raises(FormatError):
            registry_module._parse_upload(document, CommunityServiceLimits())

    secret = copy.deepcopy(valid)
    secret_data = b'password="synthetic-credential-value"'
    secret["files"][0].update(
        data=base64.b64encode(secret_data).decode(),
        size=len(secret_data),
        digest=sha256_digest(secret_data),
    )
    with pytest.raises(FormatError, match="credential-shaped plaintext"):
        registry_module._parse_upload(secret, CommunityServiceLimits())
    encoded_over_limit = copy.deepcopy(valid)
    encoded_over_limit["files"][0]["data"] = "A" * (
        CommunityServiceLimits().max_base64_bytes_per_file + 1
    )
    with pytest.raises(FormatError, match="base64 data exceeds"):
        registry_module._parse_upload(
            encoded_over_limit,
            CommunityServiceLimits(),
        )


def test_prepare_and_http_accept_more_than_four_mib_and_reject_over_limit(
    tmp_path: Path,
) -> None:
    limits = CommunityServiceLimits()
    capsule = tmp_path / "large.sova"
    trace = tmp_path / "small.sova-trace"
    raw_size = 4 * 1024 * 1024 + 1
    capsule.write_bytes(b"x" * raw_size)
    trace.write_bytes(b"trace")
    document = prepare_community_submission(
        kind="registry",
        metadata={"requiredKeyId": "sha256:" + "1" * 64},
        capsule=capsule,
        trace=trace,
        limits=limits,
    )
    payload = serialize_community_submission(document, limits=limits)
    assert document["files"][0]["size"] == raw_size
    assert len(document["files"][0]["data"]) > 4 * 1024 * 1024
    assert len(payload) <= limits.max_body_bytes

    service = CommunityHTTPService(
        CommunityServiceConfig(
            tmp_path / "large-service",
            "x" * 24,
            frozenset({"sha256:" + "1" * 64}),
            "method",
            limits=limits,
        )
    )
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    host, port = service.address
    try:
        headers = {
            "Authorization": "Bearer " + "x" * 24,
            "Content-Type": "application/json",
        }
        status, _ = _http_raw(
            host,
            port,
            "POST",
            "/v1/submissions",
            body=payload,
            headers=headers,
        )
        assert status == 202
        status, body = _http_raw(host, port, "GET", "/v1/health")
        assert status == 200
        assert json.loads(body)["uploadLimits"] == limits.to_mapping()
        over_limit_headers = {
            **headers,
            "Content-Length": str(limits.max_body_bytes + 1),
        }
        assert (
            _http_raw(
                host,
                port,
                "POST",
                "/v1/submissions",
                body=b"{}",
                headers=over_limit_headers,
            )[0]
            == 413
        )
    finally:
        service.close()
        thread.join(timeout=10)

    oversized = tmp_path / "oversized.sova"
    with oversized.open("wb") as stream:
        stream.truncate(limits.max_file_bytes + 1)
    with pytest.raises(FormatError, match="raw file limit"):
        prepare_community_submission(
            kind="registry",
            metadata={"requiredKeyId": "sha256:" + "1" * 64},
            capsule=oversized,
            trace=trace,
            limits=limits,
        )


def test_store_state_and_staging_corruption_edges(tmp_path: Path) -> None:
    artifact, trace, key_id, score, possible = _arena(tmp_path)
    config = _service_config(tmp_path / "service", key_id)
    store = CommunityRegistryStore(config)
    with pytest.raises(FormatError, match="unsafe"):
        store.status("../bad")
    with pytest.raises(FormatError, match="does not exist"):
        store.status("missing")
    with pytest.raises(FormatError, match="negative"):
        store.events_after(-1)
    with pytest.raises(FormatError, match="malformed"):
        store.object_path("bad")

    queued = store.submit(_upload(artifact, trace, key_id, score, possible))
    state = json.loads((config.root / "state.json").read_text(encoding="utf-8"))
    staged = config.root / state["submissions"][queued["id"]]["files"][0]["stagingPath"]
    staged.write_bytes(b"changed")
    rejected = store.process_next()
    assert rejected is not None and rejected["error"]["code"] == "SOVA-SERVICE-STAGING"

    other_artifact, other_trace, other_key, other_score, other_possible = _arena(
        tmp_path / "missing-stage"
    )
    other_root = tmp_path / "other-service"
    other_store = CommunityRegistryStore(
        CommunityServiceConfig(
            other_root,
            "x" * 24,
            frozenset({other_key}),
            "method",
        )
    )
    missing = other_store.submit(
        _upload(other_artifact, other_trace, other_key, other_score, other_possible)
    )
    missing_state = json.loads((other_root / "state.json").read_text(encoding="utf-8"))
    missing_path = (
        other_root / missing_state["submissions"][missing["id"]]["files"][0]["stagingPath"]
    )
    missing_path.unlink()
    missing_result = other_store.process_next()
    assert missing_result is not None and missing_result["status"] == "rejected"

    malformed_root = tmp_path / "malformed"
    malformed_root.mkdir()
    (malformed_root / "state.json").write_text("{}", encoding="utf-8")
    with pytest.raises(FormatError, match="state is malformed"):
        CommunityRegistryStore(_service_config(malformed_root, key_id))


def test_index_verifier_malformed_and_substitution_matrix(tmp_path: Path) -> None:
    config = _service_config(tmp_path / "service", "sha256:" + "0" * 64)
    store = CommunityRegistryStore(config)
    index = store.signed_index()
    with pytest.raises(FormatError, match="trust pin"):
        verify_community_service_index(index, trusted_service_key_ids=frozenset())
    with pytest.raises(FormatError, match="non-negative"):
        verify_community_service_index(
            index, trusted_service_key_ids=frozenset({store.key_id}), minimum_sequence=-1
        )
    for mutation, message in (
        ({}, "malformed"),
        ({**index, "publicKey": []}, "material"),
        ({**index, "publicKey": {**index["publicKey"], "raw": "%%%"}}, "base64"),
        ({**index, "index": {**index["index"], "sequence": 999}}, "payload"),
    ):
        with pytest.raises(FormatError, match=message):
            verify_community_service_index(
                mutation, trusted_service_key_ids=frozenset({store.key_id})
            )

    malformed_payload = {
        "artifactType": "wrong",
        "schemaVersion": "0.1.0",
        "sequence": 0,
        "entries": [],
    }
    malformed_index = {
        **index,
        "index": malformed_payload,
        "envelope": sign_dsse_payload(
            registry_module._INDEX_PAYLOAD_TYPE,
            canonical_json_bytes(malformed_payload),
            store._key,
        ),
    }
    with pytest.raises(FormatError, match="payload is malformed"):
        verify_community_service_index(
            malformed_index, trusted_service_key_ids=frozenset({store.key_id})
        )


def test_store_evidence_binding_profile_and_promotion_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_a, _trace_a, _key_a, score, possible = _arena(tmp_path / "a")
    _artifact_b, trace_b, key_b, _, _ = _arena(tmp_path / "b")
    store = CommunityRegistryStore(
        CommunityServiceConfig(
            tmp_path / "service",
            "x" * 24,
            frozenset({key_b}),
            "method",
        )
    )
    not_bound = store.submit(_upload(artifact_a, trace_b, key_b, score, possible))
    result = store.process_next()
    assert result is not None and result["status"] == "rejected"
    assert store.status(not_bound["id"])["error"]["code"] == "SOVA-SERVICE-EVIDENCE"

    artifact, trace, key_id, score, possible = _arena(tmp_path / "profile")
    profile_store = CommunityRegistryStore(
        CommunityServiceConfig(
            tmp_path / "profile-service",
            "x" * 24,
            frozenset({key_id}),
            "method",
        )
    )
    wrong_profile = _upload(artifact, trace, key_id, score, possible)
    wrong_profile["metadata"]["profileId"] = "custom"
    queued = profile_store.submit(wrong_profile)
    result = profile_store.process_next()
    assert result is not None and result["status"] == "rejected"
    assert profile_store.status(queued["id"])["error"]["code"] == "SOVA-SERVICE-PROFILE"

    staging = tmp_path / "promotion"
    staging.mkdir()
    source = staging / "case.sova"
    source.write_bytes(b"source")
    digest = sha256_digest(b"source")
    row = {
        "id": "sova-sub-promotion",
        "files": [
            {
                "name": source.name,
                "digest": digest,
                "size": 6,
                "stagingPath": "promotion/case.sova",
            }
        ],
    }
    promote_store = CommunityRegistryStore(_service_config(tmp_path, "sha256:" + "0" * 64))
    target = tmp_path / "objects" / "sha256" / digest[7:]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"different")
    with pytest.raises(FormatError, match="collision"):
        promote_store._promote(row)
    target.unlink()

    def corrupt_copy(_source: Path, destination: Path) -> None:
        destination.write_bytes(b"corrupt")

    monkeypatch.setattr(shutil, "copyfile", corrupt_copy)
    with pytest.raises(FormatError, match="digest changed"):
        promote_store._promote(row)


def _http_raw(  # noqa: PLR0913 - raw HTTP fields are intentionally independent
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, response.read()
    connection.close()
    return result


def test_http_route_rate_and_lifecycle_edges(tmp_path: Path) -> None:
    key_id = "sha256:" + "0" * 64
    config = CommunityServiceConfig(
        tmp_path / "service",
        "x" * 24,
        frozenset({key_id}),
        "method",
        limits=CommunityServiceLimits(requests_per_minute=20),
    )
    service = CommunityHTTPService(config)
    service.close()  # Closing before serving must not block.

    transport_limits = CommunityServiceLimits(
        max_body_bytes=384 * 1024,
        max_file_bytes=64,
        max_files=2,
        requests_per_minute=20,
    )
    service = CommunityHTTPService(
        CommunityServiceConfig(
            tmp_path / "live",
            "x" * 24,
            frozenset({key_id}),
            "method",
            limits=transport_limits,
        )
    )
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    host, port = service.address
    try:
        assert _http_raw(host, port, "GET", "/missing")[0] == 404
        assert _http_raw(host, port, "GET", "/v1/events?after=bad")[0] == 400
        assert _http_raw(host, port, "GET", "/v1/objects/sha256/" + "0" * 64)[0] == 404
        token = {"Authorization": "Bearer " + "x" * 24}
        assert _http_raw(host, port, "POST", "/missing", body=b"{}", headers=token)[0] == 404
        assert _http_raw(host, port, "POST", "/v1/submissions", body=b"{}", headers=token)[0] == 400
        # The limit is enforced from the declared length before any body is read.
        # Streaming the oversized body would race the server's early close, which
        # some kernels (macOS) surface to the sender as a broken pipe.
        oversized = socket.create_connection((host, port), timeout=10)
        oversized.sendall(
            b"POST /v1/submissions HTTP/1.1\r\nHost: localhost\r\n"
            + b"Authorization: Bearer "
            + b"x" * 24
            + b"\r\nContent-Length: "
            + str(transport_limits.max_body_bytes + 1).encode()
            + b"\r\nConnection: close\r\n\r\n"
        )
        assert b" 413 " in oversized.recv(4096)
        oversized.close()
        raw = socket.create_connection((host, port), timeout=10)
        raw.sendall(
            b"POST /v1/submissions HTTP/1.1\r\nHost: localhost\r\n"
            + b"Authorization: Bearer "
            + b"x" * 24
            + b"\r\nConnection: close\r\n\r\n"
        )
        assert b" 411 " in raw.recv(4096)
        raw.close()
    finally:
        service.close()
        thread.join(timeout=10)

    limited = CommunityHTTPService(
        CommunityServiceConfig(
            tmp_path / "limited",
            "x" * 24,
            frozenset({key_id}),
            "method",
            limits=CommunityServiceLimits(requests_per_minute=1),
        )
    )
    limited_thread = threading.Thread(target=limited.serve_forever, daemon=True)
    limited_thread.start()
    host, port = limited.address
    try:
        assert _http_raw(host, port, "GET", "/v1/health")[0] == 200
        assert _http_raw(host, port, "GET", "/v1/health")[0] == 429
        with pytest.raises(FormatError, match="already started"):
            limited.start()
    finally:
        limited.close()
        limited_thread.join(timeout=10)

    worker_only = CommunityHTTPService(
        CommunityServiceConfig(
            tmp_path / "worker-only",
            "x" * 24,
            frozenset({key_id}),
            "method",
        )
    )
    worker_only.start()
    worker_only.close()


def test_monitor_parsers_and_model_edges(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="UTC"):
        monitor_module._parse_timestamp("2026-01-01", name="time")
    with pytest.raises(FormatError, match="malformed"):
        monitor_module._parse_timestamp("badZ", name="time")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for value in ("", "../escape", "a\\b", "/absolute"):
        with pytest.raises(FormatError, match="relative POSIX"):
            monitor_module._relative_file(workspace, value, name="file")
    with pytest.raises(FormatError, match="regular workspace file"):
        monitor_module._relative_file(workspace, "missing.json", name="file")
    with pytest.raises(FormatError, match="must be an integer"):
        monitor_module._integer({"value": True}, "value", minimum=1, maximum=2)

    with pytest.raises(FormatError, match="snapshot is malformed"):
        monitor_module._snapshot_from_document(
            {"artifactType": "sova.behavior-snapshot", "id": "", "axes": []}
        )
    policy = workspace / "policy.json"
    policy.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="policy must be an object"):
        monitor_module._load_policy(policy)
    invalid_snapshot = workspace / "invalid.json"
    invalid_snapshot.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="snapshot document"):
        monitor_module._load_snapshot(invalid_snapshot)

    for job in (
        ("BAD ID", 1, 1),
        ("valid", 0, 1),
        ("valid", 1, 0),
    ):
        with pytest.raises(FormatError):
            MonitoringJob(job[0], invalid_snapshot, invalid_snapshot, None, job[1], job[2])


def test_monitor_spec_and_state_rejection_matrix(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "snapshot.json"
    source.write_bytes(canonical_json_bytes({"id": "x"}))
    base_job = {
        "id": "job",
        "baseline": "snapshot.json",
        "current": "snapshot.json",
        "policy": None,
        "intervalSeconds": 1,
        "retentionRuns": 1,
    }
    for document in (
        {"artifactType": "wrong", "schemaVersion": "0.1.0", "jobs": [base_job]},
        {"artifactType": "sova.monitor-service-spec", "schemaVersion": "0.1.0", "jobs": []},
        {
            "artifactType": "sova.monitor-service-spec",
            "schemaVersion": "0.1.0",
            "jobs": [{**base_job, "extra": True}],
        },
        {
            "artifactType": "sova.monitor-service-spec",
            "schemaVersion": "0.1.0",
            "jobs": [{**base_job, "id": 1}],
        },
        {
            "artifactType": "sova.monitor-service-spec",
            "schemaVersion": "0.1.0",
            "jobs": [base_job, base_job],
        },
    ):
        with pytest.raises(FormatError):
            monitoring_jobs_from_document(document, workspace=workspace)
    with pytest.raises(FormatError, match="workspace must exist"):
        monitoring_jobs_from_document(
            {
                "artifactType": "sova.monitor-service-spec",
                "schemaVersion": "0.1.0",
                "jobs": [base_job],
            },
            workspace=tmp_path / "missing",
        )

    with pytest.raises(FormatError, match="at least one"):
        ContinuousMonitorService((), tmp_path / "none")
    job = MonitoringJob("job", source, source, None, 1, 1)
    with pytest.raises(FormatError, match="unique"):
        ContinuousMonitorService((job, job), tmp_path / "duplicate")

    root = tmp_path / "state"
    root.mkdir()
    (root / "state.json").write_text("{}", encoding="utf-8")
    with pytest.raises(FormatError, match="state is malformed"):
        ContinuousMonitorService((job,), root)

    valid_root = tmp_path / "valid-state"
    ContinuousMonitorService((job,), valid_root)
    state = json.loads((valid_root / "state.json").read_text(encoding="utf-8"))
    state["jobs"] = {"different": state["jobs"]["job"]}
    (valid_root / "state.json").write_bytes(canonical_json_bytes(state) + b"\n")
    with pytest.raises(FormatError, match="job set differs"):
        ContinuousMonitorService((job,), valid_root)

    state["jobs"] = {"job": {"status": "broken", "nextRunAt": None}}
    (valid_root / "state.json").write_bytes(canonical_json_bytes(state) + b"\n")
    with pytest.raises(FormatError, match="job state"):
        ContinuousMonitorService((job,), valid_root)


def test_monitor_overlap_error_recovery_and_serve_bounds(tmp_path: Path) -> None:
    jobs = _monitor_jobs(tmp_path)
    root = tmp_path / "monitor"
    service = ContinuousMonitorService(jobs, root)
    service.release()
    service.acquire()
    with pytest.raises(FormatError, match="already held"):
        service.acquire()
    service.release()
    with pytest.raises(FormatError, match="does not exist"):
        service.run_job("missing")
    service._state["jobs"][jobs[0].identifier]["status"] = "running"
    assert service._due(jobs[0].identifier, datetime.now(UTC)) is False
    with pytest.raises(FormatError, match="already running"):
        service.run_job(jobs[0].identifier)
    service._state["jobs"][jobs[0].identifier]["status"] = "idle"

    jobs[0].current.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError):
        service.run_job(jobs[0].identifier, now=datetime(2026, 8, 9, tzinfo=UTC))
    assert service.status()["jobs"][jobs[0].identifier]["status"] == "idle"
    with pytest.raises(FormatError, match="max cycles"):
        service.serve(threading.Event(), max_cycles=0)
    with pytest.raises(FormatError, match="poll interval"):
        service.serve(threading.Event(), max_cycles=1, poll_seconds=0)


def test_monitor_nested_retention_and_polling_branch(tmp_path: Path) -> None:
    jobs = _monitor_jobs(tmp_path, retention=1)
    root = tmp_path / "monitor"
    service = ContinuousMonitorService(jobs, root)
    run_root = root / "runs" / jobs[0].identifier
    old = run_root / "000-old"
    (old / "nested").mkdir(parents=True)
    (old / "nested" / "artifact").write_text("x", encoding="utf-8")
    newer = run_root / "999-new"
    newer.mkdir()
    service._prune(jobs[0])
    assert not old.exists() and newer.exists()

    service.run_due()
    service._state["jobs"][jobs[0].identifier]["nextRunAt"] = "2999-01-01T00:00:00Z"
    service._persist()

    stop = threading.Event()

    def cancel() -> None:
        time.sleep(0.03)
        stop.set()

    thread = threading.Thread(target=cancel)
    thread.start()
    assert service.serve(stop, poll_seconds=0.01) == ()
    thread.join(timeout=2)


def test_monitor_snapshot_policy_and_empty_prune_branches(tmp_path: Path) -> None:
    snapshot = monitor_module._snapshot_from_document(
        {
            "artifactType": "sova.behavior-snapshot",
            "id": "saved-snapshot",
            "traceReference": "sha256:" + "1" * 64,
            "axes": {
                "target": {},
                "environment": {},
                "methodology": {},
                "observedEffects": [],
                "reproductionRates": {},
                "findings": [],
                "approvalSurface": {},
                "registrySnapshot": {},
            },
        }
    )
    assert snapshot.trace_reference == "sha256:" + "1" * 64
    policy = tmp_path / "policy.json"
    policy.write_text('{"maxBehaviorChanges":1}', encoding="utf-8")
    assert monitor_module._load_policy(policy)["maxBehaviorChanges"] == 1
    jobs = _monitor_jobs(tmp_path)
    service = ContinuousMonitorService(jobs, tmp_path / "empty-monitor")
    service._prune(jobs[0])
