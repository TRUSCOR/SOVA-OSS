# SPDX-License-Identifier: Apache-2.0
"""Loopback-only, restart-safe registry and verified leaderboard service."""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sova.community.arena import STANDARD_ARENA_PROFILE
from sova.community.leaderboard import LeaderboardSubmission, build_static_leaderboard
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
)
from sova.formats.errors import FormatError
from sova.trace import (
    TraceReader,
    generate_ed25519_keypair,
    sign_dsse_payload,
    verify_dsse_payload,
)
from sova.trace.integrity import Ed25519Keypair

_SUBMISSION_TYPE = "sova.community-submission"
_INDEX_PAYLOAD_TYPE = "application/vnd.sova.community-service-index+json"
_SAFE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,95})$")
_SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_FILES = frozenset({".sova", ".sova-trace"})
_SECRET = re.compile(
    rb"(?i)(?<!:)[\"']?"
    rb"(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    rb"[\"']?\s*[:=]\s*[\"']?[^\s,;\"']{12,}"
)
_SECRET_PREFIX = re.compile(
    rb"(?i)(?<!:)[\"']?"
    rb"(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    rb"[\"']?\s*[:=]\s*[\"']?[^\s,;\"']{0,11}$"
)
_MAX_EVENTS = 10_000
_RAW_ED25519_KEY_BYTES = 32
_REQUIRED_UPLOAD_FILES = 2
_MAX_PORT = 65_535
_MIN_TOKEN_LENGTH = 24
_MAX_SERVICE_ARCHIVE_ENTRIES = 2_048
_MAX_SERVICE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
_MAX_SERVICE_COMPRESSION_RATIO = 100
_MIN_COMPRESSION_RATIO_CHECK_BYTES = 1024 * 1024
_MAX_HEALTH_BYTES = 64 * 1024
_MAX_METADATA_BYTES = 256 * 1024
_ARCHIVE_SCAN_CHUNK_BYTES = 64 * 1024
_ARCHIVE_SCAN_OVERLAP_BYTES = 128
_ARCHIVE_SPOOL_MEMORY_BYTES = 1024 * 1024
_MAX_NESTED_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_NESTED_ARCHIVE_DEPTH = 3
_UPLOAD_JSON_OVERHEAD_BYTES = _MAX_METADATA_BYTES + 64 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        _request: Request,
        _file_pointer: Any,
        _code: int,
        _message: str,
        _headers: Any,
        _new_url: str,
    ) -> None:
        return None


def check_community_service_health(url: str) -> dict[str, Any]:
    """Verify one exact loopback health response without proxies or redirects."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or not 1 <= parsed.port <= _MAX_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/health"
        or parsed.query
        or parsed.fragment
    ):
        raise FormatError(
            "SOVA-SERVICE-HEALTH-URL",
            "community health check requires exact literal-IPv4 loopback HTTP URL",
        )
    request = Request(url, headers={"Accept": "application/json"})  # noqa: S310 - loopback only
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=5) as response:
            status = response.status
            body = response.read(_MAX_HEALTH_BYTES + 1)
    except OSError as error:
        raise FormatError(
            "SOVA-SERVICE-HEALTH-UNAVAILABLE",
            "community health endpoint is unavailable",
        ) from error
    if status != HTTPStatus.OK.value:
        raise FormatError(
            "SOVA-SERVICE-HEALTH-STATUS",
            "community health endpoint did not return HTTP 200",
        )
    if len(body) > _MAX_HEALTH_BYTES:
        raise FormatError("SOVA-SERVICE-HEALTH-LIMIT", "community health response is too large")
    value = strict_json_loads(body, max_bytes=_MAX_HEALTH_BYTES)
    required = {
        "artifactType",
        "schemaVersion",
        "status",
        "loopbackOnly",
        "serviceKeyId",
        "uploadLimits",
    }
    advertised_limits = value.get("uploadLimits") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("artifactType") != "sova.community-service-health"
        or value.get("schemaVersion") != "0.1.0"
        or value.get("status") != "ready"
        or value.get("loopbackOnly") is not True
        or not isinstance(value.get("serviceKeyId"), str)
        or _DIGEST.fullmatch(value["serviceKeyId"]) is None
        or not isinstance(advertised_limits, dict)
    ):
        raise FormatError(
            "SOVA-SERVICE-HEALTH-RESPONSE",
            "community health response failed its exact readiness contract",
        )
    try:
        limits = CommunityServiceLimits(
            max_body_bytes=_required_integer(advertised_limits, "maxRequestBodyBytes"),
            max_file_bytes=_required_integer(advertised_limits, "maxRawFileBytes"),
            max_files=_required_integer(advertised_limits, "maxFiles"),
        )
    except FormatError as error:
        raise FormatError(
            "SOVA-SERVICE-HEALTH-RESPONSE",
            "community health upload limits are invalid",
        ) from error
    if advertised_limits != limits.to_mapping():
        raise FormatError(
            "SOVA-SERVICE-HEALTH-RESPONSE",
            "community health upload limits are inconsistent",
        )
    return {
        "artifactType": "sova.community-service-health-verification",
        "schemaVersion": "0.1.0",
        "status": "ready",
        "serviceKeyId": value["serviceKeyId"],
        "loopbackVerified": True,
        "redirectsAllowed": False,
        "proxiesUsed": False,
        "uploadLimits": limits.to_mapping(),
    }


def _atomic_document(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_bytes(canonical_json_bytes(dict(document)) + b"\n")
    temporary.replace(path)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError
        remaining = remaining[written:]


def _required_string(value: Mapping[str, Any], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item:
        raise FormatError("SOVA-SERVICE-FIELD", f"{name} must be a non-empty string")
    return item


def _required_integer(value: Mapping[str, Any], name: str) -> int:
    item = value.get(name)
    if not isinstance(item, int) or isinstance(item, bool):
        raise FormatError("SOVA-SERVICE-FIELD", f"{name} must be an integer")
    return item


def _object_document(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission must be a JSON object")
    return value


def _event_cursor(value: str) -> int:
    if not value.isdecimal():
        raise FormatError("SOVA-SERVICE-EVENT", "event cursor must be an integer")
    return int(value)


def _inside(root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or "\x00" in relative or relative.startswith("/"):
        raise FormatError("SOVA-SERVICE-PATH", "stored path is not normalized relative POSIX")
    target = root.joinpath(*relative.split("/")).resolve()
    if root != target and root not in target.parents:
        raise FormatError("SOVA-SERVICE-PATH", "stored path escapes service root")
    return target


@dataclass(slots=True)
class _ArchiveScanState:
    entries: int = 0
    declared_uncompressed_bytes: int = 0
    scanned_uncompressed_bytes: int = 0


def _validate_archive_info(info: zipfile.ZipInfo, state: _ArchiveScanState) -> None:
    state.declared_uncompressed_bytes += info.file_size
    if state.declared_uncompressed_bytes > _MAX_SERVICE_UNCOMPRESSED_BYTES:
        raise FormatError(
            "SOVA-SERVICE-ARCHIVE",
            "submitted archive expands beyond service limit",
        )
    if (
        info.file_size > _MIN_COMPRESSION_RATIO_CHECK_BYTES
        and info.compress_size > 0
        and info.file_size / info.compress_size > _MAX_SERVICE_COMPRESSION_RATIO
    ):
        raise FormatError(
            "SOVA-SERVICE-ARCHIVE",
            "submitted archive compression ratio is unsafe",
        )


def _spool_archive_member(
    member: IO[bytes],
    spooled: IO[bytes],
    state: _ArchiveScanState,
) -> int:
    tail = b""
    read_bytes = 0
    while True:
        chunk = member.read(_ARCHIVE_SCAN_CHUNK_BYTES)
        if not chunk:
            return read_bytes
        read_bytes += len(chunk)
        state.scanned_uncompressed_bytes += len(chunk)
        if state.scanned_uncompressed_bytes > _MAX_SERVICE_UNCOMPRESSED_BYTES:
            raise FormatError(
                "SOVA-SERVICE-ARCHIVE",
                "submitted archive expands beyond service scan limit",
            )
        window = tail + chunk
        if _SECRET.search(window):
            raise FormatError(
                "SOVA-SERVICE-SECRET",
                "credential-shaped archive content was detected",
            )
        prefix = _SECRET_PREFIX.search(window)
        tail = (
            window[prefix.start() :]
            if prefix is not None
            else window[-_ARCHIVE_SCAN_OVERLAP_BYTES:]
        )
        if len(tail) > _ARCHIVE_SCAN_OVERLAP_BYTES:
            raise FormatError(
                "SOVA-SERVICE-SECRET",
                "credential-shaped archive content exceeded the scan window",
            )
        spooled.write(chunk)


def _scan_archive_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    state: _ArchiveScanState,
    depth: int,
) -> None:
    if _SECRET.search(info.filename.encode("utf-8", errors="replace")):
        raise FormatError(
            "SOVA-SERVICE-SECRET",
            "credential-shaped archive member name was detected",
        )
    with tempfile.SpooledTemporaryFile(
        max_size=_ARCHIVE_SPOOL_MEMORY_BYTES,
        mode="w+b",
    ) as spooled:
        with archive.open(info) as member:
            read_bytes = _spool_archive_member(member, spooled, state)
        if read_bytes != info.file_size:
            raise FormatError(
                "SOVA-SERVICE-ARCHIVE",
                "archive member size changed while scanning",
            )
        spooled.seek(0)
        if not zipfile.is_zipfile(spooled):
            return
        if read_bytes > _MAX_NESTED_ARCHIVE_BYTES:
            raise FormatError(
                "SOVA-SERVICE-ARCHIVE",
                "nested archive exceeds the service scan limit",
            )
        if depth >= _MAX_NESTED_ARCHIVE_DEPTH:
            raise FormatError("SOVA-SERVICE-ARCHIVE", "nested archive depth is unsafe")
        spooled.seek(0)
        _scan_archive(spooled, state=state, depth=depth + 1)


def _scan_archive(
    source: Path | IO[bytes],
    *,
    state: _ArchiveScanState,
    depth: int,
) -> None:
    try:
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            if not infos:
                raise FormatError("SOVA-SERVICE-ARCHIVE", "submitted archive entry count is unsafe")
            state.entries += len(infos)
            if state.entries > _MAX_SERVICE_ARCHIVE_ENTRIES:
                raise FormatError("SOVA-SERVICE-ARCHIVE", "submitted archive entry count is unsafe")
            for info in infos:
                _validate_archive_info(info, state)
                if info.is_dir():
                    continue
                _scan_archive_member(archive, info, state=state, depth=depth)
    except (EOFError, OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise FormatError(
            "SOVA-SERVICE-ARCHIVE", "submitted artifact is not a valid archive"
        ) from error


def _archive_preflight(path: Path) -> None:
    _scan_archive(path, state=_ArchiveScanState(), depth=0)


def _load_or_create_key(root: Path) -> Ed25519Keypair:
    key_path = root / "service-signing-key.raw"
    public_path = root / "service-signing-key.pub"
    if not key_path.exists():
        generated = generate_ed25519_keypair()
        descriptor = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            _write_all(descriptor, generated.private_key)
        finally:
            os.close(descriptor)
        public_path.write_bytes(generated.public_key)
        return generated
    private = key_path.read_bytes()
    if len(private) != _RAW_ED25519_KEY_BYTES:
        raise FormatError("SOVA-SERVICE-KEY", "service signing key has an invalid length")
    private_key = Ed25519PrivateKey.from_private_bytes(private)
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if public_path.exists() and not hmac.compare_digest(public_path.read_bytes(), public):
        raise FormatError("SOVA-SERVICE-KEY", "service public and private keys do not match")
    if not public_path.exists():
        public_path.write_bytes(public)
    return Ed25519Keypair(private, public, sha256_digest(public))


def create_community_service_token(path: Path) -> dict[str, Any]:
    """Create one local bearer-token file without printing its secret value."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32).encode("ascii")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError as error:
        raise FormatError("SOVA-SERVICE-TOKEN", "service token file already exists") from error
    try:
        _write_all(descriptor, token)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "artifactType": "sova.community-service-token-created",
        "schemaVersion": "0.1.0",
        "path": str(path),
        "secretPrinted": False,
        "minimumEntropyBits": 256,
    }


def _base64_size(raw_size: int) -> int:
    return 4 * ((raw_size + 2) // 3)


@dataclass(frozen=True, slots=True)
class CommunityServiceLimits:
    max_body_bytes: int = 48 * 1024 * 1024
    max_file_bytes: int = 16 * 1024 * 1024
    max_files: int = 2
    requests_per_minute: int = 60

    @property
    def max_base64_bytes_per_file(self) -> int:
        """Maximum padded base64 bytes for one admitted raw file."""
        return _base64_size(self.max_file_bytes)

    @property
    def max_decoded_bytes(self) -> int:
        """Maximum decoded bytes admitted across one submission."""
        return self.max_file_bytes * self.max_files

    def to_mapping(self) -> dict[str, int]:
        """Return the limits advertised by the HTTP health contract."""
        return {
            "maxRequestBodyBytes": self.max_body_bytes,
            "maxFiles": self.max_files,
            "maxRawFileBytes": self.max_file_bytes,
            "maxDecodedBytes": self.max_decoded_bytes,
            "maxBase64BytesPerFile": self.max_base64_bytes_per_file,
        }

    def __post_init__(self) -> None:
        values = (
            self.max_body_bytes,
            self.max_file_bytes,
            self.max_files,
            self.requests_per_minute,
        )
        if any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in values):
            raise FormatError("SOVA-SERVICE-LIMIT", "service limits must be positive integers")
        minimum_encoded_body = (
            self.max_base64_bytes_per_file * self.max_files + _UPLOAD_JSON_OVERHEAD_BYTES
        )
        if self.max_files != _REQUIRED_UPLOAD_FILES or minimum_encoded_body > self.max_body_bytes:
            raise FormatError("SOVA-SERVICE-LIMIT", "service limits are internally inconsistent")


@dataclass(frozen=True, slots=True)
class CommunityServiceConfig:
    root: Path
    token: str
    trusted_key_ids: frozenset[str]
    methodology_snapshot: str
    host: str = "127.0.0.1"
    port: int = 0
    limits: CommunityServiceLimits = CommunityServiceLimits()

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise FormatError(
                "SOVA-SERVICE-BIND", "registry service host must be a literal loopback address"
            ) from error
        if not address.is_loopback:
            raise FormatError("SOVA-SERVICE-BIND", "registry service is loopback-only")
        if not 0 <= self.port <= _MAX_PORT:
            raise FormatError("SOVA-SERVICE-PORT", "registry service port is invalid")
        if len(self.token) < _MIN_TOKEN_LENGTH:
            raise FormatError("SOVA-SERVICE-TOKEN", "service token must contain at least 24 chars")
        if not self.trusted_key_ids:
            raise FormatError("SOVA-SERVICE-TRUST", "at least one evidence signer must be pinned")
        if any(_DIGEST.fullmatch(item) is None for item in self.trusted_key_ids):
            raise FormatError("SOVA-SERVICE-TRUST", "evidence signer pins must be SHA-256 ids")
        if not self.methodology_snapshot:
            raise FormatError("SOVA-SERVICE-METHODOLOGY", "methodology snapshot is required")


@dataclass(frozen=True, slots=True)
class _UploadFile:
    name: str
    digest: str
    data: bytes


def prepare_community_submission(
    *,
    kind: str,
    metadata: Mapping[str, Any],
    capsule: Path,
    trace: Path,
    limits: CommunityServiceLimits | None = None,
) -> dict[str, Any]:
    """Build a bounded JSON upload document without sending it anywhere."""
    selected_limits = CommunityServiceLimits() if limits is None else limits
    rows = []
    for source in (capsule, trace):
        if not source.is_file() or source.is_symlink():
            raise FormatError("SOVA-SERVICE-UPLOAD", "submission source is missing or unsafe")
        try:
            with source.open("rb") as stream:
                data = stream.read(selected_limits.max_file_bytes + 1)
        except OSError as error:
            raise FormatError(
                "SOVA-SERVICE-UPLOAD", "submission source could not be read safely"
            ) from error
        if len(data) > selected_limits.max_file_bytes:
            raise FormatError("SOVA-SERVICE-LIMIT", "submission source exceeds raw file limit")
        rows.append(
            {
                "name": source.name,
                "digest": sha256_digest(data),
                "size": len(data),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    document = {
        "artifactType": _SUBMISSION_TYPE,
        "schemaVersion": "0.1.0",
        "kind": kind,
        "metadata": dict(metadata),
        "files": rows,
    }
    _parse_upload(document, selected_limits)
    serialize_community_submission(document, limits=selected_limits)
    return document


def _encoded_file_string_limit(limits: CommunityServiceLimits) -> int:
    return limits.max_base64_bytes_per_file


def serialize_community_submission(
    document: Mapping[str, Any],
    *,
    limits: CommunityServiceLimits | None = None,
) -> bytes:
    """Serialize one verified upload with limits consistent with HTTP admission."""
    selected = CommunityServiceLimits() if limits is None else limits
    _parse_upload(document, selected)
    body = canonical_json_bytes(
        dict(document),
        max_string_bytes=max(_MAX_METADATA_BYTES, _encoded_file_string_limit(selected)),
    )
    if len(body) > selected.max_body_bytes:
        raise FormatError(
            "SOVA-SERVICE-LIMIT", "encoded submission exceeds HTTP request body limit"
        )
    return body


def _decode_upload_file(
    row: Mapping[str, Any],
    *,
    limits: CommunityServiceLimits,
    names: set[str],
) -> _UploadFile:
    if set(row) != {"name", "digest", "size", "data"}:
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission file fields are not exact")
    name = _required_string(row, "name")
    digest = _required_string(row, "digest")
    size = _required_integer(row, "size")
    encoded = _required_string(row, "data")
    if (
        _SAFE_FILE.fullmatch(name) is None
        or Path(name).suffix not in _ALLOWED_FILES
        or name in names
        or _DIGEST.fullmatch(digest) is None
        or not 0 <= size <= limits.max_file_bytes
    ):
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission file declaration is unsafe")
    if len(encoded) > limits.max_base64_bytes_per_file:
        raise FormatError("SOVA-SERVICE-LIMIT", "submission base64 data exceeds byte limit")
    if len(encoded) != _base64_size(size):
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission base64 length is inconsistent")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FormatError(
            "SOVA-SERVICE-UPLOAD", "submission file data is invalid base64"
        ) from error
    if len(data) != size or sha256_digest(data) != digest:
        raise FormatError("SOVA-SERVICE-DIGEST", "submission file digest or size mismatches")
    if _SECRET.search(data):
        raise FormatError("SOVA-SERVICE-SECRET", "credential-shaped plaintext was detected")
    return _UploadFile(name, digest, data)


def _parse_upload(
    document: Mapping[str, Any], limits: CommunityServiceLimits
) -> tuple[str, dict[str, Any], tuple[_UploadFile, ...]]:
    if set(document) != {"artifactType", "schemaVersion", "kind", "metadata", "files"}:
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission fields are not exact")
    if document.get("artifactType") != _SUBMISSION_TYPE or document.get("schemaVersion") != "0.1.0":
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission type or version is unsupported")
    kind = document.get("kind")
    metadata = document.get("metadata")
    rows = document.get("files")
    if kind not in {"registry", "leaderboard"} or not isinstance(metadata, dict):
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission kind or metadata is invalid")
    metadata_bytes = canonical_json_bytes(metadata)
    if len(metadata_bytes) > _MAX_METADATA_BYTES:
        raise FormatError("SOVA-SERVICE-LIMIT", "submission metadata exceeds byte limit")
    if _SECRET.search(metadata_bytes):
        raise FormatError("SOVA-SERVICE-SECRET", "credential-shaped metadata was detected")
    if not isinstance(rows, list) or len(rows) != limits.max_files:
        raise FormatError("SOVA-SERVICE-UPLOAD", "submission file count is invalid")
    files: list[_UploadFile] = []
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise FormatError("SOVA-SERVICE-UPLOAD", "submission file fields are not exact")
        upload = _decode_upload_file(row, limits=limits, names=names)
        names.add(upload.name)
        files.append(upload)
    return str(kind), dict(metadata), tuple(files)


class CommunityRegistryStore:
    """Durable staged-submission state; verification never executes submitted content."""

    def __init__(self, config: CommunityServiceConfig) -> None:
        self.config = config
        self.root = config.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._key = _load_or_create_key(self.root)
        self._state_path = self.root / "state.json"
        self._state = self._load_state()
        self._recover_interrupted()

    @property
    def key_id(self) -> str:
        return self._key.key_id

    def _blank_state(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.community-service-state",
            "schemaVersion": "0.1.0",
            "sequence": 0,
            "submissions": {},
            "events": [],
        }

    def _load_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            state = self._blank_state()
            _atomic_document(self._state_path, state)
            return state
        value = strict_json_loads(self._state_path.read_bytes())
        if (
            not isinstance(value, dict)
            or value.get("artifactType") != "sova.community-service-state"
            or value.get("schemaVersion") != "0.1.0"
            or not isinstance(value.get("sequence"), int)
            or not isinstance(value.get("submissions"), dict)
            or not isinstance(value.get("events"), list)
        ):
            raise FormatError("SOVA-SERVICE-STATE", "community service state is malformed")
        return value

    def _persist(self) -> None:
        _atomic_document(self._state_path, self._state)

    def _event(self, kind: str, submission_id: str, status: str) -> None:
        sequence = int(self._state["sequence"]) + 1
        self._state["sequence"] = sequence
        events = self._state["events"]
        events.append(
            {
                "sequence": sequence,
                "kind": kind,
                "submissionId": submission_id,
                "status": status,
                "recordedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )
        if len(events) > _MAX_EVENTS:
            del events[: len(events) - _MAX_EVENTS]

    def _recover_interrupted(self) -> None:
        changed = False
        for submission_id, row in self._state["submissions"].items():
            if isinstance(row, dict) and row.get("status") == "verifying":
                row["status"] = "queued"
                row["recoveredAfterRestart"] = True
                self._event("submission.recovered", submission_id, "queued")
                changed = True
        if changed:
            self._persist()

    def submit(self, document: Mapping[str, Any]) -> dict[str, Any]:
        kind, metadata, files = _parse_upload(document, self.config.limits)
        identity = {
            "kind": kind,
            "metadata": metadata,
            "files": [{"name": item.name, "digest": item.digest} for item in files],
        }
        submission_id = "sova-sub-" + sha256_digest(canonical_json_bytes(identity))[7:31]
        with self._lock:
            existing = self._state["submissions"].get(submission_id)
            if existing is not None:
                return self._public_row(existing)
            staging = self.root / "staging" / submission_id
            staging.mkdir(parents=True)
            for item in files:
                (staging / item.name).write_bytes(item.data)
            row = {
                "id": submission_id,
                "kind": kind,
                "metadata": metadata,
                "status": "queued",
                "files": [
                    {
                        "name": item.name,
                        "digest": item.digest,
                        "size": len(item.data),
                        "stagingPath": f"staging/{submission_id}/{item.name}",
                    }
                    for item in files
                ],
                "submittedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "recoveredAfterRestart": False,
                "verification": None,
                "error": None,
            }
            self._state["submissions"][submission_id] = row
            self._event("submission.queued", submission_id, "queued")
            self._persist()
            return self._public_row(row)

    @staticmethod
    def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "artifactType": "sova.community-submission-status",
            "schemaVersion": "0.1.0",
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "submittedAt": row["submittedAt"],
            "recoveredAfterRestart": row.get("recoveredAfterRestart", False),
            "verification": row.get("verification"),
            "error": row.get("error"),
        }

    def status(self, submission_id: str) -> dict[str, Any]:
        if _SAFE_ID.fullmatch(submission_id) is None:
            raise FormatError("SOVA-SERVICE-ID", "submission id is unsafe")
        with self._lock:
            row = self._state["submissions"].get(submission_id)
            if not isinstance(row, dict):
                raise FormatError("SOVA-SERVICE-NOT-FOUND", "submission does not exist")
            return self._public_row(row)

    def events_after(self, sequence: int) -> list[dict[str, Any]]:
        if sequence < 0:
            raise FormatError("SOVA-SERVICE-EVENT", "event cursor cannot be negative")
        with self._lock:
            return [dict(row) for row in self._state["events"] if row["sequence"] > sequence]

    def _staged_paths(self, row: Mapping[str, Any]) -> dict[str, Path]:
        result: dict[str, Path] = {}
        for item in row["files"]:
            path = _inside(self.root, item["stagingPath"])
            if not path.is_file() or path.is_symlink():
                raise FormatError("SOVA-SERVICE-STAGING", "staged file is missing or unsafe")
            data = path.read_bytes()
            if len(data) != item["size"] or sha256_digest(data) != item["digest"]:
                raise FormatError("SOVA-SERVICE-STAGING", "staged file changed before review")
            result[item["name"]] = path
        return result

    def _verify_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        paths = self._staged_paths(row)
        capsules = [path for name, path in paths.items() if name.endswith(".sova")]
        traces = [path for name, path in paths.items() if name.endswith(".sova-trace")]
        if len(capsules) != 1 or len(traces) != 1:
            raise FormatError(
                "SOVA-SERVICE-EVIDENCE", "submission requires exactly one capsule and one trace"
            )
        _archive_preflight(capsules[0])
        _archive_preflight(traces[0])
        metadata = row["metadata"]
        required_key_id = _required_string(metadata, "requiredKeyId")
        if required_key_id not in self.config.trusted_key_ids:
            raise FormatError(
                "SOVA-SERVICE-TRUST", "submission signer is not pinned by this service"
            )
        descriptors = PackageReader(capsules[0]).verify("sova.capsule")
        trace_report = TraceReader(traces[0]).verify(
            require_signature=True,
            required_key_id=required_key_id,
        )
        trace_digest = sha256_digest(traces[0].read_bytes())
        if trace_report.completion != "completed" or trace_digest not in {
            item.digest for item in descriptors if item.role == "trace"
        }:
            raise FormatError(
                "SOVA-SERVICE-EVIDENCE", "trace is incomplete or not bound into the capsule"
            )
        result: dict[str, Any] = {
            "capsuleDigest": sha256_digest(capsules[0].read_bytes()),
            "traceDigest": trace_digest,
            "requiredKeyId": required_key_id,
            "signatureValid": True,
            "identityPinned": True,
            "contentExecuted": False,
        }
        with self._lock:
            for existing in self._state["submissions"].values():
                if (
                    not isinstance(existing, dict)
                    or existing.get("id") == row.get("id")
                    or existing.get("status") != "accepted"
                    or not isinstance(existing.get("verification"), dict)
                ):
                    continue
                prior = existing["verification"]
                if (
                    prior.get("capsuleDigest") == result["capsuleDigest"]
                    or prior.get("traceDigest") == result["traceDigest"]
                ):
                    raise FormatError(
                        "SOVA-SERVICE-DUPLICATE",
                        "accepted evidence cannot be submitted under another identity",
                    )
        if row["kind"] == "leaderboard":
            score = _required_integer(metadata, "score")
            possible = _required_integer(metadata, "possibleScore")
            submission = LeaderboardSubmission(
                _required_string(metadata, "category"),
                _required_string(metadata, "component"),
                _required_string(metadata, "version"),
                _required_string(metadata, "profileId"),
                _required_string(metadata, "profileDigest"),
                score,
                possible,
                capsules[0],
                traces[0],
                required_key_id,
            )
            if (submission.profile_id, submission.profile_digest) != (
                STANDARD_ARENA_PROFILE.identifier,
                STANDARD_ARENA_PROFILE.digest,
            ):
                raise FormatError("SOVA-SERVICE-PROFILE", "leaderboard profile is not standard")
            temporary = self.root / "verification" / str(row["id"])
            if temporary.exists():
                shutil.rmtree(temporary)
            build_static_leaderboard(
                (submission,),
                temporary,
                methodology_snapshot=self.config.methodology_snapshot,
            )
            shutil.rmtree(temporary)
            result["scoreEvidenceValid"] = True
        return result

    def _promote(self, row: dict[str, Any]) -> None:
        for item in row["files"]:
            source = _inside(self.root, item["stagingPath"])
            digest = str(item["digest"])
            target = self.root / "objects" / "sha256" / digest[7:]
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if target.read_bytes() != source.read_bytes():
                    raise FormatError(
                        "SOVA-SERVICE-COLLISION", "content-address collision detected"
                    )
            else:
                temporary = target.with_name(
                    f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                shutil.copyfile(source, temporary)
                if sha256_digest(temporary.read_bytes()) != digest:
                    temporary.unlink(missing_ok=True)
                    raise FormatError("SOVA-SERVICE-DIGEST", "promoted object digest changed")
                temporary.replace(target)
            item["objectPath"] = f"objects/sha256/{digest[7:]}"
        staging = self.root / "staging" / str(row["id"])
        if staging.exists():
            shutil.rmtree(staging)

    def _discard_staging(self, row: Mapping[str, Any]) -> None:
        submission_id = _required_string(row, "id")
        if _SAFE_ID.fullmatch(submission_id) is None:
            raise FormatError("SOVA-SERVICE-STAGING", "submission staging identity is unsafe")
        staging = _inside(self.root, f"staging/{submission_id}")
        if staging.is_symlink() or (staging.exists() and not staging.is_dir()):
            raise FormatError("SOVA-SERVICE-STAGING", "submission staging path is unsafe")
        if staging.exists():
            shutil.rmtree(staging)

    def process_next(self) -> dict[str, Any] | None:
        with self._lock:
            selected = next(
                (
                    row
                    for row in self._state["submissions"].values()
                    if isinstance(row, dict) and row.get("status") == "queued"
                ),
                None,
            )
            if selected is None:
                return None
            selected["status"] = "verifying"
            self._event("submission.verifying", selected["id"], "verifying")
            self._persist()
            submission_id = str(selected["id"])
        try:
            verification = self._verify_row(selected)
            with self._lock:
                self._promote(selected)
                selected["verification"] = verification
                selected["status"] = "accepted"
                selected["error"] = None
                self._event("submission.accepted", submission_id, "accepted")
                self._persist()
        except (FormatError, OSError, ValueError, KeyError, TypeError) as error:
            with self._lock:
                cleanup_failed = False
                try:
                    self._discard_staging(selected)
                except (FormatError, OSError):
                    cleanup_failed = True
                selected["status"] = "rejected"
                selected["verification"] = None
                selected["error"] = {
                    "code": error.issue.code
                    if isinstance(error, FormatError)
                    else "SOVA-SERVICE-VERIFY",
                    "message": str(error),
                    "stagingCleanupFailed": cleanup_failed,
                }
                self._event("submission.rejected", submission_id, "rejected")
                self._persist()
        return self._public_row(selected)

    def signed_index(self) -> dict[str, Any]:
        with self._lock:
            entries = []
            for row in self._state["submissions"].values():
                if not isinstance(row, dict) or row.get("status") != "accepted":
                    continue
                entries.append(
                    {
                        "id": row["id"],
                        "kind": row["kind"],
                        "metadata": row["metadata"],
                        "files": [
                            {
                                "name": item["name"],
                                "digest": item["digest"],
                                "size": item["size"],
                                "objectPath": item["objectPath"],
                            }
                            for item in row["files"]
                        ],
                        "verification": row["verification"],
                    }
                )
            entries.sort(key=lambda item: item["id"])
            payload_document = {
                "artifactType": "sova.community-service-index",
                "schemaVersion": "0.1.0",
                "sequence": self._state["sequence"],
                "entries": entries,
                "service": {
                    "loopbackOnly": True,
                    "submissionExecution": False,
                    "identityPolicy": "operator-pinned-evidence-signers",
                },
            }
        payload = canonical_json_bytes(payload_document)
        return {
            "artifactType": "sova.community-service-signed-index",
            "schemaVersion": "0.1.0",
            "index": payload_document,
            "envelope": sign_dsse_payload(_INDEX_PAYLOAD_TYPE, payload, self._key),
            "publicKey": {
                "algorithm": "ed25519",
                "keyid": self._key.key_id,
                "raw": base64.b64encode(self._key.public_key).decode("ascii"),
            },
            "trustPolicy": "pin-service-key-out-of-band",
            "identityTrusted": False,
        }

    def leaderboard(self) -> dict[str, Any]:
        with self._lock:
            rows = []
            for row in self._state["submissions"].values():
                if (
                    not isinstance(row, dict)
                    or row.get("status") != "accepted"
                    or row["kind"] != "leaderboard"
                ):
                    continue
                metadata = row["metadata"]
                possible = int(metadata["possibleScore"])
                score = int(metadata["score"])
                rows.append(
                    {
                        "submissionId": row["id"],
                        "category": metadata["category"],
                        "component": metadata["component"],
                        "version": metadata["version"],
                        "score": score,
                        "possibleScore": possible,
                        "rate": f"{score}/{possible}",
                        "evidence": row["verification"],
                    }
                )
        rows.sort(
            key=lambda item: (
                -item["score"] / item["possibleScore"],
                item["component"],
                item["version"],
            )
        )
        for rank, row in enumerate(rows, 1):
            row["rank"] = rank
        return {
            "artifactType": "sova.community-live-leaderboard",
            "schemaVersion": "0.1.0",
            "profile": {
                "id": STANDARD_ARENA_PROFILE.identifier,
                "digest": STANDARD_ARENA_PROFILE.digest,
            },
            "methodologyDigest": sha256_digest(self.config.methodology_snapshot.encode()),
            "entries": rows,
            "limitations": [
                "Ranks apply only to the pinned standard profile and declared versions.",
                "Operator trust pins authenticate evidence keys, not the truth of target claims.",
            ],
        }

    def object_path(self, digest_hex: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", digest_hex) is None:
            raise FormatError("SOVA-SERVICE-OBJECT", "object digest is malformed")
        path = self.root / "objects" / "sha256" / digest_hex
        digest = "sha256:" + digest_hex
        with self._lock:
            referenced = any(
                isinstance(row, dict)
                and row.get("status") == "accepted"
                and any(item.get("digest") == digest for item in row.get("files", []))
                for row in self._state["submissions"].values()
            )
        if not referenced or not path.is_file() or path.is_symlink():
            raise FormatError("SOVA-SERVICE-NOT-FOUND", "object does not exist")
        return path


def verify_community_service_index(
    document: Mapping[str, Any],
    *,
    trusted_service_key_ids: frozenset[str],
    minimum_sequence: int = 0,
) -> dict[str, Any]:
    """Verify a downloaded service index and require an out-of-band service-key pin."""
    if not trusted_service_key_ids:
        raise FormatError("SOVA-SERVICE-TRUST", "a service-key trust pin is required")
    if (
        not isinstance(minimum_sequence, int)
        or isinstance(minimum_sequence, bool)
        or minimum_sequence < 0
    ):
        raise FormatError("SOVA-SERVICE-INDEX", "minimum sequence must be non-negative")
    try:
        public = document["publicKey"]
        envelope = document["envelope"]
        declared_index = document["index"]
    except KeyError as error:
        raise FormatError("SOVA-SERVICE-INDEX", "signed service index is malformed") from error
    if not isinstance(public, Mapping) or not isinstance(envelope, dict):
        raise FormatError("SOVA-SERVICE-INDEX", "signed service index material is malformed")
    try:
        raw_public = base64.b64decode(_required_string(public, "raw"), validate=True)
    except (binascii.Error, ValueError) as error:
        raise FormatError("SOVA-SERVICE-INDEX", "service public key is invalid base64") from error
    key_id = sha256_digest(raw_public)
    if (
        public.get("algorithm") != "ed25519"
        or public.get("keyid") != key_id
        or key_id not in trusted_service_key_ids
    ):
        raise FormatError("SOVA-SERVICE-TRUST", "service index key is not explicitly trusted")
    payload = verify_dsse_payload(
        envelope,
        raw_public,
        expected_payload_type=_INDEX_PAYLOAD_TYPE,
    )
    parsed = strict_json_loads(payload)
    if parsed != declared_index or not isinstance(parsed, Mapping):
        raise FormatError("SOVA-SERVICE-INDEX", "signed payload and declared index differ")
    if (
        parsed.get("artifactType") != "sova.community-service-index"
        or parsed.get("schemaVersion") != "0.1.0"
        or not isinstance(parsed.get("entries"), list)
        or not isinstance(parsed.get("sequence"), int)
    ):
        raise FormatError("SOVA-SERVICE-INDEX", "service index payload is malformed")
    if parsed["sequence"] < minimum_sequence:
        raise FormatError(
            "SOVA-SERVICE-ROLLBACK", "service index sequence is older than trusted state"
        )
    return {
        "artifactType": "sova.community-service-index-verification",
        "schemaVersion": "0.1.0",
        "accepted": True,
        "serviceKeyId": key_id,
        "identityTrusted": True,
        "signatureValid": True,
        "entryCount": len(parsed["entries"]),
        "sequence": parsed["sequence"],
        "offline": True,
    }


class _RateLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[int, int]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        minute = int((time.time() if now is None else now) // 60)
        with self._lock:
            bucket_minute, count = self._buckets.get(key, (minute, 0))
            if bucket_minute != minute:
                bucket_minute, count = minute, 0
            if count >= self.limit:
                return False
            self._buckets[key] = (bucket_minute, count + 1)
            return True


class CommunityHTTPService:
    """Small loopback HTTP facade with a background verification queue."""

    def __init__(self, config: CommunityServiceConfig) -> None:
        self.config = config
        self.store = CommunityRegistryStore(config)
        self._rate = _RateLimiter(config.limits.requests_per_minute)
        self._stop = threading.Event()
        self._serving = threading.Event()
        self._worker: threading.Thread | None = None
        self._server = ThreadingHTTPServer((config.host, config.port), self._handler_type())
        self._server.daemon_threads = True

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def _handler_type(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def _send(
                self, status: HTTPStatus, document: Mapping[str, Any], *, close: bool = False
            ) -> None:
                body = canonical_json_bytes(dict(document)) + b"\n"
                self.send_response(status.value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if close:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def _error(self, status: HTTPStatus, code: str, message: str) -> None:
                self._send(status, {"error": {"code": code, "message": message}})

            def _reject_unread(self, status: HTTPStatus, code: str, message: str) -> None:
                # The request body was not read, so the connection must not carry another
                # request: the unread bytes would otherwise be parsed as one.
                self._send(status, {"error": {"code": code, "message": message}}, close=True)

            def _authorized(self) -> bool:
                expected = "Bearer " + service.config.token
                supplied = self.headers.get("Authorization", "")
                return hmac.compare_digest(supplied.encode(), expected.encode())

            def _rate_allowed(self) -> bool:
                return service._rate.allow(str(self.client_address[0]))

            def do_POST(self) -> None:
                if not self._rate_allowed():
                    self._reject_unread(
                        HTTPStatus.TOO_MANY_REQUESTS, "SOVA-SERVICE-RATE", "rate limit exceeded"
                    )
                    return
                if not self._authorized():
                    self._reject_unread(
                        HTTPStatus.UNAUTHORIZED,
                        "SOVA-SERVICE-AUTH",
                        "valid operator token required",
                    )
                    return
                if urlsplit(self.path).path != "/v1/submissions":
                    self._reject_unread(
                        HTTPStatus.NOT_FOUND, "SOVA-SERVICE-NOT-FOUND", "route not found"
                    )
                    return
                raw_length = self.headers.get("Content-Length")
                if raw_length is None or not raw_length.isdecimal():
                    self._reject_unread(
                        HTTPStatus.LENGTH_REQUIRED, "SOVA-SERVICE-LENGTH", "content length required"
                    )
                    return
                length = int(raw_length)
                if length < 1 or length > service.config.limits.max_body_bytes:
                    self._reject_unread(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "SOVA-SERVICE-LIMIT",
                        "request body exceeds limit",
                    )
                    return
                try:
                    document = _object_document(
                        strict_json_loads(
                            self.rfile.read(length),
                            max_bytes=service.config.limits.max_body_bytes,
                            max_string_bytes=max(
                                _MAX_METADATA_BYTES,
                                _encoded_file_string_limit(service.config.limits),
                            ),
                        )
                    )
                    result = service.store.submit(document)
                except (FormatError, OSError) as error:
                    code = error.issue.code if isinstance(error, FormatError) else "SOVA-SERVICE-IO"
                    self._error(HTTPStatus.BAD_REQUEST, code, str(error))
                    return
                self._send(HTTPStatus.ACCEPTED, result)

            def do_GET(self) -> None:  # noqa: PLR0911
                if not self._rate_allowed():
                    self._error(
                        HTTPStatus.TOO_MANY_REQUESTS, "SOVA-SERVICE-RATE", "rate limit exceeded"
                    )
                    return
                parsed = urlsplit(self.path)
                path = parsed.path
                try:
                    if path == "/v1/health":
                        self._send(
                            HTTPStatus.OK,
                            {
                                "artifactType": "sova.community-service-health",
                                "schemaVersion": "0.1.0",
                                "status": "ready",
                                "loopbackOnly": True,
                                "serviceKeyId": service.store.key_id,
                                "uploadLimits": service.config.limits.to_mapping(),
                            },
                        )
                        return
                    if path == "/v1/index":
                        self._send(HTTPStatus.OK, service.store.signed_index())
                        return
                    if path == "/v1/leaderboard":
                        self._send(HTTPStatus.OK, service.store.leaderboard())
                        return
                    if path.startswith("/v1/submissions/"):
                        self._send(HTTPStatus.OK, service.store.status(path.rsplit("/", 1)[-1]))
                        return
                    if path.startswith("/v1/objects/sha256/"):
                        target = service.store.object_path(path.rsplit("/", 1)[-1])
                        body = target.read_bytes()
                        self.send_response(HTTPStatus.OK.value)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Content-Disposition", "attachment")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    if path == "/v1/events":
                        values = parse_qs(parsed.query, strict_parsing=False)
                        raw_after = values.get("after", [self.headers.get("Last-Event-ID", "0")])[0]
                        events = service.store.events_after(_event_cursor(raw_after))
                        body = b"".join(
                            b"id: "
                            + str(item["sequence"]).encode()
                            + b"\nevent: "
                            + str(item["kind"]).encode()
                            + b"\ndata: "
                            + canonical_json_bytes(item)
                            + b"\n\n"
                            for item in events
                        )
                        self.send_response(HTTPStatus.OK.value)
                        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(body)
                        return
                except (FormatError, OSError) as error:
                    code = error.issue.code if isinstance(error, FormatError) else "SOVA-SERVICE-IO"
                    status = (
                        HTTPStatus.NOT_FOUND
                        if code == "SOVA-SERVICE-NOT-FOUND"
                        else HTTPStatus.BAD_REQUEST
                    )
                    self._error(status, code, str(error))
                    return
                self._error(HTTPStatus.NOT_FOUND, "SOVA-SERVICE-NOT-FOUND", "route not found")

        return Handler

    def _worker_loop(self) -> None:
        while not self._stop.wait(0.05):
            if self.store.process_next() is None:
                self._stop.wait(0.15)

    def start(self) -> None:
        if self._worker is not None:
            raise FormatError("SOVA-SERVICE-LIFECYCLE", "service is already started")
        self._worker = threading.Thread(
            target=self._worker_loop, name="sova-registry-verifier", daemon=True
        )
        self._worker.start()

    def serve_forever(self) -> None:
        self.start()
        self._serving.set()
        try:
            self._server.serve_forever(poll_interval=0.2)
        finally:
            self._serving.clear()
            self._stop.set()
            self._server.server_close()
            if self._worker is not None:
                self._worker.join(timeout=5)
            self._worker = None

    def close(self) -> None:
        self._stop.set()
        if self._serving.is_set():
            self._server.shutdown()
        self._server.server_close()
        if self._worker is not None and self._worker is not threading.current_thread():
            self._worker.join(timeout=5)
        self._worker = None


__all__ = [
    "CommunityHTTPService",
    "CommunityRegistryStore",
    "CommunityServiceConfig",
    "CommunityServiceLimits",
    "check_community_service_health",
    "create_community_service_token",
    "prepare_community_submission",
    "serialize_community_submission",
    "verify_community_service_index",
]
