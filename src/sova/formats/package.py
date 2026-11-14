# SPDX-License-Identifier: Apache-2.0
"""Deterministic, content-addressed, hostile-input-aware SOVA packages."""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sova.formats.canonical import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.formats.schema import validate_document

MAX_ENTRIES = 4096
MAX_ENTRY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PATH_BYTES = 512
MIN_RATIO_CHECK_BYTES = 1024
SHA256_IDENTIFIER_LENGTH = 71
_SHA256_IDENTIFIER = re.compile(r"^sha256:[0-9a-f]{64}$")
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class ContentDescriptor:
    """An immutable package object reference."""

    role: str
    path: str
    mediaType: str  # noqa: N815 - serialized field name is normative
    digest: str
    size: int

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> ContentDescriptor:
        """Construct a validated descriptor from untrusted manifest data."""
        required = {"role", "path", "mediaType", "digest", "size"}
        if set(value) != required:
            raise FormatError(
                "SOVA-PACKAGE-DESCRIPTOR-FIELDS",
                "content descriptor has missing or unknown fields",
                details={"fields": sorted(value)},
            )
        if not all(isinstance(value[name], str) for name in required - {"size"}):
            raise FormatError(
                "SOVA-PACKAGE-DESCRIPTOR-TYPE",
                "descriptor string fields must be strings",
            )
        if not isinstance(value["size"], int) or isinstance(value["size"], bool):
            raise FormatError(
                "SOVA-PACKAGE-DESCRIPTOR-TYPE",
                "descriptor size must be an integer",
            )
        descriptor = cls(**value)
        validate_package_path(descriptor.path)
        if (
            len(descriptor.digest) != SHA256_IDENTIFIER_LENGTH
            or _SHA256_IDENTIFIER.fullmatch(descriptor.digest) is None
        ):
            raise FormatError(
                "SOVA-PACKAGE-DIGEST-FORMAT",
                "descriptor digest must use lowercase SHA-256",
            )
        if descriptor.size < 0 or descriptor.size > MAX_ENTRY_BYTES:
            raise FormatError(
                "SOVA-PACKAGE-ENTRY-SIZE",
                "descriptor size exceeds package limits",
            )
        return descriptor


def validate_package_path(value: str) -> None:
    """Reject archive paths that are ambiguous or can escape extraction roots."""
    if not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise FormatError("SOVA-PACKAGE-PATH", "package path is empty or too long")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise FormatError("SOVA-PACKAGE-PATH", "package path is not a safe relative POSIX path")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise FormatError("SOVA-PACKAGE-PATH", "package path is not normalized")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, _ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0x800
    return info


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _fsync_directory(path: Path) -> None:
    """Best-effort directory sync on platforms that expose directory handles."""
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    if not flags:
        return
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class PackageWriter:
    """Build a deterministic SOVA package from validated typed objects."""

    def __init__(self, manifest: dict[str, Any]) -> None:
        self._manifest = dict(manifest)
        self._objects: dict[str, tuple[ContentDescriptor, bytes]] = {}
        if "objects" in self._manifest:
            raise FormatError(
                "SOVA-PACKAGE-MANIFEST-OBJECTS",
                "PackageWriter owns the manifest objects index",
            )

    def add_bytes(self, *, role: str, path: str, media_type: str, data: bytes) -> ContentDescriptor:
        """Add one bounded object and return its immutable descriptor."""
        validate_package_path(path)
        if path == "manifest.json":
            raise FormatError(
                "SOVA-PACKAGE-RESERVED-PATH",
                "manifest.json is reserved",
            )
        if path in self._objects:
            raise FormatError(
                "SOVA-PACKAGE-DUPLICATE-PATH",
                f"duplicate package path: {path}",
            )
        if len(data) > MAX_ENTRY_BYTES:
            raise FormatError(
                "SOVA-PACKAGE-ENTRY-SIZE",
                "object exceeds the configured entry limit",
                details={"path": path, "size": len(data), "limit": MAX_ENTRY_BYTES},
            )
        descriptor = ContentDescriptor(
            role=role,
            path=path,
            mediaType=media_type,
            digest=sha256_digest(data),
            size=len(data),
        )
        self._objects[path] = (descriptor, data)
        return descriptor

    def add_json(
        self,
        *,
        role: str,
        path: str,
        artifact_type: str,
        document: dict[str, Any],
    ) -> ContentDescriptor:
        """Validate and add one canonical typed JSON object."""
        validate_document(document, artifact_type)
        return self.add_bytes(
            role=role,
            path=path,
            media_type=f"application/vnd.sova.{artifact_type.removeprefix('sova.')}+json",
            data=canonical_json_bytes(document),
        )

    def finalized_manifest(self) -> dict[str, Any]:
        """Return the validated manifest with a sorted descriptor index."""
        manifest = dict(self._manifest)
        manifest["objects"] = [
            asdict(descriptor)
            for descriptor, _data in sorted(self._objects.values(), key=lambda item: item[0].path)
        ]
        artifact_type = manifest.get("artifactType")
        if not isinstance(artifact_type, str):
            raise FormatError(
                "SOVA-PACKAGE-MANIFEST-TYPE",
                "package manifest requires artifactType",
            )
        validate_document(manifest, artifact_type)
        return manifest

    def write(self, destination: Path) -> str:
        """Atomically write the package and return its exact byte digest."""
        manifest_bytes = canonical_json_bytes(self.finalized_manifest())
        total_size = len(manifest_bytes) + sum(
            len(data) for _descriptor, data in self._objects.values()
        )
        if len(self._objects) + 1 > MAX_ENTRIES or total_size > MAX_TOTAL_BYTES:
            raise FormatError(
                "SOVA-PACKAGE-TOTAL-SIZE",
                "package exceeds configured entry or total-size limits",
            )
        destination = destination.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        try:
            with zipfile.ZipFile(
                temporary,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                allowZip64=True,
            ) as archive:
                archive.writestr(_zip_info("manifest.json"), manifest_bytes, compresslevel=9)
                for path, (_descriptor, data) in sorted(self._objects.items()):
                    archive.writestr(_zip_info(path), data, compresslevel=9)
            # Windows requires a writable descriptor for fsync.
            with temporary.open("r+b") as handle:
                os.fsync(handle.fileno())
            digest = _file_digest(temporary)
            temporary.replace(destination)
            _fsync_directory(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)
        return digest


def _read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    """Read one archive member; a damaged member is an integrity failure, never a crash."""
    try:
        return archive.read(name)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError) as error:
        raise FormatError(
            "SOVA-PACKAGE-INTEGRITY",
            f"archive member is damaged and cannot be read: {name}",
        ) from error


class PackageReader:
    """Inspect and verify a package without extracting or executing its content."""

    def __init__(self, source: Path) -> None:
        self.source = source.resolve()

    def _checked_archive(self) -> zipfile.ZipFile:
        try:
            archive = zipfile.ZipFile(self.source, mode="r")
        except (OSError, zipfile.BadZipFile) as error:
            raise FormatError(
                "SOVA-PACKAGE-INVALID-ARCHIVE",
                "artifact is not a readable SOVA ZIP package",
            ) from error
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            archive.close()
            raise FormatError(
                "SOVA-PACKAGE-ENTRY-COUNT",
                "package is empty or exceeds the entry-count limit",
            )
        names: set[str] = set()
        total = 0
        for info in infos:
            validate_package_path(info.filename)
            if info.filename in names:
                archive.close()
                raise FormatError(
                    "SOVA-PACKAGE-DUPLICATE-PATH",
                    f"duplicate archive member: {info.filename}",
                )
            names.add(info.filename)
            mode = info.external_attr >> 16
            if info.is_dir() or (mode & 0o170000) not in {0, 0o100000}:
                archive.close()
                raise FormatError(
                    "SOVA-PACKAGE-UNSAFE-ENTRY",
                    "directories, links, devices, and special entries are forbidden",
                )
            if info.file_size > MAX_ENTRY_BYTES:
                archive.close()
                raise FormatError("SOVA-PACKAGE-ENTRY-SIZE", "archive member is too large")
            if info.file_size > 0 and info.compress_size == 0:
                archive.close()
                raise FormatError(
                    "SOVA-PACKAGE-COMPRESSION-METADATA",
                    "non-empty archive member has invalid compressed-size metadata",
                )
            if (
                info.file_size > MIN_RATIO_CHECK_BYTES
                and info.compress_size > 0
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                archive.close()
                raise FormatError(
                    "SOVA-PACKAGE-COMPRESSION-RATIO",
                    "archive member exceeds the decompression-ratio limit",
                )
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                archive.close()
                raise FormatError(
                    "SOVA-PACKAGE-TOTAL-SIZE",
                    "archive exceeds the total uncompressed-size limit",
                )
        if "manifest.json" not in names:
            archive.close()
            raise FormatError(
                "SOVA-PACKAGE-MISSING-MANIFEST",
                "package does not contain manifest.json",
            )
        return archive

    def raw_manifest(self) -> dict[str, Any]:
        """Read the root manifest with strict JSON but without schema selection."""
        raw = self.raw_manifest_bytes()
        document = strict_json_loads(raw)
        if not isinstance(document, dict):
            raise FormatError(
                "SOVA-PACKAGE-MANIFEST-TYPE",
                "manifest root must be an object",
            )
        return document

    def raw_manifest_bytes(self) -> bytes:
        """Return the bounded exact manifest bytes without interpreting them."""
        with self._checked_archive() as archive:
            return _read_member(archive, "manifest.json")

    def manifest(self, expected_type: str | None = None) -> dict[str, Any]:
        """Read and validate the root manifest."""
        document = self.raw_manifest()
        validate_document(document, expected_type)
        return document

    def verify(self, expected_type: str | None = None) -> list[ContentDescriptor]:
        """Verify every declared byte and reject undeclared package content."""
        manifest = self.manifest(expected_type)
        raw_objects = manifest.get("objects")
        return self.verify_object_index(raw_objects)

    def verify_object_index(self, raw_objects: Any) -> list[ContentDescriptor]:
        """Verify an object index without requiring a current manifest schema.

        This is used only by offline migration of historical manifests. It
        still enforces all archive, descriptor, size, path, and digest rules.
        """
        if not isinstance(raw_objects, list):
            raise FormatError(
                "SOVA-PACKAGE-OBJECTS-TYPE",
                "manifest objects must be an array",
            )
        descriptors = [
            ContentDescriptor.from_mapping(item)
            if isinstance(item, dict)
            else _raise_descriptor_type()
            for item in raw_objects
        ]
        declared = {descriptor.path for descriptor in descriptors}
        if len(declared) != len(descriptors):
            raise FormatError(
                "SOVA-PACKAGE-DUPLICATE-DESCRIPTOR",
                "manifest declares a package path more than once",
            )
        with self._checked_archive() as archive:
            actual = set(archive.namelist()) - {"manifest.json"}
            if actual != declared:
                raise FormatError(
                    "SOVA-PACKAGE-INDEX-MISMATCH",
                    "archive members do not match the manifest object index",
                    details={
                        "undeclared": sorted(actual - declared),
                        "missing": sorted(declared - actual),
                    },
                )
            for descriptor in descriptors:
                data = _read_member(archive, descriptor.path)
                if len(data) != descriptor.size or sha256_digest(data) != descriptor.digest:
                    raise FormatError(
                        "SOVA-PACKAGE-INTEGRITY",
                        f"content descriptor verification failed: {descriptor.path}",
                    )
        return descriptors

    def content_digest(self, expected_type: str | None = None) -> str:
        """Hash the canonical manifest/root independently from ZIP transport bytes."""
        manifest = self.manifest(expected_type)
        self.verify_object_index(manifest.get("objects"))
        return sha256_digest(canonical_json_bytes(manifest))

    def read_object(self, descriptor: ContentDescriptor) -> bytes:
        """Read one verified object without extracting the archive."""
        with self._checked_archive() as archive:
            data = _read_member(archive, descriptor.path)
        if len(data) != descriptor.size or sha256_digest(data) != descriptor.digest:
            raise FormatError(
                "SOVA-PACKAGE-INTEGRITY",
                f"content descriptor verification failed: {descriptor.path}",
            )
        return data


def _raise_descriptor_type() -> ContentDescriptor:
    raise FormatError(
        "SOVA-PACKAGE-DESCRIPTOR-TYPE",
        "object descriptors must be JSON objects",
    )


__all__ = [
    "ContentDescriptor",
    "PackageReader",
    "PackageWriter",
    "validate_package_path",
]
