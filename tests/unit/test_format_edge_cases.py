# SPDX-License-Identifier: Apache-2.0
"""Hostile and boundary inputs for shared format primitives."""

from __future__ import annotations

import math
import zipfile
from dataclasses import asdict, replace
from typing import TYPE_CHECKING

import pytest

from sova.capsule import capsule_manifest_template
from sova.formats import ContentDescriptor, PackageReader, PackageWriter
from sova.formats import package as package_module
from sova.formats.canonical import MAX_IJSON_INTEGER, canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.formats.package import validate_package_path
from sova.formats.schema import validate_document, validation_issues

if TYPE_CHECKING:
    from pathlib import Path


def test_strict_json_resource_and_syntax_limits() -> None:
    with pytest.raises(FormatError) as syntax:
        strict_json_loads(b"{")
    assert syntax.value.issue.code == "SOVA-FORMAT-INVALID-JSON"
    with pytest.raises(FormatError) as size:
        strict_json_loads(b"{}", max_bytes=1)
    assert size.value.issue.code == "SOVA-FORMAT-SIZE-LIMIT"
    with pytest.raises(FormatError) as items:
        strict_json_loads(b'{"a":1}', max_items=1)
    assert items.value.issue.code == "SOVA-FORMAT-ITEM-LIMIT"
    with pytest.raises(FormatError) as depth:
        strict_json_loads(b'{"a":{"b":1}}', max_depth=1)
    assert depth.value.issue.code == "SOVA-FORMAT-DEPTH-LIMIT"
    with pytest.raises(FormatError) as string:
        strict_json_loads(b'{"value":"12345"}', max_string_bytes=4)
    assert string.value.issue.code == "SOVA-FORMAT-STRING-LIMIT"
    assert strict_json_loads(b'{"value":"12345"}', max_string_bytes=5) == {"value": "12345"}
    with pytest.raises(FormatError) as canonical_string:
        canonical_json_bytes({"value": "12345"}, max_string_bytes=4)
    assert canonical_string.value.issue.code == "SOVA-FORMAT-STRING-LIMIT"
    with pytest.raises(FormatError) as canonical:
        canonical_json_bytes({"unsupported": {1, 2}})
    assert canonical.value.issue.code == "SOVA-FORMAT-NONCANONICAL-VALUE"


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (math.inf, "SOVA-FORMAT-NONFINITE-NUMBER"),
        ({"value": 1.5}, "SOVA-FORMAT-CANONICAL-FLOAT"),
        ({"value": MAX_IJSON_INTEGER + 1}, "SOVA-FORMAT-IJSON-INTEGER"),
        ({1: "non-string key"}, "SOVA-FORMAT-NONSTRING-KEY"),
        ({"value": "\ud800"}, "SOVA-FORMAT-INVALID-UNICODE"),
        ({"\ud800": "value"}, "SOVA-FORMAT-INVALID-UNICODE"),
    ],
)
def test_canonical_json_rejects_nonportable_values(value: object, code: str) -> None:
    with pytest.raises(FormatError) as error:
        canonical_json_bytes(value)
    assert error.value.issue.code == code


def test_strict_json_rejects_invalid_utf8_duplicate_keys_and_nonfinite() -> None:
    cases = [
        (b'"\xff"', "SOVA-FORMAT-INVALID-UTF8"),
        (b'{"a":1,"a":2}', "SOVA-FORMAT-DUPLICATE-KEY"),
        (b'{"a":NaN}', "SOVA-FORMAT-NONFINITE-NUMBER"),
    ]
    for raw, code in cases:
        with pytest.raises(FormatError) as error:
            strict_json_loads(raw)
        assert error.value.issue.code == code


@pytest.mark.parametrize(
    "value",
    ["", "/absolute", "../escape", "a/../b", "a\\b", "a//b", "a\x00b"],
)
def test_unsafe_package_paths_fail(value: str) -> None:
    with pytest.raises(FormatError):
        validate_package_path(value)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ({"role": "x"}, "SOVA-PACKAGE-DESCRIPTOR-FIELDS"),
        (
            {
                "role": 1,
                "path": "a",
                "mediaType": "text/plain",
                "digest": "sha256:" + "0" * 64,
                "size": 1,
            },
            "SOVA-PACKAGE-DESCRIPTOR-TYPE",
        ),
        (
            {
                "role": "x",
                "path": "a",
                "mediaType": "text/plain",
                "digest": "bad",
                "size": 1,
            },
            "SOVA-PACKAGE-DIGEST-FORMAT",
        ),
        (
            {
                "role": "x",
                "path": "a",
                "mediaType": "text/plain",
                "digest": "sha256:" + "0" * 64,
                "size": -1,
            },
            "SOVA-PACKAGE-ENTRY-SIZE",
        ),
        (
            {
                "role": "x",
                "path": "a",
                "mediaType": "text/plain",
                "digest": "sha256:" + "0" * 64,
                "size": True,
            },
            "SOVA-PACKAGE-DESCRIPTOR-TYPE",
        ),
    ],
)
def test_descriptor_rejects_malformed_input(value: dict[str, object], code: str) -> None:
    with pytest.raises(FormatError) as error:
        ContentDescriptor.from_mapping(value)
    assert error.value.issue.code == code


def test_writer_rejects_owned_and_duplicate_paths() -> None:
    with pytest.raises(FormatError) as owned:
        PackageWriter({"artifactType": "sova.capsule", "objects": []})
    assert owned.value.issue.code == "SOVA-PACKAGE-MANIFEST-OBJECTS"

    writer = PackageWriter({"artifactType": "sova.capsule"})
    with pytest.raises(FormatError) as reserved:
        writer.add_bytes(
            role="x",
            path="manifest.json",
            media_type="text/plain",
            data=b"x",
        )
    assert reserved.value.issue.code == "SOVA-PACKAGE-RESERVED-PATH"
    writer.add_bytes(role="x", path="a", media_type="text/plain", data=b"x")
    with pytest.raises(FormatError) as duplicate:
        writer.add_bytes(role="x", path="a", media_type="text/plain", data=b"x")
    assert duplicate.value.issue.code == "SOVA-PACKAGE-DUPLICATE-PATH"


def test_writer_rejects_missing_type_and_configured_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError) as missing_type:
        PackageWriter({}).finalized_manifest()
    assert missing_type.value.issue.code == "SOVA-PACKAGE-MANIFEST-TYPE"

    manifest = capsule_manifest_template(
        title="Limit fixture",
        summary="Limit fixture",
        author="Tester",
    )
    writer = PackageWriter(manifest)
    monkeypatch.setattr(package_module, "MAX_ENTRY_BYTES", 1)
    with pytest.raises(FormatError) as entry:
        writer.add_bytes(role="x", path="x", media_type="text/plain", data=b"xx")
    assert entry.value.issue.code == "SOVA-PACKAGE-ENTRY-SIZE"

    monkeypatch.setattr(package_module, "MAX_ENTRY_BYTES", 256 * 1024 * 1024)
    monkeypatch.setattr(package_module, "MAX_ENTRIES", 0)
    with pytest.raises(FormatError) as total:
        PackageWriter(manifest).write(tmp_path / "limited.sova")
    assert total.value.issue.code == "SOVA-PACKAGE-TOTAL-SIZE"


def test_reader_rejects_invalid_missing_and_directory_archives(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.sova"
    invalid.write_bytes(b"not zip")
    with pytest.raises(FormatError) as bad:
        PackageReader(invalid).raw_manifest()
    assert bad.value.issue.code == "SOVA-PACKAGE-INVALID-ARCHIVE"

    missing = tmp_path / "missing.sova"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("object", b"x")
    with pytest.raises(FormatError) as no_manifest:
        PackageReader(missing).raw_manifest()
    assert no_manifest.value.issue.code == "SOVA-PACKAGE-MISSING-MANIFEST"

    directory = tmp_path / "directory.sova"
    with zipfile.ZipFile(directory, "w") as archive:
        archive.writestr("manifest.json", b"{}")
        archive.writestr("objects/", b"")
    with pytest.raises(FormatError) as unsafe:
        PackageReader(directory).raw_manifest()
    assert unsafe.value.issue.code in {"SOVA-PACKAGE-PATH", "SOVA-PACKAGE-UNSAFE-ENTRY"}


def test_reader_rejects_empty_duplicate_and_resource_hostile_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = tmp_path / "empty.sova"
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(FormatError) as empty_error:
        PackageReader(empty).raw_manifest()
    assert empty_error.value.issue.code == "SOVA-PACKAGE-ENTRY-COUNT"

    duplicate = tmp_path / "duplicate.sova"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("manifest.json", b"{}")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("manifest.json", b"{}")
    with pytest.raises(FormatError) as duplicate_error:
        PackageReader(duplicate).raw_manifest()
    assert duplicate_error.value.issue.code == "SOVA-PACKAGE-DUPLICATE-PATH"

    oversized = tmp_path / "oversized.sova"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("manifest.json", b"{}")
    monkeypatch.setattr(package_module, "MAX_ENTRY_BYTES", 1)
    with pytest.raises(FormatError) as size_error:
        PackageReader(oversized).raw_manifest()
    assert size_error.value.issue.code == "SOVA-PACKAGE-ENTRY-SIZE"

    monkeypatch.setattr(package_module, "MAX_ENTRY_BYTES", 256 * 1024 * 1024)
    monkeypatch.setattr(package_module, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(FormatError) as total_error:
        PackageReader(oversized).raw_manifest()
    assert total_error.value.issue.code == "SOVA-PACKAGE-TOTAL-SIZE"

    monkeypatch.setattr(package_module, "MAX_TOTAL_BYTES", 1024 * 1024 * 1024)
    monkeypatch.setattr(package_module, "MIN_RATIO_CHECK_BYTES", 0)
    monkeypatch.setattr(package_module, "MAX_COMPRESSION_RATIO", 0.1)
    with pytest.raises(FormatError) as ratio_error:
        PackageReader(oversized).raw_manifest()
    assert ratio_error.value.issue.code == "SOVA-PACKAGE-COMPRESSION-RATIO"


def test_reader_manifest_and_object_index_failure_modes(tmp_path: Path) -> None:
    non_object = tmp_path / "non-object.sova"
    with zipfile.ZipFile(non_object, "w") as archive:
        archive.writestr("manifest.json", b"[]")
    with pytest.raises(FormatError) as root:
        PackageReader(non_object).raw_manifest()
    assert root.value.issue.code == "SOVA-PACKAGE-MANIFEST-TYPE"

    indexed = tmp_path / "indexed.sova"
    with zipfile.ZipFile(indexed, "w") as archive:
        archive.writestr("manifest.json", b"{}")
        archive.writestr("objects/a", b"actual")
    reader = PackageReader(indexed)
    with pytest.raises(FormatError) as not_array:
        reader.verify_object_index({})
    assert not_array.value.issue.code == "SOVA-PACKAGE-OBJECTS-TYPE"
    with pytest.raises(FormatError) as not_descriptor:
        reader.verify_object_index([1])
    assert not_descriptor.value.issue.code == "SOVA-PACKAGE-DESCRIPTOR-TYPE"

    descriptor = ContentDescriptor(
        role="fixture",
        path="objects/a",
        mediaType="text/plain",
        digest="sha256:" + "0" * 64,
        size=6,
    )
    with pytest.raises(FormatError) as duplicate:
        reader.verify_object_index(
            [
                {
                    "role": descriptor.role,
                    "path": descriptor.path,
                    "mediaType": descriptor.mediaType,
                    "digest": descriptor.digest,
                    "size": descriptor.size,
                },
                {
                    "role": descriptor.role,
                    "path": descriptor.path,
                    "mediaType": descriptor.mediaType,
                    "digest": descriptor.digest,
                    "size": descriptor.size,
                },
            ]
        )
    assert duplicate.value.issue.code == "SOVA-PACKAGE-DUPLICATE-DESCRIPTOR"

    with pytest.raises(FormatError) as mismatch:
        reader.verify_object_index([])
    assert mismatch.value.issue.code == "SOVA-PACKAGE-INDEX-MISMATCH"
    with pytest.raises(FormatError) as integrity:
        reader.verify_object_index(
            [
                {
                    "role": descriptor.role,
                    "path": descriptor.path,
                    "mediaType": descriptor.mediaType,
                    "digest": descriptor.digest,
                    "size": descriptor.size,
                }
            ]
        )
    assert integrity.value.issue.code == "SOVA-PACKAGE-INTEGRITY"
    with pytest.raises(FormatError) as read_integrity:
        reader.read_object(replace(descriptor, digest="sha256:" + "f" * 64))
    assert read_integrity.value.issue.code == "SOVA-PACKAGE-INTEGRITY"


def test_schema_root_and_unknown_type_fail_visibly() -> None:
    assert validation_issues([])[0].code == "SOVA-SCHEMA-ROOT-TYPE"
    assert validation_issues({})[0].code == "SOVA-SCHEMA-MISSING-TYPE"
    with pytest.raises(FormatError) as unsupported:
        validate_document({"artifactType": "unknown"})
    assert unsupported.value.issue.code == "SOVA-SCHEMA-UNSUPPORTED-TYPE"


def test_reader_reports_a_damaged_member_as_an_integrity_failure(tmp_path: Path) -> None:
    """A corrupted member must fail verification with an error code, never crash."""
    archive_path = tmp_path / "damaged.zip"
    payload = b"evidence " * 64
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"{}")
        archive.writestr("blobs/data.bin", payload)
    raw = bytearray(archive_path.read_bytes())
    marker = raw.find(b"blobs/data.bin") + len(b"blobs/data.bin")
    raw[marker + 5] ^= 0xFF  # flip one byte inside the compressed member data
    archive_path.write_bytes(bytes(raw))
    descriptor = ContentDescriptor(
        role="attachment",
        path="blobs/data.bin",
        mediaType="application/octet-stream",
        digest="sha256:" + "0" * 64,
        size=len(payload),
    )
    with pytest.raises(FormatError) as caught:
        PackageReader(archive_path).read_object(descriptor)
    assert caught.value.issue.code == "SOVA-PACKAGE-INTEGRITY"
    with pytest.raises(FormatError) as caught_index:
        PackageReader(archive_path).verify_object_index([asdict(descriptor)])
    allowed = {"SOVA-PACKAGE-INTEGRITY", "SOVA-PACKAGE-INDEX-MISMATCH"}
    assert caught_index.value.issue.code in allowed
