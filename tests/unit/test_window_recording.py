# SPDX-License-Identifier: Apache-2.0
"""Exact-window frame recording, capsule, and decisive replay contracts."""

from __future__ import annotations

import ctypes
import io
import os
import struct
import time
import zipfile
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.replay import CapsuleReplaySelection, render_capsule_timeline
from sova.runtime import window_recording
from sova.runtime.window_recording import (
    SoftwareWindowRecordingCoordinator,
    WindowFrameRecordingSession,
    review_window_frame_recording,
)
from sova.trace import TraceReader, TraceWriter

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.runtime.software_target import SoftwareTargetAttestation


def _bmp(width: int = 2, height: int = 2, *, blue: int = 40) -> bytes:
    pixel_bytes = width * height * 4
    info = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        -height,
        1,
        32,
        0,
        pixel_bytes,
        0,
        0,
        0,
        0,
    )
    offset = 54
    header = struct.pack("<2sIHHI", b"BM", offset + pixel_bytes, 0, 0, offset)
    return header + info + bytes((blue, 20, 10, 255)) * (width * height)


def _ebml_size(value: int) -> bytes:
    if value < 0x7F:
        return bytes((0x80 | value,))
    if value < 0x3FFF:
        return bytes((0x40 | (value >> 8), value & 0xFF))
    raise AssertionError


def _ebml(identifier: bytes, payload: bytes) -> bytes:
    return identifier + _ebml_size(len(payload)) + payload


def _synthetic_webm(*, duration_seconds: float = 12.0) -> bytes:
    info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">d", duration_seconds * 1000)
    )
    segment = b"".join(
        (
            _ebml(b"\x15\x49\xa9\x66", info),
            _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
            _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
        )
    )
    return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)


@dataclass
class _FakeAttestation:
    window_id: int = 77
    window_handle_digest: str = "sha256:" + "1" * 64
    process_start_digest: str = "sha256:" + "2" * 64
    checks: int = 0

    def assert_still_live(self) -> None:
        self.checks += 1


def _event(event_id: str = "event-pass", sequence: int = 4) -> dict[str, object]:
    return {
        "id": event_id,
        "kind": "oracle.completed",
        "sequence": sequence,
        "monotonicNs": time.monotonic_ns(),
        "payload": {"status": "pass"},
    }


def _recording(
    destination: Path,
    *,
    phase: str = "primary",
    event: dict[str, object] | None = None,
) -> WindowFrameRecordingSession:
    attestation = _FakeAttestation()
    session = WindowFrameRecordingSession(
        cast("SoftwareTargetAttestation", attestation),
        destination,
        phase=phase,
        interval_seconds=5.0,
        capture=lambda window_id: _bmp(blue=window_id),
    )
    if event is not None:
        session.observe(phase, event)
    session.close()
    assert attestation.checks >= 2
    return session


def _rewrite_recording(
    data: bytes,
    *,
    mutate_manifest: Callable[[dict[str, Any]], None] | None = None,
    replace_members: dict[str, bytes] | None = None,
    omit: set[str] | None = None,
    extras: dict[str, bytes] | None = None,
) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data), "r") as source:
        members = {name: source.read(name) for name in source.namelist()}
    if mutate_manifest is not None:
        manifest = strict_json_loads(members["recording.json"])
        assert isinstance(manifest, dict)
        mutate_manifest(manifest)
        members["recording.json"] = canonical_json_bytes(manifest)
    members.update(replace_members or {})
    for name in omit or set():
        members.pop(name, None)
    members.update(extras or {})
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    return stream.getvalue()


def test_window_frame_recording_is_bounded_indexed_and_reviewable(tmp_path: Path) -> None:
    session = _recording(tmp_path, event=_event())
    reviewed = review_window_frame_recording(session.archive_path.read_bytes())
    cues = strict_json_loads(session.cue_path.read_bytes())

    assert reviewed.width == 2
    assert reviewed.height == 2
    assert len(reviewed.frames) >= 3
    assert reviewed.frames[1]["reason"] == "decisive-oracle"
    assert cues["mediaDigest"] == reviewed.digest
    assert cues["synchronization"]["method"] == ("same-host-monotonic-window-frame-capture-bound")
    assert cues["cues"][0]["eventId"] == "event-pass"
    assert cues["cues"][0]["chapterOffsetSeconds"] == reviewed.frames[1]["offsetSeconds"]


def test_window_recording_without_finding_finalizes_media_but_not_fake_cues(
    tmp_path: Path,
) -> None:
    session = _recording(tmp_path)
    assert session.archive_path.is_file()
    with pytest.raises(FormatError, match="decisive passing event"):
        _ = session.cue_path


def test_window_frame_archive_rejects_corruption(tmp_path: Path) -> None:
    session = _recording(tmp_path, event=_event())
    raw = bytearray(session.archive_path.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    with pytest.raises(FormatError):
        review_window_frame_recording(bytes(raw))


def test_coordinator_requires_both_fresh_phase_recordings(tmp_path: Path) -> None:
    coordinator = SoftwareWindowRecordingCoordinator(tmp_path, interval_seconds=5.0)
    primary = coordinator.start(
        "primary",
        cast("SoftwareTargetAttestation", _FakeAttestation()),
        capture=lambda _window_id: _bmp(),
    )
    primary.observe("primary", _event())
    primary.close()
    with pytest.raises(FormatError, match="both phase recordings"):
        coordinator.attachments()
    with pytest.raises(FormatError, match="both phase recordings"):
        coordinator.artifact_paths()


def test_sovaframes_capsule_opens_at_decisive_window_frame(tmp_path: Path) -> None:
    trace = tmp_path / "primary.sova-trace"
    writer = TraceWriter(trace)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    event = next(item for item in TraceReader(trace).events() if item["kind"] == "oracle.completed")
    session = _recording(tmp_path / "recording", event=event)
    capsule = tmp_path / "finding.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="Owned application finding",
            summary="Exact-window recorded behavior fixture.",
            author="SOVA tests",
        ),
        attachments={
            "visual-replay-01.sovaframes": session.archive_path.read_bytes(),
            "replay-cues.json": session.cue_path.read_bytes(),
        },
        traces=[trace],
    )
    descriptors = PackageReader(capsule).verify("sova.capsule")
    visual = [item for item in descriptors if item.role == "visual-replay"]
    assert len(visual) == 1
    assert visual[0].mediaType == "application/vnd.sova.window-frames+zip"

    destination = tmp_path / "replay.html"
    report = render_capsule_timeline(capsule, destination)
    rendered = destination.read_text(encoding="utf-8")
    assert report["opensAtDecisiveMoment"] is True
    assert report["visualReplay"] == visual[0].path
    assert "Recorded target application window" in rendered
    assert "data:image/bmp;base64," in rendered
    assert 'id="framePlayer"' in rendered


def test_capsule_pairs_browser_and_computer_cues_and_selects_each_surface(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "primary.sova-trace"
    writer = TraceWriter(trace)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    event = next(item for item in TraceReader(trace).events() if item["id"] == event_id)
    computer = _recording(tmp_path / "computer", event=event)
    browser_media = _synthetic_webm()
    browser_cues = {
        "artifactType": "sova.replay-cues",
        "schemaVersion": "0.1.0",
        "surface": "browser",
        "mediaName": "visual-replay-01.webm",
        "mediaDigest": sha256_digest(browser_media),
        "synchronization": {
            "method": "same-host-monotonic-recorder-start-rpc-bound",
            "uncertaintyMs": "1.000",
            "frameTimestampAttested": False,
            "statement": "Synthetic browser recording fixture.",
        },
        "cues": [
            {
                "id": "browser-decisive-01",
                "label": "Exploit confirmed",
                "channel": "primary",
                "eventId": event_id,
                "eventKind": "oracle.completed",
                "eventSequence": event["sequence"],
                "oracleStatus": "pass",
                "offsetSeconds": "0.100000",
                "chapterOffsetSeconds": "0.100000",
                "preRollSeconds": "0.000000",
                "postRollSeconds": "1.000000",
            }
        ],
    }
    capsule = tmp_path / "multi-surface.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="Browser and computer finding",
            summary="One decisive event with two independently bound visual surfaces.",
            author="SOVA tests",
        ),
        traces=[trace],
        attachments={
            "visual-replay-01.webm": browser_media,
            "replay-cues.json": canonical_json_bytes(browser_cues),
            "computer-visual-replay-01.sovaframes": computer.archive_path.read_bytes(),
            "computer-replay-cues.json": computer.cue_path.read_bytes(),
        },
    )
    descriptors = PackageReader(capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "replay-cues"]) == 2

    default_report = render_capsule_timeline(capsule, tmp_path / "browser.html")
    assert default_report["visualReplaySurface"] == "browser"
    assert default_report["opensAtDecisiveMoment"] is True
    assert "Recorded browser session" in (tmp_path / "browser.html").read_text(encoding="utf-8")

    computer_report = render_capsule_timeline(
        capsule,
        tmp_path / "computer.html",
        selection=CapsuleReplaySelection(surface="computer"),
    )
    assert computer_report["visualReplaySurface"] == "computer"
    assert computer_report["opensAtDecisiveMoment"] is True
    assert computer_report["decisiveCue"]["eventId"] == event_id
    assert "Recorded target application window" in (tmp_path / "computer.html").read_text(
        encoding="utf-8"
    )
    browser_descriptor = next(
        item
        for item in descriptors
        if item.role == "visual-replay" and item.mediaType == "video/webm"
    )
    with pytest.raises(FormatError, match="must be browser or computer"):
        render_capsule_timeline(
            capsule,
            tmp_path / "invalid-surface.html",
            selection=CapsuleReplaySelection(surface="invalid"),
        )
    with pytest.raises(FormatError, match="surface selection and no-media"):
        render_capsule_timeline(
            capsule,
            tmp_path / "surface-without-media.html",
            selection=CapsuleReplaySelection(surface="computer", no_media=True),
        )
    with pytest.raises(FormatError, match="does not match the requested surface"):
        render_capsule_timeline(
            capsule,
            tmp_path / "conflicting-explicit-media.html",
            selection=CapsuleReplaySelection(
                media_object=browser_descriptor.path,
                surface="computer",
            ),
        )

    browser_only = tmp_path / "browser-only.sova"
    build_capsule(
        browser_only,
        capsule_manifest_template(
            title="Browser-only finding",
            summary="A browser-only surface selection fixture.",
            author="SOVA tests",
        ),
        traces=[trace],
        attachments={
            "visual-replay-01.webm": browser_media,
            "replay-cues.json": canonical_json_bytes(browser_cues),
        },
    )
    with pytest.raises(FormatError, match="does not identify exactly one"):
        render_capsule_timeline(
            browser_only,
            tmp_path / "missing-computer-surface.html",
            selection=CapsuleReplaySelection(surface="computer"),
        )


@pytest.mark.parametrize("data", [b"", b"not-a-zip", cast("bytes", bytearray(b"x"))])
def test_window_frame_review_rejects_empty_invalid_and_non_bytes(data: bytes) -> None:
    with pytest.raises(FormatError):
        review_window_frame_recording(data)


def test_window_frame_review_rejects_missing_duplicate_and_unsafe_members(
    tmp_path: Path,
) -> None:
    session = _recording(tmp_path / "base", event=_event())
    raw = session.archive_path.read_bytes()

    with pytest.raises(FormatError, match="duplicate entries or no manifest"):
        review_window_frame_recording(_rewrite_recording(raw, omit={"recording.json"}))

    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("recording.json", b"{}")
        with pytest.warns(UserWarning):
            archive.writestr("recording.json", b"{}")
    with pytest.raises(FormatError, match="duplicate entries or no manifest"):
        review_window_frame_recording(duplicate.getvalue())

    with pytest.raises(FormatError, match="unsafe or oversized member"):
        review_window_frame_recording(_rewrite_recording(raw, extras={"../escape": b"x"}))


def test_window_frame_review_rejects_manifest_index_integrity_and_duration_drift(
    tmp_path: Path,
) -> None:
    session = _recording(tmp_path / "base", event=_event())
    raw = session.archive_path.read_bytes()

    def remove_manifest_field(manifest: dict[str, object]) -> None:
        manifest.pop("capture")

    def invalidate_capture(manifest: dict[str, object]) -> None:
        capture = cast("dict[str, object]", manifest["capture"])
        capture["pidRedacted"] = False

    def disorder_frame(manifest: dict[str, object]) -> None:
        frames = cast("list[dict[str, object]]", manifest["frames"])
        frames[1]["offsetNanoseconds"] = -1

    def invalidate_digest(manifest: dict[str, object]) -> None:
        frames = cast("list[dict[str, object]]", manifest["frames"])
        frames[0]["digest"] = "sha256:" + "0" * 64

    def invalidate_duration(manifest: dict[str, object]) -> None:
        manifest["durationSeconds"] = "999.000000"

    cases = (
        (remove_manifest_field, "manifest shape"),
        (invalidate_capture, "manifest values"),
        (disorder_frame, "index is malformed"),
        (invalidate_digest, "digest does not match"),
        (invalidate_duration, "duration differs"),
    )
    for mutation, message in cases:
        with pytest.raises(FormatError, match=message):
            review_window_frame_recording(_rewrite_recording(raw, mutate_manifest=mutation))


def test_window_frame_review_rejects_bmp_metadata_dimension_and_member_drift(
    tmp_path: Path,
) -> None:
    session = _recording(tmp_path / "base", event=_event())
    raw = session.archive_path.read_bytes()

    def replace_frame(manifest: dict[str, object], frame: bytes, index: int = 0) -> bytes:
        frames = cast("list[dict[str, object]]", manifest["frames"])
        frames[index]["digest"] = sha256_digest(frame)
        return _rewrite_recording(
            raw,
            mutate_manifest=lambda target: target.update(manifest),
            replace_members={cast("str", frames[index]["path"]): frame},
        )

    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        manifest = strict_json_loads(archive.read("recording.json"))
    assert isinstance(manifest, dict)

    malformed = b"BM" + b"\x00" * 10
    with pytest.raises(FormatError, match="malformed BMP"):
        review_window_frame_recording(replace_frame(manifest, malformed))

    invalid_metadata = bytearray(_bmp())
    invalid_metadata[28:30] = (24).to_bytes(2, "little")
    invalid_metadata[2:6] = len(invalid_metadata).to_bytes(4, "little")
    with pytest.raises(FormatError, match="metadata is invalid"):
        review_window_frame_recording(replace_frame(manifest, bytes(invalid_metadata)))

    second_manifest = strict_json_loads(
        zipfile.ZipFile(io.BytesIO(raw), "r").read("recording.json")
    )
    assert isinstance(second_manifest, dict)
    with pytest.raises(FormatError, match="dimensions changed"):
        review_window_frame_recording(replace_frame(second_manifest, _bmp(3, 2), 1))

    with pytest.raises(FormatError, match="members differ"):
        review_window_frame_recording(_rewrite_recording(raw, extras={"extra.bin": b"x"}))


def test_window_recording_contract_properties_observation_and_duplicate_close(
    tmp_path: Path,
) -> None:
    attestation = _FakeAttestation()
    with pytest.raises(FormatError, match="exact attested window"):
        WindowFrameRecordingSession(
            cast("SoftwareTargetAttestation", attestation),
            tmp_path,
            phase="invalid",
        )
    session = WindowFrameRecordingSession(
        cast("SoftwareTargetAttestation", attestation),
        tmp_path,
        phase="primary",
        interval_seconds=5.0,
        capture=lambda _window_id: _bmp(),
    )
    with pytest.raises(FormatError, match="not finalized"):
        _ = session.archive_path
    session.observe("reproduction", _event())
    session.observe("primary", {"kind": 1})
    event = _event("fallback-clock")
    event["monotonicNs"] = True
    session.observe("primary", event)
    session.close()
    session.close()
    assert session.archive_path.is_file()


def test_window_recording_capture_start_sampler_and_cleanup_fail_closed(
    tmp_path: Path,
) -> None:
    attestation = cast("SoftwareTargetAttestation", _FakeAttestation())

    def fail_capture(_window_id: int) -> bytes:
        raise FormatError("SOVA-WINDOW-RECORDING-CAPTURE", "fixture failure")

    with pytest.raises(FormatError, match="fixture failure"):
        WindowFrameRecordingSession(
            attestation,
            tmp_path / "start",
            phase="primary",
            capture=fail_capture,
        )
    assert not list((tmp_path / "start").glob("*.partial"))

    calls = 0

    def fail_after_start(_window_id: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise FormatError("SOVA-WINDOW-RECORDING-CAPTURE", "periodic failure")
        return _bmp()

    session = WindowFrameRecordingSession(
        attestation,
        tmp_path / "sample",
        phase="primary",
        interval_seconds=0.1,
        capture=fail_after_start,
    )
    deadline = time.monotonic() + 2
    while session._failure is None and time.monotonic() < deadline:
        time.sleep(0.02)
    with pytest.raises(FormatError, match="periodic failure"):
        session.close()
    with pytest.raises(FormatError, match="periodic failure"):
        session.close()


def test_window_recording_duration_and_coordinator_phase_guards(tmp_path: Path) -> None:
    attestation = cast("SoftwareTargetAttestation", _FakeAttestation())
    session = WindowFrameRecordingSession(
        attestation,
        tmp_path / "duration",
        phase="primary",
        interval_seconds=5.0,
        capture=lambda _window_id: _bmp(),
    )
    session._started_ns = 0
    session._capture_frame("too-late")
    session.close()

    with pytest.raises(FormatError, match="outside the admitted range"):
        SoftwareWindowRecordingCoordinator(tmp_path, interval_seconds=True)
    coordinator = SoftwareWindowRecordingCoordinator(tmp_path / "coordinator", interval_seconds=5.0)
    primary = coordinator.start("primary", attestation, capture=lambda _window_id: _bmp())
    with pytest.raises(FormatError, match="cannot start twice"):
        coordinator.start("primary", attestation, capture=lambda _window_id: _bmp())
    coordinator.observe("unknown", _event())
    primary.close()


def test_capture_attested_window_requires_exact_window() -> None:
    attestation = _FakeAttestation(window_id=0)
    attestation.window_id = None  # type: ignore[assignment]
    with pytest.raises(FormatError, match="requires an attested"):
        window_recording.capture_attested_window_bmp(cast("SoftwareTargetAttestation", attestation))


class _PlatformOs:
    """Present one platform name to a single module; the os module stays untouched."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> object:
        return getattr(os, attribute)


class _Win32Call:
    """Stand-in for a ctypes foreign function that accepts argtypes/restype."""

    def __init__(self, behaviour: Callable[..., object]) -> None:
        self.behaviour = behaviour
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *args: object) -> object:
        self.calls.append(args)
        return self.behaviour(*args)


def _gdi_capture(  # noqa: PLR0913 - each Win32 result is an independent fixture knob
    monkeypatch: pytest.MonkeyPatch,
    *,
    live: bool = True,
    measured: bool = True,
    size: tuple[int, int] = (4, 3),
    window_dc: int = 501,
    memory_dc: int = 601,
    printed: bool = True,
    blitted: bool = False,
    lines: int | None = None,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    width, height = size

    def rectangle(_window: object, value: Any) -> int:
        value._obj.left, value._obj.top = 10, 20
        value._obj.right, value._obj.bottom = 10 + width, 20 + height
        return int(measured)

    user32 = SimpleNamespace(
        IsWindow=_Win32Call(lambda _window: int(live)),
        GetWindowRect=_Win32Call(rectangle),
        GetWindowDC=_Win32Call(lambda _window: window_dc),
        ReleaseDC=_Win32Call(lambda *_args: 1),
        PrintWindow=_Win32Call(lambda *_args: int(printed)),
    )
    gdi32 = SimpleNamespace(
        CreateCompatibleDC=_Win32Call(lambda _dc: memory_dc),
        CreateCompatibleBitmap=_Win32Call(lambda *_args: 701),
        SelectObject=_Win32Call(lambda *_args: 801),
        BitBlt=_Win32Call(lambda *_args: int(blitted)),
        GetDIBits=_Win32Call(lambda *_args: height if lines is None else lines),
        DeleteObject=_Win32Call(lambda _handle: 1),
        DeleteDC=_Win32Call(lambda _handle: 1),
    )
    libraries = {"user32": user32, "gdi32": gdi32}
    monkeypatch.setattr(window_recording, "os", _PlatformOs("nt"))
    # ctypes.WinDLL exists only on Windows; the GDI binding is driven through fakes.
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False)
    return user32, gdi32


def test_window_capture_binding_produces_a_bounded_bmp_and_releases_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user32, gdi32 = _gdi_capture(monkeypatch)
    attestation = _FakeAttestation(window_id=77)
    frame = window_recording.capture_attested_window_bmp(
        cast("SoftwareTargetAttestation", attestation)
    )
    assert attestation.checks == 1
    assert window_recording._validated_bmp(frame) == (4, 3)
    assert gdi32.BitBlt.calls == []
    assert gdi32.SelectObject.calls[-1] == (601, 801)
    assert gdi32.DeleteObject.calls == [(701,)]
    assert gdi32.DeleteDC.calls == [(601,)]
    assert user32.ReleaseDC.calls == [(77, 501)]

    _user32, fallback = _gdi_capture(monkeypatch, printed=False, blitted=True)
    assert window_recording._validated_bmp(window_recording._capture_window_bmp(77)) == (4, 3)
    assert len(fallback.BitBlt.calls) == 1


@pytest.mark.parametrize(
    ("knobs", "message"),
    [
        ({"live": False}, "no longer live"),
        ({"measured": False}, "bounds could not be measured"),
        ({"size": (0, 3)}, "bounded capture dimensions"),
        ({"size": (9000, 1)}, "bounded capture dimensions"),
        ({"window_dc": 0}, "device context is unavailable"),
        ({"memory_dc": 0}, "capture surface could not be created"),
        ({"printed": False}, "refused bounded visual capture"),
        ({"lines": 1}, "could not be materialized"),
    ],
)
def test_window_capture_binding_fails_closed(
    monkeypatch: pytest.MonkeyPatch, knobs: dict[str, Any], message: str
) -> None:
    user32, gdi32 = _gdi_capture(monkeypatch, **knobs)
    with pytest.raises(FormatError, match=message):
        window_recording._capture_window_bmp(77)
    if user32.GetWindowDC.calls and knobs.get("window_dc") != 0:
        # Every handle acquired before the failure is released.
        assert user32.ReleaseDC.calls == [(77, knobs.get("window_dc", 501))]
        assert gdi32.DeleteObject.calls == [(701,)]


def test_window_capture_binding_enforces_frame_budget_and_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _gdi_capture(monkeypatch)
    monkeypatch.setattr(window_recording, "_MAX_FRAME_BYTES", 8)
    with pytest.raises(FormatError, match="bounded evidence budget"):
        window_recording._capture_window_bmp(77)
    monkeypatch.setattr(window_recording, "os", _PlatformOs("posix"))
    with pytest.raises(FormatError, match="available only on Windows"):
        window_recording._capture_window_bmp(77)
