# SPDX-License-Identifier: Apache-2.0
"""Bounded, HWND-attested visual frame recording for local software targets.

The recorder intentionally captures only the exact top-level window attested by
``SoftwareTargetAttestation``.  It never enumerates or records the ambient
desktop.  Frames and their same-host monotonic offsets are written incrementally
to a bounded archive, then bound to decisive trace events by a replay-cue index.
"""

from __future__ import annotations

import ctypes
import os
import struct
import tempfile
import threading
import time
import zipfile
import zlib
from collections.abc import Callable, Mapping
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.runtime.software_target import SoftwareTargetAttestation

_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
_MAX_FRAME_BYTES = 64 * 1024 * 1024
_MAX_FRAMES = 256
_MAX_DURATION_SECONDS = 300.0
_MIN_INTERVAL_SECONDS = 0.1
_MAX_INTERVAL_SECONDS = 5.0
_MAX_DIMENSION = 8192
_MAX_PIXELS = 16_777_216
_BMP_FILE_HEADER_BYTES = 14
_BMP_INFO_HEADER_BYTES = 40
_BMP_BITS_PER_PIXEL = 32
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_FRAME_PREFIX = "frames/"
_MANIFEST_NAME = "recording.json"


def _decimal_seconds(nanoseconds: int) -> str:
    value = max(0, nanoseconds)
    whole, remainder = divmod(value, 1_000_000_000)
    return f"{whole}.{remainder // 1_000:06d}"


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, _ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    info.create_system = 3
    return info


def _capture_window_bmp(window_id: int) -> bytes:  # noqa: PLR0912, PLR0915
    """Capture one exact HWND into a top-down 32-bit BMP using Windows GDI."""
    if os.name != "nt":
        raise FormatError(
            "SOVA-WINDOW-RECORDING-PLATFORM",
            "attested window recording is currently available only on Windows",
        )
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    user32.IsWindow.argtypes = (wintypes.HWND,)
    user32.IsWindow.restype = wintypes.BOOL
    user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.GetWindowDC.argtypes = (wintypes.HWND,)
    user32.GetWindowDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = (wintypes.HWND, wintypes.HDC)
    user32.ReleaseDC.restype = ctypes.c_int
    user32.PrintWindow.argtypes = (wintypes.HWND, wintypes.HDC, wintypes.UINT)
    user32.PrintWindow.restype = wintypes.BOOL
    gdi32.CreateCompatibleDC.argtypes = (wintypes.HDC,)
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleBitmap.argtypes = (wintypes.HDC, ctypes.c_int, ctypes.c_int)
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = (wintypes.HDC, wintypes.HGDIOBJ)
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.BitBlt.argtypes = (
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
    )
    gdi32.BitBlt.restype = wintypes.BOOL
    gdi32.GetDIBits.argtypes = (
        wintypes.HDC,
        wintypes.HBITMAP,
        wintypes.UINT,
        wintypes.UINT,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.UINT,
    )
    gdi32.GetDIBits.restype = ctypes.c_int
    gdi32.DeleteObject.argtypes = (wintypes.HGDIOBJ,)
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.DeleteDC.argtypes = (wintypes.HDC,)
    gdi32.DeleteDC.restype = wintypes.BOOL

    if not user32.IsWindow(window_id):
        raise FormatError(
            "SOVA-WINDOW-RECORDING-STALE",
            "the attested software window is no longer live",
        )
    rectangle = wintypes.RECT()
    if not user32.GetWindowRect(window_id, ctypes.byref(rectangle)):
        raise FormatError(
            "SOVA-WINDOW-RECORDING-CAPTURE",
            "the attested software window bounds could not be measured",
        )
    width = int(rectangle.right - rectangle.left)
    height = int(rectangle.bottom - rectangle.top)
    if (
        width <= 0
        or height <= 0
        or width > _MAX_DIMENSION
        or height > _MAX_DIMENSION
        or width * height > _MAX_PIXELS
    ):
        raise FormatError(
            "SOVA-WINDOW-RECORDING-LIMIT",
            "the attested software window exceeds the bounded capture dimensions",
        )
    window_dc = user32.GetWindowDC(window_id)
    if not window_dc:
        raise FormatError(
            "SOVA-WINDOW-RECORDING-CAPTURE",
            "the attested software window device context is unavailable",
        )
    memory_dc = wintypes.HDC()
    bitmap = wintypes.HBITMAP()
    previous = wintypes.HGDIOBJ()
    try:
        memory_dc = gdi32.CreateCompatibleDC(window_dc)
        bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height)
        if not memory_dc or not bitmap:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-CAPTURE",
                "a bounded window capture surface could not be created",
            )
        previous = gdi32.SelectObject(memory_dc, bitmap)
        # PW_RENDERFULLCONTENT asks modern windows to render their complete
        # target-owned surface. BitBlt is a conservative fallback for windows
        # that do not implement PrintWindow.
        captured = bool(user32.PrintWindow(window_id, memory_dc, 0x2))
        if not captured:
            captured = bool(
                gdi32.BitBlt(memory_dc, 0, 0, width, height, window_dc, 0, 0, 0x00CC0020)
            )
        if not captured:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-CAPTURE",
                "the attested software window refused bounded visual capture",
            )
        pixel_bytes = width * height * 4
        if pixel_bytes <= 0 or pixel_bytes > _MAX_FRAME_BYTES:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-LIMIT",
                "one software frame exceeds the bounded evidence budget",
            )
        pixels = ctypes.create_string_buffer(pixel_bytes)
        # BITMAPINFOHEADER, negative height means top-down BGRA pixels.
        info = struct.pack(
            "<IiiHHIIiiII",
            _BMP_INFO_HEADER_BYTES,
            width,
            -height,
            1,
            _BMP_BITS_PER_PIXEL,
            0,
            pixel_bytes,
            0,
            0,
            0,
            0,
        )
        info_buffer = ctypes.create_string_buffer(info)
        lines = gdi32.GetDIBits(
            memory_dc,
            bitmap,
            0,
            height,
            pixels,
            info_buffer,
            0,
        )
        if lines != height:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-CAPTURE",
                "the attested software window frame could not be materialized",
            )
        offset = _BMP_FILE_HEADER_BYTES + _BMP_INFO_HEADER_BYTES
        file_header = struct.pack("<2sIHHI", b"BM", offset + pixel_bytes, 0, 0, offset)
        return file_header + info + pixels.raw
    finally:
        if memory_dc and previous:
            gdi32.SelectObject(memory_dc, previous)
        if bitmap:
            gdi32.DeleteObject(bitmap)
        if memory_dc:
            gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(window_id, window_dc)


def _validated_bmp(data: bytes) -> tuple[int, int]:
    if len(data) < _BMP_FILE_HEADER_BYTES + _BMP_INFO_HEADER_BYTES or data[:2] != b"BM":
        raise FormatError(
            "SOVA-WINDOW-RECORDING-FRAME",
            "window recording contains a malformed BMP frame",
        )
    declared_size = int.from_bytes(data[2:6], "little")
    info_size = int.from_bytes(data[14:18], "little")
    width = int.from_bytes(data[18:22], "little", signed=True)
    height = abs(int.from_bytes(data[22:26], "little", signed=True))
    planes = int.from_bytes(data[26:28], "little")
    depth = int.from_bytes(data[28:30], "little")
    if (
        declared_size != len(data)
        or info_size != _BMP_INFO_HEADER_BYTES
        or width <= 0
        or height <= 0
        or width > _MAX_DIMENSION
        or height > _MAX_DIMENSION
        or width * height > _MAX_PIXELS
        or planes != 1
        or depth != _BMP_BITS_PER_PIXEL
    ):
        raise FormatError(
            "SOVA-WINDOW-RECORDING-FRAME",
            "window recording BMP frame metadata is invalid",
        )
    return width, height


def _read_archive_member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        return archive.read(name)
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as error:
        raise FormatError(
            "SOVA-WINDOW-RECORDING-ARCHIVE",
            "window frame recording contains a corrupt compressed member",
        ) from error


@dataclass(frozen=True, slots=True)
class ReviewedWindowFrameRecording:
    """Fully validated visual frame archive ready for inert replay."""

    digest: str
    duration_seconds: str
    width: int
    height: int
    frames: tuple[dict[str, Any], ...]


def capture_attested_window_bmp(attestation: SoftwareTargetAttestation) -> bytes:
    """Capture only one still-live, OS-attested target-owned window."""
    if attestation.window_id is None or attestation.window_handle_digest is None:
        raise FormatError(
            "SOVA-WINDOW-RECORDING-CONTRACT",
            "window capture requires an attested target-owned window",
        )
    attestation.assert_still_live()
    return _capture_window_bmp(attestation.window_id)


def review_window_frame_recording(  # noqa: PLR0912, PLR0915
    data: bytes,
) -> ReviewedWindowFrameRecording:
    """Fail-closed validation for an untrusted ``.sovaframes`` archive."""
    if not isinstance(data, bytes) or not 0 < len(data) <= _MAX_ARCHIVE_BYTES:
        raise FormatError(
            "SOVA-WINDOW-RECORDING-LIMIT",
            "window frame recording is empty or exceeds 128 MiB",
        )
    with tempfile.TemporaryFile() as stream:
        stream.write(data)
        stream.seek(0)
        try:
            archive = zipfile.ZipFile(stream, "r")
        except (OSError, zipfile.BadZipFile) as error:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-ARCHIVE",
                "window frame recording is not a valid bounded archive",
            ) from error
        with archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)) or _MANIFEST_NAME not in names:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-ARCHIVE",
                    "window frame recording has duplicate entries or no manifest",
                )
            if any(
                item.is_dir()
                or item.filename.startswith(("/", "\\"))
                or ".." in Path(item.filename).parts
                or item.file_size <= 0
                or item.file_size > _MAX_FRAME_BYTES
                for item in infos
            ):
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-ARCHIVE",
                    "window frame recording contains an unsafe or oversized member",
                )
            total = sum(item.file_size for item in infos)
            if total > _MAX_ARCHIVE_BYTES:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-LIMIT",
                    "window frame recording expands beyond the evidence budget",
                )
            manifest_raw = _read_archive_member(archive, _MANIFEST_NAME)
            manifest = strict_json_loads(manifest_raw, max_bytes=256 * 1024)
            if not isinstance(manifest, dict) or set(manifest) != {
                "artifactType",
                "schemaVersion",
                "capture",
                "durationSeconds",
                "frames",
            }:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-MANIFEST",
                    "window frame recording manifest shape is invalid",
                )
            capture = manifest.get("capture")
            frames = manifest.get("frames")
            if (
                manifest.get("artifactType") != "sova.window-frame-recording"
                or manifest.get("schemaVersion") != "0.1.0"
                or not isinstance(capture, dict)
                or set(capture)
                != {
                    "method",
                    "processStartDigest",
                    "windowHandleDigest",
                    "pidRedacted",
                }
                or capture.get("method") != "windows-gdi-exact-attested-hwnd/0.1"
                or capture.get("pidRedacted") is not True
                or not isinstance(capture.get("processStartDigest"), str)
                or not isinstance(capture.get("windowHandleDigest"), str)
                or not isinstance(frames, list)
                or not 1 <= len(frames) <= _MAX_FRAMES
                or not isinstance(manifest.get("durationSeconds"), str)
            ):
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-MANIFEST",
                    "window frame recording manifest values are invalid",
                )
            expected_members = {_MANIFEST_NAME}
            reviewed: list[dict[str, Any]] = []
            dimensions: tuple[int, int] | None = None
            previous_offset = -1
            for index, frame in enumerate(frames, 1):
                expected_path = f"{_FRAME_PREFIX}{index:04d}.bmp"
                if (
                    not isinstance(frame, dict)
                    or set(frame) != {"path", "digest", "offsetNanoseconds", "reason"}
                    or frame.get("path") != expected_path
                    or not isinstance(frame.get("digest"), str)
                    or isinstance(frame.get("offsetNanoseconds"), bool)
                    or not isinstance(frame.get("offsetNanoseconds"), int)
                    or frame["offsetNanoseconds"] < previous_offset
                    or not isinstance(frame.get("reason"), str)
                    or not frame["reason"]
                ):
                    raise FormatError(
                        "SOVA-WINDOW-RECORDING-MANIFEST",
                        "window frame recording index is malformed or unordered",
                    )
                frame_data = _read_archive_member(archive, expected_path)
                if sha256_digest(frame_data) != frame["digest"]:
                    raise FormatError(
                        "SOVA-WINDOW-RECORDING-INTEGRITY",
                        "window frame digest does not match the recording manifest",
                    )
                observed_dimensions = _validated_bmp(frame_data)
                if dimensions is None:
                    dimensions = observed_dimensions
                elif observed_dimensions != dimensions:
                    raise FormatError(
                        "SOVA-WINDOW-RECORDING-DIMENSIONS",
                        "window dimensions changed during one bounded recording",
                    )
                previous_offset = frame["offsetNanoseconds"]
                expected_members.add(expected_path)
                reviewed.append(
                    {
                        "offsetSeconds": _decimal_seconds(frame["offsetNanoseconds"]),
                        "digest": frame["digest"],
                        "reason": frame["reason"],
                        "data": frame_data,
                    }
                )
            if set(names) != expected_members or dimensions is None:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-ARCHIVE",
                    "window frame recording members differ from its manifest",
                )
            declared_duration = manifest["durationSeconds"]
            actual_duration = _decimal_seconds(previous_offset)
            if declared_duration != actual_duration:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-MANIFEST",
                    "window frame recording duration differs from its final frame",
                )
    return ReviewedWindowFrameRecording(
        sha256_digest(data),
        actual_duration,
        dimensions[0],
        dimensions[1],
        tuple(reviewed),
    )


class WindowFrameRecordingSession:
    """Incremental exact-window recorder with bounded periodic/event frames."""

    def __init__(
        self,
        attestation: SoftwareTargetAttestation,
        destination: Path,
        *,
        phase: str,
        interval_seconds: float = 0.5,
        capture: Callable[[int], bytes] = _capture_window_bmp,
    ) -> None:
        if (
            phase not in {"primary", "reproduction"}
            or attestation.window_id is None
            or attestation.window_handle_digest is None
            or isinstance(interval_seconds, bool)
            or not _MIN_INTERVAL_SECONDS <= interval_seconds <= _MAX_INTERVAL_SECONDS
            or not callable(capture)
        ):
            raise FormatError(
                "SOVA-WINDOW-RECORDING-CONTRACT",
                "window recording requires an exact attested window and bounded interval",
            )
        attestation.assert_still_live()
        destination.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink() or not destination.resolve().is_dir():
            raise FormatError(
                "SOVA-WINDOW-RECORDING-PATH",
                "window recording destination must be a real directory",
            )
        self._attestation = attestation
        self._phase = phase
        self._capture = capture
        self._interval_seconds = float(interval_seconds)
        self._started_ns = time.monotonic_ns()
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._frames: list[dict[str, Any]] = []
        self._cues: list[dict[str, Any]] = []
        self._closed = False
        self._failure: FormatError | None = None
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{phase}-window-",
            suffix=".sovaframes.partial",
            dir=destination.resolve(),
        )
        os.close(descriptor)
        self._partial = Path(raw_path)
        self._archive_path = destination.resolve() / f"{phase}-visual-replay.sovaframes"
        self._cue_path = destination.resolve() / f"{phase}-window-replay-cues.json"
        self._archive = zipfile.ZipFile(
            self._partial,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
            allowZip64=False,
        )
        try:
            self._capture_frame("recording-start")
        except BaseException:
            self._archive.close()
            self._partial.unlink(missing_ok=True)
            raise
        self._thread = threading.Thread(
            target=self._sample,
            name=f"sova-window-recorder-{phase}",
            daemon=True,
        )
        self._thread.start()

    @property
    def archive_path(self) -> Path:
        if not self._closed or self._failure is not None:
            raise FormatError(
                "SOVA-WINDOW-RECORDING-INCOMPLETE",
                "window frame recording has not finalized successfully",
            )
        return self._archive_path

    @property
    def cue_path(self) -> Path:
        if not self._closed or self._failure is not None or not self._cue_path.is_file():
            raise FormatError(
                "SOVA-WINDOW-RECORDING-INCOMPLETE",
                "window replay cues did not finalize for a decisive passing event",
            )
        return self._cue_path

    def _capture_frame(self, reason: str) -> None:
        with self._lock:
            if self._closed or self._failure is not None or len(self._frames) >= _MAX_FRAMES:
                return
            offset = time.monotonic_ns() - self._started_ns
            if offset > int(_MAX_DURATION_SECONDS * 1_000_000_000):
                return
            self._attestation.assert_still_live()
            data = self._capture(self._attestation.window_id or 0)
            _validated_bmp(data)
            path = f"{_FRAME_PREFIX}{len(self._frames) + 1:04d}.bmp"
            self._archive.writestr(_zip_info(path), data)
            self._frames.append(
                {
                    "path": path,
                    "digest": sha256_digest(data),
                    "offsetNanoseconds": offset,
                    "reason": reason,
                }
            )
            if self._partial.stat().st_size > _MAX_ARCHIVE_BYTES:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-LIMIT",
                    "window recording exceeded the 128 MiB archive budget",
                )

    def _sample(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                self._capture_frame("periodic")
            except FormatError as error:
                with self._lock:
                    self._failure = error
                self._stop.set()
                return

    def observe(self, channel: str, event: Mapping[str, Any]) -> None:
        """Capture action/oracle boundaries and index every persisted pass event."""
        if channel != self._phase or not isinstance(event, Mapping):
            return
        kind = event.get("kind")
        if not isinstance(kind, str):
            return
        payload = event.get("payload")
        decisive = (
            kind == "oracle.completed"
            and isinstance(payload, Mapping)
            and payload.get("status") == "pass"
        )
        if decisive or kind.startswith(("action.", "effect.", "verification.")):
            self._capture_frame("decisive-oracle" if decisive else kind)
        if not decisive:
            return
        event_time = event.get("monotonicNs")
        if isinstance(event_time, bool) or not isinstance(event_time, int):
            event_time = time.monotonic_ns()
        cue_offset = max(0, event_time - self._started_ns)
        capture_offset = self._frames[-1]["offsetNanoseconds"]
        self._cues.append(
            {
                "id": f"decisive-{len(self._cues) + 1:02d}",
                "label": "Exploit confirmed",
                "channel": channel,
                "eventId": event.get("id"),
                "eventKind": "oracle.completed",
                "eventSequence": event.get("sequence"),
                "oracleStatus": "pass",
                "offsetSeconds": _decimal_seconds(cue_offset),
                "chapterOffsetSeconds": _decimal_seconds(capture_offset),
                "preRollSeconds": "2.000000",
                "postRollSeconds": "3.000000",
            }
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                if self._failure is not None:
                    raise self._failure
                return
        self._stop.set()
        self._thread.join(timeout=max(2.0, self._interval_seconds * 3))
        failure: FormatError | None = None
        try:
            if self._thread.is_alive():
                raise FormatError(  # noqa: TRY301 - cleanup is reported transactionally
                    "SOVA-WINDOW-RECORDING-CLEANUP",
                    "window recording sampler did not stop within its bounded deadline",
                )
            if self._failure is not None:
                raise self._failure
            self._capture_frame("recording-stop")
            # Preserve a strictly later finalized duration even when the OS and
            # trace event are observed within the same microsecond bucket.
            time.sleep(0.02)
            self._capture_frame("recording-final-bound")
            manifest = {
                "artifactType": "sova.window-frame-recording",
                "schemaVersion": "0.1.0",
                "capture": {
                    "method": "windows-gdi-exact-attested-hwnd/0.1",
                    "processStartDigest": self._attestation.process_start_digest,
                    "windowHandleDigest": self._attestation.window_handle_digest,
                    "pidRedacted": True,
                },
                "durationSeconds": _decimal_seconds(self._frames[-1]["offsetNanoseconds"]),
                "frames": list(self._frames),
            }
            self._archive.writestr(_zip_info(_MANIFEST_NAME), canonical_json_bytes(manifest))
            self._archive.close()
            if self._partial.stat().st_size > _MAX_ARCHIVE_BYTES:
                raise FormatError(  # noqa: TRY301 - cleanup is reported transactionally
                    "SOVA-WINDOW-RECORDING-LIMIT",
                    "finalized window recording exceeds 128 MiB",
                )
            raw = self._partial.read_bytes()
            reviewed = review_window_frame_recording(raw)
            self._archive_path.write_bytes(raw)
            if self._cues:
                cue_document = {
                    "artifactType": "sova.replay-cues",
                    "schemaVersion": "0.1.0",
                    "surface": "computer",
                    "mediaName": self._archive_path.name,
                    "mediaDigest": reviewed.digest,
                    "synchronization": {
                        "method": "same-host-monotonic-window-frame-capture-bound",
                        "uncertaintyMs": f"{self._interval_seconds * 1000:.3f}",
                        "frameTimestampAttested": False,
                        "statement": (
                            "Trace cues and frame offsets share the SOVA host monotonic "
                            "clock. Every frame is bound to the exact OS-attested HWND and "
                            "archive digest; frame timestamps are not independently "
                            "cryptographically attested."
                        ),
                    },
                    "cues": list(self._cues),
                }
                self._cue_path.write_bytes(canonical_json_bytes(cue_document) + b"\n")
        except FormatError as error:
            failure = error
        finally:
            with self._lock:
                self._closed = True
                if failure is not None:
                    self._failure = failure
            with suppress(Exception):
                self._archive.close()
            self._partial.unlink(missing_ok=True)
            if failure is not None:
                self._archive_path.unlink(missing_ok=True)
                self._cue_path.unlink(missing_ok=True)
        if failure is not None:
            raise failure


class SoftwareWindowRecordingCoordinator:
    """Own phase recorders and expose capsule-ready evidence bytes."""

    def __init__(self, destination: Path, *, interval_seconds: float = 0.5) -> None:
        if (
            isinstance(interval_seconds, bool)
            or not _MIN_INTERVAL_SECONDS <= interval_seconds <= _MAX_INTERVAL_SECONDS
        ):
            raise FormatError(
                "SOVA-WINDOW-RECORDING-CONTRACT",
                "software recording interval is outside the admitted range",
            )
        self._destination = destination
        self._interval_seconds = float(interval_seconds)
        self._sessions: dict[str, WindowFrameRecordingSession] = {}
        self._lock = threading.RLock()

    def start(
        self,
        phase: str,
        attestation: SoftwareTargetAttestation,
        *,
        capture: Callable[[int], bytes] = _capture_window_bmp,
    ) -> WindowFrameRecordingSession:
        with self._lock:
            if phase in self._sessions:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-PHASE",
                    "one software recording phase cannot start twice",
                )
            session = WindowFrameRecordingSession(
                attestation,
                self._destination,
                phase=phase,
                interval_seconds=self._interval_seconds,
                capture=capture,
            )
            self._sessions[phase] = session
            return session

    def observe(self, channel: str, event: Mapping[str, Any]) -> None:
        with self._lock:
            session = self._sessions.get(channel)
        if session is not None:
            session.observe(channel, event)

    def attachments(self) -> dict[str, bytes]:
        with self._lock:
            missing = sorted({"primary", "reproduction"} - set(self._sessions))
            if missing:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-MISSING",
                    "passing software finding lacks both phase recordings",
                    details={"phases": missing},
                )
            sessions = dict(self._sessions)
        attachments: dict[str, bytes] = {}
        for phase in ("primary", "reproduction"):
            session = sessions[phase]
            media_name = (
                "visual-replay-01.sovaframes"
                if phase == "primary"
                else "reproduction-visual-replay-01.sovaframes"
            )
            cues_name = (
                "replay-cues.json" if phase == "primary" else "reproduction-replay-cues.json"
            )
            attachments[media_name] = session.archive_path.read_bytes()
            attachments[cues_name] = session.cue_path.read_bytes()
        return attachments

    def artifact_paths(self) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
        """Return finalized primary/reproduction media and cue paths in phase order."""
        with self._lock:
            missing = sorted({"primary", "reproduction"} - set(self._sessions))
            if missing:
                raise FormatError(
                    "SOVA-WINDOW-RECORDING-MISSING",
                    "passing software finding lacks both phase recordings",
                    details={"phases": missing},
                )
            sessions = dict(self._sessions)
        return (
            tuple(sessions[phase].archive_path for phase in ("primary", "reproduction")),
            tuple(sessions[phase].cue_path for phase in ("primary", "reproduction")),
        )


__all__ = [
    "ReviewedWindowFrameRecording",
    "SoftwareWindowRecordingCoordinator",
    "WindowFrameRecordingSession",
    "capture_attested_window_bmp",
    "review_window_frame_recording",
]
