# SPDX-License-Identifier: Apache-2.0
"""Narrow optional adapter for the official non-interactive Codex CLI."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from sova.trace import TraceWriter

_SAFE_ENV_KEYS = {
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
}
_MAX_PROMPT_BYTES = 32 * 1024
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Process result used by the real and deterministic test runners."""

    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    """Injectable subprocess boundary."""

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class CodexRunResult:
    """Visible optional-lane result."""

    status: str
    events_captured: int
    returncode: int | None
    reason: str | None = None


def _subprocess_runner(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> CommandResult:
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0  # type: ignore[attr-defined,unused-ignore]
    try:
        process = subprocess.Popen(  # noqa: S603 - shell is false and argv is fixed/typed
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            start_new_session=os.name != "nt",
        )
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        _terminate_process_tree(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        raise FormatError(
            "SOVA-CODEX-TIMEOUT",
            "optional Codex run exceeded its duration budget; bounded tree termination was applied",
        ) from error
    return CommandResult(process.returncode, stdout, stderr)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Stop the exact adapter-owned process tree after a duration-budget breach."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined,unused-ignore]
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass
        else:
            return
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        taskkill = Path(system_root) / "System32" / "taskkill.exe"
        if taskkill.is_file():
            try:
                subprocess.run(  # noqa: S603 - executable and PID are adapter-controlled
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
        else:
            process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined,unused-ignore]
    except (OSError, ProcessLookupError):
        process.kill()


class CodexExecAdapter:
    """Capture observable official Codex JSONL without handling auth material."""

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: CommandRunner = _subprocess_runner,
        timeout_seconds: int = 120,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> None:
        self.executable = executable or shutil.which("codex")
        self.runner = runner
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    @staticmethod
    def _environment() -> dict[str, str]:
        """Pass operating context but never provider/API key environment values."""
        return {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}

    def preflight(self, fixture_directory: Path) -> CodexRunResult:
        """Use only the official login-status command; never read auth files."""
        if self.executable is None:
            return CodexRunResult("unavailable", 0, None, "codex executable not found")
        self._validate_fixture_directory(fixture_directory)
        try:
            result = self.runner(
                [self.executable, "login", "status"],
                cwd=fixture_directory,
                environment=self._environment(),
                timeout_seconds=10,
            )
        except (FormatError, OSError) as error:
            return CodexRunResult("unavailable", 0, None, str(error))
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace")[:500]
            return CodexRunResult("unavailable", 0, result.returncode, message)
        return CodexRunResult("authenticated", 0, result.returncode)

    def capture(
        self,
        *,
        prompt: str,
        fixture_directory: Path,
        output_schema: Path,
        trace_writer: TraceWriter,
    ) -> CodexRunResult:
        """Run one bounded read-only ephemeral turn and map JSONL to trace events."""
        self._validate_fixture_directory(fixture_directory)
        self._validate_child(output_schema, fixture_directory)
        if len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES:
            raise FormatError("SOVA-CODEX-PROMPT-LIMIT", "prompt exceeds the adapter budget")
        preflight = self.preflight(fixture_directory)
        if preflight.status != "authenticated":
            return preflight
        executable = self.executable
        if executable is None:
            return CodexRunResult("unavailable", 0, None, "codex executable not found")
        command = [
            executable,
            "exec",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--json",
            "--ignore-user-config",
            "--ignore-rules",
            "--output-schema",
            str(output_schema),
            prompt,
        ]
        result = self.runner(
            command,
            cwd=fixture_directory,
            environment=self._environment(),
            timeout_seconds=self.timeout_seconds,
        )
        if len(result.stdout) > self.max_output_bytes:
            raise FormatError(
                "SOVA-CODEX-OUTPUT-LIMIT",
                "Codex JSONL output exceeds the adapter byte budget",
            )
        captured = 0
        parent: str | None = None
        for line in result.stdout.splitlines():
            item = strict_json_loads(line, max_bytes=self.max_output_bytes)
            if not isinstance(item, dict):
                raise FormatError("SOVA-CODEX-JSONL-TYPE", "Codex JSONL item must be an object")
            kind, payload = _map_codex_event(item)
            event_id = trace_writer.append(
                kind,
                payload,
                phase="codex-exec",
                actor={"id": "external:openai:codex", "kind": "agent", "name": "Codex"},
                target={
                    "id": "sova:target:codex-fixture",
                    "kind": "fixture",
                    "name": fixture_directory.name,
                },
                parents=[parent] if parent else [],
            )
            if event_id is not None:
                parent = event_id
                captured += 1
        if result.returncode != 0:
            trace_writer.append(
                "error.adapter",
                {
                    "adapter": "codex-exec",
                    "returncode": result.returncode,
                    "stderr": result.stderr.decode("utf-8", errors="replace")[:2000],
                },
                phase="codex-exec",
                parents=[parent] if parent else [],
            )
            return CodexRunResult(
                "failed",
                captured,
                result.returncode,
                "Codex exited non-zero; rate or plan limits remain an optional-lane result.",
            )
        return CodexRunResult("completed", captured, result.returncode)

    @staticmethod
    def _validate_fixture_directory(path: Path) -> None:
        resolved = path.resolve()
        if not resolved.is_dir() or not (resolved / ".sova-codex-fixture").is_file():
            raise FormatError(
                "SOVA-CODEX-UNSAFE-FIXTURE",
                "Codex runs require an isolated directory with a .sova-codex-fixture marker",
            )
        forbidden_everywhere = {".git", ".codex", "confidential"}
        if any(part.casefold() in forbidden_everywhere for part in resolved.parts):
            raise FormatError(
                "SOVA-CODEX-UNSAFE-FIXTURE",
                "fixture path crosses a forbidden project or confidential boundary",
            )
        repository_root = next(
            (
                candidate
                for candidate in (resolved, *resolved.parents)
                if (candidate / ".git").exists()
            ),
            None,
        )
        if repository_root is not None:
            relative_parts = {
                part.casefold() for part in resolved.relative_to(repository_root).parts
            }
            if "private" in relative_parts:
                raise FormatError(
                    "SOVA-CODEX-UNSAFE-FIXTURE",
                    "fixture path crosses a forbidden project or confidential boundary",
                )

    @staticmethod
    def _validate_child(path: Path, parent: Path) -> None:
        resolved = path.resolve()
        try:
            resolved.relative_to(parent.resolve())
        except ValueError as error:
            raise FormatError(
                "SOVA-CODEX-SCHEMA-PATH",
                "structured-output schema must be inside the isolated fixture directory",
            ) from error
        if not resolved.is_file():
            raise FormatError(
                "SOVA-CODEX-SCHEMA-PATH",
                "structured-output schema does not exist",
            )


def _map_codex_event(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    event_type = str(item.get("type", "unknown"))
    if event_type == "thread.started":
        return "run.external-started", item
    if event_type == "turn.started":
        return "phase.started", item
    if event_type == "turn.completed":
        return "run.external-completed", item
    if event_type in {"turn.failed", "error"}:
        return "error.external", item
    if event_type.startswith("item."):
        inner = item.get("item")
        item_type = inner.get("type") if isinstance(inner, dict) else "unknown"
        mapping = {
            "agent_message": "model.response",
            "reasoning": "model.reasoning-summary",
            "command_execution": "tool.command",
            "file_change": "filesystem.change",
            "mcp_tool_call": "mcp.tool-call",
            "web_search": "retrieval.web-search",
            "plan_update": "actor.plan-update",
        }
        return mapping.get(str(item_type), "x.codex.item"), item
    return "x.codex.event", item


__all__ = ["CodexExecAdapter", "CodexRunResult"]
