# SPDX-License-Identifier: Apache-2.0
"""Bounded Model Context Protocol client contracts and stdio transport."""

from __future__ import annotations

import os
import queue
import re
import subprocess
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, Self

from sova import __version__
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_PROTOCOL_VERSION = "2025-11-25"
_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_MAX_STDERR_BYTES = 128 * 1024
_MIN_MESSAGE_BYTES = 1024
_MAX_CONFIGURED_MESSAGE_BYTES = 64 * 1024 * 1024
_MAX_STARTUP_SECONDS = 120
_MAX_DEFERRED_RESPONSES = 128
_SENSITIVE_ENV = re.compile(
    r"(?:token|secret|password|credential|cookie|authorization|api[_-]?key)",
    re.IGNORECASE,
)
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
_BACKEND_ENV_KEYS = _SAFE_ENV_KEYS | {
    "ANONYMIZED_TELEMETRY",
    "CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS",
    "CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS",
    "CI",
    "CUA_DRIVER_DISABLE_UNRESTRICTED",
    "CUA_DRIVER_PERMISSION_MODE",
    "CUA_DRIVER_RS_HOME",
    "CUA_DRIVER_RS_PERMISSIONS_GATE",
    "CUA_DRIVER_RS_TELEMETRY_ENABLED",
    "CUA_DRIVER_SESSION_POLICY_APPROVED",
    "CUA_DRIVER_SESSION_POLICY_FILE",
    "CUA_DRIVER_TELEMETRY_HOME",
    "MELRA_BROWSER",
    "MELRA_BROWSER_PROFILE",
    "MELRA_HOME",
    "MELRA_POLICY",
    "MELRA_WORKSPACE",
    "PLAYWRIGHT_BROWSERS_PATH",
    "UV_CACHE_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "UV_TOOL_DIR",
}


@dataclass(frozen=True, slots=True)
class MCPTool:
    """One server-advertised tool definition; annotations remain untrusted hints."""

    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]


@dataclass(frozen=True, slots=True)
class MCPToolResult:
    """Raw protocol result prior to SOVA evidence normalization."""

    content: tuple[dict[str, Any], ...]
    structured_content: dict[str, Any] | None
    is_error: bool


class MCPClient(Protocol):
    """Small adapter-facing MCP client surface."""

    @property
    def server_name(self) -> str: ...

    def list_tools(self) -> tuple[MCPTool, ...]: ...

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class StdioServerSpec:
    """Exact local MCP server process receipt and launch limits."""

    name: str
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    version: str
    source: str
    license: str
    package_digest: str | None = None
    startup_timeout_seconds: float = 20.0
    max_message_bytes: int = _MAX_MESSAGE_BYTES

    def __post_init__(self) -> None:
        if not self.name or not self.argv or not self.cwd.resolve().is_dir():
            raise FormatError("SOVA-MCP-SPEC", "invalid MCP stdio server specification")
        if not 0 < self.startup_timeout_seconds <= _MAX_STARTUP_SECONDS:
            raise FormatError("SOVA-MCP-SPEC", "invalid MCP startup timeout")
        if not _MIN_MESSAGE_BYTES <= self.max_message_bytes <= _MAX_CONFIGURED_MESSAGE_BYTES:
            raise FormatError("SOVA-MCP-SPEC", "invalid MCP message budget")
        sensitive = sorted(key for key in self.environment if _SENSITIVE_ENV.search(key))
        if sensitive:
            raise FormatError(
                "SOVA-MCP-ENV",
                "stdio server environment must not carry secret-shaped variables",
            )
        unsupported = sorted(set(self.environment) - _BACKEND_ENV_KEYS)
        if unsupported:
            raise FormatError(
                "SOVA-MCP-ENV",
                "stdio server environment contains a non-allowlisted variable",
            )


class StdioMCPClient:
    """Synchronous newline-delimited JSON-RPC MCP client with bounded I/O."""

    def __init__(self, spec: StdioServerSpec) -> None:
        self.spec = spec
        environment = {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}
        environment.update(dict(spec.environment))
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0
        try:
            self._process = subprocess.Popen(  # noqa: S603 - argv only; shell is false
                list(spec.argv),
                cwd=spec.cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
            )
        except OSError as error:
            raise FormatError("SOVA-MCP-START", "MCP server process could not start") from error
        self._responses: queue.Queue[dict[str, Any] | BaseException] = queue.Queue()
        self._stderr = bytearray()
        self._closed = False
        self._request_id = 0
        self._write_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        self._stderr_reader.start()
        try:
            self._initialize()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def server_name(self) -> str:
        return self.spec.name

    @property
    def process_id(self) -> int:
        """Return the local child PID for lifecycle verification only."""
        return self._process.pid

    def _read_stdout(self) -> None:
        stream = self._process.stdout
        if stream is None:
            self._responses.put(FormatError("SOVA-MCP-PIPE", "missing MCP stdout pipe"))
            return
        try:
            while line := stream.readline(self.spec.max_message_bytes + 1):
                if len(line) > self.spec.max_message_bytes:
                    raise FormatError(  # noqa: TRY301 - normalized by transport thread
                        "SOVA-MCP-MESSAGE-LIMIT", "MCP response exceeds byte budget"
                    )
                value = strict_json_loads(line, max_bytes=self.spec.max_message_bytes)
                if not isinstance(value, dict):
                    raise FormatError(  # noqa: TRY301 - normalized by transport thread
                        "SOVA-MCP-MESSAGE-TYPE", "MCP message must be an object"
                    )
                if "id" in value:
                    self._responses.put(value)
        except BaseException as error:  # noqa: BLE001 - transport thread reports all failures
            self._responses.put(error)

    def _read_stderr(self) -> None:
        stream = self._process.stderr
        if stream is None:
            return
        while len(self._stderr) < _MAX_STDERR_BYTES:
            data = stream.read(min(4096, _MAX_STDERR_BYTES - len(self._stderr)))
            if not data:
                return
            self._stderr.extend(data)

    def _send(self, message: dict[str, Any]) -> None:
        stream = self._process.stdin
        if stream is None or self._closed:
            raise FormatError("SOVA-MCP-CLOSED", "MCP client is closed")
        payload = canonical_json_bytes(message) + b"\n"
        if len(payload) > self.spec.max_message_bytes:
            raise FormatError("SOVA-MCP-MESSAGE-LIMIT", "MCP request exceeds byte budget")
        with self._write_lock:
            try:
                stream.write(payload)
                stream.flush()
            except OSError as error:
                raise FormatError("SOVA-MCP-WRITE", "MCP request pipe failed") from error

    def _request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        self._request_id += 1
        request_id = self._request_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        deferred: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout_seconds
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FormatError("SOVA-MCP-TIMEOUT", f"MCP {method} timed out")
                try:
                    item = self._responses.get(timeout=remaining)
                except queue.Empty as error:
                    raise FormatError("SOVA-MCP-TIMEOUT", f"MCP {method} timed out") from error
                if isinstance(item, BaseException):
                    if isinstance(item, FormatError):
                        raise item
                    raise FormatError("SOVA-MCP-READ", "MCP response pipe failed") from item
                if item.get("id") != request_id:
                    deferred.append(item)
                    if len(deferred) > _MAX_DEFERRED_RESPONSES:
                        raise FormatError(
                            "SOVA-MCP-RESPONSE-LIMIT",
                            "too many unrelated MCP responses were received",
                        )
                    continue
                if "error" in item:
                    error_value = item["error"]
                    code = error_value.get("code") if isinstance(error_value, dict) else None
                    raise FormatError(
                        "SOVA-MCP-REMOTE-ERROR",
                        "MCP server returned a JSON-RPC error",
                        details={"remoteCode": code},
                    )
                result = item.get("result")
                if not isinstance(result, dict):
                    raise FormatError("SOVA-MCP-RESULT", "MCP result must be an object")
                return result
        finally:
            for item in deferred:
                self._responses.put(item)

    def _initialize(self) -> None:
        result = self._request(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "sova-oss", "version": __version__},
            },
            timeout_seconds=self.spec.startup_timeout_seconds,
        )
        protocol = result.get("protocolVersion")
        if not isinstance(protocol, str):
            raise FormatError("SOVA-MCP-INITIALIZE", "server omitted protocol version")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def list_tools(self) -> tuple[MCPTool, ...]:
        tools: list[MCPTool] = []
        cursor: str | None = None
        while True:
            params = {} if cursor is None else {"cursor": cursor}
            result = self._request("tools/list", params, timeout_seconds=20)
            raw_tools = result.get("tools")
            if not isinstance(raw_tools, list):
                raise FormatError("SOVA-MCP-TOOLS", "tools/list omitted its tool array")
            for raw in raw_tools:
                if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                    raise FormatError("SOVA-MCP-TOOL-SCHEMA", "invalid tool definition")
                input_schema = raw.get("inputSchema")
                if not isinstance(input_schema, dict):
                    raise FormatError("SOVA-MCP-TOOL-SCHEMA", "tool inputSchema is invalid")
                output_schema = raw.get("outputSchema")
                annotations = raw.get("annotations")
                tools.append(
                    MCPTool(
                        raw["name"],
                        str(raw.get("description", "")),
                        input_schema,
                        output_schema if isinstance(output_schema, dict) else None,
                        annotations if isinstance(annotations, dict) else {},
                    )
                )
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return tuple(tools)
            if not isinstance(next_cursor, str) or not next_cursor:
                raise FormatError("SOVA-MCP-PAGINATION", "invalid tools/list cursor")
            cursor = next_cursor

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        result = self._request(
            "tools/call",
            {"name": name, "arguments": dict(arguments)},
            timeout_seconds=timeout_seconds,
        )
        content = result.get("content", [])
        if not isinstance(content, list) or not all(isinstance(item, dict) for item in content):
            raise FormatError("SOVA-MCP-TOOL-RESULT", "tool content is invalid")
        structured = result.get("structuredContent")
        if structured is not None and not isinstance(structured, dict):
            raise FormatError("SOVA-MCP-TOOL-RESULT", "structuredContent is invalid")
        return MCPToolResult(tuple(content), structured, bool(result.get("isError", False)))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process.stdin is not None:
            with suppress(OSError):
                self._process.stdin.close()
        if self._process.poll() is None:
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # The server may exit between poll/wait and the signal on
                # Windows.  Treat that access/process-lookup race as benign,
                # then verify termination with another bounded wait.
                with suppress(OSError):
                    self._process.terminate()
                try:
                    self._process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with suppress(OSError):
                        self._process.kill()
                    with suppress(subprocess.TimeoutExpired):
                        self._process.wait(timeout=2)
        for stream in (self._process.stdout, self._process.stderr):
            if stream is not None:
                with suppress(OSError):
                    stream.close()
        self._reader.join(timeout=2)
        self._stderr_reader.join(timeout=2)
        reader_alive = getattr(self._reader, "is_alive", None)
        stderr_alive = getattr(self._stderr_reader, "is_alive", None)
        if (
            self._process.poll() is None
            or (callable(reader_alive) and reader_alive())
            or (callable(stderr_alive) and stderr_alive())
        ):
            raise FormatError(
                "SOVA-MCP-CLEANUP",
                "MCP server process or transport readers did not terminate "
                "within the cleanup bound",
            )


__all__ = [
    "MCPClient",
    "MCPTool",
    "MCPToolResult",
    "StdioMCPClient",
    "StdioServerSpec",
]
