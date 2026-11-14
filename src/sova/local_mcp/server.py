# SPDX-License-Identifier: Apache-2.0
"""Bounded newline-delimited JSON-RPC server for local SOVA MCP."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, BinaryIO

from sova import __version__
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.local_mcp.model import MCP_PROTOCOL_VERSION
from sova.local_mcp.tools import (
    LOCAL_TOOL_DEFINITIONS,
    LocalToolContext,
    dispatch_local_tool,
    tool_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


def _error(request_id: Any, code: int, message: str, *, sova_code: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": {"sovaCode": sova_code}},
    }


class LocalSOVAMCPServer:
    """One local, account-free MCP server with no network listener."""

    def __init__(self, context: LocalToolContext) -> None:
        self.context = context
        self.initialized = False

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:  # noqa: PLR0911
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(request_id, -32600, "Invalid Request", sova_code="SOVA-MCP-REQUEST")
        if not isinstance(params, dict):
            return _error(request_id, -32602, "Invalid params", sova_code="SOVA-MCP-PARAMS")
        if method == "initialize":
            self.initialized = True
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "sova-oss-local", "version": __version__},
                    "instructions": (
                        "SOVA is local-first. No MCP tool can approve a gated invocation; "
                        "use the separate interactive control channel."
                    ),
                },
            }
        if method == "notifications/initialized":
            return None
        if not self.initialized:
            return _error(
                request_id,
                -32002,
                "Server not initialized",
                sova_code="SOVA-MCP-NOT-INITIALIZED",
            )
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [item.to_mcp_mapping() for item in LOCAL_TOOL_DEFINITIONS],
                    "_meta": {"sova/toolManifest": tool_manifest()},
                },
            }
        if method != "tools/call":
            return _error(request_id, -32601, "Method not found", sova_code="SOVA-MCP-METHOD")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, -32602, "Invalid params", sova_code="SOVA-MCP-TOOL")
        try:
            result = dispatch_local_tool(self.context, name, arguments)
        except FormatError as error:
            return _error(request_id, -32000, str(error), sova_code=error.issue.code)
        encoded = canonical_json_bytes(result).decode("utf-8")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": encoded}],
                "structuredContent": result,
                "isError": False,
            },
        }


def _object_message(line: bytes) -> dict[str, Any]:
    message = strict_json_loads(line, max_bytes=_MAX_MESSAGE_BYTES)
    if not isinstance(message, dict):
        raise FormatError("SOVA-MCP-REQUEST", "MCP request must be an object")
    return message


def serve_stdio(
    context: LocalToolContext,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
) -> None:
    """Serve MCP on inherited stdio; no socket or hosted control plane exists."""
    source = input_stream or sys.stdin.buffer
    sink = output_stream or sys.stdout.buffer
    server = LocalSOVAMCPServer(context)
    while line := source.readline(_MAX_MESSAGE_BYTES + 1):
        response: dict[str, Any] | None
        if len(line) > _MAX_MESSAGE_BYTES:
            response = _error(None, -32700, "Parse error", sova_code="SOVA-MCP-MESSAGE-LIMIT")
        else:
            try:
                response = server.handle(_object_message(line))
            except FormatError as error:
                response = _error(None, -32700, "Parse error", sova_code=error.issue.code)
        if response is not None:
            sink.write(canonical_json_bytes(response) + b"\n")
            sink.flush()


__all__ = ["LocalSOVAMCPServer", "serve_stdio"]
