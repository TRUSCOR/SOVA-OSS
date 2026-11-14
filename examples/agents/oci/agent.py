#!/usr/bin/env python3
"""Dependency-free conforming SOVA OCI agent example."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

PROTOCOL = "sova.oci-agent/0.1"
AGENT_ID = "example-contained-agent"


def response_for(prompt: str) -> dict[str, Any]:
    try:
        request = json.loads(prompt)
    except json.JSONDecodeError:
        request = {}
    contract = request.get("contract") if isinstance(request, dict) else None
    if contract == "sova.semantic-browser-planner/0.1.0":
        return {
            "status": "blocked",
            "actions": [],
            "coverage": ["conforming example"],
            "reason": "The example adapter intentionally proposes no target action.",
        }
    if contract == "sova.agent-arena-challenger/0.1.0":
        return {"message": "contained example challenge"}
    if contract == "sova.agent-arena-defender/0.1.0":
        return {"message": "contained example defense", "signals": []}
    if contract == "sova.agent-arena-advisory-judge/0.1.0":
        return {
            "assessment": "not-observed",
            "limitations": ["deterministic contained example"],
        }
    return {"status": "blocked"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sova-request-stdin", action="store_true", required=True)
    args = parser.parse_args()
    if not args.sova_request_stdin:
        return 2
    request = json.loads(sys.stdin.read())
    operation = request.get("operation")
    runtime_digest = request.get("runtimeDigest")
    payload = request.get("payload")
    if request.get("protocol") != PROTOCOL or not isinstance(payload, dict):
        return 2
    if operation == "describe":
        value: dict[str, Any] = {
            "agentId": AGENT_ID,
            "operations": ["describe", "self-test", "respond"],
            "capabilities": ["arena-message", "semantic-action-planner"],
        }
    elif operation == "self-test":
        value = {"status": "pass"}
    elif operation == "respond" and isinstance(payload.get("prompt"), str):
        value = {
            "responseText": "contained example response",
            "structured": response_for(payload["prompt"]),
            "tokenCount": None,
        }
    else:
        return 2
    sys.stdout.write(
        json.dumps(
            {
                "protocol": PROTOCOL,
                "runtimeDigest": runtime_digest,
                "operation": operation,
                "accepted": True,
                "response": value,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
