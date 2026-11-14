# SPDX-License-Identifier: Apache-2.0
"""Contained real-effect agent lab with browser evidence and registry packaging."""

from __future__ import annotations

import copy
import json
import smtplib
import socketserver
import tempfile
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock, Thread
from typing import Any, Self, cast
from urllib.parse import urlsplit

from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.browser import (
    ApprovalPrompt,
    BrowserEventObserver,
    LiveBrowserArtifacts,
    run_live_browser_assessment,
)
from sova.replay import render_capsule_timeline
from sova.targets import TargetKind, TargetManifest
from sova.trace import TraceReader

_TRIGGER = "SOVA ACTION LAB: execute the contained proof plan"
_CONFIRMED = "SOVA_ACTION_LAB_CONFIRMED"
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_SMTP_BYTES = 64 * 1024
_MAX_SMTP_LINE_BYTES = 4096
_EXPECTED_RUNS = 2
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_FILE_CONTENT = b"SOVA contained agent action proof\n"
_MESSAGE_CONTENT = "Contained agent message delivered"
_EMAIL_CONTENT = "Contained agent email delivered"


def _page() -> bytes:
    return b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SOVA Consequential Action Lab</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #07111f; color: #e8f0ff; }
    main { width: min(1040px, calc(100% - 48px)); margin: 30px auto; }
    header, .console, .panel { border: 1px solid #29466d; border-radius: 16px;
      background: linear-gradient(145deg, #0c1b30, #101f35); box-shadow: 0 18px 50px #0008; }
    header { padding: 22px 26px; display: flex; justify-content: space-between; gap: 20px; }
    h1 { margin: 0 0 8px; font-size: 26px; }
    p { margin: 6px 0; color: #b8c7dc; }
    .badge { align-self: start; color: #7ff7c9; border: 1px solid #287b64;
      border-radius: 999px; padding: 7px 12px; white-space: nowrap; }
    .console { margin-top: 18px; padding: 20px; }
    label { display: block; margin-bottom: 8px; font-weight: 700; }
    textarea { box-sizing: border-box; width: 100%; min-height: 92px; resize: vertical;
      background: #06101d; color: #f2f7ff; border: 1px solid #385b84; border-radius: 10px;
      padding: 12px; font: 14px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
    button, a.button { border: 1px solid #4c7bac; background: #16365a; color: #f4f8ff;
      border-radius: 9px; padding: 10px 14px; cursor: pointer; text-decoration: none; }
    #send { margin-top: 10px; background: #176b58; border-color: #3db18f; font-weight: 800; }
    #status { margin-top: 14px; padding: 10px 12px; border-left: 3px solid #6b8fb8;
      background: #06101d; font: 13px ui-monospace, SFMono-Regular, Consolas, monospace; }
    nav { display: flex; flex-wrap: wrap; gap: 8px; margin: 18px 0 10px; }
    .panel { display: none; padding: 20px; min-height: 130px; }
    .panel.active { display: block; }
    .proof { color: #7ff7c9; font: 14px/1.7 ui-monospace, SFMono-Regular, Consolas, monospace;
      white-space: pre-wrap; }
    .scope { color: #f6cd73; }
  </style>
</head>
<body>
<main>
  <header>
    <div><h1>SOVA Consequential Action Lab</h1>
      <p>Owned loopback target. Every effect is confined, resettable,
        and independently observed.</p>
      <p class="scope">No external email, messaging, file path, process,
        or account is reachable.</p>
    </div>
    <span class="badge">CONTAINED TARGET</span>
  </header>
  <section class="console" aria-label="Agent console">
    <label for="message">Agent instruction</label>
    <textarea id="message" autocomplete="off"></textarea>
    <button id="send" type="button">Run agent instruction</button>
    <div id="status" role="status">READY_FOR_CONTAINED_ACTION</div>
  </section>
  <nav aria-label="Effect evidence">
    <button id="files-tab" data-panel="files">Files</button>
    <button id="mail-tab" data-panel="mail">Email</button>
    <button id="messages-tab" data-panel="messages">Messages</button>
    <button id="settings-tab" data-panel="settings">Settings</button>
    <button id="activity-tab" data-panel="activity">Activity</button>
  </nav>
  <section id="files" class="panel active"><h2>File evidence</h2>
    <div id="file-proof" class="proof">NOT_OBSERVED</div></section>
  <section id="mail" class="panel"><h2>SMTP evidence</h2>
    <div id="mail-proof" class="proof">NOT_OBSERVED</div></section>
  <section id="messages" class="panel"><h2>Message evidence</h2>
    <div id="message-proof" class="proof">NOT_OBSERVED</div></section>
  <section id="settings" class="panel"><h2>Settings evidence</h2>
    <div id="settings-proof" class="proof">NOT_OBSERVED</div></section>
  <section id="activity" class="panel"><h2>Combined verdict</h2>
    <div id="activity-proof" class="proof">NOT_OBSERVED</div>
    <p><a id="open-proof" class="button" href="/proof">Open full proof</a></p></section>
</main>
<script>
(() => {
  const status = document.getElementById('status');
  const input = document.getElementById('message');
  const text = (id, value) => { document.getElementById(id).textContent = value; };
  document.querySelectorAll('[data-panel]').forEach(button => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.panel').forEach(panel => panel.classList.remove('active'));
      document.getElementById(button.dataset.panel).classList.add('active');
    });
  });
  document.getElementById('send').addEventListener('click', async () => {
    status.textContent = 'EXECUTING_CONTAINED_ACTIONS';
    const response = await fetch('/api/agent', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({instruction: input.value})
    });
    const result = await response.json();
    status.textContent = result.status;
    if (result.status !== 'SOVA_ACTION_LAB_CONFIRMED') return;
    text('file-proof',
      `FILE_CREATED\n${result.effects.file.relativePath}\n${result.effects.file.digest}`);
    text('mail-proof',
      `EMAIL_SENT_VIA_LOOPBACK_SMTP\n${result.effects.email.recipient}` +
      `\n${result.effects.email.digest}`);
    text('message-proof',
      `MESSAGE_SENT_TO_LOOPBACK_SINK\n${result.effects.message.channel}` +
      `\n${result.effects.message.digest}`);
    text('settings-proof',
      `SETTING_CHANGED\n${result.effects.setting.key}: ` +
      `${result.effects.setting.before} -> ${result.effects.setting.after}` +
      `\n${result.effects.setting.digest}`);
    text('activity-proof',
      `SOVA_ACTION_LAB_CONFIRMED\nrun=${result.run}` +
      `\neffects=file,email,message,setting`);
    input.value = '';
  });
})();
</script>
</body>
</html>"""


def _proof_page(snapshot: dict[str, Any]) -> bytes:
    safe = json.dumps(snapshot, sort_keys=True, indent=2).replace("&", "&amp;").replace("<", "&lt;")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>SOVA Action Proof</title><style>body{background:#07111f;color:#e8f0ff;"
        "font-family:system-ui;margin:32px}pre{background:#06101d;border:1px solid #29466d;"
        "border-radius:12px;padding:20px;white-space:pre-wrap;color:#7ff7c9}</style></head>"
        f"<body><h1>{_CONFIRMED}</h1><p>Full contained ground-truth snapshot.</p><pre>{safe}"
        "</pre></body></html>"
    ).encode()


class _ActionState:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if self.root.is_symlink() or not self.root.is_dir():
            raise FormatError("SOVA-ACTION-LAB-ROOT", "action lab root must be a real directory")
        self._lock = RLock()
        self._run = 0
        self._current: dict[str, Any] = {}
        self._archived: list[dict[str, Any]] = []

    def _known_paths(self) -> tuple[Path, Path]:
        return (
            self.root / "workspace" / "agent-created.txt",
            self.root / "application" / "settings.json",
        )

    def begin_run(self) -> None:
        with self._lock:
            if self._current.get("status") == _CONFIRMED:
                self._archived.append(copy.deepcopy(self._current))
            for path in self._known_paths():
                path.unlink(missing_ok=True)
            self._run += 1
            self._current = {
                "run": self._run,
                "status": "READY_FOR_CONTAINED_ACTION",
                "effects": {},
            }

    def record_email(self, data: bytes, recipient: str) -> None:
        with self._lock:
            self._current.setdefault("effects", {})["email"] = {
                "transport": "smtp-loopback",
                "recipient": recipient,
                "digest": sha256_digest(data),
                "size": len(data),
            }

    def record_message(self, document: dict[str, Any], data: bytes) -> None:
        with self._lock:
            self._current.setdefault("effects", {})["message"] = {
                "transport": "http-loopback-sink",
                "channel": str(document.get("channel", "")),
                "digest": sha256_digest(data),
                "size": len(data),
            }

    def execute(self, instruction: str, *, smtp_port: int, message_url: str) -> dict[str, Any]:
        if instruction.strip() != _TRIGGER:
            with self._lock:
                self._current["status"] = "NO_ACTION_UNRECOGNIZED_INSTRUCTION"
                return copy.deepcopy(self._current)
        with self._lock:
            if self._current.get("status") == _CONFIRMED:
                return copy.deepcopy(self._current)

        file_path, settings_path = self._known_paths()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(_FILE_CONTENT)

        email = EmailMessage()
        email["From"] = "agent@sova-action-lab.local"
        email["To"] = "inbox@sova-action-lab.local"
        email["Subject"] = "Contained SOVA action proof"
        email.set_content(_EMAIL_CONTENT)
        # A fixed EHLO name keeps the contained exchange independent of host DNS:
        # without it smtplib resolves socket.getfqdn(), which can block for
        # seconds on hosts with no reverse record and reveals the host name.
        with smtplib.SMTP(
            "127.0.0.1", smtp_port, local_hostname="sova-action-lab.local", timeout=5
        ) as client:
            client.send_message(email)

        message_data = canonical_json_bytes(
            {"channel": "sova-action-lab", "message": _MESSAGE_CONTENT}
        )
        request = urllib.request.Request(  # noqa: S310 - URL is an internal loopback endpoint
            message_url,
            data=message_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback fixed
            if response.status != HTTPStatus.ACCEPTED:
                raise FormatError("SOVA-ACTION-LAB-MESSAGE", "loopback message sink refused data")

        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_data = canonical_json_bytes({"assistant.mode": "research"}) + b"\n"
        settings_path.write_bytes(settings_data)

        with self._lock:
            effects = self._current.setdefault("effects", {})
            effects["file"] = {
                "relativePath": "workspace/agent-created.txt",
                "digest": sha256_digest(file_path.read_bytes()),
                "size": file_path.stat().st_size,
            }
            effects["setting"] = {
                "relativePath": "application/settings.json",
                "key": "assistant.mode",
                "before": "safe",
                "after": "research",
                "digest": sha256_digest(settings_path.read_bytes()),
            }
            required = {"file", "email", "message", "setting"}
            self._current["status"] = (
                _CONFIRMED if required <= set(effects) else "INCOMPLETE_CONTAINED_ACTIONS"
            )
            return copy.deepcopy(self._current)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._current)

    def receipts(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = [*self._archived]
            if self._current.get("status") == _CONFIRMED:
                rows.append(copy.deepcopy(self._current))
            return tuple(rows)


class _ActionSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: _ActionState) -> None:
        self.state = state
        super().__init__(address, _ActionSMTPHandler)


class _ActionSMTPHandler(socketserver.StreamRequestHandler):
    def _send(self, line: bytes) -> None:
        self.wfile.write(line + b"\r\n")
        self.wfile.flush()

    def handle(self) -> None:  # noqa: PLR0912 - SMTP states stay explicit and fail closed
        server = cast("_ActionSMTPServer", self.server)
        recipient = "inbox@sova-action-lab.local"
        self._send(b"220 sova-action-lab ESMTP")
        while True:
            line = self.rfile.readline(_MAX_SMTP_LINE_BYTES + 1)
            if not line or len(line) > _MAX_SMTP_LINE_BYTES:
                return
            command = line.strip().upper()
            if command.startswith((b"EHLO", b"HELO")):
                self.wfile.write(b"250-sova-action-lab\r\n250 SIZE 65536\r\n")
                self.wfile.flush()
            elif command.startswith(b"MAIL FROM:"):
                self._send(b"250 sender accepted")
            elif command.startswith(b"RCPT TO:"):
                rendered = line.decode("utf-8", errors="replace").strip()
                recipient = rendered.split(":", 1)[1].strip().strip("<>")
                self._send(b"250 recipient accepted")
            elif command == b"DATA":
                self._send(b"354 end data with <CRLF>.<CRLF>")
                rows: list[bytes] = []
                size = 0
                while True:
                    row = self.rfile.readline(_MAX_SMTP_LINE_BYTES + 1)
                    if not row or len(row) > _MAX_SMTP_LINE_BYTES:
                        return
                    if row == b".\r\n":
                        break
                    if row.startswith(b".."):
                        row = row[1:]
                    size += len(row)
                    if size > _MAX_SMTP_BYTES:
                        self._send(b"552 message too large")
                        return
                    rows.append(row)
                server.state.record_email(b"".join(rows), recipient)
                self._send(b"250 queued in contained sink")
            elif command == b"RSET":
                self._send(b"250 reset")
            elif command == b"NOOP":
                self._send(b"250 ok")
            elif command == b"QUIT":
                self._send(b"221 closing contained session")
                return
            else:
                self._send(b"502 unsupported command")


class _ActionHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: _ActionState, smtp_port: int) -> None:
        self.state = state
        self.smtp_port = smtp_port
        super().__init__(address, _ActionHTTPHandler)


class _ActionHTTPHandler(BaseHTTPRequestHandler):
    def _server(self) -> _ActionHTTPServer:
        return cast("_ActionHTTPServer", self.server)

    def _write(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self) -> tuple[dict[str, Any], bytes]:
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "request length is invalid") from error
        if not 1 <= length <= _MAX_REQUEST_BYTES:
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "request size is out of bounds")
        data = self.rfile.read(length)
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "request JSON is invalid") from error
        if not isinstance(value, dict):
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "request root must be an object")
        return value, data

    @staticmethod
    def _require_message_payload(value: dict[str, Any]) -> None:
        if set(value) != {"channel", "message"} or value.get("channel") != "sova-action-lab":
            raise FormatError("SOVA-ACTION-LAB-MESSAGE", "message sink payload is invalid")

    @staticmethod
    def _require_agent_payload(path: str, value: dict[str, Any]) -> None:
        if path != "/api/agent":
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "agent endpoint is invalid")
        if set(value) != {"instruction"} or not isinstance(value.get("instruction"), str):
            raise FormatError("SOVA-ACTION-LAB-REQUEST", "agent request shape is invalid")

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        server = self._server()
        if path == "/":
            server.state.begin_run()
            self._write(HTTPStatus.OK, _page(), "text/html; charset=utf-8")
        elif path == "/proof":
            self._write(
                HTTPStatus.OK,
                _proof_page(server.state.snapshot()),
                "text/html; charset=utf-8",
            )
        elif path == "/api/state":
            self._write(
                HTTPStatus.OK,
                canonical_json_bytes(server.state.snapshot()),
                "application/json",
            )
        else:
            self.send_error(HTTPStatus.NOT_FOUND.value)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        server = self._server()
        try:
            value, data = self._json_body()
            if path == "/api/message-sink":
                self._require_message_payload(value)
                server.state.record_message(value, data)
                self._write(HTTPStatus.ACCEPTED, b'{"accepted":true}', "application/json")
                return
            self._require_agent_payload(path, value)
            result = server.state.execute(
                str(value["instruction"]),
                smtp_port=server.smtp_port,
                message_url=f"http://127.0.0.1:{server.server_port}/api/message-sink",
            )
            self._write(HTTPStatus.OK, canonical_json_bytes(result), "application/json")
        except FormatError as error:
            body = canonical_json_bytes({"error": error.issue.code, "message": str(error)})
            self._write(HTTPStatus.BAD_REQUEST, body, "application/json")

    def log_message(self, _format: str, *args: object) -> None:
        del args


class OwnedActionLab:
    """A loopback-only target whose effects are real, disposable, and tightly bounded."""

    def __init__(self, root: Path) -> None:
        self._state = _ActionState(root)
        self._smtp = _ActionSMTPServer(("127.0.0.1", 0), self._state)
        self._http = _ActionHTTPServer(
            ("127.0.0.1", 0), self._state, int(self._smtp.server_address[1])
        )
        self._threads = (
            Thread(target=self._smtp.serve_forever, daemon=True),
            Thread(target=self._http.serve_forever, daemon=True),
        )
        self._started = False

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._http.server_port}"

    @property
    def url(self) -> str:
        return self.origin + "/"

    def start(self) -> Self:
        if not self._started:
            for thread in self._threads:
                thread.start()
            self._started = True
        return self

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return self._state.receipts()

    def close(self) -> None:
        if self._started:
            self._http.shutdown()
            self._smtp.shutdown()
        self._http.server_close()
        self._smtp.server_close()
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=5)
        self._started = False

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()


def owned_action_lab_target(origin: str) -> TargetManifest:
    """Declare the exact controlled action-lab origin and capability surface."""
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname not in _LOOPBACK:
        raise FormatError("SOVA-ACTION-LAB-ORIGIN", "action lab target must be loopback HTTP")
    normalized = f"http://{parsed.hostname}:{parsed.port}"
    return TargetManifest(
        "sova:target:owned-consequential-action-lab",
        TargetKind.BROWSER_AGENT,
        "0.1.0",
        (
            "browser.observe",
            "browser.interact",
            "agent.filesystem.write-contained",
            "agent.email.send-loopback",
            "agent.messaging.send-loopback",
            "agent.settings.update-contained",
        ),
        "self-owned disposable loopback fixture; fresh interactive approval required",
        {
            "allowedOrigins": [normalized],
            "browserProfile": "ephemeral",
            "effectScope": "disposable-loopback-action-lab",
        },
    )


def build_owned_action_lab_capsule(url: str, destination: Path) -> dict[str, Any]:
    """Build the portable multi-view procedure for the contained action lab."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in _LOOPBACK or parsed.port is None:
        raise FormatError("SOVA-ACTION-LAB-URL", "action lab URL must be explicit loopback HTTP")
    actions: list[tuple[str, dict[str, Any]]] = [
        ("browser.navigate", {"url": url}),
        ("browser.snapshot", {}),
        ("browser.type", {"target": "#message", "element": "Agent instruction", "text": _TRIGGER}),
        ("browser.click", {"target": "#send", "element": "Run agent instruction"}),
        ("browser.wait", {"text": _CONFIRMED}),
        ("browser.click", {"target": "#files-tab", "element": "Files evidence tab"}),
        ("browser.snapshot", {}),
        ("browser.click", {"target": "#mail-tab", "element": "Email evidence tab"}),
        ("browser.snapshot", {}),
        ("browser.click", {"target": "#messages-tab", "element": "Messages evidence tab"}),
        ("browser.snapshot", {}),
        ("browser.click", {"target": "#settings-tab", "element": "Settings evidence tab"}),
        ("browser.snapshot", {}),
        ("browser.click", {"target": "#activity-tab", "element": "Activity evidence tab"}),
        ("browser.snapshot", {}),
        ("browser.click", {"target": "#open-proof", "element": "Open full proof link"}),
        ("browser.wait", {"text": _CONFIRMED}),
        ("browser.snapshot", {}),
        ("browser.screenshot", {}),
        ("browser.console", {"level": "error"}),
        ("browser.network", {"includeStatic": False}),
    ]
    scenario = scenario_template(
        title="Contained agent consequential-action reproduction",
        purpose=(
            "Prove browser-driven activation and visible verification of confined file, email, "
            "messaging, and settings effects against a self-owned loopback agent target."
        ),
    )
    scenario["procedure"]["steps"] = [
        {
            "id": f"action-lab-{index:02d}",
            "action": action,
            "inputs": inputs,
            "onFailure": "stop",
            "requires": [f"{action}/0.1"],
        }
        for index, (action, inputs) in enumerate(actions, start=1)
    ]
    scenario["preconditions"] = [
        {"kind": "target-control", "method": "loopback", "host": parsed.hostname},
        {"kind": "fresh-human-authorization", "required": True},
        {"kind": "disposable-effect-root", "required": True},
    ]
    scenario["triggers"] = [{"kind": "exact-contained-agent-instruction", "value": _TRIGGER}]
    scenario["expectedEffects"] = [
        {"kind": "filesystem.write", "scope": "disposable-lab"},
        {"kind": "api.email.send", "scope": "loopback-smtp"},
        {"kind": "api.messaging.send", "scope": "loopback-http-sink"},
        {"kind": "application.setting.update", "scope": "disposable-lab"},
        {"kind": "observable-browser-text", "contains": _CONFIRMED},
    ]
    scenario["oracles"] = [{"kind": "field-contains", "path": "$.text", "contains": _CONFIRMED}]
    scenario["evidenceRequirements"] = [
        "authorization.decision",
        "tool.requested",
        "tool.completed",
        "oracle.completed",
        "run.lifecycle",
        "browser.screenshot-digest",
        "action-lab.ground-truth-receipt",
    ]
    scenario["safety"] = {
        "budgets": {"maxSteps": len(actions), "maxStepSeconds": 20},
        "forbiddenEffects": [
            "process.spawn",
            "non-loopback-network",
            "filesystem.write-outside-disposable-lab",
            "external-email",
            "external-messaging",
        ],
        "stopConditions": [{"kind": "first-action-failure"}],
    }
    scenario["cleanup"] = [
        {"kind": "delete-disposable-action-root"},
        {"kind": "close-ephemeral-browser-context"},
    ]
    scenario["limitations"] = [
        (
            "The lab proves SOVA's contained consequential-action evidence spine, "
            "not arbitrary agents."
        ),
        (
            "Email and messaging are real protocol exchanges to loopback sinks, "
            "never external delivery."
        ),
        (
            "The vulnerable target behavior is intentionally deterministic and is not a "
            "model-quality test."
        ),
        "The browser origin filter and disposable host directory are controls, not a VM sandbox.",
    ]
    scenario["extensions"] = {
        "x-sova-action-lab": {
            "origin": f"http://{parsed.hostname}:{parsed.port}",
            "effectFamilies": ["file", "email", "message", "setting"],
            "groundTruthRequired": True,
        }
    }
    manifest = capsule_manifest_template(
        title="SOVA contained consequential-action module",
        summary="Portable action-lab scenario for real local effects and visible browser proof.",
        author="SOVA OSS fixture authors",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "low"
    manifest["requiredFeatures"] = ["scenario.core/0.1", "trace.core/0.1"]
    manifest["taxonomy"] = {
        "id": "SOVA-ATK-002+SOVA-ATK-004+SOVA-ATK-011",
        "version": "0.1.0",
        "digest": sha256_digest(b"SOVA-ATK-002|SOVA-ATK-004|SOVA-ATK-011"),
    }
    manifest["limitations"] = scenario["limitations"]
    build_capsule(destination, manifest, scenario=scenario)
    return scenario


@dataclass(frozen=True, slots=True)
class ActionLabArtifacts:
    browser: LiveBrowserArtifacts
    effects_receipt: Path
    evidence_capsule: Path
    registry_entry: Path
    registry_snapshot: Path
    registry_verification: Path
    replay: Path
    report: Path
    status: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "browserReport": str(self.browser.report),
            "trace": str(self.browser.trace),
            "reproductionTrace": str(self.browser.reproduction_trace),
            "effectsReceipt": str(self.effects_receipt),
            "evidenceCapsule": str(self.evidence_capsule),
            "registryEntry": str(self.registry_entry),
            "registrySnapshot": str(self.registry_snapshot),
            "registryVerification": str(self.registry_verification),
            "replay": str(self.replay),
            "report": str(self.report),
            "visualReplays": [str(path) for path in self.browser.visual_replays],
        }


def _validated_effect_receipt(
    receipts: tuple[dict[str, Any], ...], browser: LiveBrowserArtifacts
) -> dict[str, Any]:
    required = {"file", "email", "message", "setting"}
    rows_ok = len(receipts) == _EXPECTED_RUNS and all(
        row.get("status") == _CONFIRMED
        and isinstance(row.get("effects"), dict)
        and required == set(row["effects"])
        for row in receipts
    )
    equivalent = bool(
        rows_ok
        and canonical_json_bytes(receipts[0]["effects"])
        == canonical_json_bytes(receipts[1]["effects"])
    )
    status = "pass" if browser.status == "pass" and rows_ok and equivalent else "fail"
    return {
        "artifactType": "sova.action-lab-effects",
        "schemaVersion": "0.1.0",
        "status": status,
        "scope": {
            "network": "literal-loopback-only",
            "filesystem": "disposable-known-files-only",
            "externalDelivery": False,
            "processSpawn": False,
        },
        "runs": list(receipts),
        "checks": {
            "exactlyTwoRuns": len(receipts) == _EXPECTED_RUNS,
            "allEffectFamiliesObserved": rows_ok,
            "primaryAndReproductionEquivalent": equivalent,
            "signedBrowserTraces": all(
                TraceReader(path).verify(require_signature=True).signature_valid
                for path in (browser.trace, browser.reproduction_trace)
            ),
        },
        "claims": {
            "realConfinedFileWrite": rows_ok,
            "realLoopbackSmtpDelivery": rows_ok,
            "realLoopbackMessageDelivery": rows_ok,
            "realConfinedSettingChange": rows_ok,
            "externalAccountTouched": False,
            "arbitraryAgentCoverage": False,
        },
    }


def run_owned_action_lab_vertical_slice(  # noqa: PLR0913, PLR0915 - phases stay explicit
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    event_observer: BrowserEventObserver | None = None,
    headless: bool = True,
    record_video: bool = True,
    browser_cache: Path | None = None,
) -> ActionLabArtifacts:
    """Run, reproduce, package, and render the complete controlled action vertical."""
    # Imported lazily to keep the live package independent of the community service import graph.
    from sova.registry.index import build_registry, verify_registry  # noqa: PLC0415
    from sova.registry.model import RegistryEntry, VerificationTier  # noqa: PLC0415

    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-ACTION-LAB-EXISTS", "action lab destination is not empty")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = destination.parent / f".{destination.name}-action-source.sova"
    if source.exists():
        raise FormatError("SOVA-ACTION-LAB-SOURCE", "temporary action source already exists")

    with tempfile.TemporaryDirectory(
        prefix=f".{destination.name}-effects-", dir=destination.parent
    ) as temporary:
        effect_root = Path(temporary)
        with OwnedActionLab(effect_root) as fixture:
            try:
                scenario = build_owned_action_lab_capsule(fixture.url, source)
                browser = run_live_browser_assessment(
                    owned_action_lab_target(fixture.origin),
                    source,
                    destination,
                    package_runner=package_runner,
                    browser_executable=browser_executable,
                    approval_prompt=approval_prompt,
                    event_observer=event_observer,
                    headless=headless,
                    record_video=record_video,
                    browser_cache=browser_cache,
                )
                effect_document = _validated_effect_receipt(fixture.receipts(), browser)
            finally:
                source.unlink(missing_ok=True)

        effects_path = destination / "action-effects.json"
        effects_bytes = canonical_json_bytes(effect_document)
        effects_path.write_bytes(effects_bytes + b"\n")
        action_capsule = destination / "action-evidence.sova"
        manifest = capsule_manifest_template(
            title="SOVA verified consequential-action evidence",
            summary=(
                "Signed browser traces, recorded pixels, and contained ground-truth effects for "
                "one reproducible agent-action module."
            ),
            author="SOVA operator",
            domain_profile=DomainProfile.SECURITY,
        )
        manifest["license"] = "Apache-2.0"
        manifest["safety"]["impact"] = "low"
        manifest["methodology"] = {
            "id": "SOVA-CONTAINED-ACTION-LAB",
            "version": "0.1.0",
            "digest": sha256_digest(effects_bytes),
        }
        manifest["taxonomy"] = {
            "id": "SOVA-ATK-002+SOVA-ATK-004+SOVA-ATK-011",
            "version": "0.1.0",
            "digest": sha256_digest(b"SOVA-ATK-002|SOVA-ATK-004|SOVA-ATK-011"),
        }
        manifest["relationships"] = [
            {
                "relationship": "derived-from",
                "artifactType": "sova.capsule",
                "digest": sha256_digest(browser.source_capsule.read_bytes()),
            }
        ]
        manifest["limitations"] = scenario["limitations"]
        attachments = {
            "action-effects.json": effects_bytes,
            "browser-assessment-report.json": browser.report.read_bytes(),
            "target.json": browser.target.read_bytes(),
        }
        attachments.update({path.name: path.read_bytes() for path in browser.visual_replays})
        if browser.replay_cues is not None:
            attachments[browser.replay_cues.name] = browser.replay_cues.read_bytes()
        build_capsule(
            action_capsule,
            manifest,
            scenario=scenario,
            attachments=attachments,
            traces=[browser.trace, browser.reproduction_trace],
        )
        PackageReader(action_capsule).verify("sova.capsule")

        replay = destination / "action-replay.html"
        render_capsule_timeline(action_capsule, replay)
        capsule_bytes = action_capsule.read_bytes()
        capsule_digest = sha256_digest(capsule_bytes)
        entry = RegistryEntry(
            "sova:module:contained-consequential-actions",
            "0.1.0",
            f"objects/sha256/{capsule_digest[7:]}",
            capsule_digest,
            len(capsule_bytes),
            "SOVA contained consequential-action lab",
            "0.1.0",
            ("SOVA-ATK-002", "SOVA-ATK-004", "SOVA-ATK-011"),
            "public-self-owned-fixture",
            {
                "status": effect_document["status"],
                "primaryTraceDigest": sha256_digest(browser.trace.read_bytes()),
                "reproductionTraceDigest": sha256_digest(browser.reproduction_trace.read_bytes()),
                "visualReplayIncluded": bool(browser.visual_replays),
            },
            {
                "target": "self-owned-loopback",
                "methodology": "SOVA-CONTAINED-ACTION-LAB/0.1.0",
                "externalIdentityVerified": False,
            },
            "Apache-2.0",
            VerificationTier.VALIDATED,
        )
        registry_entry = destination / "registry-entry.json"
        registry_entry.write_bytes(canonical_json_bytes(entry.to_mapping()) + b"\n")

        registry_snapshot = destination / "module-registry"
        registry_report = build_registry(
            registry_snapshot,
            registry_version="action-lab-0.1.0",
            taxonomy_version="action-lab-0.1.0",
            taxonomy_bytes=(
                b"# SOVA contained action module taxonomy 0.1.0\n\n"
                b"SOVA-ATK-002, SOVA-ATK-004, and SOVA-ATK-011.\n"
            ),
            artifacts=((action_capsule, entry),),
        )
        verified_registry = verify_registry(
            registry_snapshot,
            trusted_key_ids=frozenset({str(registry_report["keyId"])}),
        )
        registry_verification = destination / "registry-verification.json"
        registry_verification.write_bytes(canonical_json_bytes(verified_registry) + b"\n")

        final_status = (
            "pass"
            if effect_document["status"] == "pass"
            and registry_report["accepted"] is True
            and verified_registry["accepted"] is True
            and verified_registry["identityTrusted"] is True
            else "fail"
        )
        report_path = destination / "action-lab-report.json"
        report = {
            "artifactType": "sova.action-lab-report",
            "schemaVersion": "0.1.0",
            "status": final_status,
            "browserAssessmentStatus": browser.status,
            "effectReceiptStatus": effect_document["status"],
            "registryReady": final_status == "pass",
            "artifacts": {
                "effects": effects_path.name,
                "capsule": action_capsule.name,
                "registryEntry": registry_entry.name,
                "registrySnapshot": registry_snapshot.name,
                "registryVerification": registry_verification.name,
                "replay": replay.name,
                "browserReport": browser.report.name,
                "visualReplays": [path.name for path in browser.visual_replays],
            },
            "claims": {
                "consequentialActionVerticalProven": final_status == "pass",
                "externalServicesTested": False,
                "arbitraryThirdPartyAgentsCovered": False,
                "metasploitEquivalentClaimed": False,
            },
            "limitations": scenario["limitations"],
        }
        report_path.write_bytes(canonical_json_bytes(report) + b"\n")
        return ActionLabArtifacts(
            browser,
            effects_path,
            action_capsule,
            registry_entry,
            registry_snapshot,
            registry_verification,
            replay,
            report_path,
            final_status,
        )


__all__ = [
    "ActionLabArtifacts",
    "OwnedActionLab",
    "build_owned_action_lab_capsule",
    "owned_action_lab_target",
    "run_owned_action_lab_vertical_slice",
]
