"""Session manager — tracks all connected agents."""

import logging
import time
import threading
import uuid

log = logging.getLogger("phantom.c2.session")


class Session:
    """Represents a connected agent session."""

    def __init__(self, session_id: str, agent_id: str, addr: tuple,
                 info: dict, sock=None):
        self.session_id = session_id
        self.agent_id = agent_id
        self.addr = addr
        self.info = info
        self.socket = sock
        self.registered_at = time.time()
        self.last_beacon = time.time()
        self.alive = True
        self.task_queue: list[dict] = []
        self.responses: list[dict] = []

    @property
    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "addr": f"{self.addr[0]}:{self.addr[1]}",
            "hostname": self.info.get("hostname", "?"),
            "username": self.info.get("username", "?"),
            "os": self.info.get("os", "?"),
            "agent_type": self.info.get("agent_type", "?"),
            "integrity": self.info.get("integrity", "?"),
            "alive": self.alive,
            "last_beacon": int(time.time() - self.last_beacon),
            "pending_tasks": len(self.task_queue),
        }


class SessionManager:
    """Manages all agent sessions."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._active_session: str | None = None

    def register(self, session_id: str, agent_id: str, addr: tuple,
                 info: dict, socket=None):
        with self._lock:
            session = Session(session_id, agent_id, addr, info, socket)
            self._sessions[session_id] = session
            log.info(f"[+] Session created: {session_id} ({info.get('hostname', '?')}@{addr[0]})")

    def update_beacon(self, session_id: str, payload: dict):
        with self._lock:
            if session_id in self._sessions:
                s = self._sessions[session_id]
                s.last_beacon = time.time()
                s.info.update({k: v for k, v in payload.items() if v is not None})

    def get_pending_task(self, session_id: str) -> dict | None:
        with self._lock:
            if session_id in self._sessions:
                q = self._sessions[session_id].task_queue
                if q:
                    return q.pop(0)
        return None

    def queue_task(self, session_id: str, command: str, args: dict | None = None,
                   raw: str | None = None, timeout: int = 30) -> str | None:
        with self._lock:
            if session_id not in self._sessions:
                return None
            task_id = f"task-{uuid.uuid4().hex[:8]}"
            task = {
                "message_id": str(uuid.uuid4()),
                "timestamp": int(time.time()),
                "sequence": 0,
                "session_id": session_id,
                "type": "task",
                "payload": {
                    "task_id": task_id,
                    "command": command,
                    "args": args or {},
                    "timeout": timeout,
                },
            }
            if raw:
                task["payload"]["raw"] = raw
            self._sessions[session_id].task_queue.append(task)
            return task_id

    def store_response(self, session_id: str, payload: dict):
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].responses.append(payload)
                task_id = payload.get("task_id", "?")
                status = payload.get("status", "?")
                log.info(f"[*] Response from {session_id}: task={task_id} status={status}")

    def get_responses(self, session_id: str) -> list[dict]:
        with self._lock:
            if session_id in self._sessions:
                responses = list(self._sessions[session_id].responses)
                self._sessions[session_id].responses.clear()
                return responses
        return []

    def mark_dead(self, session_id: str):
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].alive = False
                log.warning(f"[-] Session dead: {session_id}")

    def list_sessions(self) -> list[dict]:
        with self._lock:
            return [s.summary for s in self._sessions.values()]

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def set_active(self, session_id: str) -> bool:
        if session_id in self._sessions:
            self._active_session = session_id
            return True
        return False

    @property
    def active(self) -> str | None:
        return self._active_session

    @property
    def count(self) -> int:
        return len(self._sessions)

    @property
    def alive_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.alive)
