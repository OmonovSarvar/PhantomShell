"""System reconnaissance module."""

import os
import platform
import socket
import subprocess

NAME = "recon"


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15).decode(errors="replace").strip()
    except Exception:
        return ""


def cmd_sysinfo() -> dict:
    uname = platform.uname()
    info = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "kernel": uname.release,
        "arch": platform.machine(),
        "cpu": platform.processor() or _run("lscpu | head -15"),
        "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "uid": os.getuid() if hasattr(os, "getuid") else -1,
        "gid": os.getgid() if hasattr(os, "getgid") else -1,
        "groups": _run("id"),
        "home": os.path.expanduser("~"),
        "shell": os.getenv("SHELL", "unknown"),
        "path": os.getenv("PATH", ""),
        "memory": _run("free -h 2>/dev/null || sysctl hw.memsize 2>/dev/null"),
        "disk": _run("df -h / 2>/dev/null"),
        "uptime": _run("uptime"),
        "users_logged_in": _run("who 2>/dev/null"),
        "interfaces": _run("ip -br addr 2>/dev/null || ifconfig 2>/dev/null"),
        "routes": _run("ip route 2>/dev/null || netstat -rn 2>/dev/null"),
        "dns": _run("cat /etc/resolv.conf 2>/dev/null | grep nameserver"),
        "listening_ports": _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    }
    return info


def cmd_env(filter: str = "") -> dict:
    env = dict(os.environ)
    if filter:
        env = {k: v for k, v in env.items() if filter.lower() in k.lower()}
    return {"variables": env, "count": len(env)}


def cmd_services(all: bool = False) -> dict:
    if os.path.exists("/usr/bin/systemctl"):
        flag = "--all" if all else ""
        output = _run(f"systemctl list-units --type=service {flag} --no-pager")
    else:
        output = _run("service --status-all 2>/dev/null")
    return {"services": output}


def cmd_ports(all: bool = False) -> dict:
    if all:
        output = _run("ss -antp 2>/dev/null || netstat -antp 2>/dev/null")
    else:
        output = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    return {"ports": output}


def cmd_firewall() -> dict:
    iptables = _run("iptables -L -n -v 2>/dev/null")
    nftables = _run("nft list ruleset 2>/dev/null")
    ufw = _run("ufw status verbose 2>/dev/null")
    return {"iptables": iptables, "nftables": nftables, "ufw": ufw}


def cmd_netmap() -> dict:
    return {
        "interfaces": _run("ip -br addr 2>/dev/null || ifconfig"),
        "routes": _run("ip route 2>/dev/null || netstat -rn"),
        "arp": _run("ip neigh 2>/dev/null || arp -a"),
        "dns": _run("cat /etc/resolv.conf 2>/dev/null"),
        "hosts": _run("cat /etc/hosts 2>/dev/null"),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
    }


COMMANDS = {
    "sysinfo": {"handler": cmd_sysinfo, "description": "Comprehensive system information"},
    "env": {"handler": cmd_env, "description": "Environment variables"},
    "services": {"handler": cmd_services, "description": "List running services"},
    "ports": {"handler": cmd_ports, "description": "List listening ports"},
    "firewall": {"handler": cmd_firewall, "description": "Show firewall rules"},
    "netmap": {"handler": cmd_netmap, "description": "Map network interfaces, routes, ARP, DNS"},
}
