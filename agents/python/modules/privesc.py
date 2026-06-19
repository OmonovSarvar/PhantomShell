"""Privilege escalation enumeration module."""

import os
import subprocess

NAME = "privesc"

GTFOBINS = {
    "aa-exec", "ab", "agetty", "alpine", "ar", "aria2c", "arj", "arp", "as",
    "ascii-xfr", "ash", "aspell", "atobm", "awk", "base32", "base64",
    "basenc", "bash", "bridge", "busctl", "busybox", "byebug", "bzip2",
    "capsh", "cat", "chmod", "chown", "chroot", "cmp", "column", "comm",
    "cobc", "cpan", "cpio", "cpulimit", "csh", "csplit", "csvtool", "curl",
    "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmesg",
    "docker", "dpkg", "dvips", "easy_install", "eb", "ed", "emacs",
    "env", "eqn", "expand", "expect", "facter", "file", "find", "fish",
    "flock", "fmt", "fold", "ftp", "gawk", "gcc", "gdb", "gem", "gimp",
    "git", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight",
    "iconv", "iftop", "install", "ionice", "ip", "irb", "ispell", "jjs",
    "join", "journalctl", "jq", "jrunscript", "ksh", "ksshell", "kubectl",
    "latex", "ldconfig", "less", "logsave", "look", "ltrace", "lua",
    "make", "man", "mawk", "more", "mount", "mtr", "mv", "mysql", "nano",
    "nasm", "nawk", "nc", "nice", "nl", "nmap", "node", "nohup", "npm",
    "nsenter", "od", "openssl", "openvpn", "paste", "perf", "perl", "pg",
    "php", "pic", "pico", "pip", "pkexec", "pr", "pry", "psql", "puppet",
    "python", "python3", "rake", "readelf", "red", "redcarpet", "restic",
    "rev", "rlwrap", "rpm", "rpmquery", "rsync", "ruby", "run-parts",
    "rview", "rvim", "sash", "scanmem", "scp", "screen", "script", "sed",
    "service", "setarch", "sftp", "shuf", "smbclient", "socat", "sort",
    "split", "sqlite3", "ss", "ssh", "start-stop-daemon", "stdbuf",
    "strace", "strings", "su", "sysctl", "systemctl", "tac", "tail",
    "tar", "taskset", "tclsh", "tee", "telnet", "tftp", "time", "timeout",
    "tmux", "top", "troff", "ul", "unexpand", "uniq", "unshare", "unzip",
    "update-alternatives", "uudecode", "uuencode", "valgrind", "vi", "vim",
    "vimdiff", "virsh", "w3m", "wall", "watch", "wc", "wget", "whois",
    "wish", "xargs", "xdotool", "xmodmap", "xmore", "xz", "yarn", "yum",
    "zsh", "zypper",
}

KERNEL_CVES = [
    {"cve": "CVE-2016-5195", "name": "DirtyCow", "versions": "< 4.8.3", "min": (2, 6), "max": (4, 8, 3)},
    {"cve": "CVE-2021-3156", "name": "Baron Samedit (sudo)", "versions": "sudo < 1.9.5p2", "check": "sudo --version"},
    {"cve": "CVE-2021-4034", "name": "PwnKit (pkexec)", "versions": "polkit < 0.120", "check": "pkexec --version"},
    {"cve": "CVE-2022-0847", "name": "DirtyPipe", "versions": "5.8 - 5.16.11", "min": (5, 8), "max": (5, 16, 11)},
    {"cve": "CVE-2022-2586", "name": "nf_tables", "versions": "5.x", "min": (5, 0), "max": (5, 19)},
    {"cve": "CVE-2023-0386", "name": "OverlayFS", "versions": "5.11 - 6.2", "min": (5, 11), "max": (6, 2)},
    {"cve": "CVE-2023-2640", "name": "GameOverlay", "versions": "Ubuntu specific", "check": "cat /etc/os-release"},
    {"cve": "CVE-2023-32233", "name": "Netfilter nf_tables", "versions": "< 6.4", "min": (5, 0), "max": (6, 3, 99)},
    {"cve": "CVE-2024-1086", "name": "nf_tables use-after-free", "versions": "5.14 - 6.6", "min": (5, 14), "max": (6, 6)},
]


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=30).decode(errors="replace").strip()
    except Exception:
        return ""


def _parse_kernel() -> tuple:
    ver = _run("uname -r").split("-")[0]
    parts = ver.split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def cmd_privesc_check() -> dict:
    results = {}

    suid = _run("find / -perm -4000 -type f 2>/dev/null")
    suid_list = [s.strip() for s in suid.splitlines() if s.strip()]
    suid_gtfo = [s for s in suid_list if os.path.basename(s) in GTFOBINS]
    results["suid"] = {"all": suid_list, "gtfobins_matches": suid_gtfo}

    sgid = _run("find / -perm -2000 -type f 2>/dev/null")
    results["sgid"] = [s.strip() for s in sgid.splitlines() if s.strip()]

    results["sudo"] = _run("sudo -l 2>/dev/null")

    caps = _run("getcap -r / 2>/dev/null")
    results["capabilities"] = [c.strip() for c in caps.splitlines() if c.strip()]

    crontab = _run("cat /etc/crontab 2>/dev/null")
    cron_d = _run("ls -la /etc/cron.d/ 2>/dev/null")
    user_cron = _run("crontab -l 2>/dev/null")
    results["cron"] = {"system": crontab, "cron_d": cron_d, "user": user_cron}

    writable_services = _run("find /etc/systemd /lib/systemd -writable -type f 2>/dev/null")
    results["writable_services"] = [s.strip() for s in writable_services.splitlines() if s.strip()]

    groups = _run("id")
    results["groups"] = groups
    results["docker"] = "docker" in groups.lower()
    results["lxd"] = "lxd" in groups.lower()

    nfs = _run("cat /etc/exports 2>/dev/null")
    results["nfs_no_root_squash"] = "no_root_squash" in nfs if nfs else False
    results["nfs_exports"] = nfs

    writable_path = []
    for d in os.getenv("PATH", "").split(":"):
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            writable_path.append(d)
    results["writable_path_dirs"] = writable_path

    localhost_services = _run("ss -tlnp 2>/dev/null | grep '127.0.0'")
    results["localhost_services"] = localhost_services

    writable_py = _run("python3 -c \"import sys; print('\\n'.join(sys.path))\" 2>/dev/null")
    writable_py_dirs = []
    for d in writable_py.splitlines():
        if d.strip() and os.path.isdir(d.strip()) and os.access(d.strip(), os.W_OK):
            writable_py_dirs.append(d.strip())
    results["writable_python_paths"] = writable_py_dirs

    timers = _run("systemctl list-timers --all --no-pager 2>/dev/null")
    results["timers"] = timers

    results["kernel"] = _run("uname -r")

    return results


def cmd_privesc_suggest() -> dict:
    check = cmd_privesc_check()
    suggestions = []

    if check.get("suid", {}).get("gtfobins_matches"):
        for b in check["suid"]["gtfobins_matches"]:
            name = os.path.basename(b)
            suggestions.append({
                "vector": f"SUID - {name}",
                "path": b,
                "risk": "high",
                "info": f"GTFOBins SUID binary. Check: https://gtfobins.github.io/gtfobins/{name}/#suid",
            })

    if check.get("docker"):
        suggestions.append({
            "vector": "Docker Group",
            "risk": "high",
            "info": "docker run -v /:/host -it alpine chroot /host bash",
        })

    if check.get("writable_python_paths"):
        suggestions.append({
            "vector": "Python Library Hijacking",
            "paths": check["writable_python_paths"],
            "risk": "medium",
            "info": "Writable Python paths — check for scripts run as root that import from these",
        })

    if check.get("writable_services"):
        suggestions.append({
            "vector": "Writable Systemd Service",
            "paths": check["writable_services"],
            "risk": "high",
            "info": "Modify ExecStart to run a reverse shell",
        })

    if check.get("nfs_no_root_squash"):
        suggestions.append({
            "vector": "NFS no_root_squash",
            "risk": "high",
            "info": "Mount share, create SUID binary as root",
        })

    if check.get("lxd"):
        suggestions.append({
            "vector": "LXD Group",
            "risk": "high",
            "info": "lxd init + lxc mount host filesystem",
        })

    return {"suggestions": suggestions, "count": len(suggestions)}


def cmd_vuln_scan() -> dict:
    kernel = _parse_kernel()
    if not kernel:
        return {"error": "Could not parse kernel version"}

    vulnerable = []
    for cve in KERNEL_CVES:
        if "min" in cve and "max" in cve:
            if cve["min"] <= kernel <= cve["max"]:
                vulnerable.append({
                    "cve": cve["cve"],
                    "name": cve["name"],
                    "affected": cve["versions"],
                    "kernel": ".".join(str(p) for p in kernel),
                })
        elif "check" in cve:
            output = _run(cve["check"])
            if output:
                vulnerable.append({
                    "cve": cve["cve"],
                    "name": cve["name"],
                    "affected": cve["versions"],
                    "check_output": output[:200],
                })

    return {"kernel": ".".join(str(p) for p in kernel), "vulnerabilities": vulnerable, "count": len(vulnerable)}


COMMANDS = {
    "privesc_check": {"handler": cmd_privesc_check, "description": "Comprehensive privilege escalation enumeration"},
    "privesc_suggest": {"handler": cmd_privesc_suggest, "description": "Analyze and suggest privesc paths"},
    "vuln_scan": {"handler": cmd_vuln_scan, "description": "Scan for known kernel/software CVEs"},
}
