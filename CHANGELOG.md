# Changelog

## [5.2.0] - 2026-06-20

### Added — Phase 5: C2 Dashboard + Polish
- Web dashboard: dark-themed SPA with real-time agent management
- Socket.IO WebSocket events for live session/beacon/credential updates
- REST API: sessions, listeners, credentials, network, reports, builder endpoints
- Interactive web terminal for remote command execution
- Agent builder UI: generate payloads for Python/C#/PowerShell/PHP/Go
- Credential vault with auto-harvest from steal_* commands, CSV export
- Network map visualization (canvas-based node graph)
- Report engine: executive/technical/findings templates, HTML/JSON export
- Keyboard shortcuts: Ctrl+K command palette, Ctrl+1-7 section switch

### Added — Phase 3+4: C++ Tools, Go Agent, Tunneling, Playbooks
- C++ red team tools (6 standalone Windows binaries):
  PhantomLoader (5 injection techniques), PhantomInject (5 methods),
  PhantomDump (4 LSASS dump techniques), PhantomKey (keylogger),
  PhantomSocks (SOCKS5 RFC 1928), PhantomScan (async scanner)
- Go cross-platform agent: static binary, goroutine scanner, 7 modules
  Cross-compile: Linux/Windows/macOS/ARM64, zero external dependencies
- Python tunneling transports: DNS (base32 subdomain), WebSocket (RFC 6455),
  ICMP (raw sockets), Named Pipe (Windows ctypes + Unix domain sockets)
- Tunnel module: SOCKS5 proxy, port forwarding, chisel auto-deploy
- YAML playbook engine with variable substitution and conditionals
- 5 example playbooks: auto_enum, credential_harvest, ad_attack, pivot_chain, auto_persist

### Added — Phase 2: Windows + Active Directory
- C# Windows agent (.NET 8) with TCP/HTTP transport, AES-256-GCM encryption
- C# Windows post-exploitation: token manipulation, credential dumping, UAC bypass (FodHelper/CMSTP/ComputerDefaults/EventViewer), AMSI/ETW bypass, registry/service control
- PowerShell agent with in-memory execution, AMSI bypass, module loading
- Active Directory attacks across Python, C#, PowerShell:
  - Domain enumeration (users, computers, groups, trusts, GPOs)
  - Kerberoasting (hashcat-ready TGS output)
  - AS-REP Roasting (hashcat-ready AS-REP output)
  - ACL/DACL abuse scanner (WriteDACL, GenericAll, ForceChangePassword chains)
  - RBCD abuse (write msDS-AllowedToActOnBehalfOfOtherIdentity)
  - Delegation enumeration (unconstrained, constrained, RBCD)
  - ADCS vulnerability scanner (ESC1-ESC8)
  - LAPS password retrieval (v1 + v2)
  - Shadow Credentials (msDS-KeyCredentialLink)
  - gMSA password extraction
  - Domain trust enumeration
  - Password policy + spray
- PowerShell lateral movement: WMI, PSRemoting, SMB, DCOM, WinRM
- PowerShell persistence: registry, scheduled tasks, WMI subscriptions, COM hijack, services
- PowerShell credential dumping: SAM, DPAPI, Credential Manager, cached credentials

### Changed
- Version bumped to 5.2 across all agents
- README updated with multi-language badges and new description

## [5.0.0] - 2026-06-19

### Added — Phase 1: Multi-Language Foundation
- JSON wire protocol with 4-byte length-prefix framing
- Python agent with modular architecture (transport, crypto, core, modules)
- AES-256-GCM encryption with ECDH X25519 key exchange
- HMAC-SHA256 agent authentication (PSK-based)
- TCP transport with retry logic and reconnection
- HTTP(S) transport with User-Agent rotation, URL jitter, TLS support
- C2 server with TCP + HTTP listeners, session management, interactive CLI
- Python privesc module: 220+ GTFOBins with exploit/sudo commands, kernel CVE scanner
- Python credential parser: 10+ config formats (env, wp-config, database.yml, django, pgpass, etc.)
- PHP agent dual-mode: JSON C2 protocol + plaintext nc fallback
- Unified command registry (proto/commands.json) for help, tab completion, validation
- Monorepo structure: agents/python, agents/php, agents/csharp, agents/powershell, c2/

### Changed
- PHP agent upgraded from v4.0 to v5.0 with JSON wire protocol support
- Hardcoded IPs replaced with placeholders across entire codebase

## [4.0.0] - 2026-06-12

### Added
- Self-adaptive 3-mode architecture (FULL / NORMAL / MINIMAL)
- Auto-detection of server capabilities (memory, exec, disk, network)
- 8-method execution bypass engine (proc_open → mail+putenv)
- Interactive shell with arrow key history, tab completion, Ctrl+C
- 100+ built-in commands across 17 categories
- PHP-native SOCKS4 proxy server
- PHP-native TCP port forwarding
- Kernel CVE vulnerability scanner (DirtyCow, DirtyPipe, GameOver, nf_tables)
- GTFOBins SUID matcher
- Automated privilege escalation (auto_root)
- Network subnet scanner (auto_pivot)
- 10 persistence methods (cron, SSH, systemd, rc, motd, ld_preload, PHP, web, WSL)
- Credential harvesting suite (configs, SSH keys, history, passwords, browsers)
- C2 integration (Discord, Telegram, HTTP callback, Sliver, Meterpreter)
- Data exfiltration with gzip compression
- Anti-forensics (log cleaning, process hiding, timestomping)
- Lateral movement (SSH, SCP, WMI, SMB)
- Multiple backdoor deployment options
- Background job management
- PTY upgrade via python/script
- Module loader for MINIMAL mode
- Standalone normal.php and loader.php
- Auto-report JSON generation

### Architecture
- Zero external dependencies
- PHP 5.6+ compatible
- Non-blocking socket I/O with stream_select
- Automatic reconnection on disconnect
- Process title masking ([kworker/0:1-events])

## [3.0.0] - Previous

- Basic reverse shell with execution methods
- File upload/download
- System info gathering
