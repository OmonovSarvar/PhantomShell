# Changelog

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
