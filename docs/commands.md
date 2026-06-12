# Command Reference

## Core Shell
| Command | Description |
|---------|-------------|
| `help` | Show help (help <cmd> for details) |
| `cd <dir>` | Change directory (cd - for previous) |
| `pwd` | Print working directory |
| `clear` | Clear screen |
| `history` | Show command history |
| `pty` | Upgrade to PTY shell |
| `alias` | Show command aliases |
| `mode` | Show current mode |
| `capabilities` | Show detected capabilities |
| `exit` / `quit` | Disconnect (reconnects) |
| `die` | Kill shell permanently |

## File Operations
| Command | Description |
|---------|-------------|
| `cat <file>` | Display file contents |
| `head <file> [n]` | First n lines (default 10) |
| `tail <file> [n]` | Last n lines (default 10) |
| `ls [args]` | List files |
| `upload <file>` | Upload file (base64, end with --EOF--) |
| `download <file>` | Download file as base64 |
| `edit <file>` | Built-in line editor |
| `cp / mv / rm / mkdir / touch` | Standard file operations |

## System Reconnaissance
| Command | Description |
|---------|-------------|
| `sysinfo` | Full system information dump |
| `env` | Environment variables |
| `services` | Running services |
| `ports` | Listening ports |
| `firewall` | Firewall rules (iptables + nftables) |
| `netmap` | Network map (interfaces, routes, ARP, hosts) |

## Vulnerability Scanner
| Command | Description |
|---------|-------------|
| `vuln_scan` | Full vulnerability scan (kernel, SUID, sudo, docker, polkit, caps, configs) |

## Exploits
| Command | Description |
|---------|-------------|
| `exploit_suggest` | Suggest kernel exploits for this kernel |
| `exploit_fetch <CVE>` | Download exploit source |
| `exploit_compile <CVE>` | Compile downloaded exploit |

## Privilege Escalation
| Command | Description |
|---------|-------------|
| `privesc_check` | Check all privesc vectors |
| `privesc_auto` | Try automatic escalation |
| `privesc_suggest` | Step-by-step privesc guide |

## Pivoting
| Command | Description |
|---------|-------------|
| `pivot_list` | Show all pivoting commands |
| `pivot_portfwd <lp> <rh> <rp>` | TCP port forwarding |
| `pivot_socks` | Start SOCKS4 proxy on :1080 |
| `pivot_tunnel <rh> <rp> <lp>` | Reverse tunnel |
| `pivot_ligolo` | Ligolo-ng guide |
| `pivot_chisel` | Chisel guide |
| `pivot_ssh` | SSH tunneling guide |
| `pivot_rpivot` | rpivot guide |
| `pivot_earthworm` | EarthWorm guide |
| `pivot_proxychain` | Generate proxychains config |

## Network
| Command | Description |
|---------|-------------|
| `portscan <host> <ports> [timeout]` | Port scanner with banners |
| `connect <host> <port>` | Raw TCP connection |
| `listen <port>` | TCP listener |
| `bannergrab <host> <port>` | Grab service banner |

## Persistence
| Command | Description |
|---------|-------------|
| `persist_all` | Install ALL persistence methods |
| `persist_cron` | Crontab entry |
| `persist_ssh` | SSH authorized_keys |
| `persist_systemd` | Systemd service |
| `persist_rc` | .bashrc / .profile / .zshrc |
| `persist_motd` | MOTD script |
| `persist_ldpreload` | LD_PRELOAD shared library |
| `persist_php` | PHP auto_prepend_file |
| `persist_web` | Web shell in webroot |
| `persist_wsl` | WSL persistence check |

## Anti-Forensics
| Command | Description |
|---------|-------------|
| `clean_logs` | Wipe system logs |
| `clean_self` | Shred and delete this shell |
| `hide_process` | Rename to kernel thread |
| `hide_connection` | Connection hiding (LD_PRELOAD) |
| `timestomp <file> [ref]` | Change file timestamps |
| `alter_conn <ip> <port>` | Spawn alternate connection |
| `memory_only` | Generate memory-only payload |

## Lateral Movement
| Command | Description |
|---------|-------------|
| `lateral_ssh <user@host> [pass]` | SSH to another host |
| `lateral_scp <src> <user@host:dest>` | SCP file transfer |
| `lateral_wmi <user@host> <cmd>` | WMI execution |
| `lateral_smb <host> [share]` | SMB enumeration |

## Credential Harvesting
| Command | Description |
|---------|-------------|
| `steal_all` | Run all stealing modules |
| `steal_configs` | Find config files with secrets |
| `steal_ssh` | Dump SSH private keys |
| `steal_history` | Search shell history for creds |
| `steal_passwords` | Grep for passwords in files |
| `steal_etc` | Dump /etc/passwd and /etc/shadow |
| `steal_browsers` | Find browser credential files |

## Backdoors
| Command | Description |
|---------|-------------|
| `backdoor_php [path]` | Deploy PHP eval shell |
| `backdoor_python` | Python reverse shell one-liner |
| `backdoor_bash` | Bash reverse shell one-liner |
| `backdoor_nc` | Netcat reverse shell |
| `backdoor_socat` | Socat reverse shell |
| `backdoor_web` / `webshell` | Deploy web shell to webroot |

## C2 Integration
| Command | Description |
|---------|-------------|
| `c2_discord <webhook>` | Send beacon to Discord |
| `c2_telegram <token> <chat_id>` | Send beacon to Telegram |
| `c2_http <url>` | HTTP callback with system info |
| `c2_sliver` | Sliver setup guide |
| `c2_cobalt` | Cobalt Strike guide |
| `c2_meterpreter` | Meterpreter payload command |
| `c2_venom` | Venom tool reference |

## Data Exfiltration
| Command | Description |
|---------|-------------|
| `exfil <file>` | Exfiltrate file (gzip + base64) |
| `compress <file>` | Compress file/directory |

## Automation
| Command | Description |
|---------|-------------|
| `auto_root` | Try all privilege escalation methods |
| `auto_pivot` | Scan subnets for live hosts |
| `auto_persist` | Install all persistence |
| `auto_clean` | Clean logs + hide process |
| `auto_report` | Generate JSON report |

## Job Control
| Command | Description |
|---------|-------------|
| `background <cmd>` | Run command in background |
| `fg [job_id]` | Bring job to foreground |
| `jobs` | List running jobs |
| `kill <PID\|%job>` | Kill process or job |
