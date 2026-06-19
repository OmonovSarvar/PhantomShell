"""Network pivoting module."""

import os
import socket
import selectors
import struct
import threading
import logging

NAME = "pivoting"
log = logging.getLogger("phantom.modules.pivoting")

_active_pivots: dict[int, dict] = {}
_pivot_counter = 0


def _next_id() -> int:
    global _pivot_counter
    _pivot_counter += 1
    return _pivot_counter


def cmd_pivot_portfwd(direction: str = "local", local: str = "0.0.0.0:8080",
                      remote: str = "127.0.0.1:80") -> dict:
    lhost, lport = local.rsplit(":", 1)
    rhost, rport = remote.rsplit(":", 1)
    lport, rport = int(lport), int(rport)
    pivot_id = _next_id()

    def relay(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()

    def handler(client, addr):
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((rhost, rport))
            t1 = threading.Thread(target=relay, args=(client, upstream), daemon=True)
            t2 = threading.Thread(target=relay, args=(upstream, client), daemon=True)
            t1.start()
            t2.start()
        except Exception as e:
            log.error(f"Port forward connection failed: {e}")
            client.close()

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lhost, lport))
        srv.listen(5)
        _active_pivots[pivot_id]["socket"] = srv
        while _active_pivots.get(pivot_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handler, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_pivots[pivot_id] = {
        "type": "portfwd",
        "direction": direction,
        "local": f"{lhost}:{lport}",
        "remote": f"{rhost}:{rport}",
        "active": True,
    }

    t = threading.Thread(target=listener, daemon=True)
    t.start()

    return {"id": pivot_id, "status": "started", "local": f"{lhost}:{lport}", "remote": f"{rhost}:{rport}"}


def cmd_pivot_socks(port: int = 1080, auth: str = "") -> dict:
    pivot_id = _next_id()

    def handle_socks(client):
        try:
            data = client.recv(256)
            if not data or data[0] != 0x05:
                client.close()
                return
            client.send(b"\x05\x00")

            data = client.recv(256)
            if not data or len(data) < 4:
                client.close()
                return

            cmd = data[1]
            atyp = data[3]

            if cmd != 0x01:
                client.send(b"\x05\x07\x00\x01" + b"\x00" * 6)
                client.close()
                return

            if atyp == 0x01:
                addr = socket.inet_ntoa(data[4:8])
                port_bytes = data[8:10]
            elif atyp == 0x03:
                alen = data[4]
                addr = data[5:5 + alen].decode()
                port_bytes = data[5 + alen:5 + alen + 2]
            elif atyp == 0x04:
                addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                port_bytes = data[20:22]
            else:
                client.close()
                return

            dst_port = struct.unpack(">H", port_bytes)[0]
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((addr, dst_port))

            bind_addr = remote.getsockname()
            reply = b"\x05\x00\x00\x01"
            reply += socket.inet_aton(bind_addr[0])
            reply += struct.pack(">H", bind_addr[1])
            client.send(reply)

            def relay(src, dst):
                try:
                    while True:
                        d = src.recv(4096)
                        if not d:
                            break
                        dst.sendall(d)
                except Exception:
                    pass
                finally:
                    src.close()
                    dst.close()

            t1 = threading.Thread(target=relay, args=(client, remote), daemon=True)
            t2 = threading.Thread(target=relay, args=(remote, client), daemon=True)
            t1.start()
            t2.start()

        except Exception as e:
            log.error(f"SOCKS5 error: {e}")
            try:
                client.close()
            except Exception:
                pass

    def listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        _active_pivots[pivot_id]["socket"] = srv
        while _active_pivots.get(pivot_id, {}).get("active", False):
            try:
                srv.settimeout(1.0)
                client, addr = srv.accept()
                threading.Thread(target=handle_socks, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    _active_pivots[pivot_id] = {"type": "socks5", "port": port, "active": True}
    t = threading.Thread(target=listener, daemon=True)
    t.start()
    return {"id": pivot_id, "status": "started", "type": "socks5", "port": port}


def cmd_pivot_list() -> dict:
    pivots = []
    for pid, info in _active_pivots.items():
        pivots.append({"id": pid, **{k: v for k, v in info.items() if k != "socket"}})
    return {"pivots": pivots, "count": len(pivots)}


COMMANDS = {
    "pivot_portfwd": {"handler": cmd_pivot_portfwd, "description": "Create port forward"},
    "pivot_socks": {"handler": cmd_pivot_socks, "description": "Start SOCKS5 proxy"},
    "pivot_list": {"handler": cmd_pivot_list, "description": "List active pivots"},
}
