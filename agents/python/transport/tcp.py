import socket
import struct
import time
import logging

log = logging.getLogger("phantom.transport.tcp")


class TcpTransport:
    """TCP transport with 4-byte length-prefix framing."""

    def __init__(self, host: str, port: int, timeout: float = 30.0,
                 retry_count: int = -1, retry_delay: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self._sock: socket.socket | None = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(self.timeout)
                self._sock.connect((self.host, self.port))
                self._connected = True
                log.info(f"Connected to {self.host}:{self.port}")
                return True
            except OSError as e:
                attempts += 1
                log.warning(f"Connection failed (attempt {attempts}): {e}")
                self._cleanup_socket()
                if self.retry_count != -1 and attempts >= self.retry_count:
                    return False
                time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        if not self._connected or not self._sock:
            return False
        try:
            frame = struct.pack(">I", len(data)) + data
            self._sock.sendall(frame)
            return True
        except OSError as e:
            log.error(f"Send failed: {e}")
            self._connected = False
            return False

    def recv(self) -> bytes | None:
        if not self._connected or not self._sock:
            return None
        try:
            length_data = self._recv_exact(4)
            if not length_data:
                return None
            length = struct.unpack(">I", length_data)[0]
            if length > 10 * 1024 * 1024:
                log.error(f"Message too large: {length} bytes")
                return None
            return self._recv_exact(length)
        except OSError as e:
            log.error(f"Recv failed: {e}")
            self._connected = False
            return None

    def _recv_exact(self, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                self._connected = False
                return None
            buf.extend(chunk)
        return bytes(buf)

    def disconnect(self):
        self._cleanup_socket()
        log.info("Disconnected")

    def _cleanup_socket(self):
        self._connected = False
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
