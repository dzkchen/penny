from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin, urlparse


class GuardrailError(ValueError):
    pass


@dataclass
class SafeResponse:
    status_code: int
    text: str
    headers: dict[str, str]


def _hostname_allowed(hostname: str, i_own_this: bool) -> bool:
    lowered = hostname.lower().strip("[]")
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
        return ip.is_private or ip.is_loopback or (i_own_this and not ip.is_multicast)
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        if i_own_this:
            return True
        return False
    for address in addresses:
        candidate = address[4][0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback:
            return True
    return i_own_this


def host_allowed(hostname: str | None, i_own_this: bool) -> bool:
    """Public predicate sharing TargetGate's authorization rule.

    Non-HTTP probes (the TCP port scan, the TLS handshake inspector) cannot go
    through :class:`TargetGate` because they are not HTTP requests, but they must
    obey the same gate: localhost/private hosts are allowed by default and any
    public host requires ``i_own_this``.
    """
    if not hostname:
        return False
    return _hostname_allowed(hostname, i_own_this)


class TargetGate:
    def __init__(
        self,
        base_url: str,
        *,
        i_own_this: bool = False,
        max_requests: int = 25,
        min_interval_seconds: float = 0.25,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 4096,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"}:
            raise GuardrailError("target must use http or https")
        if not parsed.hostname:
            raise GuardrailError("target must include a hostname")
        if not _hostname_allowed(parsed.hostname, i_own_this):
            raise GuardrailError("public targets require --i-own-this and are limited to read-only probes")
        self.base_url = base_url.rstrip("/")
        self.parsed = parsed
        self.i_own_this = i_own_this
        self.max_requests = max_requests
        self.min_interval_seconds = min_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.request_count = 0
        self._last_request = 0.0

    def validate_method(self, method: str) -> None:
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise GuardrailError(f"unsafe HTTP method blocked: {method}")

    def build_url(self, path: str) -> str:
        candidate = urljoin(f"{self.base_url}/", path.lstrip("/"))
        parsed = urlparse(candidate)
        if parsed.scheme != self.parsed.scheme or parsed.netloc != self.parsed.netloc:
            raise GuardrailError("probe URL attempted to leave the approved target")
        return candidate

    def _rate_limit(self) -> None:
        if self.request_count >= self.max_requests:
            raise GuardrailError("HTTP request cap reached")
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)
        self._last_request = time.monotonic()
        self.request_count += 1

    def request(self, method: str, path: str, headers: Mapping[str, str] | None = None) -> SafeResponse:
        self.validate_method(method)
        url = self.build_url(path)
        self._rate_limit()
        headers = dict(headers or {})
        try:
            import httpx

            response = httpx.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
            if 300 <= response.status_code < 400 and response.headers.get("location"):
                location = response.headers["location"]
                redirected = urlparse(urljoin(url, location))
                if redirected.netloc != self.parsed.netloc:
                    raise GuardrailError("redirect to unapproved host blocked")
            body = response.content[: self.max_response_bytes].decode("utf-8", errors="replace")
            return SafeResponse(status_code=response.status_code, text=body, headers=dict(response.headers))
        except ImportError:
            from urllib.error import HTTPError
            from urllib.request import Request, urlopen

            request = Request(url, method=method, headers=headers)
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    status = int(response.status)
                    raw = response.read(self.max_response_bytes)
                    return SafeResponse(status_code=status, text=raw.decode("utf-8", errors="replace"), headers=dict(response.headers))
            except HTTPError as error:
                raw = error.read(self.max_response_bytes)
                return SafeResponse(status_code=int(error.code), text=raw.decode("utf-8", errors="replace"), headers=dict(error.headers))
