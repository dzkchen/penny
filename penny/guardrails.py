from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
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


DEFAULT_TXT_LABEL = "_penny"
DEFAULT_TXT_VALUE = "penny-verify=authorized"
_TXT_CHUNK_RE = re.compile(r'"([^"]*)"')


def _is_private_or_loopback_host(hostname: str) -> bool:
    lowered = hostname.lower().strip("[]")
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for address in addresses:
        candidate = address[4][0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback:
            return True
    return False


def _public_ip_literal(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname.lower().strip("[]"))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback)


def _txt_label() -> str:
    label = os.environ.get("PENNY_TARGET_TXT_LABEL", DEFAULT_TXT_LABEL).strip().strip(".")
    return label or DEFAULT_TXT_LABEL


def _expected_txt_value() -> str:
    value = os.environ.get("PENNY_TARGET_TXT_VALUE", DEFAULT_TXT_VALUE).strip()
    return value or DEFAULT_TXT_VALUE


def _candidate_txt_names(hostname: str) -> list[str]:
    lowered = hostname.lower().strip(".")
    label = _txt_label()
    candidates = [lowered]
    if label:
        candidates.insert(0, f"{label}.{lowered}")
    seen: dict[str, None] = {}
    for candidate in candidates:
        seen.setdefault(candidate, None)
    return list(seen)


def _parse_txt_output(text: str) -> list[str]:
    records: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        chunks = _TXT_CHUNK_RE.findall(line)
        if chunks:
            records.append("".join(chunks))
            continue
        lowered = line.lower()
        if "text =" in lowered:
            _, _, tail = line.partition("=")
            candidate = tail.strip().strip('"')
            if candidate:
                records.append(candidate)
    return records


def _lookup_txt_records(hostname: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore[import-not-found]

        answers = dns.resolver.resolve(hostname, "TXT")
        records: list[str] = []
        for answer in answers:
            strings = getattr(answer, "strings", None)
            if strings:
                records.append("".join(chunk.decode("utf-8", errors="ignore") for chunk in strings))
                continue
            records.append(str(answer).strip('"'))
        if records:
            return records
    except Exception:  # noqa: BLE001 - fail closed below
        pass

    commands = (
        ["dig", "+short", "TXT", hostname],
        ["nslookup", "-type=TXT", hostname],
    )
    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=3.0, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        records = _parse_txt_output(completed.stdout)
        if records:
            return records
    return []


def _has_matching_txt_record(hostname: str) -> bool:
    expected = _expected_txt_value()
    for candidate in _candidate_txt_names(hostname):
        if expected in _lookup_txt_records(candidate):
            return True
    return False


def txt_record_hint(hostname: str) -> str:
    names = _candidate_txt_names(hostname)
    value = _expected_txt_value()
    if len(names) == 1:
        return f'{names[0]} TXT "{value}"'
    return f'{names[0]} TXT "{value}" (or {names[1]} TXT "{value}")'


def host_authorization_error(hostname: str | None, i_own_this: bool) -> str | None:
    if not hostname:
        return "target must include a hostname"
    if _is_private_or_loopback_host(hostname):
        return None
    if not i_own_this:
        return "public targets require --i-own-this and a matching DNS TXT proof record"
    if _public_ip_literal(hostname):
        return "public IP literals are blocked; use a DNS hostname with a matching TXT proof record"
    # TXT ownership proof can be disabled with PENNY_DISABLE_TXT_PROOF=1 (kept in code,
    # bypassed for trusted local testing). Re-enable for production / shared use.
    if os.environ.get("PENNY_DISABLE_TXT_PROOF", "").strip() in ("1", "true", "yes"):
        return None
    if not _has_matching_txt_record(hostname):
        return f"missing TXT proof record; expected {txt_record_hint(hostname)}"
    return None


def _hostname_allowed(hostname: str, i_own_this: bool) -> bool:
    return host_authorization_error(hostname, i_own_this) is None


def host_allowed(hostname: str | None, i_own_this: bool) -> bool:
    """Public predicate sharing TargetGate's authorization rule.

    Non-HTTP probes (the TCP port scan, the TLS handshake inspector) cannot go
    through :class:`TargetGate` because they are not HTTP requests, but they must
    obey the same gate: localhost/private hosts are allowed by default and any
    public host requires ``i_own_this`` plus a matching DNS TXT proof record.
    """
    return host_authorization_error(hostname, i_own_this) is None


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
        authorization_error = host_authorization_error(parsed.hostname, i_own_this)
        if authorization_error:
            raise GuardrailError(authorization_error)
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
