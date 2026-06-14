"""Transport-security / man-in-the-middle *exposure* detection.

Penny does not perform interception attacks (ARP/DNS spoofing, rogue APs, TLS
forging) — those target other people's traffic and fall outside the "scan a host
you own" model the rest of the tool enforces. What this module does is the
defensive half: it finds the weaknesses that *make* a man-in-the-middle attack
possible, so the owner can close them.

It checks three things, all read-only:

* **TLS quality** — a normal client handshake (``ssl``) reads the negotiated
  protocol/cipher and the certificate, and flags expired / self-signed /
  hostname-mismatched certs, obsolete protocol versions (< TLS 1.2), and any
  legacy TLS 1.0/1.1 the server still accepts.
* **HSTS depth** — whether ``Strict-Transport-Security`` is present, long-lived,
  and covers subdomains. Missing/weak HSTS is what lets an SSL-strip downgrade
  stick.
* **Cleartext downgrade** — whether the same host still serves content over plain
  ``http://`` without redirecting to HTTPS (the foothold for SSL stripping).

The pure decision logic lives in :func:`analyze_transport` and is unit-tested
offline; the network gathering wrapper is thin and never raises into a scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate, host_authorization_error
from .models import Finding, Location

# Below this the cert is "about to expire"; below TLS 1.2 the protocol is obsolete.
_HSTS_MIN_MAX_AGE = 15552000  # 180 days, the commonly recommended floor
_CERT_EXPIRY_WARN_DAYS = 14
_OBSOLETE_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
_WEAK_CIPHER_RE = re.compile(r"\b(RC4|3DES|DES|NULL|EXPORT|MD5|ANON|RC2)\b", re.I)


@dataclass(frozen=True)
class TlsInfo:
    """Result of a read-only TLS handshake. ``error`` is set if none could be made."""

    negotiated_version: str = ""
    cipher: str = ""
    legacy_versions: list[str] = field(default_factory=list)
    cert_expired: bool = False
    cert_self_signed: bool = False
    hostname_mismatch: bool = False
    days_to_expiry: int | None = None
    error: str = ""


def _severity_max(values: list[str]) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return max(values, key=lambda value: order.get(value, 0)) if values else "Info"


def _parse_hsts(header: str) -> tuple[int | None, bool, bool]:
    """Return ``(max_age, include_subdomains, preload)`` for a Strict-Transport-Security value."""
    lowered = header.lower()
    max_age: int | None = None
    match = re.search(r"max-age\s*=\s*\"?(\d+)", lowered)
    if match:
        max_age = int(match.group(1))
    return max_age, "includesubdomains" in lowered, "preload" in lowered


def analyze_transport(
    target: str,
    *,
    tls: TlsInfo | None,
    hsts_header: str,
    plaintext_http_served: bool | None,
) -> list[Finding]:
    """Decide what (if anything) about ``target``'s transport enables MitM."""
    scheme = (urlparse(target).scheme or "").lower()
    issues: list[dict[str, str]] = []
    severities: list[str] = []

    def add(issue: str, severity: str, detail: str) -> None:
        issues.append({"issue": issue, "severity": severity, "detail": detail})
        severities.append(severity)

    if scheme != "https":
        add(
            "no_tls",
            "Critical",
            "Target is served over plaintext HTTP, so all traffic can be read and modified in transit.",
        )

    if scheme == "https" and tls is not None and not tls.error:
        if tls.cert_expired:
            add("certificate_expired", "Critical", "TLS certificate is expired; clients that proceed cannot trust the channel.")
        if tls.cert_self_signed:
            add("certificate_self_signed", "High", "Self-signed certificate cannot be validated against a trusted CA.")
        if tls.hostname_mismatch:
            add("certificate_hostname_mismatch", "High", "Certificate does not match the requested hostname.")
        if tls.negotiated_version and tls.negotiated_version in _OBSOLETE_TLS:
            add("obsolete_tls_version", "High", f"Connection negotiated {tls.negotiated_version}, which is broken/deprecated.")
        legacy = sorted(set(tls.legacy_versions) & _OBSOLETE_TLS)
        if legacy:
            add("legacy_tls_accepted", "High", f"Server still accepts {', '.join(legacy)}, enabling downgrade attacks.")
        if tls.cipher and _WEAK_CIPHER_RE.search(tls.cipher):
            add("weak_cipher", "High", f"Negotiated cipher {tls.cipher} uses weak/deprecated cryptography.")
        if tls.days_to_expiry is not None and 0 <= tls.days_to_expiry < _CERT_EXPIRY_WARN_DAYS:
            add("certificate_expiring", "Medium", f"Certificate expires in {tls.days_to_expiry} day(s).")

    if scheme == "https":
        cleartext = plaintext_http_served is True
        if not hsts_header.strip():
            severity = "High" if cleartext else "Medium"
            add(
                "hsts_missing",
                severity,
                "No Strict-Transport-Security header; a downgraded HTTP request is not refused by the browser.",
            )
        else:
            max_age, include_subdomains, _preload = _parse_hsts(hsts_header)
            if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
                add("hsts_short_max_age", "Medium", f"HSTS max-age={max_age} is below the recommended {_HSTS_MIN_MAX_AGE}.")
            if not include_subdomains:
                add("hsts_no_subdomains", "Low", "HSTS does not set includeSubDomains, leaving subdomains downgradable.")
        if cleartext:
            add(
                "plaintext_http_accepted",
                "High",
                "The host serves content over http:// without redirecting to HTTPS, the foothold for SSL stripping.",
            )

    if not issues:
        return []

    severity = _severity_max(severities)
    labels = ", ".join(sorted({issue["issue"] for issue in issues}))
    return [
        Finding(
            title="Transport susceptible to man-in-the-middle / downgrade",
            severity=severity,
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A011",
            owasp=[
                "A02:2021-Cryptographic Failures",
                "A02:2025-Security Misconfiguration",
                "WSTG-CRYP-01",
                "WSTG-CRYP-03",
            ],
            location=Location(file=f"transport:{urlparse(target).hostname or target}", line=1, column=1),
            snippet=f"Transport-security weaknesses enabling MitM: {labels}.",
            evidence={
                "dynamic_probe": {
                    "probe": "transport_security",
                    "status": "confirmed",
                    "scheme": scheme,
                    "issues": issues,
                    "tls": None
                    if tls is None
                    else {
                        "negotiated_version": tls.negotiated_version,
                        "cipher": tls.cipher,
                        "legacy_versions": tls.legacy_versions,
                        "days_to_expiry": tls.days_to_expiry,
                    },
                    "stored_response": "header presence, TLS version/cipher, and certificate flags only",
                },
                "attack_path": "An attacker positioned on the network path (rogue Wi-Fi, ARP/DNS spoofing, a compromised hop) can read or alter traffic because the transport does not force and validate strong TLS.",
            },
            impact="Weak transport security lets a network attacker intercept or tamper with traffic, steal session cookies/credentials, and inject content.",
            remediation="Serve only over HTTPS with a valid CA-issued certificate, redirect all HTTP to HTTPS, send HSTS (long max-age + includeSubDomains, consider preload), disable TLS < 1.2 and weak ciphers.",
        )
    ]


def _inspect_tls(host: str, port: int, timeout: float = 5.0) -> TlsInfo:
    """Read-only TLS handshake; returns what was negotiated and any cert problems."""
    import socket
    import ssl

    expired = self_signed = mismatch = False
    version = cipher = error = ""
    days: int | None = None

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                version = tls_sock.version() or ""
                cipher = (tls_sock.cipher() or ("", "", 0))[0]
                cert = tls_sock.getpeercert() or {}
                days = _days_to_expiry(cert.get("notAfter"))
    except ssl.SSLCertVerificationError as verify_error:
        message = str(verify_error).lower()
        expired = "expired" in message
        self_signed = "self signed" in message or "self-signed" in message
        mismatch = "hostname mismatch" in message or "doesn't match" in message or "ip address mismatch" in message
        version, cipher, days = _inspect_tls_no_verify(host, port, timeout)
    except Exception as connect_error:  # noqa: BLE001 - unreachable/odd TLS must not crash the scan
        error = str(connect_error)

    legacy = _legacy_versions_accepted(host, port, timeout) if not error else []
    return TlsInfo(
        negotiated_version=version,
        cipher=cipher,
        legacy_versions=legacy,
        cert_expired=expired,
        cert_self_signed=self_signed,
        hostname_mismatch=mismatch,
        days_to_expiry=days,
        error=error,
    )


def _inspect_tls_no_verify(host: str, port: int, timeout: float) -> tuple[str, str, int | None]:
    """After a verify failure, reconnect without verification to read version/cipher/expiry."""
    import socket
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                return tls_sock.version() or "", (tls_sock.cipher() or ("", "", 0))[0], _days_to_expiry(cert.get("notAfter"))
    except Exception:  # noqa: BLE001
        return "", "", None


def _legacy_versions_accepted(host: str, port: int, timeout: float) -> list[str]:
    """Best-effort: which obsolete TLS versions the server still completes a handshake with."""
    import socket
    import ssl

    accepted: list[str] = []
    candidates = [("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)), ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))]
    for label, version in candidates:
        if version is None:
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, OSError):
            continue  # OpenSSL refuses to even configure this obsolete version — good
        try:
            with socket.create_connection((host, port), timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    if tls_sock.version():
                        accepted.append(label)
        except Exception:  # noqa: BLE001 - handshake refused == version not accepted
            continue
    return accepted


def _days_to_expiry(not_after: str | None) -> int | None:
    if not not_after:
        return None
    import ssl
    from datetime import UTC, datetime

    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return (expires - datetime.now(UTC)).days


def _plaintext_http_served(host: str) -> bool | None:
    """True if http:// serves content without redirecting to HTTPS; None if undetermined."""
    try:
        gate = TargetGate(f"http://{host}", max_requests=3)
        response = gate.request("GET", "/")
    except GuardrailError:
        return None
    except Exception:  # noqa: BLE001 - no plaintext listener / connection refused
        return False
    status = response.status_code
    if 200 <= status < 300:
        return True
    if 300 <= status < 400:
        location = response.headers.get("location", "") or response.headers.get("Location", "")
        return not location.lower().startswith("https://")
    return None


def run_transport_probes(
    target: str,
    *,
    feed: EventFeed,
    gate=None,
) -> list[Finding]:
    """Gather transport facts about ``target`` and analyze them. Never raises into a scan."""
    parsed = urlparse(target)
    host = parsed.hostname or target
    authorization_error = host_authorization_error(host)
    if authorization_error:
        feed.emit("gate", f"Transport probe blocked for {host}: {authorization_error}")
        return []
    scheme = (parsed.scheme or "").lower()
    feed.emit("attack", f"Transport-security probe on {host} (read-only TLS + HSTS + downgrade check)")

    hsts_header = ""
    try:
        active_gate = gate or TargetGate(target, max_requests=3)
        response = active_gate.request("GET", "/")
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        hsts_header = headers.get("strict-transport-security", "")
    except Exception as error:  # noqa: BLE001
        feed.emit("red", f"Transport probe could not fetch {target}: {error}")

    tls: TlsInfo | None = None
    plaintext: bool | None = None
    if scheme == "https":
        tls = _inspect_tls(host, parsed.port or 443)
        plaintext = _plaintext_http_served(host)

    return analyze_transport(target, tls=tls, hsts_header=hsts_header, plaintext_http_served=plaintext)
