"""Bounded TCP-connect port scan for owned/consented targets.

This is a network-level companion to the HTTP probes: instead of asking *what
does the web app do*, it asks *what services on this host are reachable from the
network at all*. A datastore (Redis, MongoDB, Elasticsearch, Memcached) or a
management surface (RDP, VNC, Docker API) that answers on a public interface is
frequently unauthenticated and is a far bigger problem than any single web bug.

Safety mirrors :class:`~penny.guardrails.TargetGate`:

* localhost/private hosts are allowed by default; any public host requires a
  matching DNS TXT proof record (enforced via
  :func:`penny.guardrails.host_authorization_error`).
* It is a plain TCP *connect* scan — it opens a socket and immediately closes it.
  Nothing is written to the port, so it never sends a payload to a service.
* The port list is a fixed, curated set of common services; short timeouts keep
  it quick and unobtrusive.

The socket layer is injected (``connect``) so the classification logic is unit
tested offline without touching the network.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import host_authorization_error
from .models import Finding, Location
from .redaction import redact_text

# Probe every port concurrently. A sequential scan blocks the full `timeout` on
# each firewalled/dropped port, so N filtered ports cost ~N*timeout; one connect
# per thread collapses that to ~a single timeout of wall-clock. Capped so a custom
# port list can't spawn an unbounded number of threads.
MAX_SCAN_WORKERS = 32

# Curated common-service ports. Kept deliberately small so the scan stays quick
# and clearly bounded rather than a full 65k sweep.
DEFAULT_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2375: "docker",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Service exposure risk. Datastores and caches are routinely deployed with no
# authentication and assume a private network, so reachability == Critical. DB
# and remote-management surfaces are High; legacy plaintext protocols are Medium.
_CRITICAL_SERVICES = {"redis", "mongodb", "memcached", "elasticsearch"}
_HIGH_SERVICES = {"mysql", "postgres", "mssql", "oracle", "docker", "vnc", "rdp", "smb"}
_MEDIUM_SERVICES = {"ftp", "telnet", "pop3", "imap", "smtp"}

_SERVICE_NOTE = {
    "redis": "Redis usually ships with no authentication; network reachability often means full read/write.",
    "mongodb": "MongoDB bound to a public interface has historically exposed entire databases unauthenticated.",
    "memcached": "Memcached has no auth and is abusable for data theft and UDP reflection/amplification.",
    "elasticsearch": "Elasticsearch exposes indices and a query API with no auth by default.",
    "mysql": "A reachable database port lets attackers attempt credential and CVE attacks directly.",
    "postgres": "A reachable database port lets attackers attempt credential and CVE attacks directly.",
    "mssql": "A reachable database port lets attackers attempt credential and CVE attacks directly.",
    "oracle": "A reachable database port lets attackers attempt credential and CVE attacks directly.",
    "docker": "An exposed Docker API (2375) is remote code execution / host takeover.",
    "vnc": "VNC exposes an interactive desktop; weak/no auth is full host access.",
    "rdp": "RDP is a top brute-force and CVE target when reachable from untrusted networks.",
    "smb": "SMB exposed to untrusted networks is a frequent ransomware and lateral-movement vector.",
    "ftp": "FTP and Telnet transmit credentials in cleartext and are trivially sniffed.",
    "telnet": "FTP and Telnet transmit credentials in cleartext and are trivially sniffed.",
}


def _risk_for(service: str) -> str | None:
    if service in _CRITICAL_SERVICES:
        return "Critical"
    if service in _HIGH_SERVICES:
        return "High"
    if service in _MEDIUM_SERVICES:
        return "Medium"
    return None


def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


# --- Banner grabbing -------------------------------------------------------
#
# A connect scan only proves a port is open. A banner grab upgrades that to *what*
# is listening and, for the unauthenticated-datastore case, whether it answers
# without credentials — i.e. "Redis 6.2, no auth" instead of "6379 open". We send a
# single, minimal, read-only command per service (or nothing, for services that
# announce themselves on connect) and read a small, capped response. Nothing is
# written that changes state: `INFO` / `version` / `GET` only read.

# Cap how much we read so a chatty or hostile service cannot stream unbounded data.
_BANNER_READ_BYTES = 2048

# Per-service connect-time probe. Empty bytes => the service speaks first (SSH, FTP,
# SMTP, etc.), so we just read. Each non-empty probe is a read-only status command.
_SERVICE_PROBES: dict[str, bytes] = {
    "redis": b"INFO\r\n",
    "memcached": b"version\r\n",
    "http": b"GET / HTTP/1.0\r\n\r\n",
    "http-alt": b"GET / HTTP/1.0\r\n\r\n",
    "http-proxy": b"GET / HTTP/1.0\r\n\r\n",
    "elasticsearch": b"GET / HTTP/1.0\r\n\r\n",
    "docker": b"GET /version HTTP/1.0\r\n\r\n",
    "mongodb": b"GET / HTTP/1.0\r\n\r\n",  # Mongo replies with an HTTP hint on the wire port
}


def _grab_banner(host: str, port: int, service: str, timeout: float) -> str:
    """Connect, send one read-only probe (if any), and return a small decoded banner.

    Returns ``""`` on any socket error so a flaky or filtered port never breaks the
    scan. Only reads; the per-service probe is a status/INFO/GET command.
    """
    probe = _SERVICE_PROBES.get(service, b"")
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    return ""
            chunks: list[bytes] = []
            received = 0
            try:
                while received < _BANNER_READ_BYTES:
                    data = sock.recv(min(1024, _BANNER_READ_BYTES - received))
                    if not data:
                        break
                    chunks.append(data)
                    received += len(data)
            except OSError:
                pass
    except OSError:
        return ""
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


# (regex, product label) pairs run against the banner to extract a product + version.
# Ordered most-specific first. The version group, when present, is appended.
_BANNER_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"redis_version:([0-9][0-9.]*)", re.I), "Redis"),
    (re.compile(r"^VERSION ([0-9][0-9.]*)", re.I | re.M), "Memcached"),
    (re.compile(r"\bSSH-[0-9.]+-(\S+)", re.I), "SSH"),
    (re.compile(r'"number"\s*:\s*"([0-9][0-9.]*)"'), "Elasticsearch"),  # ES version JSON
    (re.compile(r"\bServer:\s*([^\r\n]+)", re.I), "HTTP server"),
    (re.compile(r"\bDocker/([0-9][0-9.]*)", re.I), "Docker"),
    (re.compile(r"\b220[- ].*?\b(ProFTPD|vsFTPd|Pure-FTPd|FileZilla|Microsoft FTP)[^\r\n]*", re.I), "FTP"),
    (re.compile(r"\b220[- ]([^\r\n]*?(?:SMTP|Postfix|Exim|Sendmail)[^\r\n]*)", re.I), "SMTP"),
    (re.compile(r"\bMySQL\b", re.I), "MySQL"),
    (re.compile(r"\bmongodb\b|It looks like you are trying to access MongoDB", re.I), "MongoDB"),
)
# Authentication-required signatures: their presence means the datastore is NOT open.
# Used to flag the high-value "reachable AND unauthenticated" case precisely.
_AUTH_REQUIRED_RE = re.compile(
    r"\bNOAUTH\b|authentication required|-ERR.*auth|access denied|401 Unauthorized|"
    r"unauthorized|requires authentication|command denied",
    re.I,
)
# Datastore services where an INFO/version reply with real data (no auth error) is
# itself proof of unauthenticated access — the headline upgrade for the scan.
_UNAUTH_PROOF_SERVICES = {"redis", "memcached", "elasticsearch", "mongodb"}


def _parse_banner(service: str, banner: str) -> dict[str, str | bool]:
    """Turn a raw banner into {product, version, auth} hints. Empty dict if nothing."""
    if not banner:
        return {}
    info: dict[str, str | bool] = {}
    for pattern, product in _BANNER_SIGNATURES:
        match = pattern.search(banner)
        if not match:
            continue
        info["product"] = product
        if match.groups():
            captured = match.group(1).strip()
            if captured:
                info["version"] = redact_text(captured)[:60]
        break
    auth_required = bool(_AUTH_REQUIRED_RE.search(banner))
    if auth_required:
        # An explicit auth challenge is conclusive for any service.
        info["unauthenticated"] = False
    elif service in _UNAUTH_PROOF_SERVICES and info.get("product"):
        # For a datastore we only claim "no auth" on an *affirmative* application-level
        # reply we recognized (a parsed product signature) with no auth error — e.g.
        # Redis answering INFO with `redis_version:`. We deliberately do NOT infer
        # "no auth" from unrecognized bytes: some datastores (notably MongoDB on its
        # 27017 wire port) return binary noise to our probe, and treating that as an
        # open datastore would wrongly escalate an authenticated server to Critical.
        info["unauthenticated"] = True
    return info


def _describe_service(service: str, banner_info: dict[str, str | bool]) -> str:
    """Human-readable upgrade, e.g. 'Redis 6.2, no auth' from a parsed banner."""
    product = str(banner_info.get("product") or service)
    version = banner_info.get("version")
    label = f"{product} {version}" if version else product
    if banner_info.get("unauthenticated") is True:
        label += ", no auth"
    elif banner_info.get("unauthenticated") is False:
        label += ", auth required"
    return label


def run_port_scan(
    target: str,
    *,
    feed: EventFeed,
    ports: dict[int, str] | None = None,
    timeout: float = 0.6,
    connect: Callable[[str, int, float], bool] | None = None,
    grab_banner: Callable[[str, int, str, float], str] | None = None,
    banners: bool = True,
) -> list[Finding]:
    """Scan ``target``'s host for reachable common services. Read-only connect scan.

    When ``banners`` is set (the default), each *open* port is followed up with a
    single read-only banner grab to identify the product/version and, for datastores,
    whether it answers without authentication — upgrading "6379 open" to
    "Redis 6.2, no auth". The banner grabber is injectable for offline tests.
    """
    host = urlparse(target).hostname or target
    authorization_error = host_authorization_error(host)
    if authorization_error:
        feed.emit("gate", f"Port scan blocked for {host}: {authorization_error}")
        return []
    ports = ports or DEFAULT_PORTS
    connect = connect or _tcp_connect
    grab_banner = grab_banner or _grab_banner
    feed.emit("attack", f"Port scan on {host} ({len(ports)} common ports, connect-only)")

    def probe(port: int) -> tuple[int, bool]:
        try:
            return port, connect(host, port, timeout)
        except Exception:  # noqa: BLE001 - a flaky socket must never crash the scan
            return port, False

    # `pool.map` yields results in input order, so the "open:" lines below still
    # emit in ascending port order — same output as the old sequential scan, but
    # the connects all happen in parallel.
    scan_ports = sorted(ports)
    with ThreadPoolExecutor(max_workers=max(1, min(len(scan_ports), MAX_SCAN_WORKERS))) as pool:
        results = list(pool.map(probe, scan_ports))

    open_ports: dict[int, str] = {}
    for port, is_open in results:
        if is_open:
            open_ports[port] = ports[port]

    banner_info: dict[int, dict[str, str | bool]] = {}
    if banners and open_ports:
        # Banner-grab the open ports in parallel; a longer per-socket timeout than the
        # connect scan since some services are slow to speak. Failures degrade to no
        # banner — the port is still reported, just without product/version detail.
        banner_timeout = max(timeout, 1.5)

        def fetch(item: tuple[int, str]) -> tuple[int, dict[str, str | bool]]:
            port, service = item
            try:
                raw = grab_banner(host, port, service, banner_timeout)
                # Parse inside the guard too: a flaky banner grab OR an unexpected
                # parse error must never crash the scan, only drop the banner.
                return port, _parse_banner(service, raw)
            except Exception:  # noqa: BLE001
                return port, {}

        with ThreadPoolExecutor(max_workers=max(1, min(len(open_ports), MAX_SCAN_WORKERS))) as pool:
            banner_info = dict(pool.map(fetch, sorted(open_ports.items())))

    for port in sorted(open_ports):
        service = open_ports[port]
        described = _describe_service(service, banner_info.get(port, {}))
        feed.emit("red", f"  open: {port}/{service} ({described})")

    return _classify_open_ports(host, open_ports, banner_info, feed=feed)


def _classify_open_ports(
    host: str,
    open_ports: dict[int, str],
    banner_info: dict[int, dict[str, str | bool]] | None = None,
    *,
    feed: EventFeed | None = None,
) -> list[Finding]:
    if not open_ports:
        if feed:
            feed.emit("red", "Port scan found no reachable services on the common-port list")
        return []

    banner_info = banner_info or {}

    def _enrich(port: int, entry: dict) -> dict:
        info = banner_info.get(port) or {}
        if info.get("product"):
            entry["product"] = info["product"]
        if info.get("version"):
            entry["version"] = info["version"]
        if "unauthenticated" in info:
            entry["unauthenticated"] = info["unauthenticated"]
        return entry

    findings: list[Finding] = []
    inventory = [_enrich(port, {"port": port, "service": service}) for port, service in sorted(open_ports.items())]

    risky: list[dict[str, str | int]] = []
    severities: list[str] = []
    for port, service in sorted(open_ports.items()):
        risk = _risk_for(service)
        if risk:
            info = banner_info.get(port) or {}
            # A datastore we confirmed answers without authentication is the worst
            # case: escalate it to Critical regardless of the base service tier.
            if info.get("unauthenticated") is True:
                risk = "Critical"
            severities.append(risk)
            entry = {
                "port": port,
                "service": service,
                "severity": risk,
                "note": _SERVICE_NOTE.get(service, ""),
            }
            risky.append(_enrich(port, entry))

    if risky:
        severity = _highest(severities)
        services = ", ".join(
            f"{item['port']}/{_describe_service(str(item['service']), banner_info.get(int(item['port']), {}))}"
            for item in risky
        )
        findings.append(
            Finding(
                title="Sensitive network service reachable on target host",
                severity=severity,
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="N002",
                owasp=[
                    "A05:2021-Security Misconfiguration",
                    "WSTG-CONF-01",
                ],
                location=Location(file=f"network:{host}", line=1, column=1),
                snippet=f"Reachable sensitive service(s): {services}.",
                evidence={
                    "dynamic_probe": {
                        "probe": "port_scan",
                        "status": "confirmed",
                        "host": host,
                        "risky_services": risky,
                        "stored_response": "host, open ports, service guesses, and parsed banner product/version/auth only",
                    },
                    "attack_path": "Datastores, caches, and management services exposed to the network are frequently unauthenticated and bypass the application's access controls entirely.",
                },
                impact="A reachable datastore or management port can expose or let an attacker tamper with all data, or take over the host, without ever touching the web app.",
                remediation="Bind these services to localhost or a private network, put them behind a firewall/security group, and require authentication. Never expose databases, caches, or admin daemons to untrusted networks.",
            )
        )

    findings.append(
        Finding(
            title="Open network ports on target host",
            severity="Info",
            confidence="high",
            status="informational",
            source="dynamic",
            detector_id="N001",
            owasp=["WSTG-INFO-01"],
            location=Location(file=f"network:{host}", line=1, column=1),
            snippet=f"{len(inventory)} reachable port(s) on {host}.",
            evidence={
                "dynamic_probe": {
                    "probe": "port_scan",
                    "status": "informational",
                    "host": host,
                    "open_ports": inventory,
                    "stored_response": "host, open ports, and service guesses only",
                },
            },
            impact="Each reachable service is attack surface; minimize what is exposed to the network.",
            remediation="Close or firewall ports that do not need to be reachable from this network.",
        )
    )
    return findings


def _highest(severities: list[str]) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return max(severities, key=lambda value: order.get(value, 0)) if severities else "Info"
