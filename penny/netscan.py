"""Bounded TCP-connect port scan for owned/consented targets.

This is a network-level companion to the HTTP probes: instead of asking *what
does the web app do*, it asks *what services on this host are reachable from the
network at all*. A datastore (Redis, MongoDB, Elasticsearch, Memcached) or a
management surface (RDP, VNC, Docker API) that answers on a public interface is
frequently unauthenticated and is a far bigger problem than any single web bug.

Safety mirrors :class:`~penny.guardrails.TargetGate`:

* localhost/private hosts are allowed by default; any public host requires
  ``i_own_this`` (enforced via :func:`penny.guardrails.host_allowed`).
* It is a plain TCP *connect* scan — it opens a socket and immediately closes it.
  Nothing is written to the port, so it never sends a payload to a service.
* The port list is a fixed, curated set of common services; short timeouts keep
  it quick and unobtrusive.

The socket layer is injected (``connect``) so the classification logic is unit
tested offline without touching the network.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import host_allowed
from .models import Finding, Location

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


def run_port_scan(
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    ports: dict[int, str] | None = None,
    timeout: float = 0.6,
    connect: Callable[[str, int, float], bool] | None = None,
) -> list[Finding]:
    """Scan ``target``'s host for reachable common services. Read-only connect scan."""
    host = urlparse(target).hostname or target
    if not host_allowed(host, i_own_this):
        feed.emit("gate", f"Port scan blocked for {host}: public hosts require --i-own-this")
        return []
    ports = ports or DEFAULT_PORTS
    connect = connect or _tcp_connect
    feed.emit("attack", f"Port scan on {host} ({len(ports)} common ports, connect-only)")

    open_ports: dict[int, str] = {}
    for port in sorted(ports):
        try:
            is_open = connect(host, port, timeout)
        except Exception:  # noqa: BLE001 - a flaky socket must never crash the scan
            continue
        if is_open:
            service = ports[port]
            open_ports[port] = service
            feed.emit("red", f"  open: {port}/{service}")
    return _classify_open_ports(host, open_ports, feed=feed)


def _classify_open_ports(host: str, open_ports: dict[int, str], *, feed: EventFeed | None = None) -> list[Finding]:
    if not open_ports:
        if feed:
            feed.emit("red", "Port scan found no reachable services on the common-port list")
        return []

    findings: list[Finding] = []
    inventory = [{"port": port, "service": service} for port, service in sorted(open_ports.items())]

    risky: list[dict[str, str | int]] = []
    severities: list[str] = []
    for port, service in sorted(open_ports.items()):
        risk = _risk_for(service)
        if risk:
            severities.append(risk)
            risky.append(
                {
                    "port": port,
                    "service": service,
                    "severity": risk,
                    "note": _SERVICE_NOTE.get(service, ""),
                }
            )

    if risky:
        severity = _highest(severities)
        services = ", ".join(f"{item['port']}/{item['service']}" for item in risky)
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
                        "stored_response": "host, open ports, and service guesses only",
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
