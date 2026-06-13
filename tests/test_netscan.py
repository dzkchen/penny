from __future__ import annotations

from penny.feed import EventFeed
from penny.netscan import run_port_scan


def _scan(open_ports: set[int], *, target: str = "http://10.1.2.3:8000", i_own_this: bool = False) -> list:
    """Run the port scan with an injected connect() so no real sockets are opened."""

    def connect(host: str, port: int, timeout: float) -> bool:
        return port in open_ports

    return run_port_scan(target, i_own_this=i_own_this, feed=EventFeed(quiet=True), connect=connect)


def test_unauthenticated_datastore_is_critical() -> None:
    findings = _scan({80, 3306, 6379})
    ids = {f.detector_id for f in findings}
    assert ids == {"N001", "N002"}

    risky = next(f for f in findings if f.detector_id == "N002")
    assert risky.severity == "Critical"  # redis drives it to Critical
    services = {item["service"] for item in risky.evidence["dynamic_probe"]["risky_services"]}
    assert services == {"mysql", "redis"}


def test_database_without_datastore_is_high() -> None:
    risky = next(f for f in _scan({5432}) if f.detector_id == "N002")
    assert risky.severity == "High"


def test_only_benign_web_ports_yield_inventory_only() -> None:
    findings = _scan({80, 443})
    assert [f.detector_id for f in findings] == ["N001"]
    assert findings[0].severity == "Info"
    ports = {item["port"] for item in findings[0].evidence["dynamic_probe"]["open_ports"]}
    assert ports == {80, 443}


def test_no_open_ports_yields_nothing() -> None:
    assert _scan(set()) == []


def test_public_host_requires_ownership() -> None:
    # 8.8.8.8 is a public IP literal (no DNS lookup) so the gate must block it.
    assert _scan({6379}, target="http://8.8.8.8") == []


def test_public_ip_literal_stays_blocked_even_with_ownership() -> None:
    assert _scan({6379}, target="http://8.8.8.8", i_own_this=True) == []
