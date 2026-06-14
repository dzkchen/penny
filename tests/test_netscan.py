from __future__ import annotations

from penny.feed import EventFeed
from penny.netscan import (
    _describe_service,
    _grab_banner,
    _parse_banner,
    run_port_scan,
)


def _scan(
    open_ports: set[int],
    *,
    target: str = "http://10.1.2.3:8000",
    i_own_this: bool = False,
    banners: bool = False,
    grab_banner=None,
) -> list:
    """Run the port scan with an injected connect() so no real sockets are opened."""

    def connect(host: str, port: int, timeout: float) -> bool:
        return port in open_ports

    return run_port_scan(
        target,
        i_own_this=i_own_this,
        feed=EventFeed(quiet=True),
        connect=connect,
        banners=banners,
        grab_banner=grab_banner,
    )


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


# --- Banner grabbing -------------------------------------------------------


def test_parse_banner_extracts_redis_version_and_no_auth() -> None:
    info = _parse_banner("redis", "# Server\r\nredis_version:6.2.6\r\nuptime:99\r\n")
    assert info["product"] == "Redis"
    assert info["version"] == "6.2.6"
    assert info["unauthenticated"] is True


def test_parse_banner_marks_redis_auth_required() -> None:
    info = _parse_banner("redis", "-NOAUTH Authentication required.\r\n")
    assert info.get("unauthenticated") is False


def test_describe_service_upgrades_to_product_version_no_auth() -> None:
    info = {"product": "Redis", "version": "6.2.6", "unauthenticated": True}
    assert _describe_service("redis", info) == "Redis 6.2.6, no auth"


def test_banner_grab_upgrades_finding_and_escalates_to_critical() -> None:
    # mysql alone is High; an UNAUTHENTICATED redis banner must drive it to Critical.
    def grab_banner(host, port, service, timeout):
        if service == "redis":
            return "redis_version:6.2.6\r\nrole:master\r\n"
        return ""

    findings = _scan({3306, 6379}, banners=True, grab_banner=grab_banner)
    risky = next(f for f in findings if f.detector_id == "N002")
    assert risky.severity == "Critical"

    redis_entry = next(
        item for item in risky.evidence["dynamic_probe"]["risky_services"] if item["service"] == "redis"
    )
    assert redis_entry["product"] == "Redis"
    assert redis_entry["version"] == "6.2.6"
    assert redis_entry["unauthenticated"] is True
    assert redis_entry["severity"] == "Critical"
    # The human-readable summary carries the upgrade.
    assert "Redis 6.2.6, no auth" in risky.snippet


def test_banner_grab_failure_degrades_gracefully() -> None:
    # A banner grab that always fails (empty) must still report the open port.
    findings = _scan({6379}, banners=True, grab_banner=lambda *a: "")
    risky = next(f for f in findings if f.detector_id == "N002")
    assert risky.severity == "Critical"  # redis itself is Critical-tier by service
    redis_entry = risky.evidence["dynamic_probe"]["risky_services"][0]
    assert "product" not in redis_entry  # no banner parsed, but the port is still flagged


def test_default_grab_banner_handles_unreachable_port() -> None:
    # No listener on this port/host: the real grabber must return "" not raise.
    assert _grab_banner("127.0.0.1", 1, "redis", 0.2) == ""


def test_unrecognized_datastore_bytes_do_not_claim_no_auth() -> None:
    # MongoDB's 27017 wire port returns binary noise to our HTTP probe. With no parsed
    # product signature, we must NOT infer "unauthenticated" (which would wrongly
    # escalate an authenticated server to Critical).
    info = _parse_banner("mongodb", "\x00\x01\x02 some binary noise \xff\xfe")
    assert "unauthenticated" not in info
    assert "product" not in info


def test_recognized_mongodb_http_hint_is_parsed() -> None:
    # The legacy HTTP-on-wire-port hint IS a recognized signature → product set.
    info = _parse_banner("mongodb", "It looks like you are trying to access MongoDB over HTTP on the native driver port.")
    assert info["product"] == "MongoDB"
    assert info["unauthenticated"] is True


def test_explicit_auth_error_marks_authenticated_even_for_datastore() -> None:
    info = _parse_banner("elasticsearch", '{"error":"401 Unauthorized","status":401}')
    assert info.get("unauthenticated") is False
