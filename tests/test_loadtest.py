from __future__ import annotations

from penny.feed import EventFeed
from penny.loadtest import CEILING_CONCURRENCY, run_load_test


def _feed() -> EventFeed:
    return EventFeed(quiet=True)


def test_load_test_blocks_public_host_without_ownership() -> None:
    # 8.8.8.8 is public; without --i-own-this the gate must refuse (no DNS needed).
    findings = run_load_test("http://8.8.8.8", i_own_this=False, feed=_feed(), fetch=lambda url, t: (200, 0.01))
    assert findings == []


def test_load_test_healthy_target_reports_info_profile() -> None:
    findings = run_load_test(
        "http://127.0.0.1:9", i_own_this=False, feed=_feed(),
        fetch=lambda url, t: (200, 0.01), max_concurrency=10, max_total_requests=500,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "A014"
    assert finding.severity == "Info"
    assert finding.evidence["dynamic_probe"]["knee_concurrency"] is None


def test_load_test_flags_fragile_target() -> None:
    # Server returns 500 for everything: error knee at concurrency 1 => fragile.
    findings = run_load_test(
        "http://127.0.0.1:9", i_own_this=False, feed=_feed(),
        fetch=lambda url, t: (503, 0.01), max_concurrency=10, max_total_requests=500,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "Medium"
    assert finding.status == "confirmed"
    assert finding.evidence["dynamic_probe"]["knee_concurrency"] == 1


def test_load_test_clamps_concurrency_to_request_cap() -> None:
    findings = run_load_test(
        "http://127.0.0.1:9", i_own_this=False, feed=_feed(),
        fetch=lambda url, t: (200, 0.01), max_concurrency=5, max_total_requests=500,
    )
    ladder = findings[0].evidence["dynamic_probe"]["ladder"]
    assert max(stage["concurrency"] for stage in ladder) <= 5
    assert max(stage["concurrency"] for stage in ladder) <= CEILING_CONCURRENCY
