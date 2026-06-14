from __future__ import annotations

import io
from pathlib import Path

from penny.live import LiveScanFeed, print_scan_summary


def test_feed_collapses_findings_and_records_events() -> None:
    feed = LiveScanFeed()
    feed.emit("red", "D012 hit in src/a.ts:1")
    feed.emit("red", "D012 hit in src/b.ts:2")
    feed.emit("red", "D020 hit in src/c.ts:9")
    feed.emit("scan", "Walking /repo")

    assert feed._dets["D012"] == ["src/a.ts:1", "src/b.ts:2"]
    assert feed._dets["D020"] == ["src/c.ts:9"]
    # All events are still recorded for downstream consumers.
    assert any(event.channel == "scan" for event in feed.events)
    assert sum(len(v) for v in feed._dets.values()) == 3


def test_feed_keeps_non_hit_red_lines_as_log() -> None:
    feed = LiveScanFeed()
    feed.emit("red", "Confirmed SQL injection at /api?id")
    # Probe results are not "X hit in Y", so they're not collapsed into detectors.
    assert not feed._dets
    assert any("Confirmed SQL injection" in event.message for event in feed.events)


def test_rich_render_does_not_raise() -> None:
    from rich.console import Console

    feed = LiveScanFeed()
    feed.emit("scan", "Walking /repo")
    feed.emit("scan", "Loaded 13 source file(s)")
    feed.emit("osv", "OSV review: 1 vulnerable dependency package(s)")
    feed.emit("ai", "AI review sending 10 source file(s) to claude-sonnet-4-6")
    feed.emit("red", "D012 hit in src/a.ts:1")
    feed._expanded = True
    feed._ctrlo = True
    buffer = io.StringIO()
    Console(file=buffer, force_terminal=True, width=80).print(feed)  # invokes __rich__
    output = buffer.getvalue()
    assert "penny" in output and "D012" in output
    assert "Walking /repo" not in output
    assert "────" in output
    assert "OSV review" in output
    assert "AI review sending" in output
    assert "ctrl-o collapse" in output
    assert "ctrl-c cancel" in output


def test_print_scan_summary_renders(capsys) -> None:
    payload = {
        "findings": [
            {
                "id": "F-001",
                "severity": "Critical",
                "detector_id": "D001",
                "title": "Client-visible credential",
                "location": {"file": "a.ts", "line": 5},
                "status": "suspected",
            }
        ],
        "summary": {"total": 1, "by_severity": {"Critical": 1}, "confirmed_count": 0},
    }
    print_scan_summary(payload, Path("."), verbose=True)
    out = capsys.readouterr().out
    assert "Scan complete" in out
    assert "D001" in out
    assert "a.ts:5" in out  # verbose expansion lists the location
    assert "Detector" in out
    assert "Hits" in out


def test_print_scan_summary_keeps_long_titles_visible(capsys) -> None:
    payload = {
        "findings": [
            {
                "id": "F-001",
                "severity": "Critical",
                "detector_id": "AI001",
                "title": "Broken Access Control: Admin Privilege Escalation via Client-Controlled Header",
                "location": {"file": "app/api/admin/promote/route.ts", "line": 6},
                "status": "suspected",
            }
        ],
        "summary": {"total": 1, "by_severity": {"Critical": 1}, "confirmed_count": 0},
    }
    print_scan_summary(payload, Path("."))
    out = capsys.readouterr().out
    assert "Client-Controlled Header" in out
    assert "Next:" not in out
    assert "Tip:" not in out
    assert "Use /show" not in out
    assert "Detector" in out


def test_print_scan_summary_clean_scan(capsys) -> None:
    print_scan_summary({"findings": [], "summary": {"total": 0}}, Path("."))
    assert "clean scan" in capsys.readouterr().out.lower()
