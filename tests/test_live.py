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
    feed.emit("red", "D012 hit in src/a.ts:1")
    feed._expanded = True
    buffer = io.StringIO()
    Console(file=buffer, force_terminal=True, width=80).print(feed)  # invokes __rich__
    output = buffer.getvalue()
    assert "penny" in output and "D012" in output


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


def test_print_scan_summary_clean_scan(capsys) -> None:
    print_scan_summary({"findings": [], "summary": {"total": 0}}, Path("."))
    assert "clean scan" in capsys.readouterr().out.lower()
