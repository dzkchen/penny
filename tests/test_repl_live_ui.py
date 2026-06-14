from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import penny.repl as repl_module
from penny.feed import EventFeed
from penny.repl import PrettyFeed, Session


def test_make_scan_feed_uses_pretty_feed_for_custom_printer(tmp_path) -> None:
    session = Session(out_dir=tmp_path, printer=lambda _text="": None)

    feed, live_dashboard = session._make_scan_feed()

    assert isinstance(feed, PrettyFeed)
    assert live_dashboard is False


def test_scan_uses_live_dashboard_in_interactive_shell(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}
    lines: list[str] = []

    class FakeLiveFeed(EventFeed):
        def __init__(self) -> None:
            super().__init__(quiet=True)
            self.entered = False

        def __enter__(self):
            self.entered = True
            return self

        def __exit__(self, *exc_info) -> bool:
            return False

    @contextmanager
    def fake_resolved_scan_source(path: str):
        yield Path(path)

    class FakeResult:
        payload = {"findings": [], "summary": {"total": 0}}
        findings_path = tmp_path / ".penny" / "runs" / "latest" / "findings.json"

    def fake_run_scan(resolved: Path, **kwargs):
        captured["resolved"] = resolved
        captured["feed"] = kwargs["feed"]
        return FakeResult()

    def fake_print_scan_summary(payload: dict, out_dir: Path, *, verbose: bool = False) -> None:
        captured["summary_payload"] = payload
        captured["summary_out_dir"] = out_dir
        captured["summary_verbose"] = verbose

    monkeypatch.setattr(repl_module, "LiveScanFeed", FakeLiveFeed)
    monkeypatch.setattr(repl_module, "resolved_scan_source", fake_resolved_scan_source)
    monkeypatch.setattr(repl_module, "run_scan", fake_run_scan)
    monkeypatch.setattr(repl_module, "print_scan_summary", fake_print_scan_summary)

    session = Session(out_dir=tmp_path)
    session.printer = lines.append

    session._scan([str(tmp_path)])

    assert isinstance(captured["feed"], FakeLiveFeed)
    assert captured["feed"].entered is True
    assert captured["summary_payload"] == FakeResult.payload
    assert captured["summary_out_dir"] == tmp_path
    assert not any("Scanning " in line for line in lines)
    assert not any("Use /show <id>" in line for line in lines)


def test_scan_uses_shared_summary_layout_for_custom_printer(monkeypatch, tmp_path) -> None:
    lines: list[str] = []

    @contextmanager
    def fake_resolved_scan_source(path: str):
        yield Path(path)

    class FakeResult:
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
        findings_path = tmp_path / ".penny" / "runs" / "latest" / "findings.json"

    def fake_run_scan(resolved: Path, **kwargs):
        kwargs["feed"].emit("scan", f"Walking {resolved}")
        return FakeResult()

    monkeypatch.setattr(repl_module, "resolved_scan_source", fake_resolved_scan_source)
    monkeypatch.setattr(repl_module, "run_scan", fake_run_scan)

    session = Session(out_dir=tmp_path, printer=lines.append)
    session._scan(["./next-vuln-fixture"])

    output = "\n".join(lines)
    assert "Scan complete" in output
    assert "Detector" in output
    assert "Hits" in output
    assert "Client-Controlled Header" in output
    assert "Walking" not in output
    assert "Use /show <id>" not in output


def test_audit_announces_full_audit_without_extra_notice(monkeypatch, tmp_path) -> None:
    session = Session(out_dir=tmp_path, printer=lambda _text="": None)
    session.target = None
    session.findings_path = tmp_path / "findings.json"
    session.payload = {"scan": {"source": "./fallback"}}

    lines: list[str] = []
    session.out = lines.append
    session._scan = lambda args, force=None: None
    session._report = lambda args, announce_path=True: None

    session._audit(["./next-vuln-fixture"])

    assert "Running FULL audit" in lines[0]
    assert not any("No target set" in line for line in lines)


def test_audit_suppresses_report_path_announcement(tmp_path) -> None:
    session = Session(out_dir=tmp_path, printer=lambda _text="": None)
    session.target = "http://localhost:3000"
    session.payload = {"scan": {"source": "./next-vuln-fixture"}}

    captured: dict[str, object] = {}
    lines: list[str] = []
    session.out = lines.append
    session._scan = lambda args, force=None: None
    session._report = lambda args, announce_path=True: captured.update(args=args, announce_path=announce_path)

    session._audit(["./next-vuln-fixture"])

    assert captured["announce_path"] is False
    assert any("Full audit complete" in line for line in lines)
