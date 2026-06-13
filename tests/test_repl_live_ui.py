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
    assert any("Use /show <id>" in line for line in lines)
