from __future__ import annotations

import builtins

from penny.cli import _ask_loop
from penny.feed import EventFeed
from penny.scanner import run_scan

from .conftest import ROOT


def test_ask_loop_exits_cleanly(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    answers = iter(["What should Blue fix first?", "quit"])
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    feed = EventFeed(quiet=True)

    _ask_loop(result.findings_path, None, False, feed)

    assert any("Interactive ask mode" in event.message for event in feed.events)
    assert any("Blue fix queue" in event.message for event in feed.events)
