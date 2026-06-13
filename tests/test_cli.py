from __future__ import annotations

import builtins

import pytest

from penny.cli import _ask_loop, _enforce_fail_on, _resolve_findings_path
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


def test_enforce_fail_on_trips_on_threshold() -> None:
    payload = {"findings": [{"severity": "High"}, {"severity": "Low"}]}
    with pytest.raises(SystemExit) as exc:
        _enforce_fail_on(payload, "high", EventFeed(quiet=True))
    assert exc.value.code == 1


def test_enforce_fail_on_passes_below_threshold() -> None:
    payload = {"findings": [{"severity": "Low"}, {"severity": "Medium"}]}
    _enforce_fail_on(payload, "critical", EventFeed(quiet=True))  # must not raise


def test_enforce_fail_on_noop_when_unset() -> None:
    payload = {"findings": [{"severity": "Critical"}]}
    _enforce_fail_on(payload, None, EventFeed(quiet=True))  # must not raise


def test_enforce_fail_on_rejects_bad_threshold() -> None:
    with pytest.raises(SystemExit) as exc:
        _enforce_fail_on({"findings": []}, "bogus", EventFeed(quiet=True))
    assert exc.value.code == 2


def test_resolve_findings_path_prefers_out_run_tree(tmp_path) -> None:
    latest = tmp_path / ".penny" / "runs" / "latest" / "findings.json"
    latest.parent.mkdir(parents=True)
    latest.write_text("{}", encoding="utf-8")
    assert _resolve_findings_path(None, tmp_path) == latest


def test_resolve_findings_path_honours_explicit(tmp_path) -> None:
    explicit = tmp_path / "custom.json"
    assert _resolve_findings_path(explicit, tmp_path) == explicit
