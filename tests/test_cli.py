from __future__ import annotations

import builtins
from contextlib import contextmanager
from pathlib import Path

import pytest

import penny.cli as cli
from penny.cli import _ask_loop, _enforce_fail_on, _github_fix_command, _report_command, _resolve_findings_path, _run_scan_command
from penny.feed import EventFeed
from penny.live import LiveScanFeed
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


def test_run_scan_command_uses_live_feed_and_forwards_options(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}

    @contextmanager
    def fake_resolved_scan_source(path: str):
        captured["source_label"] = path
        yield tmp_path / "resolved-target"

    class FakeResult:
        payload = {"findings": [], "summary": {"total": 0}}
        findings_path = tmp_path / ".penny" / "runs" / "latest" / "findings.json"

    def fake_run_scan(resolved: Path, **kwargs):
        captured["resolved"] = resolved
        captured["kwargs"] = kwargs
        return FakeResult()

    monkeypatch.setattr(cli, "resolved_scan_source", fake_resolved_scan_source)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)

    result, feed = _run_scan_command(
        "./demo-app",
        target="http://localhost:3000",
        static_only=True,
        out=tmp_path,
        i_own_this=True,
        osv=True,
        ai=True,
        active=True,
        fail_on=None,
        diff="main",
        endpoint=["/api/orders?id=1"],
        agentic=True,
        brute=True,
        browser=True,
        netscan=True,
        load_test=True,
        i_accept=True,
        wordlist="words.txt",
        pages=12,
        verbose=False,
    )

    assert isinstance(feed, LiveScanFeed)
    assert result.findings_path == FakeResult.findings_path
    assert captured["source_label"] == "./demo-app"
    assert captured["resolved"] == tmp_path / "resolved-target"
    kwargs = captured["kwargs"]
    assert kwargs["feed"] is feed
    assert kwargs["source_label"] == "./demo-app"
    assert kwargs["static_only"] is True
    assert kwargs["use_osv"] is True
    assert kwargs["use_ai"] is True
    assert kwargs["use_active"] is True
    assert kwargs["diff_base"] == "main"
    assert kwargs["endpoints"] == ["/api/orders?id=1"]
    assert kwargs["browser"] is True
    assert kwargs["netscan"] is True


def test_github_fix_command_uses_live_feed(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}

    def fake_github_fix_roundtrip(source: str, *, workdir: Path, branch: str, auto_yes: bool, push: bool, feed):
        captured["source"] = source
        captured["workdir"] = workdir
        captured["branch"] = branch
        captured["auto_yes"] = auto_yes
        captured["push"] = push
        captured["feed"] = feed
        return {"scan_payload": {"findings": [], "summary": {"total": 0}}}

    import penny.github_fix as github_fix_module

    monkeypatch.setattr(github_fix_module, "github_fix_roundtrip", fake_github_fix_roundtrip)

    _github_fix_command("owner/repo", tmp_path, "penny/fixes", True, False, EventFeed(quiet=True))

    assert captured["source"] == "owner/repo"
    assert captured["workdir"] == tmp_path
    assert captured["branch"] == "penny/fixes"
    assert captured["auto_yes"] is True
    assert captured["push"] is False
    assert isinstance(captured["feed"], LiveScanFeed)


def test_report_command_can_suppress_extra_output(monkeypatch, tmp_path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text('{"session_id":"demo","summary":{"total":0},"findings":[]}', encoding="utf-8")
    feed = EventFeed(quiet=True)

    monkeypatch.setattr(cli, "generate_report", lambda payload, use_llm=False: "# Penny Security Report\n\n## 1. Purple-Team Verdict\n\nClean.\n\n## 2. Executive Summary\n")

    _report_command(findings, tmp_path, feed, announce=False)

    assert not feed.events
