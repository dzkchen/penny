from __future__ import annotations

import json

import httpx

import penny.ask as ask_module
from penny import llm
from penny.ask import answer_question
from penny.feed import EventFeed
from penny.scanner import run_scan

from .conftest import ROOT


class _FakeResp:
    """Minimal stand-in for an httpx.Response used by llm.complete."""

    def __init__(self, payload: dict, *, status: int = 200, http_error: bool = False) -> None:
        self._payload = payload
        self.status_code = status
        self._http_error = http_error
        self.text = json.dumps(payload)

    def raise_for_status(self) -> None:
        if self._http_error:
            raise httpx.HTTPStatusError("err", request=httpx.Request("POST", "http://x"), response=self)

    def json(self) -> dict:
        return self._payload


def _with_key(monkeypatch) -> None:
    monkeypatch.setattr(llm, "_DOTENV_LOADED", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    monkeypatch.delenv("PENNY_DISABLE_LLM", raising=False)


def _findings_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    return result.findings_path


def test_complete_returns_none_without_key(monkeypatch) -> None:
    # Pretend the .env has already been loaded so the real key is never read.
    monkeypatch.setattr(llm, "_DOTENV_LOADED", True)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert llm.available() is False
    assert llm.complete("hello") is None


def test_complete_reports_timeout(monkeypatch) -> None:
    _with_key(monkeypatch)

    def boom(*args, **kwargs):
        raise httpx.TimeoutException("slow")

    monkeypatch.setattr(httpx, "post", boom)
    feed = EventFeed(quiet=True)
    assert llm.complete("hi", feed=feed) is None
    assert any("timed out" in event.message for event in feed.events)


def test_complete_reports_http_error_with_detail(monkeypatch) -> None:
    _with_key(monkeypatch)
    resp = _FakeResp({"error": {"message": "schema rejected"}}, status=400, http_error=True)
    monkeypatch.setattr(httpx, "post", lambda *a, **k: resp)
    feed = EventFeed(quiet=True)
    assert llm.complete("hi", feed=feed) is None
    assert any("400" in event.message and "schema rejected" in event.message for event in feed.events)


def test_complete_reports_refusal(monkeypatch) -> None:
    _with_key(monkeypatch)
    resp = _FakeResp({"stop_reason": "refusal", "content": []})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: resp)
    feed = EventFeed(quiet=True)
    assert llm.complete("hi", feed=feed) is None
    assert any("refus" in event.message.lower() for event in feed.events)


def test_complete_warns_when_structured_output_truncated(monkeypatch) -> None:
    # stop_reason=max_tokens with no text block is the AI-review "no usable response" cause.
    _with_key(monkeypatch)
    resp = _FakeResp({"stop_reason": "max_tokens", "content": []})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: resp)
    feed = EventFeed(quiet=True)
    assert llm.complete("hi", feed=feed, max_tokens=10) is None
    assert any("token" in event.message.lower() for event in feed.events)


def test_complete_returns_text_on_success(monkeypatch) -> None:
    _with_key(monkeypatch)
    resp = _FakeResp({"stop_reason": "end_turn", "content": [{"type": "text", "text": "hello world"}]})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: resp)
    assert llm.complete("hi") == "hello world"


def test_answer_question_falls_back_when_llm_unavailable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ask_module, "llm_available", lambda: False)
    findings_path = _findings_path(tmp_path, monkeypatch)

    answer = answer_question("What should Blue fix first?", findings_path=findings_path, use_llm=True)

    assert "Blue fix queue" in answer


def test_answer_question_uses_llm_answer_when_available(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ask_module, "llm_available", lambda: True)
    monkeypatch.setattr(ask_module, "llm_complete", lambda *args, **kwargs: "AI: fix F-001 first")
    findings_path = _findings_path(tmp_path, monkeypatch)

    answer = answer_question("Summarize the risk", findings_path=findings_path, use_llm=True)

    assert answer == "AI: fix F-001 first"


def test_answer_question_llm_failure_falls_back(tmp_path, monkeypatch) -> None:
    # complete() returns None on any API/network failure; the static answer is used.
    monkeypatch.setattr(ask_module, "llm_available", lambda: True)
    monkeypatch.setattr(ask_module, "llm_complete", lambda *args, **kwargs: None)
    findings_path = _findings_path(tmp_path, monkeypatch)

    answer = answer_question("What should Blue fix first?", findings_path=findings_path, use_llm=True)

    assert "Blue fix queue" in answer
