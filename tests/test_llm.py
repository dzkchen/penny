from __future__ import annotations

import penny.ask as ask_module
from penny import llm
from penny.ask import answer_question
from penny.feed import EventFeed
from penny.scanner import run_scan

from .conftest import ROOT


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
