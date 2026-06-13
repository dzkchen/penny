from __future__ import annotations

import json
from pathlib import Path

import penny.ai_review as ai_module
from penny.ai_review import ai_review
from penny.feed import EventFeed
from penny.repo import SourceFile
from penny.scanner import run_scan


def _py(name: str, text: str) -> SourceFile:
    return SourceFile(path=Path(name), relative_path=name, text=text)


def _ai_payload() -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "title": "Missing ownership check on order read",
                    "severity": "High",
                    "confidence": "high",
                    "file": "app.py",
                    "line": 2,
                    "category": "BOLA / IDOR",
                    "owasp": "A01:2021-Broken Access Control",
                    "impact": "Any user can read any order by id.",
                    "remediation": "Bind the order id to the authenticated user.",
                }
            ]
        }
    )


def test_ai_review_skips_without_key(monkeypatch) -> None:
    monkeypatch.setattr(ai_module.llm, "available", lambda: False)

    assert ai_review([_py("app.py", "x = 1\n")]) == []


def test_ai_review_parses_and_rebuilds_snippet(monkeypatch) -> None:
    monkeypatch.setattr(ai_module.llm, "available", lambda: True)
    monkeypatch.setattr(ai_module.llm, "deep_model", lambda: "claude-sonnet-4-6")
    monkeypatch.setattr(ai_module.llm, "complete", lambda *args, **kwargs: _ai_payload())

    files = [_py("app.py", "def get_order(order_id):\n    return ORDERS[order_id]\n")]
    findings = ai_review(files)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "ai"
    assert finding.detector_id == "AI001"
    assert finding.severity == "High"
    assert finding.location.file == "app.py"
    assert finding.location.line == 2
    # Snippet is rebuilt from the real source line, not trusted from the model.
    assert finding.snippet == "return ORDERS[order_id]"
    assert finding.evidence["ai_generated"] is True


def test_run_scan_includes_ai_findings_when_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    monkeypatch.setattr(ai_module.llm, "available", lambda: True)
    monkeypatch.setattr(ai_module.llm, "deep_model", lambda: "claude-sonnet-4-6")
    monkeypatch.setattr(ai_module.llm, "complete", lambda *args, **kwargs: _ai_payload())
    (tmp_path / "app.py").write_text("def get_order(order_id):\n    return ORDERS[order_id]\n", encoding="utf-8")

    result = run_scan(tmp_path, static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True), use_ai=True)

    detector_ids = {finding["detector_id"] for finding in result.payload["findings"]}
    assert "AI001" in detector_ids
