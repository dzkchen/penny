from __future__ import annotations

import json
from pathlib import Path

import penny.ai_review as ai_module
from penny.ai_review import ai_review, triage_secret_findings
from penny.feed import EventFeed
from penny.models import Finding, Location
from penny.repo import SourceFile
from penny.scanner import run_scan


def _py(name: str, text: str) -> SourceFile:
    return SourceFile(path=Path(name), relative_path=name, text=text)


def _high_entropy_d002(file: str, line: int) -> Finding:
    return Finding(
        title="High-entropy committed token",
        severity="High",
        confidence="medium",
        status="suspected",
        source="static",
        detector_id="D002",
        owasp=[],
        location=Location(file=file, line=line),
        snippet="",
        evidence={},
        impact="",
        remediation="",
    )


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


def test_triage_drops_benign_high_entropy_token(monkeypatch) -> None:
    monkeypatch.setattr(ai_module.llm, "available", lambda: True)
    monkeypatch.setattr(ai_module.llm, "fast_model", lambda: "claude-haiku-4-5")
    verdicts = json.dumps(
        {"verdicts": [{"index": 0, "is_secret": False, "reason": "git sha"},
                      {"index": 1, "is_secret": True, "reason": "looks like an API key"}]}
    )
    monkeypatch.setattr(ai_module.llm, "complete", lambda *a, **k: verdicts)

    findings = [
        _high_entropy_d002("build.py", 1),  # ordinal 0 -> benign, dropped
        _high_entropy_d002("config.py", 2),  # ordinal 1 -> real, kept
    ]
    files = [_py("build.py", "BUILD = 'abc'\n"), _py("config.py", "KEY = 'abc'\n")]

    kept = triage_secret_findings(findings, files)

    assert [f.location.file for f in kept] == ["config.py"]


def test_triage_is_noop_without_key(monkeypatch) -> None:
    monkeypatch.setattr(ai_module.llm, "available", lambda: False)
    findings = [_high_entropy_d002("build.py", 1)]

    assert triage_secret_findings(findings, [_py("build.py", "X = 'abc'\n")]) == findings


def test_triage_leaves_known_prefix_secrets_alone(monkeypatch) -> None:
    # Only confidence='medium' high-entropy hits are triaged; high-confidence
    # known-prefix secrets must never be sent for triage or dropped.
    monkeypatch.setattr(ai_module.llm, "available", lambda: True)
    called = {"complete": False}

    def _complete(*a, **k):
        called["complete"] = True
        return json.dumps({"verdicts": [{"index": 0, "is_secret": False, "reason": "x"}]})

    monkeypatch.setattr(ai_module.llm, "complete", _complete)
    known = _high_entropy_d002("app.py", 1)
    known.confidence = "high"  # known-prefix secret
    known.title = "Committed application secret"

    kept = triage_secret_findings([known], [_py("app.py", "x = 1\n")])

    assert kept == [known]
    assert called["complete"] is False  # no candidates -> no API call
