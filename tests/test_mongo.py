from __future__ import annotations

import json
from datetime import UTC, datetime

from penny.feed import EventFeed
from penny.mongo import scan_history_doc, vuln_pattern_doc
from penny.scanner import run_scan

from .conftest import ROOT


def test_mongo_docs_contain_only_stats_and_generic_patterns(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    finding = result.payload["findings"][0]
    now = datetime.now(UTC)

    history = scan_history_doc(result.payload, now=now)
    pattern = vuln_pattern_doc(finding, now=now)
    encoded = json.dumps({"history": history, "pattern": pattern}, default=str)

    assert "location" not in pattern
    assert "snippet" not in pattern
    assert "evidence" not in pattern
    assert "frontend/src" not in encoded
    assert "http://127.0.0.1" not in encoded
    assert len(pattern["embedding"]) == 64
