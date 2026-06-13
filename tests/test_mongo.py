from __future__ import annotations

import json
from datetime import UTC, datetime

from penny.feed import EventFeed
from penny.mongo import safe_pattern_result, safe_trend_result, scan_history_doc, trend_pipeline, vector_search_pipeline, vuln_pattern_doc
from penny.scanner import run_scan

from .conftest import ROOT


def test_mongo_docs_contain_only_stats_and_generic_patterns(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    monkeypatch.setenv("PENNY_DISABLE_VOYAGE", "1")  # force deterministic hash embeddings
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
    from penny.embeddings import embedding_dimensions

    assert len(pattern["embedding"]) == embedding_dimensions()


def test_vector_search_pipeline_targets_atlas_vector_index(monkeypatch) -> None:
    monkeypatch.setenv("PENNY_DISABLE_VOYAGE", "1")  # force deterministic hash embeddings
    from penny.embeddings import embedding_dimensions

    pipeline = vector_search_pipeline("service key in client code", limit=3)

    assert pipeline[0]["$vectorSearch"]["index"] == "vuln_pattern_vector_index"
    assert pipeline[0]["$vectorSearch"]["path"] == "embedding"
    assert len(pipeline[0]["$vectorSearch"]["queryVector"]) == embedding_dimensions()
    assert pipeline[0]["$vectorSearch"]["limit"] == 3
    assert pipeline[1]["$project"]["score"] == {"$meta": "vectorSearchScore"}


def test_safe_pattern_result_strips_database_only_fields() -> None:
    result = safe_pattern_result(
        {
            "_id": "database-id",
            "detector_id": "D001",
            "title": "Client-visible service-role credential",
            "severity": "Critical",
            "remediation": "Move service credentials server-side.",
            "pattern_text": "generic pattern",
            "embedding": [0.1],
            "score": 0.8,
        }
    )

    assert result == {
        "detector_id": "D001",
        "title": "Client-visible service-role credential",
        "severity": "Critical",
        "remediation": "Move service credentials server-side.",
        "pattern_text": "generic pattern",
        "score": 0.8,
    }


def test_trend_pipeline_aggregates_scan_history_without_sensitive_fields() -> None:
    now = datetime(2026, 6, 13, tzinfo=UTC)
    pipeline = trend_pipeline(days=7, limit=5, now=now)
    encoded = json.dumps(pipeline, default=str)

    assert "by_detector" in encoded
    assert "critical_count" in encoded
    assert "high_count" in encoded
    assert "location" not in encoded
    assert "snippet" not in encoded
    assert "evidence" not in encoded
    assert pipeline[-1] == {"$limit": 5}


def test_safe_trend_result_normalizes_counts() -> None:
    result = safe_trend_result({"_id": "D001", "count": 4.0, "critical_count": 2.0, "high_count": 1.0})

    assert result == {"detector_id": "D001", "count": 4, "critical_count": 2, "high_count": 1}
