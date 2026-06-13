from __future__ import annotations

from penny.reporting import generate_report


def test_report_warns_when_findings_have_no_scan_provenance() -> None:
    report = generate_report(
        {
            "session_id": "legacy",
            "summary": {"total": 0, "high_count": 0},
            "findings": [],
        }
    )

    assert "legacy findings file without scan provenance" in report


def test_report_includes_scan_scope_when_available() -> None:
    report = generate_report(
        {
            "session_id": "current",
            "scan": {
                "source": "./actual-app",
                "resolved_path": "/tmp/actual-app",
                "file_count": 12,
                "static_only": True,
            },
            "summary": {"total": 0, "high_count": 0},
            "findings": [],
        }
    )

    assert "## 3. Scan Scope" in report
    assert "Scan source: `./actual-app`" in report
    assert "Resolved local path: `/tmp/actual-app`" in report
    assert "Source files inspected: 12" in report
