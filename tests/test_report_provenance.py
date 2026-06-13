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


def test_report_fix_block_falls_back_to_remediation_for_new_detectors() -> None:
    report = generate_report(
        {
            "session_id": "current",
            "scan": {"source": ".", "resolved_path": "/tmp/app", "file_count": 1, "static_only": True},
            "summary": {"total": 1, "high_count": 1},
            "findings": [
                {
                    "id": "F-001",
                    "detector_id": "D014",
                    "title": "Possible server-side request forgery (SSRF)",
                    "severity": "High",
                    "status": "suspected",
                    "confidence": "medium",
                    "source": "static",
                    "owasp": ["A10:2021-Server-Side Request Forgery"],
                    "location": {"file": "server/app.py", "line": 2, "column": 1},
                    "snippet": "requests.get(...)",
                    "evidence": {},
                    "impact": "SSRF impact.",
                    "remediation": "Validate the destination against an allowlist of trusted hosts.",
                }
            ],
        }
    )

    # Detectors beyond D001–D006 still get a Section-7 block via their remediation.
    assert "(D014)" in report
    assert "Validate the destination against an allowlist of trusted hosts." in report
