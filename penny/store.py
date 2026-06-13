from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import SCHEMA_VERSION, Finding, validate_findings_payload
from .redaction import redact_value


def summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    severity = Counter(finding.severity for finding in findings)
    status = Counter(finding.status for finding in findings)
    detectors = Counter(finding.detector_id for finding in findings)
    return {
        "total": len(findings),
        "by_severity": dict(severity),
        "by_status": dict(status),
        "by_detector": dict(detectors),
        "critical_count": severity.get("Critical", 0),
        "high_count": severity.get("High", 0),
        "confirmed_count": status.get("confirmed", 0),
    }


def build_findings_payload(session_id: str, findings: list[Finding], *, scan: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "created_at": datetime.now(UTC).isoformat(),
        "tool": "penny",
        "scan": scan or {},
        "summary": summarize_findings(findings),
        "findings": [finding.to_public_dict() for finding in findings],
    }
    redacted = redact_value(payload)
    validate_findings_payload(redacted)
    return redacted


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class FindingsStore:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir.resolve()

    def run_dir(self, session_id: str) -> Path:
        return self.out_dir / ".penny" / "runs" / session_id

    def latest_dir(self) -> Path:
        return self.out_dir / ".penny" / "runs" / "latest"

    def write_findings(self, session_id: str, findings: list[Finding], *, scan: dict[str, Any] | None = None) -> tuple[dict[str, Any], Path]:
        payload = build_findings_payload(session_id, findings, scan=scan)
        run_path = self.run_dir(session_id) / "findings.json"
        latest_path = self.latest_dir() / "findings.json"
        for path in (run_path, latest_path):
            _write_json(path, payload)
        return payload, run_path

    def write_report(self, session_id: str, report_markdown: str) -> Path:
        report_markdown = report_markdown.rstrip() + "\n"
        run_path = self.run_dir(session_id) / "report.md"
        latest_path = self.latest_dir() / "report.md"
        for path in (run_path, latest_path):
            _write_text(path, report_markdown)
        return run_path


def copy_report_to_findings_dir(report_path: Path, findings_path: Path) -> None:
    target = findings_path.parent / "report.md"
    if target.resolve() != report_path.resolve():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(report_path, target)
