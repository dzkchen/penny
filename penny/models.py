from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


@dataclass
class Location:
    file: str
    line: int
    column: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "column": self.column}


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    status: str
    source: str
    detector_id: str
    owasp: list[str]
    location: Location
    snippet: str
    evidence: dict[str, Any]
    impact: str
    remediation: str
    id: str = ""
    fingerprint: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    secret_value: str | None = field(default=None, repr=False, compare=False)

    def ensure_fingerprint(self) -> None:
        if self.fingerprint:
            return
        material = "|".join(
            [
                self.detector_id,
                self.location.file,
                str(self.location.line),
                self.title,
                self.snippet,
            ]
        )
        self.fingerprint = sha256(material.encode("utf-8")).hexdigest()[:16]

    def to_public_dict(self) -> dict[str, Any]:
        self.ensure_fingerprint()
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "source": self.source,
            "detector_id": self.detector_id,
            "owasp": self.owasp,
            "location": self.location.to_dict(),
            "snippet": self.snippet,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "created_at": self.created_at,
        }


def dedupe_cross_detector(findings: list[Finding]) -> list[Finding]:
    """Drop AI-sourced findings that duplicate a deterministic finding at the same location.

    Deterministic detectors are higher-precision and carry curated remediation, so when
    `--ai` flags the same `(file, line)` we keep the deterministic finding and discard the
    AI duplicate. Returns the list unchanged when there are no AI findings.
    """
    deterministic = {
        (finding.location.file, finding.location.line)
        for finding in findings
        if finding.source != "ai"
    }
    return [
        finding
        for finding in findings
        if not (finding.source == "ai" and (finding.location.file, finding.location.line) in deterministic)
    ]


def assign_finding_ids(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 99),
            item.location.file,
            item.location.line,
            item.detector_id,
        ),
    )
    for index, finding in enumerate(ordered, start=1):
        finding.ensure_fingerprint()
        finding.id = f"F-{index:03d}"
    return ordered


def now_session_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def validate_findings_payload(payload: dict[str, Any]) -> None:
    required_root = {"schema_version", "session_id", "created_at", "findings", "summary"}
    missing_root = required_root - payload.keys()
    if missing_root:
        raise ValueError(f"findings payload missing root keys: {sorted(missing_root)}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {payload['schema_version']}")
    required_finding = {
        "id",
        "fingerprint",
        "title",
        "severity",
        "confidence",
        "status",
        "source",
        "detector_id",
        "owasp",
        "location",
        "snippet",
        "evidence",
        "impact",
        "remediation",
        "created_at",
    }
    for finding in payload["findings"]:
        missing = required_finding - finding.keys()
        if missing:
            raise ValueError(f"finding {finding.get('id', '<unknown>')} missing keys: {sorted(missing)}")
        if "secret_value" in finding:
            raise ValueError(f"finding {finding['id']} contains non-public secret field")
        location = finding["location"]
        for key in ("file", "line", "column"):
            if key not in location:
                raise ValueError(f"finding {finding['id']} missing location.{key}")


def relative_location(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
