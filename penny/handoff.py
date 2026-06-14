from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import redact_text


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass(frozen=True)
class HandoffResult:
    path: Path
    repo_root: Path
    report_path: Path | None
    finding_count: int
    file_count: int
    agent: str


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    cleaned = cleaned.strip(".-")
    return cleaned or "manual"


def _location_text(finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    file_path = str(location.get("file") or "").strip()
    line = location.get("line")
    if file_path and line:
        return f"{file_path}:{line}"
    if file_path:
        return file_path
    route = finding.get("route") or finding.get("url") or location.get("route")
    return str(route or "runtime/no file")


def _file_for_grouping(finding: dict[str, Any]) -> str | None:
    location = finding.get("location") or {}
    file_path = str(location.get("file") or "").strip()
    if not file_path or file_path.startswith("dynamic:"):
        return None
    return file_path


def _compact(value: Any, *, limit: int = 900) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=True, sort_keys=True)
        except TypeError:
            text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str]:
    severity = str(finding.get("severity") or "Info")
    return (SEVERITY_ORDER.get(severity, 99), str(finding.get("id") or finding.get("detector_id") or ""))


def _render_finding_bullet(finding: dict[str, Any]) -> list[str]:
    finding_id = finding.get("id") or "unassigned"
    detector = finding.get("detector_id") or "unknown"
    severity = finding.get("severity") or "Info"
    status = finding.get("status") or "suspected"
    title = finding.get("title") or "Untitled finding"
    remediation = finding.get("remediation") or "Inspect the vulnerable code path and apply a minimal fix."
    impact = _compact(finding.get("impact"), limit=500)
    evidence = _compact(finding.get("evidence"), limit=700)
    lines = [
        f"- [{finding_id}] {severity} {status} {detector}: {title}",
        f"  - Location: `{_location_text(finding)}`",
        f"  - Remediation: {remediation}",
    ]
    if impact:
        lines.append(f"  - Impact: {impact}")
    if evidence:
        lines.append(f"  - Evidence: {evidence}")
    return lines


def render_handoff(
    payload: dict[str, Any],
    repo_root: Path,
    *,
    agent: str = "codex",
    report_path: Path | None = None,
) -> str:
    repo_root = repo_root.resolve()
    report_path = report_path.resolve() if report_path else None
    findings = sorted(payload.get("findings", []), key=_finding_sort_key)
    session_id = str(payload.get("session_id") or "manual")
    scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
    source = scan.get("source") or scan.get("resolved_path") or "unknown"
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    by_file: dict[str, list[dict[str, Any]]] = {}
    runtime: list[dict[str, Any]] = []
    for finding in findings:
        file_path = _file_for_grouping(finding)
        if file_path:
            by_file.setdefault(file_path, []).append(finding)
        else:
            runtime.append(finding)

    lines = [
        "# Penny Remediation Handoff",
        "",
        f"- Repo: `{repo_root}`",
        f"- Source: `{source}`",
        f"- Session: `{session_id}`",
        f"- Generated: `{generated}`",
        f"- Intended agent: `{agent}`",
        f"- Report: `{report_path}`" if report_path else "- Report: `not supplied`",
        f"- Findings: `{len(findings)}`",
        "",
        "## Coding Agent Instructions",
        "",
        "- Work inside the repo shown above.",
        "- Treat this handoff as the security scope; inspect the code before editing.",
        "- Use the Penny report path above for narrative context when it is supplied.",
        "- Make the smallest code changes that fully address the findings.",
        "- Do not invent, hardcode, or expose secrets. Move credentials to server-side configuration.",
        "- Preserve unrelated behavior and formatting where practical.",
        "- Run the relevant tests, type checks, or build commands before reporting completion.",
        "- Leave unrelated user changes intact.",
        "",
        "## Priority Order",
        "",
    ]

    if findings:
        for index, finding in enumerate(findings, start=1):
            finding_id = finding.get("id") or "unassigned"
            severity = finding.get("severity") or "Info"
            status = finding.get("status") or "suspected"
            title = finding.get("title") or "Untitled finding"
            location = _location_text(finding)
            priority = f"{index}. [{finding_id}] {severity} {status}: {title} (`{location}`)"
            lines.append(priority)
    else:
        lines.append("No findings were present in the supplied Penny payload.")

    lines.extend(["", "## File Work Items", ""])
    if by_file:
        for file_path in sorted(by_file):
            lines.extend([f"### `{file_path}`", ""])
            for finding in by_file[file_path]:
                lines.extend(_render_finding_bullet(finding))
            lines.append("")
    else:
        lines.append("No file-located findings were present.")
        lines.append("")

    if runtime:
        lines.extend(["## Runtime Or Route Findings", ""])
        for finding in runtime:
            lines.extend(_render_finding_bullet(finding))
        lines.append("")

    lines.extend(
        [
            "## Suggested Verification",
            "",
            "- Re-run the affected unit/integration tests.",
            "- Re-run the Penny scan or the relevant active probe against an owned target.",
            "- Review the final diff for accidental secret exposure or unrelated churn.",
            "",
        ]
    )
    return redact_text("\n".join(lines))


def create_fix_handoff(
    payload: dict[str, Any],
    repo_root: Path,
    *,
    out_path: Path | None = None,
    agent: str = "codex",
    report_path: Path | None = None,
) -> HandoffResult:
    repo_root = repo_root.resolve()
    if report_path and not report_path.is_absolute():
        report_path = repo_root / report_path
    report_path = report_path.resolve() if report_path else None
    session_id = _slug(str(payload.get("session_id") or "manual"))
    if out_path is None:
        out_path = repo_root / ".penny" / "handoffs" / f"{session_id}-remediation.md"
    elif not out_path.is_absolute():
        out_path = repo_root / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text = render_handoff(payload, repo_root, agent=agent, report_path=report_path)
    out_path.write_text(text, encoding="utf-8")

    file_paths = {_file_for_grouping(finding) for finding in payload.get("findings", [])}
    file_count = len({file_path for file_path in file_paths if file_path})
    return HandoffResult(
        path=out_path,
        repo_root=repo_root,
        report_path=report_path,
        finding_count=len(payload.get("findings", [])),
        file_count=file_count,
        agent=agent,
    )
