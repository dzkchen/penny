from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .redaction import redact_text


def load_findings(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _severity_rollup(findings: list[dict[str, Any]]) -> str:
    counts = Counter(finding["severity"] for finding in findings)
    lines = ["| Severity | Count |", "|---|---:|"]
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        if counts.get(severity, 0):
            lines.append(f"| {severity} | {counts[severity]} |")
    if len(lines) == 2:
        lines.append("| None | 0 |")
    return "\n".join(lines)


def _scan_scope(payload: dict[str, Any]) -> str:
    scan = payload.get("scan") or {}
    if not scan:
        return "This report was generated from a legacy findings file without scan provenance. Re-run `penny run` or `penny scan` against the intended local source tree before trusting file paths."
    source = scan.get("source", "unknown")
    resolved_path = scan.get("resolved_path", "unknown")
    file_count = scan.get("file_count", "unknown")
    static_only = scan.get("static_only", False)
    return "\n".join(
        [
            f"- Scan source: `{source}`",
            f"- Resolved local path: `{resolved_path}`",
            f"- Source files inspected: {file_count}",
            f"- Dynamic probes: {'skipped' if static_only else 'enabled when a target was provided'}",
        ]
    )


def _status_word(finding: dict[str, Any]) -> str:
    if finding["status"] == "confirmed":
        return "confirmed"
    if finding["status"] == "unconfirmed":
        return "not dynamically confirmed"
    return "suspected"


def _render_dependency_table(deps: list[dict[str, Any]], evidence: dict[str, Any]) -> str:
    lines = [
        f"- Vulnerable dependencies: {evidence.get('package_count', len(deps))} "
        f"package(s), {evidence.get('advisory_count', 0)} advisory(ies)",
        "",
        "| Package | Ecosystem | Detected | Recommended | CVEs |",
        "|---|---|---|---|---|",
    ]
    for dep in deps:
        cves = ", ".join(dep.get("cves", [])) or "—"
        lines.append(
            f"| {dep.get('package', '?')} | {dep.get('ecosystem', '?')} "
            f"| {dep.get('detected_version', '?')} | {dep.get('recommended_version', '?')} | {cves} |"
        )
    return "\n".join(lines)


def _render_evidence(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {}) or {}
    if not evidence:
        return ""
    deps = evidence.get("vulnerable_dependencies")
    if finding["detector_id"] == "D005" and deps:
        return _render_dependency_table(deps, evidence)
    if evidence.get("ai_generated"):
        model = evidence.get("model", "ai")
        reason = evidence.get("reason", "")
        line = f"- Evidence: AI review ({model})" + (f" — {reason}" if reason else "")
        return redact_text(line)
    scalars = [
        f"- {key}: {evidence[key]}"
        for key in sorted(evidence)
        if not isinstance(evidence[key], (dict, list))
    ]
    if scalars:
        return redact_text("\n".join(scalars))
    return f"- Evidence: {redact_text(json.dumps(evidence, sort_keys=True))}"


def _finding_details(findings: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    for finding in findings:
        location = finding["location"]
        parts = [
            f"### {finding['id']} - {finding['title']}",
            "",
            f"- Severity: {finding['severity']}",
            f"- Status: {_status_word(finding)}",
            f"- Confidence: {finding['confidence']}",
            f"- Detector: {finding['detector_id']}",
            f"- OWASP: {', '.join(finding.get('owasp', []))}",
            f"- Location: `{location['file']}:{location['line']}`",
        ]
        evidence_block = _render_evidence(finding)
        if evidence_block:
            parts.append(evidence_block)
        snippet = redact_text(finding.get("snippet", "")).strip()
        if snippet:
            parts += ["", "Redacted snippet:", "", "```text", snippet, "```"]
        parts += ["", f"Impact: {finding['impact']}", "", f"Remediation: {finding['remediation']}"]
        blocks.append("\n".join(parts))
    return "\n\n".join(blocks)


def _confirmed_attack_path(findings: list[dict[str, Any]]) -> str:
    confirmed = [finding for finding in findings if finding["status"] == "confirmed"]
    if not confirmed:
        return "No finding was dynamically confirmed. Treat suspected findings as actionable review items, not proven exploits."
    lines = []
    for finding in confirmed:
        probe = finding.get("evidence", {}).get("dynamic_probe", {})
        if probe.get("probe") == "service_key_table_read":
            lines.append(
                f"- {finding['id']}: {finding['title']} was confirmed. "
                f"Anon status/count: {probe.get('anon_status', 'n/a')}/{probe.get('anon_row_count', 'n/a')}; "
                f"service status/count: {probe.get('service_status', 'n/a')}/{probe.get('service_row_count', 'n/a')}."
            )
        elif probe.get("probe") == "bola_order_read":
            lines.append(
                f"- {finding['id']}: {finding['title']} was confirmed. "
                f"User `{probe.get('requested_as', 'unknown')}` accessed authorized order `{probe.get('authorized_order_id', 'n/a')}` "
                f"and cross-user order `{probe.get('cross_user_order_id', 'n/a')}`."
            )
        elif probe.get("probe") == "cors_origin_reflection":
            lines.append(
                f"- {finding['id']}: {finding['title']} was confirmed. "
                f"An untrusted Origin received `{probe.get('allow_origin', 'n/a')}`."
            )
        else:
            lines.append(f"- {finding['id']}: {finding['title']} was confirmed by `{probe.get('probe', 'dynamic probe')}`.")
    return "\n".join(lines)


def _fixes(findings: list[dict[str, Any]]) -> str:
    has_d001 = any(finding["detector_id"] == "D001" for finding in findings)
    has_d002 = any(finding["detector_id"] == "D002" for finding in findings)
    has_d003 = any(finding["detector_id"] == "D003" for finding in findings)
    has_d004 = any(finding["detector_id"] == "D004" for finding in findings)
    has_d005 = any(finding["detector_id"] == "D005" for finding in findings)
    has_d006 = any(finding["detector_id"] == "D006" for finding in findings)
    sections: list[str] = []
    if has_d001:
        sections.append(
            """### Move service credentials server-side

```diff
- export const serviceRoleKey = "[REDACTED:service_key]";
- export const supabase = createClient(supabaseUrl, serviceRoleKey);
+ export const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
+ export const supabase = createClient(supabaseUrl, anonKey);
```

Server-side code should load the service credential from a private environment variable and expose narrow, authenticated routes instead of shipping privileged credentials to the browser.

```python
service_role_key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
```
"""
        )
    if has_d002:
        sections.append(
            """### Rotate and remove committed secrets

```diff
- STRIPE_SECRET = "[REDACTED:secret]"
+ STRIPE_SECRET = os.environ["STRIPE_SECRET"]
```

Rotate any real exposed credential, remove it from source history if needed, and keep only non-sensitive examples in committed files.
"""
        )
    if has_d003:
        sections.append(
            """### Tighten row-level policies

```sql
alter table private_notes enable row level security;

drop policy if exists "public can read private notes" on private_notes;

create policy "users can read their own private notes"
on private_notes
for select
using (auth.uid() = user_id);
```

The important fix is to bind every row predicate to the authenticated user or another explicit authorization rule.
"""
        )
    if has_d004:
        sections.append(
            """### Enforce object ownership on reads

```python
def get_order(order_id: str, current_user_id: str):
    order = orders.get(order_id)
    if order is None or order["user_id"] != current_user_id:
        raise HTTPException(status_code=404)
    return order
```

Every object fetch should bind the requested object ID to the authenticated user or an authorization policy before returning data.
"""
        )
    if has_d005:
        sections.append(
            """### Upgrade vulnerable dependencies

```text
jinja2>=2.10.2
lodash>=4.17.21
```

Upgrade vulnerable packages to fixed versions or later, regenerate lockfiles, and run dependency tests before release.
"""
        )
    if has_d006:
        sections.append(
            """### Restrict CORS origins

```python
ALLOWED_ORIGINS = {"https://app.example.com"}

origin = request.headers.get("origin")
if origin in ALLOWED_ORIGINS:
    response.headers["Access-Control-Allow-Origin"] = origin
```

Avoid `Access-Control-Allow-Origin: *` on APIs that may return user-specific or credential-adjacent data.
"""
        )
    return "\n\n".join(sections) if sections else "No concrete fixes were generated because there are no findings."


def generate_report(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    confirmed = [finding for finding in findings if finding["status"] == "confirmed"]
    critical = [finding for finding in findings if finding["severity"] == "Critical"]
    verdict = (
        "Critical client-exposed service credential confirmed."
        if any(finding["detector_id"] == "D001" and finding["status"] == "confirmed" for finding in findings)
        else "No critical exploit was dynamically confirmed; review suspected issues before release."
    )
    executive = (
        f"Penny found {summary.get('total', len(findings))} issue(s), including "
        f"{len(critical)} critical and {summary.get('high_count', 0)} high finding(s). "
        f"{len(confirmed)} finding(s) were dynamically confirmed."
    )
    return "\n\n".join(
        [
            "# Penny Security Report",
            "## 1. Purple-Team Verdict",
            verdict,
            "## 2. Executive Summary",
            executive,
            "## 3. Scan Scope",
            _scan_scope(payload),
            "## 4. Severity Rollup",
            _severity_rollup(findings),
            "## 5. Confirmed Attack Path",
            _confirmed_attack_path(findings),
            "## 6. Per-Finding Details",
            _finding_details(findings) if findings else "No findings.",
            "## 7. Fixes And Patches",
            _fixes(findings),
            "## 8. Methodology, Guardrails, And Limitations",
            "\n".join(
                [
                    "- Static detectors inspect allowlisted source files under size limits.",
                    "- Dynamic probes are read-only and pass through Python target guardrails.",
                    "- Evidence is redacted before persistence.",
                    "- Suspected findings are not described as exploited unless a dynamic probe confirms them.",
                    "- Reports stay on the local filesystem; optional Mongo mirrors receive only redacted aggregate stats and generic patterns.",
                ]
            ),
        ]
    )
