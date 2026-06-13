from __future__ import annotations

import csv
import html
from pathlib import Path
from typing import Any


def findings_to_html(payload: dict[str, Any], report_markdown: str) -> str:
    summary = payload.get("summary", {})
    findings = payload.get("findings", [])
    rows = []
    for finding in findings:
        location = finding.get("location", {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.get('id', ''))}</td>"
            f"<td>{html.escape(finding.get('severity', ''))}</td>"
            f"<td>{html.escape(finding.get('status', ''))}</td>"
            f"<td>{html.escape(finding.get('detector_id', ''))}</td>"
            f"<td>{html.escape(finding.get('title', ''))}</td>"
            f"<td>{html.escape(str(location.get('file', '')))}:{html.escape(str(location.get('line', '')))}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Penny Security Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; line-height: 1.45; color: #172026; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d7dee4; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f7; }}
    pre {{ white-space: pre-wrap; background: #f6f8fa; padding: 1rem; border: 1px solid #d7dee4; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>Penny Security Report</h1>
  <p>Total findings: {int(summary.get("total", len(findings)))}. Confirmed: {int(summary.get("confirmed_count", 0))}.</p>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Detector</th><th>Title</th><th>Location</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <h2>Markdown Report</h2>
  <pre>{html.escape(report_markdown)}</pre>
</body>
</html>
"""


def findings_to_csv(payload: dict[str, Any]) -> str:
    rows: list[list[str]] = [["id", "severity", "status", "confidence", "detector_id", "title", "file", "line", "owasp"]]
    for finding in payload.get("findings", []):
        location = finding.get("location", {})
        rows.append(
            [
                str(finding.get("id", "")),
                str(finding.get("severity", "")),
                str(finding.get("status", "")),
                str(finding.get("confidence", "")),
                str(finding.get("detector_id", "")),
                str(finding.get("title", "")),
                str(location.get("file", "")),
                str(location.get("line", "")),
                "; ".join(str(item) for item in finding.get("owasp", [])),
            ]
        )
    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerows(rows)
    return buffer.getvalue()


def write_exports(payload: dict[str, Any], report_markdown: str, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"
    csv_path = out_dir / "findings.csv"
    html_path.write_text(findings_to_html(payload, report_markdown), encoding="utf-8")
    csv_path.write_text(findings_to_csv(payload), encoding="utf-8")
    return {"html": html_path, "csv": csv_path}
