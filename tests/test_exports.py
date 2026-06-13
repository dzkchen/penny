from __future__ import annotations

import csv
import json

from penny.exports import findings_to_sarif, write_exports
from penny.feed import EventFeed
from penny.reporting import generate_report
from penny.scanner import run_scan

from .conftest import PAYMENT_SECRET, ROOT, SERVICE_KEY


def test_report_exports_write_html_and_csv_without_raw_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    report = generate_report(result.payload)

    paths = write_exports(result.payload, report, tmp_path)

    html = paths["html"].read_text(encoding="utf-8")
    csv_text = paths["csv"].read_text(encoding="utf-8")
    assert "<title>Penny Security Report</title>" in html
    assert "findings.csv" not in html
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert rows
    assert {"id", "severity", "status", "detector_id", "title"}.issubset(rows[0])
    combined = html + csv_text
    assert SERVICE_KEY not in combined
    assert PAYMENT_SECRET not in combined


def test_write_exports_emits_valid_sarif(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    report = generate_report(result.payload)

    paths = write_exports(result.payload, report, tmp_path)

    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Penny"
    assert run["results"], "expected at least one SARIF result for the planted app"
    levels = {res["level"] for res in run["results"]}
    assert levels <= {"error", "warning", "note"}
    for res in run["results"]:
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
    assert SERVICE_KEY not in paths["sarif"].read_text(encoding="utf-8")


def test_sarif_handles_empty_findings() -> None:
    sarif = json.loads(findings_to_sarif({"findings": []}))
    assert sarif["runs"][0]["results"] == []
