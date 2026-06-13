from __future__ import annotations

import csv

from penny.exports import write_exports
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
