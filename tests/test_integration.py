from __future__ import annotations

import json

from penny.ask import answer_question
from penny.feed import EventFeed
from penny.reporting import generate_report
from penny.scanner import run_scan
from penny.store import FindingsStore

from .conftest import PAYMENT_SECRET, ROOT, SERVICE_KEY


def test_run_scan_confirms_service_key_and_persists_redacted_outputs(tmp_path, planted_server, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    feed = EventFeed(quiet=True)

    result = run_scan(ROOT / "planted-app", target=planted_server, out_dir=tmp_path, feed=feed)
    report = generate_report(result.payload)
    report_path = FindingsStore(tmp_path).write_report(result.session_id, report)

    assert result.findings_path.exists()
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / ".penny/runs/latest/findings.json").exists()
    assert report_path.exists()
    assert (tmp_path / "report.md").exists()

    payload = json.loads(result.findings_path.read_text(encoding="utf-8"))
    service_finding = next(finding for finding in payload["findings"] if finding["detector_id"] == "D001")
    assert service_finding["status"] == "confirmed"
    assert service_finding["evidence"]["dynamic_probe"]["service_row_count"] == 3
    assert payload["summary"]["total"] == 3

    combined_output = (tmp_path / "findings.json").read_text(encoding="utf-8") + (tmp_path / "report.md").read_text(encoding="utf-8")
    for raw in (SERVICE_KEY, PAYMENT_SECRET, "alice@example.test", "bob@example.test", "carol@example.test"):
        assert raw not in combined_output
    assert "Critical client-exposed service credential confirmed" in combined_output
    assert "OWASP" in combined_output
    assert "create policy" in combined_output

    answer = answer_question(
        "What did Red confirm and what should Blue fix first?",
        findings_path=tmp_path / ".penny/runs/latest/findings.json",
    )
    assert "Red confirmed" in answer
    assert "Move service credentials" in answer
