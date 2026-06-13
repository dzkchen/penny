from __future__ import annotations

import json
from typing import Any

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding


def _row_count(response_text: str) -> int:
    try:
        parsed: Any = json.loads(response_text)
    except json.JSONDecodeError:
        return 0
    if isinstance(parsed, list):
        return len(parsed)
    if isinstance(parsed, dict):
        if isinstance(parsed.get("data"), list):
            return len(parsed["data"])
        if "id" in parsed:
            return 1
    return 0


def confirm_service_key_read(findings: list[Finding], target: str, *, i_own_this: bool, feed: EventFeed) -> None:
    service_findings = [finding for finding in findings if finding.detector_id == "D001" and finding.secret_value]
    if not service_findings:
        return
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
    except GuardrailError as error:
        feed.emit("gate", f"Target blocked: {error}")
        for finding in service_findings:
            finding.status = "unconfirmed"
            finding.confidence = "medium"
            finding.evidence["dynamic_probe"] = {"status": "blocked", "reason": str(error)}
        return

    feed.emit("gate", f"Target {target} allowed")
    for finding in service_findings:
        try:
            anon = gate.request(
                "GET",
                "/rest/v1/private_notes",
                headers={"apikey": "anon", "authorization": "Bearer anon"},
            )
            service = gate.request(
                "GET",
                "/rest/v1/private_notes",
                headers={
                    "apikey": finding.secret_value or "",
                    "authorization": f"Bearer {finding.secret_value or ''}",
                },
            )
        except Exception as error:
            finding.status = "unconfirmed"
            finding.confidence = "medium"
            finding.evidence["dynamic_probe"] = {"status": "unconfirmed", "reason": str(error)}
            feed.emit("red", f"{finding.id or finding.detector_id} unconfirmed: {error}")
            continue

        anon_count = _row_count(anon.text)
        service_count = _row_count(service.text)
        confirmed = service.status_code == 200 and service_count > 0 and (anon.status_code in {401, 403} or anon_count == 0)
        dynamic_evidence = {
            "probe": "service_key_table_read",
            "status": "confirmed" if confirmed else "unconfirmed",
            "anon_status": anon.status_code,
            "anon_row_count": anon_count,
            "service_status": service.status_code,
            "service_row_count": service_count,
            "stored_response": "row counts and status codes only",
        }
        finding.evidence["dynamic_probe"] = dynamic_evidence
        if confirmed:
            finding.status = "confirmed"
            finding.confidence = "high"
            finding.evidence["attack_path"] = "Anon access was blocked or empty, while the leaked service credential read protected rows."
            feed.emit("red", f"Confirmed: anon blocked/empty, service key returned {service_count} redacted rows")
        else:
            finding.status = "unconfirmed"
            finding.confidence = "medium"
            feed.emit("red", "Service-key read probe did not confirm protected row access")
