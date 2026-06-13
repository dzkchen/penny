from __future__ import annotations

import json
from typing import Any

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location
from .redaction import redact_text


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


def confirm_bola_order_access(findings: list[Finding], target: str, *, i_own_this: bool, feed: EventFeed) -> None:
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
        first = gate.request("GET", "/api/orders/1001", headers={"x-user-id": "user-a"})
        second = gate.request("GET", "/api/orders/1002", headers={"x-user-id": "user-a"})
    except Exception as error:
        feed.emit("red", f"BOLA probe unconfirmed: {error}")
        return
    try:
        first_json = json.loads(first.text)
        second_json = json.loads(second.text)
    except json.JSONDecodeError:
        feed.emit("red", "BOLA probe unconfirmed: non-JSON order response")
        return
    first_owner = first_json.get("user_id") if isinstance(first_json, dict) else None
    second_owner = second_json.get("user_id") if isinstance(second_json, dict) else None
    confirmed = (
        first.status_code == 200
        and second.status_code == 200
        and first_owner == "user-a"
        and second_owner
        and second_owner != "user-a"
    )
    if not confirmed:
        feed.emit("red", "BOLA probe did not confirm cross-user object access")
        return
    findings.append(
        Finding(
            title="Broken object-level authorization on order endpoint",
            severity="High",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="D004",
            owasp=["A01:2021-Broken Access Control"],
            location=Location(file="dynamic:/api/orders/{order_id}", line=1, column=1),
            snippet="GET /api/orders/1002 as user-a returned another user's order metadata.",
            evidence={
                "dynamic_probe": {
                    "probe": "bola_order_read",
                    "status": "confirmed",
                    "authorized_order_status": first.status_code,
                    "cross_user_order_status": second.status_code,
                    "requested_as": "user-a",
                    "authorized_order_id": "1001",
                    "cross_user_order_id": "1002",
                    "cross_user_owner_matched_request_user": False,
                    "stored_response": "status codes and ownership comparison only",
                },
                "attack_path": "A user with access to order 1001 could change the ID to 1002 and read another user's order metadata.",
            },
            impact="A user can read another user's object by changing an object identifier.",
            remediation="Authorize every object lookup by both object ID and authenticated user ID before returning the object.",
        )
    )
    feed.emit("red", "Confirmed: user-a could read another user's order by changing the object ID")


def confirm_cors_policy(findings: list[Finding], target: str, *, i_own_this: bool, feed: EventFeed) -> None:
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
        response = gate.request("GET", "/health", headers={"origin": "https://attacker.example"})
    except Exception as error:
        feed.emit("red", f"CORS probe unconfirmed: {error}")
        return
    allow_origin = response.headers.get("access-control-allow-origin", "")
    allow_credentials = response.headers.get("access-control-allow-credentials", "")
    confirmed = allow_origin == "*" or allow_origin == "https://attacker.example"
    cors_findings = [finding for finding in findings if finding.detector_id == "D006"]
    evidence = {
        "probe": "cors_origin_reflection",
        "status": "confirmed" if confirmed else "unconfirmed",
        "request_origin": "https://attacker.example",
        "allow_origin": redact_text(allow_origin),
        "allow_credentials": redact_text(allow_credentials),
        "stored_response": "CORS headers only",
    }
    if confirmed and cors_findings:
        for finding in cors_findings:
            finding.status = "confirmed"
            finding.confidence = "high"
            finding.evidence["dynamic_probe"] = evidence
        feed.emit("red", "Confirmed: target returned a permissive CORS origin header")
    elif confirmed:
        findings.append(
            Finding(
                title="Permissive CORS policy",
                severity="Medium",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D006",
                owasp=["A05:2021-Security Misconfiguration"],
                location=Location(file="dynamic:/health", line=1, column=1),
                snippet="GET /health with an untrusted Origin returned a permissive CORS header.",
                evidence={"dynamic_probe": evidence},
                impact="Permissive CORS can let attacker-controlled web pages read browser-accessible API responses.",
                remediation="Restrict Access-Control-Allow-Origin to trusted frontend origins and avoid wildcard origins on sensitive APIs.",
            )
        )
        feed.emit("red", "Confirmed: target returned a permissive CORS origin header")
    elif cors_findings:
        for finding in cors_findings:
            finding.status = "unconfirmed"
            finding.confidence = "medium"
            finding.evidence["dynamic_probe"] = evidence
