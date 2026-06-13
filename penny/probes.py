from __future__ import annotations

import json
import re
from typing import Any

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location
from .redaction import redact_text

# Object-ownership keys a generic BOLA check looks for, so the probe is not tied
# to the planted app's exact `user_id` field.
_OWNER_KEYS = ("user_id", "userId", "owner", "owner_id", "ownerId", "uid", "account_id", "accountId", "customer_id")
# Tried in addition to any caller-provided --endpoint paths, so the probe is no
# longer hardwired to a single demo route.
_DEFAULT_BOLA_PATHS = ("/api/orders/1001",)


def preflight_target(target: str, *, i_own_this: bool, feed: EventFeed) -> None:
    """Emit a one-line reachability note so the report reflects what was actually probed.

    Without this, a target whose endpoints don't match Penny's probe recipes looks
    like it was "covered" when in fact every probe quietly found nothing. Stating
    the root status up front makes the dynamic phase honest.
    """
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
        root = gate.request("GET", "/")
    except GuardrailError as error:
        feed.emit("gate", f"Target blocked: {error}")
        return
    except Exception as error:  # noqa: BLE001 - reachability is best-effort
        feed.emit("gate", f"Target unreachable: {error}")
        return
    server = root.headers.get("server", "")
    suffix = f", server={server}" if server else ""
    feed.emit("gate", f"Target reachable (GET / -> {root.status_code}{suffix}); running read-only probes")


def _owner_of(parsed: Any) -> str | None:
    if isinstance(parsed, dict):
        for key in _OWNER_KEYS:
            value = parsed.get(key)
            if value not in (None, ""):
                return str(value)
    return None


def _sibling_id_paths(endpoints: list[str] | None) -> list[tuple[str, str, str, str]]:
    """Build ``(path_a, path_b, id_a, id_b)`` pairs from id-bearing endpoint templates.

    Increments the last integer in each path so the probe can compare two adjacent
    objects. Caller ``--endpoint`` paths are tried first, then the planted default.
    """
    pairs: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for endpoint in list(endpoints or []) + list(_DEFAULT_BOLA_PATHS):
        path = endpoint.split("?", 1)[0]
        match = re.search(r"(\d+)(?!.*\d)", path)
        if not match or path in seen:
            continue
        seen.add(path)
        id_a = match.group(1)
        id_b = str(int(id_a) + 1)
        path_b = path[: match.start()] + id_b + path[match.end():]
        pairs.append((path, path_b, id_a, id_b))
    return pairs


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


def confirm_bola_order_access(
    findings: list[Finding],
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    endpoints: list[str] | None = None,
) -> None:
    """Probe object-id endpoints for missing per-object authorization.

    Generalised beyond the planted demo: it walks every id-bearing endpoint (the
    caller's ``--endpoint`` paths plus the default), compares two adjacent objects
    by any common ownership key, and reports honestly when no such endpoint exists
    on the target (404/unreachable) instead of silently doing nothing.
    """
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
    except GuardrailError as error:
        feed.emit("gate", f"BOLA probe blocked: {error}")
        return

    attempted = 0
    absent = 0
    for path_a, path_b, id_a, id_b in _sibling_id_paths(endpoints):
        try:
            first = gate.request("GET", path_a, headers={"x-user-id": "user-a"})
            second = gate.request("GET", path_b, headers={"x-user-id": "user-a"})
        except Exception as error:  # noqa: BLE001 - per-endpoint, keep probing others
            feed.emit("red", f"BOLA probe error on {path_a}: {error}")
            continue
        if first.status_code == 404 or second.status_code == 404:
            absent += 1
            continue
        attempted += 1
        try:
            first_json = json.loads(first.text)
            second_json = json.loads(second.text)
        except json.JSONDecodeError:
            continue
        first_owner = _owner_of(first_json)
        second_owner = _owner_of(second_json)
        confirmed = (
            first.status_code == 200
            and second.status_code == 200
            and first_owner is not None
            and second_owner is not None
            and first_owner != second_owner
        )
        if not confirmed:
            continue
        base = path_a.rsplit("/", 1)[0]
        findings.append(
            Finding(
                title="Broken object-level authorization on order endpoint",
                severity="High",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D004",
                owasp=["A01:2021-Broken Access Control"],
                location=Location(file=f"dynamic:{base}/{{id}}", line=1, column=1),
                snippet=f"GET {path_b} as user-a returned an object owned by a different user.",
                evidence={
                    "dynamic_probe": {
                        "probe": "bola_object_read",
                        "status": "confirmed",
                        "authorized_order_status": first.status_code,
                        "cross_user_order_status": second.status_code,
                        "requested_as": "user-a",
                        "authorized_order_id": id_a,
                        "cross_user_order_id": id_b,
                        "cross_user_owner_matched_request_user": False,
                        "endpoint": path_a,
                        "stored_response": "status codes and ownership comparison only",
                    },
                    "attack_path": f"A user with access to {path_a} could change the ID to {id_b} and read another user's object metadata.",
                },
                impact="A user can read another user's object by changing an object identifier.",
                remediation="Authorize every object lookup by both object ID and authenticated user ID before returning the object.",
            )
        )
        feed.emit("red", f"Confirmed: user-a could read another user's object via {path_b}")
        return

    if attempted == 0:
        feed.emit("red", "BOLA probe: no object-id endpoint responded on this target (404/unreachable) — not applicable")
    else:
        feed.emit("red", "BOLA probe did not confirm cross-user object access")


def confirm_cors_policy(findings: list[Finding], target: str, *, i_own_this: bool, feed: EventFeed) -> None:
    try:
        gate = TargetGate(target, i_own_this=i_own_this)
        response = gate.request("GET", "/health", headers={"origin": "https://attacker.example"})
        # Not every target has /health; fall back to the root so CORS reflection
        # can still be checked on a reachable path instead of giving up silently.
        if response.status_code == 404:
            response = gate.request("GET", "/", headers={"origin": "https://attacker.example"})
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
