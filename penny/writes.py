"""Safe write-path testing for owned targets you explicitly consent to (A015).

GET-only probes can prove a *read* vulnerability but cannot tell you whether your
*write* endpoints are protected. This module fills that gap **without** being a
destructive engine. Three hard rules make it safe:

1. **POST only.** It never issues PUT/PATCH/DELETE, so it cannot overwrite or
   delete existing data. It can only *create* records — and every record it
   creates is tagged with an obvious marker (:data:`PENNY_WRITE_MARKER`) so you
   can find and delete them afterwards.
2. **Double opt-in.** It runs only when the target is owned/consented
   (``i_own_this`` via :func:`penny.guardrails.host_allowed`) *and* the caller
   passes ``i_accept`` (the ``--i-accept`` flag). An optional ``confirm`` hook
   lets an interactive caller approve each individual write.
3. **No privilege-escalation attempt.** To detect mass assignment it sends one
   *unexpected, non-privileged* marker field and checks whether the server echoes
   it back — it never tries to set ``is_admin``/``role`` to a privileged value.

What it detects: write endpoints that accept an *unauthenticated* create (broken
access control) and endpoints that blindly bind unexpected fields (mass
assignment). The HTTP client is injected so the logic is unit-tested offline.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .feed import EventFeed
from .guardrails import host_allowed
from .models import Finding, Location
from .redaction import redact_text

PENNY_WRITE_MARKER = "penny_safe_write_probe"
# An unexpected field name no schema should accept. If it round-trips, the server
# is binding arbitrary input (mass-assignment risk) — proven without us ever
# trying to set a privileged value like is_admin/role.
_UNEXPECTED_FIELD = "penny_unexpected_field"

# Benign create payload. Common field names so a typical "create" endpoint accepts
# it, plus the marker field used for the mass-assignment check.
_TEST_PAYLOAD = {
    "name": PENNY_WRITE_MARKER,
    "title": PENNY_WRITE_MARKER,
    "description": "Created by Penny safe-write probe; safe to delete.",
    _UNEXPECTED_FIELD: PENNY_WRITE_MARKER,
}

# Conservative built-in list of collection-style endpoints that typically accept a
# POST create. Anything else should be supplied explicitly via --endpoint.
_DEFAULT_WRITE_PATHS = (
    "/api/items",
    "/api/posts",
    "/api/comments",
    "/api/notes",
    "/api/todos",
    "/items",
    "/posts",
    "/comments",
)


@dataclass
class WriteResponse:
    status_code: int
    text: str
    headers: dict[str, str]


# client(url, json_body, headers, timeout) -> WriteResponse; only ever called for POST.
WriteClient = Callable[[str, dict, dict, float], WriteResponse]


def _default_client(url: str, json_body: dict, headers: dict, timeout: float) -> WriteResponse:
    import httpx

    response = httpx.post(url, json=json_body, headers=headers, timeout=timeout, follow_redirects=False)
    body = response.content[:4096].decode("utf-8", errors="replace")
    return WriteResponse(status_code=response.status_code, text=body, headers=dict(response.headers))


def _candidate_write_paths(endpoints: Iterable[str] | None) -> list[str]:
    paths: dict[str, None] = {}
    for spec in endpoints or []:
        path = (spec or "").split("?", 1)[0].strip()
        if path.startswith("/"):
            paths[path] = None
    for path in _DEFAULT_WRITE_PATHS:
        paths.setdefault(path, None)
    return list(paths)


def _same_host_url(base: str, path: str) -> str | None:
    base_parsed = urlparse(base)
    candidate = urljoin(f"{base.rstrip('/')}/", path.lstrip("/"))
    parsed = urlparse(candidate)
    if parsed.scheme != base_parsed.scheme or parsed.netloc != base_parsed.netloc:
        return None
    return candidate


def run_safe_write_probe(
    target: str,
    *,
    i_own_this: bool,
    i_accept: bool,
    feed: EventFeed,
    endpoints: Iterable[str] | None = None,
    client: WriteClient | None = None,
    confirm: Callable[[str], bool] | None = None,
    max_writes: int = 12,
    timeout_seconds: float = 5.0,
) -> list[Finding]:
    """POST a marked, benign test record to candidate write endpoints (consented)."""
    host = urlparse(target).hostname or target
    if not host_allowed(host, i_own_this):
        feed.emit("gate", f"Write-path probe blocked for {host}: public hosts require --i-own-this")
        return []
    if not i_accept:
        feed.emit("gate", "Write-path probe skipped: pass --i-accept to allow benign test POSTs (creates marked records)")
        return []

    client = client or _default_client
    feed.emit(
        "attack",
        f"Safe write-path probe on {host}: POST-only, marked '{PENNY_WRITE_MARKER}' records, no PUT/PATCH/DELETE",
    )

    unauth_writes: list[dict] = []
    mass_assignment: list[dict] = []
    writes_done = 0
    for path in _candidate_write_paths(endpoints):
        if writes_done >= max_writes:
            feed.emit("attack", "Write-path probe reached its write cap; stopping")
            break
        url = _same_host_url(target, path)
        if url is None:
            continue
        if confirm is not None and not confirm(url):
            feed.emit("attack", f"Skipped {path} (not confirmed)")
            continue
        writes_done += 1
        feed.emit("red", f"  POST {path} (benign marked record)")
        try:
            response = client(url, dict(_TEST_PAYLOAD), {}, timeout_seconds)
        except Exception:  # noqa: BLE001 - a failed write must never crash the scan
            continue
        # Accepted create with no credentials => broken access control on writes.
        if response.status_code in {200, 201}:
            unauth_writes.append({"path": path, "status": response.status_code})
            feed.emit("red", f"  unauthenticated create accepted at {path} ({response.status_code})")
            # Server echoed our unexpected field => it binds arbitrary input.
            if _UNEXPECTED_FIELD in response.text or PENNY_WRITE_MARKER in response.text:
                mass_assignment.append({"path": path, "echoed_field": _UNEXPECTED_FIELD})
                feed.emit("red", f"  unexpected field round-tripped at {path} (mass-assignment risk)")

    return _build_write_findings(unauth_writes, mass_assignment, feed=feed)


def _build_write_findings(unauth_writes: list[dict], mass_assignment: list[dict], *, feed: EventFeed) -> list[Finding]:
    findings: list[Finding] = []
    if unauth_writes:
        findings.append(
            Finding(
                title="Write endpoint accepts unauthenticated creates",
                severity="High",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="A015",
                owasp=["A01:2021-Broken Access Control", "API1:2023-Broken Object Level Authorization", "WSTG-ATHZ-02"],
                location=Location(file=f"dynamic:{unauth_writes[0]['path']}", line=1, column=1),
                snippet=redact_text(f"{len(unauth_writes)} endpoint(s) created a record from an unauthenticated POST."),
                evidence={
                    "dynamic_probe": {
                        "probe": "safe_write_access_control",
                        "status": "confirmed",
                        "unauthenticated_writes": unauth_writes,
                        "marker": PENNY_WRITE_MARKER,
                        "stored_response": "paths and status codes only; created records are marker-tagged",
                    },
                    "attack_path": "An anonymous client can create records, so the endpoint enforces no authentication/authorization on writes.",
                },
                impact="Unauthenticated writes let anyone inject data, spam, or tamper with application state.",
                remediation="Require authentication and authorization on every state-changing endpoint; deny by default. Delete the Penny test records (search for the marker).",
            )
        )
    if mass_assignment:
        findings.append(
            Finding(
                title="Mass assignment: endpoint binds unexpected request fields",
                severity="High",
                confidence="medium",
                status="confirmed",
                source="dynamic",
                detector_id="A015",
                owasp=["A08:2021-Software and Data Integrity Failures", "API6:2023-Unrestricted Access to Sensitive Business Flows", "API3:2023-Broken Object Property Level Authorization"],
                location=Location(file=f"dynamic:{mass_assignment[0]['path']}", line=1, column=1),
                snippet=f"{len(mass_assignment)} endpoint(s) round-tripped an unexpected, unbound field.",
                evidence={
                    "dynamic_probe": {
                        "probe": "safe_write_mass_assignment",
                        "status": "confirmed",
                        "mass_assignment": mass_assignment,
                        "stored_response": "paths and the echoed field name only",
                    },
                    "attack_path": "The endpoint persisted a field that is not part of its schema, so an attacker could likewise set privileged fields (role, is_admin, owner_id) the API never meant to expose.",
                },
                impact="Mass assignment lets an attacker set fields the API never intended to accept — privilege escalation, ownership takeover, or integrity violations.",
                remediation="Bind only an explicit allow-list of fields (DTO/serializer with declared fields); never spread raw request bodies into models.",
            )
        )
    if not findings:
        feed.emit("red", "Write-path probe: no unauthenticated creates or mass-assignment behaviour observed")
    return findings
