"""Active (intrusive but non-destructive) probes.

The detectors and the read-only confirmation probes never try to *exploit*
anything. Active mode (``--active``) goes one step further: it sends crafted —
but safe — requests to a live target to demonstrate a real weakness.

Two probes ship today:

* ``probe_sql_injection`` — appends benign SQL metacharacters to GET query
  parameters and looks for database error signatures (error-based SQLi). It only
  ever issues read-only GET requests through :class:`TargetGate`, so it inherits
  the method/rate/redirect guardrails.
* ``probe_firebase_open_rules`` — the meaningful active test for a Firebase app:
  it reads the Realtime Database REST endpoint without auth to prove whether the
  security rules expose data to anonymous clients. Read-only, top-level only.

Every probe takes its HTTP gate by injection so the logic is unit-testable
offline. Active mode is opt-in, and reaching any public host still requires
``--i-own-this`` (enforced by :class:`TargetGate`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from urllib.parse import quote

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location
from .redaction import redact_text
from .repo import SourceFile

# Benign, non-destructive payloads: they probe for error/condition handling,
# never modify or drop data.
SQLI_PAYLOADS = ("'", "' OR '1'='1", "1)) OR 1=1-- -", "' AND '1'='2")

_SQL_ERROR_SIGNATURES = [
    re.compile(pattern, re.I)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning:\s*\w*_?(?:mysqli?|pg|sqlite)",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"syntax error at or near",
        r"sqlite3?\.(?:operational|programming)error",
        r"\bSQLITE_ERROR\b",
        r"\bORA-\d{5}\b",
        r"\bpsql:\b|\bPG::\w+\b|\bpq:\s",
        r"\bSQLSTATE\[",
        r"npgsql|sqlclient|odbc sql",
    )
]

FIREBASE_DB_RE = re.compile(r"https://[A-Za-z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app)", re.I)
_QUERY_ENDPOINT_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-/.]+\?[A-Za-z0-9_\-]+=[^'"`<>\s]*)['"`]""")


def _sql_error_signature(text: str) -> str | None:
    for pattern in _SQL_ERROR_SIGNATURES:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _with_param(path: str, param: str, value: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{param}={quote(value, safe='')}"


def discover_firebase_databases(files: Iterable[SourceFile]) -> list[str]:
    found: set[str] = set()
    for file in files:
        for match in FIREBASE_DB_RE.finditer(file.text):
            found.add(match.group(0).rstrip("/"))
    return sorted(found)


def parse_endpoint_specs(specs: Iterable[str]) -> list[tuple[str, str]]:
    """Parse user-supplied `--endpoint` values into (path, param) pairs.

    Accepts `/api/users?id=1`, `/api/users?id`, or `/api/users?a=1&b=2` (one pair
    per parameter). SPAs build URLs dynamically, so source discovery often finds
    nothing — this lets the user point A001 at the endpoints they know exist.
    """
    endpoints: dict[tuple[str, str], None] = {}
    for raw in specs:
        spec = (raw or "").strip()
        if not spec:
            continue
        path, _, query = spec.partition("?")
        path = path or "/"
        if not query:
            continue
        for clause in query.split("&"):
            param = clause.split("=", 1)[0].strip()
            if param:
                endpoints[(path, param)] = None
    return list(endpoints)


def discover_query_endpoints(files: Iterable[SourceFile]) -> list[tuple[str, str]]:
    """Best-effort (path, param) pairs pulled from URL string literals in source."""
    endpoints: dict[tuple[str, str], None] = {}
    for file in files:
        for match in _QUERY_ENDPOINT_RE.finditer(file.text):
            url = match.group(1)
            path, _, query = url.partition("?")
            param = query.split("=", 1)[0]
            if param:
                endpoints[(path, param)] = None
    return list(endpoints)


def probe_sql_injection(gate, endpoints: Iterable[tuple[str, str]], *, feed: EventFeed | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path, param in endpoints:
        try:
            baseline = gate.request("GET", _with_param(path, param, "1"))
        except Exception as error:  # noqa: BLE001 - probe must never crash the scan
            if feed:
                feed.emit("red", f"SQLi probe skipped {path}?{param}: {error}")
            continue
        baseline_has_error = _sql_error_signature(baseline.text) is not None
        hit = None
        for payload in SQLI_PAYLOADS:
            try:
                response = gate.request("GET", _with_param(path, param, payload))
            except Exception:  # noqa: BLE001
                continue
            signature = _sql_error_signature(response.text)
            if signature and not baseline_has_error:
                hit = (payload, response, signature)
                break
        if not hit:
            if feed:
                feed.emit("red", f"No SQL injection at {path}?{param}")
            continue
        payload, response, signature = hit
        findings.append(
            Finding(
                title="SQL injection confirmed via database error response",
                severity="Critical",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="A001",
                owasp=["A03:2021-Injection"],
                location=Location(file=f"dynamic:{path}", line=1, column=1),
                snippet=redact_text(f"GET {path}?{param}=<sql payload> triggered a database error"),
                evidence={
                    "dynamic_probe": {
                        "probe": "sql_injection",
                        "status": "confirmed",
                        "endpoint": path,
                        "parameter": param,
                        "payload": payload,
                        "response_status": response.status_code,
                        "error_signature": signature,
                        "stored_response": "status code and error signature only",
                    },
                    "attack_path": f"Injecting SQL metacharacters into `{param}` reaches the database, so an attacker can read or modify data with crafted queries.",
                },
                impact="A reachable SQL injection lets an attacker read, modify, or destroy database contents.",
                remediation="Use parameterized queries / prepared statements; never build SQL by interpolating request input.",
            )
        )
        if feed:
            feed.emit("red", f"Confirmed SQL injection at {path}?{param}")
    return findings


def _top_level_count(text: str) -> int:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return 0
    return len(parsed) if isinstance(parsed, dict) else 0


def run_firebase_open_rules_probe(gate, database_url: str, *, feed: EventFeed | None = None) -> list[Finding]:
    """Probe one already-gated Firebase database for anonymous read access."""
    try:
        response = gate.request("GET", "/.json?shallow=true")
    except Exception as error:  # noqa: BLE001
        if feed:
            feed.emit("red", f"Firebase probe failed for {database_url}: {error}")
        return []
    denied = "permission denied" in response.text.lower()
    if response.status_code != 200 or denied:
        if feed:
            feed.emit("red", f"Firebase rules deny anonymous read at {database_url} (status {response.status_code})")
        return []
    return [
        Finding(
            title="Firebase database is readable without authentication",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A002",
            owasp=["A01:2021-Broken Access Control"],
            location=Location(file=f"dynamic:{database_url}", line=1, column=1),
            snippet=redact_text(f"GET {database_url}/.json?shallow=true returned data without auth"),
            evidence={
                "dynamic_probe": {
                    "probe": "firebase_open_rules",
                    "status": "confirmed",
                    "database_url": database_url,
                    "response_status": response.status_code,
                    "top_level_keys": _top_level_count(response.text),
                    "stored_response": "status code and top-level key count only",
                },
                "attack_path": "Anyone on the internet can read the Realtime Database directly via its REST endpoint — no app or login required.",
            },
            impact="Open Firebase security rules expose the database to anonymous reads (and often writes), leaking or letting anyone tamper with all user data.",
            remediation="Lock down the Firebase security rules so every path requires an authenticated, authorized user; never deploy `if true` / `.read: true` rules.",
        )
    ]


def probe_firebase_open_rules(database_url: str, *, i_own_this: bool, feed: EventFeed | None = None) -> list[Finding]:
    try:
        gate = TargetGate(database_url, i_own_this=i_own_this, max_requests=4)
    except GuardrailError as error:
        if feed:
            feed.emit("gate", f"Firebase probe blocked for {database_url}: {error}")
        return []
    return run_firebase_open_rules_probe(gate, database_url, feed=feed)


def run_active_probes(
    files: list[SourceFile],
    target: str | None,
    *,
    i_own_this: bool,
    feed: EventFeed,
    extra_endpoints: list[str] | None = None,
) -> list[Finding]:
    """Orchestrate every active probe. Opt-in; never raises into the scan."""
    feed.emit("attack", "Active mode: sending non-destructive probe requests")
    findings: list[Finding] = []

    databases = discover_firebase_databases(files)
    for database_url in databases:
        feed.emit("attack", f"Probing Firebase rules at {database_url}")
        findings.extend(probe_firebase_open_rules(database_url, i_own_this=i_own_this, feed=feed))

    if target:
        discovered = discover_query_endpoints(files)
        user_supplied = parse_endpoint_specs(extra_endpoints or [])
        if user_supplied:
            feed.emit("attack", f"Added {len(user_supplied)} endpoint(s) from --endpoint")
        # Deduplicate while preserving order (user-supplied first).
        endpoints = list(dict.fromkeys(user_supplied + discovered))
        if endpoints:
            try:
                gate = TargetGate(target, i_own_this=i_own_this, max_requests=40)
            except GuardrailError as error:
                feed.emit("gate", f"SQLi probe blocked: {error}")
            else:
                feed.emit("attack", f"Probing {len(endpoints)} endpoint(s) for SQL injection")
                findings.extend(probe_sql_injection(gate, endpoints, feed=feed))
        else:
            feed.emit("attack", "No query-string endpoints found in source to test for SQLi")
    elif not databases:
        feed.emit("attack", "Active mode found nothing to probe (no target and no Firebase config)")

    return findings
