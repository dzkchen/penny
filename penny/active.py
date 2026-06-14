"""Active (intrusive but non-destructive) probes.

The detectors and the read-only confirmation probes never try to *exploit*
anything. Active mode (``--active``) goes one step further: it sends crafted —
but safe — requests to a live target to demonstrate a real weakness.

Active mode includes:

* ``probe_sql_injection`` — appends benign SQL metacharacters to GET query
  parameters and looks for database error signatures (error-based SQLi). It only
  ever issues read-only GET requests through :class:`TargetGate`, so it inherits
  the method/rate/redirect guardrails.
* ``probe_firebase_open_rules`` — the meaningful active test for a Firebase app:
  it reads the Realtime Database REST endpoint without auth to prove whether the
  security rules expose data to anonymous clients. Read-only, top-level only.
* ``probe_checklist_baseline`` — a bounded OWASP/API/WSTG-style live baseline
  for security headers, cookie flags, HTTP methods, exposed files/admin metadata,
  directory listings, verbose errors, CORS preflight, and cache controls.

Every probe takes its HTTP gate by injection so the logic is unit-testable
offline. Active mode is opt-in, and reaching any public host still requires
``--i-own-this`` (enforced by :class:`TargetGate`).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import quote
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location
from .redaction import redact_text
from .repo import SourceFile

# Benign, non-destructive payloads: they probe for error/condition handling,
# never modify or drop data.
SQLI_PAYLOADS = ("'", "' OR '1'='1", "1)) OR 1=1-- -", "' AND '1'='2")

# Boolean-based blind SQLi: a TRUE clause should leave the result set looking like
# the baseline; a logically-FALSE clause should change it. These are pure SELECT
# conditions — they read, never write, and never drop data.
SQLI_BOOLEAN_PAIRS = (
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND '1'='1", "' AND '1'='2"),
    (" OR 1=1", " OR 1=2"),
    (" AND 1=1", " AND 1=2"),
)
# Time-based blind SQLi: a TRUE branch that sleeps proves injection on targets
# that show no error and no boolean differential. Read-only (the DB just waits).
# We keep the sleep short and only trust it if the slow response is dramatically
# slower than a no-op control to avoid flagging ordinary network jitter.
SQLI_TIME_PAYLOADS = (
    "' AND SLEEP(2)-- -",
    "'; SELECT pg_sleep(2)-- -",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(2))-- -",
    " AND SLEEP(2)",
)
_SQLI_TIME_DELAY_SECONDS = 2.0
# A real time-based hit must be slower than the control by at least the injected
# delay minus this slack, so a slow-but-not-injectable endpoint is not flagged.
_SQLI_TIME_SLACK_SECONDS = 1.0

# Reflected-XSS canary: a unique marker wrapped in the HTML-significant characters
# an XSS payload needs. We never inject an executing script — if these characters
# come back *unencoded* in an HTML response, the sink does not escape output and a
# real payload would execute. Detection only.
_XSS_MARKER = "penny7xq9zmark"
_XSS_PROBE = f"<{_XSS_MARKER}>"
_XSS_ATTR_PROBE = f'"{_XSS_MARKER}'
_HTML_CONTENT_TYPE_RE = re.compile(r"text/html|application/xhtml", re.I)

# Common query-parameter names to fan out across known endpoints so coverage does
# not depend on finding a parameter already wired up in the source. Kept curated
# (not a giant fuzzing list) so the request budget stays bounded.
PARAM_WORDLIST = (
    "id", "user", "user_id", "username", "name", "q", "query", "search", "s",
    "page", "sort", "order", "filter", "category", "cat", "file", "path", "dir",
    "url", "redirect", "next", "return", "callback", "lang", "email", "token",
    "key", "code", "ref", "type", "action", "view", "item", "product", "post",
    "comment", "message", "data", "value", "format", "limit", "offset", "sid",
)

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
# State-changing or diagnostic verbs that should not be broadly reachable. WebDAV
# verbs are included because an unintentionally-enabled WebDAV layer is a classic
# way to upload/move files on a server that only meant to serve static content.
_STATE_CHANGING_METHODS = {"PUT", "DELETE", "PATCH"}
_WEBDAV_WRITE_METHODS = {"MKCOL", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK"}
_WEBDAV_READ_METHODS = {"PROPFIND"}
# TRACE enables Cross-Site Tracing; CONNECT can turn a server into a proxy.
_DIAGNOSTIC_METHODS = {"TRACE", "CONNECT"}
# High-risk = anything that writes/changes state or is a known attack primitive.
_HIGH_RISK_HTTP_METHODS = _STATE_CHANGING_METHODS | _WEBDAV_WRITE_METHODS | _DIAGNOSTIC_METHODS
_UNSAFE_HTTP_METHODS = _HIGH_RISK_HTTP_METHODS | _WEBDAV_READ_METHODS
_MISSING_CACHE_DIRECTIVES = {"no-store", "no-cache", "private"}
_ATTACKER_ORIGIN = "https://attacker.example"
_CHECKLIST_BASE_PATHS = ("/", "/api", "/health")
_DIRECTORY_LISTING_PATHS = ("/static/", "/assets/", "/uploads/", "/files/", "/public/", "/backup/", "/logs/")
_CACHE_PROBE_PATHS = ("/api/me", "/api/users", "/me", "/profile", "/account")
_SENSITIVE_RESPONSE_RE = re.compile(
    r"\b(email|user_?id|account|profile|token|secret|api[_-]?key|session|private|order|balance)\b",
    re.I,
)
_DIRECTORY_LISTING_RE = re.compile(r"(<title>\s*Index of\b|\bIndex of /|Parent Directory)", re.I)
_VERBOSE_ERROR_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+", re.I)),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|werkzeug\.debug", re.I)),
    ("Django debug page", re.compile(r"You're seeing this error because you have DEBUG = True|Django Version:", re.I)),
    ("Java exception", re.compile(r"\bjava\.[a-z0-9_.]+(?:Exception|Error)\b", re.I)),
    (".NET exception", re.compile(r"\bSystem\.[A-Za-z0-9_.]+Exception\b|Server Error in '.+' Application", re.I)),
    ("JavaScript stack trace", re.compile(r"\bat [A-Za-z0-9_.$<>]+\s*\([^)]*:\d+:\d+\)", re.I)),
    ("database error", re.compile(r"SQLSTATE\[|SQLException|sqlite3?\.(?:Operational|Programming)Error|ORA-\d{5}", re.I)),
]


@dataclass(frozen=True)
class ExposedPathCheck:
    path: str
    label: str
    severity: str
    pattern: re.Pattern[str]


_EXPOSED_PATH_CHECKS = (
    ExposedPathCheck("/.env", "environment file", "High", re.compile(r"(?m)^[A-Z0-9_]{3,}\s*=\s*[^#\n]+")),
    ExposedPathCheck("/.git/config", "Git repository metadata", "High", re.compile(r"\[core\]|repositoryformatversion", re.I)),
    ExposedPathCheck("/.aws/credentials", "AWS credential file", "High", re.compile(r"aws_access_key_id|aws_secret_access_key", re.I)),
    ExposedPathCheck("/config.json", "runtime config JSON", "Medium", re.compile(r'"(?:apiKey|api_key|secret|token|database|supabase|firebase)"', re.I)),
    ExposedPathCheck("/appsettings.json", "application settings JSON", "Medium", re.compile(r'"(?:ConnectionStrings|Password|Secret|ApiKey)"', re.I)),
    ExposedPathCheck("/backup.zip", "backup archive", "High", re.compile(r"^PK\x03\x04|application/zip", re.I)),
    ExposedPathCheck("/phpinfo.php", "PHP info page", "High", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    ExposedPathCheck("/server-status", "server status page", "Medium", re.compile(r"Apache Server Status|Server uptime|Total accesses", re.I)),
    ExposedPathCheck("/actuator/env", "Spring actuator environment", "High", re.compile(r"propertySources|systemEnvironment|SPRING_", re.I)),
    ExposedPathCheck("/actuator/health", "Spring actuator health", "Low", re.compile(r'"status"\s*:\s*"UP"|components', re.I)),
    ExposedPathCheck("/swagger.json", "Swagger schema", "Low", re.compile(r'"swagger"\s*:\s*"2\.0"|openapi', re.I)),
    ExposedPathCheck("/openapi.json", "OpenAPI schema", "Low", re.compile(r'"openapi"\s*:\s*"', re.I)),
    ExposedPathCheck("/api-docs", "API documentation", "Low", re.compile(r"swagger|openapi|api docs", re.I)),
    ExposedPathCheck("/docs", "API documentation UI", "Low", re.compile(r"swagger|openapi|redoc|api documentation", re.I)),
    ExposedPathCheck("/graphql", "GraphQL explorer", "Low", re.compile(r"graphiql|graphql playground|__schema", re.I)),
)


def _sql_error_signature(text: str) -> str | None:
    for pattern in _SQL_ERROR_SIGNATURES:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _with_param(path: str, param: str, value: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{param}={quote(value, safe='')}"


def _headers(response) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in getattr(response, "headers", {}).items()}


def _header(response, name: str) -> str:
    return _headers(response).get(name.lower(), "")


def _dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _candidate_paths(endpoints: Iterable[tuple[str, str]]) -> list[str]:
    endpoint_paths = [path or "/" for path, _ in endpoints]
    return _dedupe([*_CHECKLIST_BASE_PATHS, *endpoint_paths])


def _severity_rank(severity: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(severity, 0)


def _highest_severity(values: Iterable[str]) -> str:
    severities = list(values)
    return max(severities, key=_severity_rank) if severities else "Info"


def _normalized_body(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())[:512]


def _distinct_from_baseline(response, baseline) -> bool:
    if baseline is None:
        return True
    if response.status_code != baseline.status_code:
        return True
    body = _normalized_body(response.text)
    baseline_body = _normalized_body(baseline.text)
    if not body:
        return False
    return body != baseline_body


def _parse_methods(value: str) -> set[str]:
    return {part.strip().upper() for part in re.split(r"[,\s]+", value or "") if part.strip()}


def _set_cookie_values(headers: dict[str, str]) -> list[str]:
    raw = headers.get("set-cookie", "")
    if not raw:
        return []
    return re.split(r",\s*(?=[A-Za-z0-9_.-]+=)", raw)


def _cookie_issues(headers: dict[str, str], *, secure_transport: bool) -> list[dict[str, Any]]:
    sensitive_name = re.compile(r"(session|sid|auth|jwt|token|refresh|access)", re.I)
    issues: list[dict[str, Any]] = []
    for value in _set_cookie_values(headers):
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:  # noqa: BLE001 - malformed Set-Cookie should not break the scan
            continue
        for name, morsel in cookie.items():
            attrs = {key.lower() for key, attr_value in morsel.items() if attr_value}
            missing: list[str] = []
            if sensitive_name.search(name) and "httponly" not in attrs:
                missing.append("HttpOnly")
            if secure_transport and "secure" not in attrs:
                missing.append("Secure")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if missing:
                issues.append({"cookie": redact_text(name), "missing": missing})
    return issues


def _security_header_issues(response, *, target: str) -> list[dict[str, str]]:
    headers = _headers(response)
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    issues: list[dict[str, str]] = []
    if not csp:
        issues.append({"header": "Content-Security-Policy", "reason": "missing"})
    if "frame-ancestors" not in csp.lower() and xfo.lower() not in {"deny", "sameorigin"}:
        issues.append({"header": "X-Frame-Options or CSP frame-ancestors", "reason": "missing clickjacking control"})
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        issues.append({"header": "X-Content-Type-Options", "reason": "missing nosniff"})
    if "referrer-policy" not in headers:
        issues.append({"header": "Referrer-Policy", "reason": "missing"})
    if "permissions-policy" not in headers:
        issues.append({"header": "Permissions-Policy", "reason": "missing"})
    if urlparse(target).scheme == "https" and "strict-transport-security" not in headers:
        issues.append({"header": "Strict-Transport-Security", "reason": "missing on HTTPS response"})
    return issues


def _technology_headers(response) -> dict[str, str]:
    headers = _headers(response)
    exposed = {}
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"):
        value = headers.get(name)
        if value:
            exposed[name] = redact_text(value)[:120]
    return exposed


def _exposed_path_match(check: ExposedPathCheck, response) -> str | None:
    content_type = _header(response, "content-type")
    haystack = f"{response.text}\n{content_type}"
    match = check.pattern.search(haystack)
    if not match:
        return None
    return redact_text(match.group(0))[:120]


def _verbose_error_signature(text: str) -> str | None:
    for label, pattern in _VERBOSE_ERROR_SIGNATURES:
        if pattern.search(text):
            return label
    return None


def _cache_allows_storage(cache_control: str) -> bool:
    directives = {part.strip().lower().split("=", 1)[0] for part in cache_control.split(",")}
    return not (_MISSING_CACHE_DIRECTIVES & directives)


def _looks_sensitive_response(response) -> bool:
    headers = _headers(response)
    if "set-cookie" in headers:
        return True
    content_type = headers.get("content-type", "")
    return "json" in content_type.lower() and _SENSITIVE_RESPONSE_RE.search(response.text) is not None


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


def _sqli_finding(
    path: str,
    param: str,
    *,
    method: str,
    confidence: str,
    snippet: str,
    probe_evidence: dict[str, Any],
) -> Finding:
    evidence = {
        "probe": "sql_injection",
        "status": "confirmed",
        "endpoint": path,
        "parameter": param,
        "method": method,
        "stored_response": "status codes, timings, and matched signatures only",
    }
    evidence.update(probe_evidence)
    return Finding(
        title=f"SQL injection confirmed ({method})",
        severity="Critical",
        confidence=confidence,
        status="confirmed",
        source="dynamic",
        detector_id="A001",
        owasp=["A03:2021-Injection"],
        location=Location(file=f"dynamic:{path}", line=1, column=1),
        snippet=redact_text(snippet),
        evidence={
            "dynamic_probe": evidence,
            "attack_path": f"Injecting SQL metacharacters into `{param}` reaches the database, so an attacker can read or modify data with crafted queries.",
        },
        impact="A reachable SQL injection lets an attacker read, modify, or destroy database contents.",
        remediation="Use parameterized queries / prepared statements; never build SQL by interpolating request input.",
    )


def _detect_error_based_sqli(gate, path: str, param: str, baseline) -> Finding | None:
    baseline_has_error = _sql_error_signature(baseline.text) is not None
    if baseline_has_error:
        return None
    for payload in SQLI_PAYLOADS:
        try:
            response = gate.request("GET", _with_param(path, param, payload))
        except Exception:  # noqa: BLE001
            continue
        signature = _sql_error_signature(response.text)
        if signature:
            return _sqli_finding(
                path,
                param,
                method="error-based",
                confidence="high",
                snippet=f"GET {path}?{param}=<sql payload> triggered a database error",
                probe_evidence={
                    "payload": payload,
                    "response_status": response.status_code,
                    "error_signature": signature,
                },
            )
    return None


def _detect_boolean_based_sqli(gate, path: str, param: str, baseline) -> Finding | None:
    """A TRUE clause should mirror the baseline; a FALSE clause should diverge."""
    baseline_body = _normalized_body(baseline.text)
    for true_payload, false_payload in SQLI_BOOLEAN_PAIRS:
        try:
            true_resp = gate.request("GET", _with_param(path, param, "1" + true_payload))
            false_resp = gate.request("GET", _with_param(path, param, "1" + false_payload))
        except Exception:  # noqa: BLE001
            continue
        if _sql_error_signature(true_resp.text) or _sql_error_signature(false_resp.text):
            continue  # an error path is the error-based detector's job, not boolean inference
        true_body = _normalized_body(true_resp.text)
        false_body = _normalized_body(false_resp.text)
        true_matches_baseline = true_resp.status_code == baseline.status_code and true_body == baseline_body
        false_diverges = false_resp.status_code != baseline.status_code or false_body != baseline_body
        if true_matches_baseline and false_diverges and true_body != false_body:
            return _sqli_finding(
                path,
                param,
                method="boolean-based blind",
                confidence="medium",
                snippet=f"GET {path}?{param} returned baseline content for a TRUE clause and different content for a FALSE clause",
                probe_evidence={
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "true_status": true_resp.status_code,
                    "false_status": false_resp.status_code,
                    "differential": "TRUE clause matched baseline; FALSE clause diverged",
                },
            )
    return None


def _detect_time_based_sqli(gate, path: str, param: str, *, now) -> Finding | None:
    """A TRUE branch that sleeps proves injection when nothing else differs."""
    try:
        control_start = now()
        gate.request("GET", _with_param(path, param, "1"))
        control_elapsed = now() - control_start
    except Exception:  # noqa: BLE001
        return None
    for payload in SQLI_TIME_PAYLOADS:
        try:
            start = now()
            response = gate.request("GET", _with_param(path, param, "1" + payload))
            elapsed = now() - start
        except Exception:  # noqa: BLE001
            continue
        delay = elapsed - control_elapsed
        if delay >= _SQLI_TIME_DELAY_SECONDS - _SQLI_TIME_SLACK_SECONDS:
            return _sqli_finding(
                path,
                param,
                method="time-based blind",
                confidence="medium",
                snippet=f"GET {path}?{param} with a SLEEP() clause took {elapsed:.1f}s vs {control_elapsed:.1f}s control",
                probe_evidence={
                    "payload": payload,
                    "response_status": response.status_code,
                    "control_seconds": round(control_elapsed, 2),
                    "injected_seconds": round(elapsed, 2),
                    "injected_delay_seconds": _SQLI_TIME_DELAY_SECONDS,
                },
            )
    return None


def probe_sql_injection(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
    enable_time_based: bool = True,
    max_time_based_endpoints: int = 5,
    now=None,
) -> list[Finding]:
    """Detect SQL injection via error-, boolean-, then time-based inference.

    Every technique is read-only: it issues GET requests through the gate and only
    *reads* the response (status, body shape, or latency). No payload modifies or
    drops data — boolean clauses are SELECT conditions and time clauses just make
    the database wait.
    """
    now = now or time.monotonic
    findings: list[Finding] = []
    time_based_used = 0
    for path, param in endpoints:
        try:
            baseline = gate.request("GET", _with_param(path, param, "1"))
        except Exception as error:  # noqa: BLE001 - probe must never crash the scan
            if feed:
                feed.emit("red", f"SQLi probe skipped {path}?{param}: {error}")
            continue
        finding = _detect_error_based_sqli(gate, path, param, baseline)
        if finding is None:
            finding = _detect_boolean_based_sqli(gate, path, param, baseline)
        if finding is None and enable_time_based and time_based_used < max_time_based_endpoints:
            time_based_used += 1
            finding = _detect_time_based_sqli(gate, path, param, now=now)
        if finding is None:
            if feed:
                feed.emit("red", f"No SQL injection at {path}?{param}")
            continue
        findings.append(finding)
        if feed:
            method = finding.evidence["dynamic_probe"]["method"]
            feed.emit("red", f"Confirmed SQL injection ({method}) at {path}?{param}")
    return findings


def probe_reflected_xss(gate, endpoints: Iterable[tuple[str, str]], *, feed: EventFeed | None = None) -> list[Finding]:
    """Detect reflected XSS by checking whether HTML-significant characters survive.

    Sends a unique marker wrapped in ``<`` / ``>`` / ``"`` (never an executing
    script). If the marker comes back with those characters *unencoded* in an HTML
    response — and the baseline value did not already contain it — the output sink
    is not escaping, so a real payload would execute. Detection only.
    """
    findings: list[Finding] = []
    reflected: list[dict[str, Any]] = []
    for path, param in endpoints:
        try:
            baseline = gate.request("GET", _with_param(path, param, _XSS_MARKER))
        except Exception:  # noqa: BLE001
            continue
        # If the bare marker is not even echoed, this parameter isn't a reflection sink.
        if _XSS_MARKER not in baseline.text:
            continue
        # The marker echoes; now check whether the dangerous characters survive raw.
        for context, probe in (("element", _XSS_PROBE), ("attribute", _XSS_ATTR_PROBE)):
            try:
                response = gate.request("GET", _with_param(path, param, probe))
            except Exception:  # noqa: BLE001
                continue
            content_type = _header(response, "content-type")
            html_response = bool(_HTML_CONTENT_TYPE_RE.search(content_type)) or "<html" in response.text.lower()
            if probe in response.text and html_response:
                reflected.append(
                    {
                        "endpoint": path,
                        "parameter": param,
                        "context": context,
                        "response_status": response.status_code,
                        "content_type": redact_text(content_type),
                    }
                )
                if feed:
                    feed.emit("red", f"Reflected XSS at {path}?{param} ({context} context)")
                break
        else:
            if feed:
                feed.emit("red", f"No reflected XSS at {path}?{param}")
    if not reflected:
        return findings
    findings.append(
        Finding(
            title="Reflected cross-site scripting (unescaped input reflected into HTML)",
            severity="High",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A012",
            owasp=["A03:2021-Injection", "WSTG-INPV-01"],
            location=Location(file=f"dynamic:{reflected[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(reflected)} parameter(s) reflected HTML-significant characters unescaped.",
            evidence={
                "dynamic_probe": {
                    "probe": "reflected_xss",
                    "status": "confirmed",
                    "reflections": reflected,
                    "marker": _XSS_MARKER,
                    "stored_response": "endpoint, parameter, reflection context, and status only",
                },
                "attack_path": "Input is reflected into the HTML response without encoding, so an attacker-supplied script in this parameter would run in the victim's browser.",
            },
            impact="Reflected XSS lets an attacker run script in a victim's session: steal cookies/tokens, perform actions as the user, or deface the page.",
            remediation="Context-encode all user input on output (HTML/attribute/JS), prefer framework auto-escaping, and add a restrictive Content-Security-Policy.",
        )
    )
    return findings


def discover_params(
    gate,
    paths: Iterable[str],
    *,
    feed: EventFeed | None = None,
    wordlist: Iterable[str] = PARAM_WORDLIST,
    max_paths: int = 6,
) -> list[tuple[str, str]]:
    """Fan a parameter wordlist across known paths to find live input sinks.

    SPAs and minified bundles rarely reveal their query parameters in source, so
    coverage otherwise depends on what the user happened to pass via ``--endpoint``.
    For each path we send a unique marker as each candidate parameter (read-only
    GET) and keep the parameter when the response either reflects the marker or
    differs from a no-parameter baseline — i.e. the server actually consumed it.
    Returns ``(path, param)`` pairs to feed the injection detectors.
    """
    discovered: dict[tuple[str, str], None] = {}
    marker = _XSS_MARKER
    for path in _dedupe(list(paths))[:max_paths]:
        try:
            baseline = gate.request("GET", path)
        except Exception:  # noqa: BLE001
            continue
        baseline_body = _normalized_body(baseline.text)
        for param in wordlist:
            try:
                response = gate.request("GET", _with_param(path, param, marker))
            except GuardrailError:
                # Hit the request cap — stop discovery, keep what we have.
                if feed:
                    feed.emit("red", "Parameter discovery stopped at request cap")
                return list(discovered)
            except Exception:  # noqa: BLE001
                continue
            consumed = marker in response.text or (
                response.status_code != baseline.status_code or _normalized_body(response.text) != baseline_body
            )
            if consumed:
                discovered[(path, param)] = None
    if feed and discovered:
        feed.emit("attack", f"Parameter discovery found {len(discovered)} live (path, param) pair(s)")
    return list(discovered)


def probe_security_headers(gate, target: str, *, feed: EventFeed | None = None) -> list[Finding]:
    try:
        response = gate.request("GET", "/")
    except Exception as error:  # noqa: BLE001
        if feed:
            feed.emit("red", f"Security-header probe skipped: {error}")
        return []
    issues = _security_header_issues(response, target=target)
    exposed_stack = _technology_headers(response)
    if not issues and not exposed_stack:
        if feed:
            feed.emit("red", "Security-header probe found no obvious gaps at /")
        return []
    severity = "Medium" if any(issue["header"] in {"Content-Security-Policy", "X-Frame-Options or CSP frame-ancestors"} for issue in issues) else "Low"
    return [
        Finding(
            title="Weak or missing browser security headers",
            severity=severity,
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A003",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "A05:2021-Security Misconfiguration",
                "API8:2023-Security Misconfiguration",
                "WSTG-CONF-07",
            ],
            location=Location(file="dynamic:/", line=1, column=1),
            snippet=f"GET / returned {len(issues)} missing/weak security header(s).",
            evidence={
                "dynamic_probe": {
                    "probe": "security_headers",
                    "status": "confirmed",
                    "response_status": response.status_code,
                    "missing_or_weak_headers": issues,
                    "exposed_technology_headers": exposed_stack,
                    "stored_response": "header names and redacted header values only",
                },
                "attack_path": "Browsers did not receive the expected hardening directives, increasing exposure to XSS, clickjacking, MIME sniffing, referrer leakage, or fingerprinting.",
            },
            impact="Missing browser security headers remove defense-in-depth controls that reduce exploitability of common web bugs.",
            remediation="Set a restrictive Content-Security-Policy, frame protections, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, and HSTS on HTTPS sites.",
        )
    ]


def probe_cookie_attributes(gate, target: str, *, feed: EventFeed | None = None) -> list[Finding]:
    try:
        response = gate.request("GET", "/")
    except Exception as error:  # noqa: BLE001
        if feed:
            feed.emit("red", f"Cookie-attribute probe skipped: {error}")
        return []
    issues = _cookie_issues(_headers(response), secure_transport=urlparse(target).scheme == "https")
    if not issues:
        return []
    return [
        Finding(
            title="Session cookies missing protective attributes",
            severity="Medium",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A004",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "A07:2021-Identification and Authentication Failures",
                "WSTG-SESS-02",
            ],
            location=Location(file="dynamic:/", line=1, column=1),
            snippet=f"GET / set {len(issues)} cookie(s) without expected protective attributes.",
            evidence={
                "dynamic_probe": {
                    "probe": "cookie_attributes",
                    "status": "confirmed",
                    "response_status": response.status_code,
                    "cookie_issues": issues,
                    "stored_response": "cookie names and missing attribute names only",
                },
                "attack_path": "A browser accepted cookies that are easier to steal, send cross-site, or expose to script than hardened session cookies.",
            },
            impact="Weak cookie attributes increase the impact of XSS, CSRF, and session theft.",
            remediation="Set HttpOnly on sensitive cookies, Secure on HTTPS cookies, and an explicit SameSite policy appropriate to the application.",
        )
    ]


def probe_http_methods(gate, paths: Iterable[str], *, feed: EventFeed | None = None) -> list[Finding]:
    exposures: list[dict[str, Any]] = []
    high_risk_seen: set[str] = set()
    for path in _dedupe(paths)[:12]:
        try:
            response = gate.request("OPTIONS", path)
        except Exception:  # noqa: BLE001
            continue
        methods = _parse_methods(_header(response, "allow")) | _parse_methods(_header(response, "access-control-allow-methods"))
        risky = sorted(methods & _UNSAFE_HTTP_METHODS)
        if risky:
            high = sorted(methods & _HIGH_RISK_HTTP_METHODS)
            high_risk_seen.update(high)
            exposures.append(
                {
                    "path": path,
                    "status": response.status_code,
                    "methods": risky,
                    "high_risk": high,
                }
            )
    if not exposures:
        if feed:
            feed.emit("red", "HTTP-method probe found no advertised unsafe methods")
        return []
    # Any write/diagnostic verb (PUT/DELETE/PATCH, WebDAV writes, TRACE, CONNECT)
    # is High; a read-only WebDAV PROPFIND alone is Medium.
    severity = "High" if high_risk_seen else "Medium"
    return [
        Finding(
            title="Unsafe HTTP methods advertised by live target",
            severity=severity,
            confidence="medium",
            status="confirmed",
            source="dynamic",
            detector_id="A005",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "API8:2023-Security Misconfiguration",
                "WSTG-CONF-06",
            ],
            location=Location(file="dynamic:OPTIONS", line=1, column=1),
            snippet=f"OPTIONS responses advertised unsafe methods on {len(exposures)} path(s)"
            + (f" (high-risk: {', '.join(sorted(high_risk_seen))})" if high_risk_seen else "")
            + ".",
            evidence={
                "dynamic_probe": {
                    "probe": "http_methods",
                    "status": "confirmed",
                    "advertised_methods": exposures,
                    "high_risk_methods": sorted(high_risk_seen),
                    "stored_response": "paths, status codes, and advertised methods only",
                },
                "attack_path": "Attackers can target state-changing (PUT/DELETE/PATCH, WebDAV) or diagnostic (TRACE/CONNECT) methods if the server, proxy, or CORS layer exposes them unintentionally.",
            },
            impact="Unexpected HTTP verbs expand the attack surface and can enable verb tampering, file upload/overwrite via WebDAV, Cross-Site Tracing, or unsafe proxy behavior.",
            remediation="Disable TRACE/CONNECT and any state-changing or WebDAV methods that are not required on each route; allow only the verbs each endpoint actually needs.",
        )
    ]


def probe_exposed_paths(gate, *, feed: EventFeed | None = None) -> list[Finding]:
    try:
        baseline = gate.request("GET", "/__penny_probe_missing_resource__")
    except Exception:  # noqa: BLE001
        baseline = None
    exposures: list[dict[str, Any]] = []
    for check in _EXPOSED_PATH_CHECKS:
        try:
            response = gate.request("GET", check.path)
        except Exception:  # noqa: BLE001
            continue
        signature = _exposed_path_match(check, response)
        if response.status_code == 200 and signature and _distinct_from_baseline(response, baseline):
            exposures.append(
                {
                    "path": check.path,
                    "type": check.label,
                    "severity": check.severity,
                    "status": response.status_code,
                    "signature": signature,
                }
            )
    if not exposures:
        if feed:
            feed.emit("red", "Exposure probe found no sensitive files, debug endpoints, or public API schemas")
        return []
    severity = _highest_severity(exposure["severity"] for exposure in exposures)
    return [
        Finding(
            title="Sensitive files or administrative metadata exposed",
            severity=severity,
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A006",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "A05:2021-Security Misconfiguration",
                "API8:2023-Security Misconfiguration",
                "API9:2023-Improper Inventory Management",
                "WSTG-INFO-03",
                "WSTG-CONF-04",
                "WSTG-CONF-05",
            ],
            location=Location(file="dynamic:exposed-paths", line=1, column=1),
            snippet=f"{len(exposures)} sensitive or administrative path(s) returned recognizable content.",
            evidence={
                "dynamic_probe": {
                    "probe": "exposed_paths",
                    "status": "confirmed",
                    "exposures": exposures,
                    "stored_response": "paths, status codes, and redacted content signatures only",
                },
                "attack_path": "Publicly reachable deployment files, debug surfaces, or API inventories give attackers configuration data and route maps.",
            },
            impact="Exposed operational files and admin metadata can leak secrets, source layout, framework details, or API inventory.",
            remediation="Remove these files from the web root, require authentication for administrative surfaces, and avoid publishing internal API schemas unless intentionally public.",
        )
    ]


def probe_directory_listing(gate, *, feed: EventFeed | None = None) -> list[Finding]:
    listings: list[dict[str, Any]] = []
    for path in _DIRECTORY_LISTING_PATHS:
        try:
            response = gate.request("GET", path)
        except Exception:  # noqa: BLE001
            continue
        if response.status_code == 200 and _DIRECTORY_LISTING_RE.search(response.text):
            listings.append({"path": path, "status": response.status_code})
    if not listings:
        return []
    return [
        Finding(
            title="Directory listing is enabled",
            severity="Medium",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A007",
            owasp=["A02:2025-Security Misconfiguration", "A05:2021-Security Misconfiguration", "WSTG-CONF-02"],
            location=Location(file="dynamic:directory-listing", line=1, column=1),
            snippet=f"{len(listings)} directory path(s) returned an index listing.",
            evidence={
                "dynamic_probe": {
                    "probe": "directory_listing",
                    "status": "confirmed",
                    "listings": listings,
                    "stored_response": "paths and status codes only",
                },
                "attack_path": "An attacker can browse files directly from server-generated directory indexes.",
            },
            impact="Directory listings can reveal source artifacts, uploaded files, backups, and other unlinked content.",
            remediation="Disable autoindex/directory browsing and serve only intended static assets.",
        )
    ]


def probe_verbose_errors(gate, *, feed: EventFeed | None = None) -> list[Finding]:
    try:
        response = gate.request("GET", "/__penny_probe_error_surface__")
    except Exception as error:  # noqa: BLE001
        if feed:
            feed.emit("red", f"Verbose-error probe skipped: {error}")
        return []
    signature = _verbose_error_signature(response.text)
    if not signature:
        return []
    return [
        Finding(
            title="Verbose error details exposed to clients",
            severity="Medium",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A008",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "A10:2025-Mishandling of Exceptional Conditions",
                "API8:2023-Security Misconfiguration",
                "WSTG-ERRH-01",
                "WSTG-ERRH-02",
            ],
            location=Location(file="dynamic:/__penny_probe_error_surface__", line=1, column=1),
            snippet=f"A synthetic missing-resource request returned a {signature}.",
            evidence={
                "dynamic_probe": {
                    "probe": "verbose_errors",
                    "status": "confirmed",
                    "response_status": response.status_code,
                    "error_signature": signature,
                    "stored_response": "status code and error signature only",
                },
                "attack_path": "Unexpected requests expose implementation details useful for targeted exploitation.",
            },
            impact="Stack traces and framework error pages reveal code paths, versions, filesystem paths, and backend technologies.",
            remediation="Disable debug error pages in production and return generic client-facing errors while logging details server-side.",
        )
    ]


def probe_cors_preflight(gate, paths: Iterable[str], *, feed: EventFeed | None = None) -> list[Finding]:
    issues: list[dict[str, Any]] = []
    headers = {
        "origin": _ATTACKER_ORIGIN,
        "access-control-request-method": "DELETE",
        "access-control-request-headers": "authorization,content-type",
    }
    for path in _dedupe(paths)[:8]:
        try:
            response = gate.request("OPTIONS", path, headers=headers)
        except Exception:  # noqa: BLE001
            continue
        response_headers = _headers(response)
        allow_origin = response_headers.get("access-control-allow-origin", "")
        allow_credentials = response_headers.get("access-control-allow-credentials", "")
        allow_methods = _parse_methods(response_headers.get("access-control-allow-methods", ""))
        allow_headers = response_headers.get("access-control-allow-headers", "")
        permissive_origin = allow_origin == "*" or allow_origin == _ATTACKER_ORIGIN
        risky_methods = sorted(allow_methods & _UNSAFE_HTTP_METHODS)
        risky_headers = "authorization" in allow_headers.lower()
        if permissive_origin and (allow_credentials.lower() == "true" or risky_methods or risky_headers):
            issues.append(
                {
                    "path": path,
                    "status": response.status_code,
                    "allow_origin": redact_text(allow_origin),
                    "allow_credentials": redact_text(allow_credentials),
                    "risky_methods": risky_methods,
                    "allows_authorization_header": risky_headers,
                }
            )
    if not issues:
        return []
    severity = "High" if any(issue["allow_credentials"].lower() == "true" for issue in issues) else "Medium"
    return [
        Finding(
            title="Permissive CORS preflight policy",
            severity=severity,
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A009",
            owasp=[
                "A02:2025-Security Misconfiguration",
                "A05:2021-Security Misconfiguration",
                "API8:2023-Security Misconfiguration",
                "WSTG-CLNT-07",
            ],
            location=Location(file="dynamic:CORS", line=1, column=1),
            snippet=f"OPTIONS preflight allowed an untrusted origin on {len(issues)} path(s).",
            evidence={
                "dynamic_probe": {
                    "probe": "cors_preflight",
                    "status": "confirmed",
                    "request_origin": _ATTACKER_ORIGIN,
                    "issues": issues,
                    "stored_response": "CORS headers only",
                },
                "attack_path": "A malicious site can ask the browser for permission to send credentialed or sensitive cross-origin API requests.",
            },
            impact="Permissive CORS preflight can expose authenticated APIs to attacker-controlled browser origins.",
            remediation="Allow only trusted origins, avoid wildcard CORS on authenticated APIs, and restrict allowed methods and headers to what each route needs.",
        )
    ]


def probe_cache_controls(gate, paths: Iterable[str], *, feed: EventFeed | None = None) -> list[Finding]:
    checked_paths = _dedupe([*paths, *_CACHE_PROBE_PATHS])[:10]
    cacheable_sensitive: list[dict[str, Any]] = []
    for path in checked_paths:
        try:
            response = gate.request("GET", path)
        except Exception:  # noqa: BLE001
            continue
        if response.status_code != 200 or not _looks_sensitive_response(response):
            continue
        cache_control = _header(response, "cache-control")
        if _cache_allows_storage(cache_control):
            cacheable_sensitive.append(
                {
                    "path": path,
                    "status": response.status_code,
                    "cache_control": redact_text(cache_control or "<missing>"),
                    "content_type": redact_text(_header(response, "content-type")),
                }
            )
    if not cacheable_sensitive:
        return []
    return [
        Finding(
            title="Sensitive response may be cached by clients",
            severity="Medium",
            confidence="medium",
            status="confirmed",
            source="dynamic",
            detector_id="A010",
            owasp=["A02:2025-Security Misconfiguration", "API8:2023-Security Misconfiguration", "WSTG-SESS-06"],
            location=Location(file="dynamic:cache-control", line=1, column=1),
            snippet=f"{len(cacheable_sensitive)} sensitive-looking response(s) lacked no-store/private cache controls.",
            evidence={
                "dynamic_probe": {
                    "probe": "cache_controls",
                    "status": "confirmed",
                    "cacheable_sensitive_responses": cacheable_sensitive,
                    "stored_response": "paths, status codes, content type, and Cache-Control header only",
                },
                "attack_path": "Sensitive API or session responses can remain in browser or intermediary caches after use.",
            },
            impact="Cached private responses can leak account data on shared systems or through intermediary caches.",
            remediation="Send Cache-Control: no-store for highly sensitive responses, or at least private/no-cache where browser caching is acceptable.",
        )
    ]


def probe_checklist_baseline(
    gate,
    target: str,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
) -> list[Finding]:
    paths = _candidate_paths(endpoints)
    findings: list[Finding] = []
    findings.extend(probe_security_headers(gate, target, feed=feed))
    findings.extend(probe_cookie_attributes(gate, target, feed=feed))
    findings.extend(probe_http_methods(gate, paths, feed=feed))
    findings.extend(probe_exposed_paths(gate, feed=feed))
    findings.extend(probe_directory_listing(gate, feed=feed))
    findings.extend(probe_verbose_errors(gate, feed=feed))
    findings.extend(probe_cors_preflight(gate, paths, feed=feed))
    findings.extend(probe_cache_controls(gate, paths, feed=feed))
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
        # Budget covers the checklist baseline, parameter discovery, and the
        # error/boolean/time injection passes plus the new injection/traversal/SSTI/
        # redirect/SSRF passes (each endpoint costs several GETs across them all).
        param_paths = _candidate_paths(endpoints)
        per_endpoint = len(SQLI_PAYLOADS) + 2 * len(SQLI_BOOLEAN_PAIRS) + len(SQLI_TIME_PAYLOADS) + 4
        # NoSQL, SSTI, traversal, command-injection, open-redirect, and SSRF each fan a
        # handful of payloads across every endpoint; reserve headroom so the request cap
        # is not hit mid-pass (which would silently truncate coverage).
        extra_per_endpoint = 24
        # `discovery_cost` is the request count for the parameter-discovery sweep.
        # `max_discovered` bounds how many (path, param) pairs that sweep can feed back
        # into the injection passes — one per (path, wordlist-entry). Each discovered
        # pair is then injection-probed at `per_endpoint + extra_per_endpoint` cost,
        # same as a known endpoint, so the cap must cover both. The estimate is an
        # upper bound (it assumes every probe discovers a live param), so it can only
        # over-budget, never truncate coverage.
        discovery_paths = min(len(param_paths), 6)
        discovery_cost = discovery_paths * (len(PARAM_WORDLIST) + 1)
        max_discovered = discovery_paths * len(PARAM_WORDLIST)
        request_budget = max(
            300,
            100 + discovery_cost + (len(endpoints) + max_discovered) * (per_endpoint + extra_per_endpoint),
        )
        try:
            gate = TargetGate(target, i_own_this=i_own_this, max_requests=request_budget)
        except GuardrailError as error:
            feed.emit("gate", f"Active target blocked: {error}")
        else:
            feed.emit("attack", "Running checklist-style live probes (headers, cookies, methods, exposures, errors, CORS, cache)")
            findings.extend(probe_checklist_baseline(gate, target, endpoints, feed=feed))
            from .transport import run_transport_probes

            findings.extend(run_transport_probes(target, i_own_this=i_own_this, feed=feed))
            # nuclei-style templated checks (tech/CVE fingerprints, exposed surfaces).
            from .templates import run_template_checks

            findings.extend(run_template_checks(gate, feed=feed))
            # Expand the injection surface: fan a parameter wordlist across known
            # paths so coverage doesn't depend on params being visible in source.
            feed.emit("attack", f"Discovering query parameters across {min(len(param_paths), 6)} path(s)")
            endpoints = list(dict.fromkeys(endpoints + discover_params(gate, param_paths, feed=feed)))
            if endpoints:
                feed.emit("attack", f"Probing {len(endpoints)} endpoint(s) for SQL injection and reflected XSS")
                findings.extend(probe_sql_injection(gate, endpoints, feed=feed))
                findings.extend(probe_reflected_xss(gate, endpoints, feed=feed))

                # Extended injection surface: NoSQL operator injection, SSTI, path
                # traversal, time-based command injection, and out-of-band SSRF.
                from .injection import (
                    probe_command_injection,
                    probe_nosql_injection,
                    probe_open_redirect,
                    probe_path_traversal,
                    probe_ssti,
                )

                feed.emit("attack", f"Probing {len(endpoints)} endpoint(s) for NoSQL injection, SSTI, traversal, and command injection")
                findings.extend(probe_nosql_injection(gate, endpoints, feed=feed))
                findings.extend(probe_ssti(gate, endpoints, feed=feed))
                findings.extend(probe_path_traversal(gate, endpoints, feed=feed))
                findings.extend(probe_command_injection(gate, endpoints, feed=feed))

                # Open redirect needs a gate that *reports* (does not block) off-host
                # redirects so the probe can read the Location header.
                try:
                    redirect_gate = TargetGate(
                        target,
                        i_own_this=i_own_this,
                        max_requests=max(50, len(endpoints) * 8),
                        inspect_offhost_redirects=True,
                    )
                except GuardrailError:
                    redirect_gate = None
                if redirect_gate is not None:
                    findings.extend(probe_open_redirect(redirect_gate, endpoints, target=target, feed=feed))

                from .ssrf import probe_ssrf

                feed.emit("attack", "Probing URL-style parameters for SSRF via a self-hosted callback listener")
                findings.extend(probe_ssrf(gate, endpoints, target=target, feed=feed))
            else:
                feed.emit("attack", "No query-string endpoints found or discovered to test for injection")

            # JWT tampering and GraphQL introspection use their own curated path lists,
            # so they run whether or not query-string endpoints were discovered.
            from .api_probes import probe_graphql_introspection, probe_jwt_tampering

            feed.emit("attack", "Probing for JWT signature bypass and GraphQL introspection")
            findings.extend(probe_jwt_tampering(gate, feed=feed))
            findings.extend(probe_graphql_introspection(gate, feed=feed))
    elif not databases:
        feed.emit("attack", "Active mode found nothing to probe (no target and no Firebase config)")

    return findings
