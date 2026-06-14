"""Active injection / traversal / redirect probes (detectors A016-A020).

These extend the active-mode HTTP surface beyond SQL injection and reflected XSS
(both in :mod:`penny.active`) to the remaining high-impact input-handling bugs an
attacker reaches through ordinary GET parameters:

* ``probe_nosql_injection`` (A016) — operator-injection against Mongo-style query
  layers. A document store that builds a filter from raw request input treats
  ``param[$ne]=`` as the operator ``{"$ne": ...}`` instead of a literal, so an
  authentication or lookup check can be turned always-true. Detection is the same
  TRUE/FALSE differential the boolean-blind SQLi probe uses — read-only.
* ``probe_ssti`` (A017) — server-side template injection. We send a benign
  arithmetic marker (``{{<n>*<m>}}``-style across several engines) and look for the
  *product* in the response. Seeing the evaluated number proves the template engine
  executed attacker input — a step from RCE on most engines. We never send a payload
  that reads files or runs commands; arithmetic is the safe canary.
* ``probe_path_traversal`` (A018) — directory traversal. We request well-known
  host files via ``../`` sequences (and encoded variants) and match their canonical
  signatures (``root:x:0:0`` for ``/etc/passwd``, the ``[fonts]`` section of
  ``win.ini``). Read-only: we only read what the server hands back.
* ``probe_command_injection`` (A019) — OS command injection, time-based. Like the
  time-based SQLi probe, a TRUE branch that ``sleep``s proves the parameter reaches
  a shell when nothing else differs. We compare against a no-op control and only
  trust a delay dramatically larger than the control to avoid flagging jitter. The
  injected command is a bare ``sleep`` — it does not read, write, or exfiltrate.
* ``probe_open_redirect`` (A020) — unvalidated redirects. We point redirect-style
  parameters at an off-site canary host and flag the endpoint when the server issues
  a 3xx whose ``Location`` actually leaves the target's origin. Read-only; the gate
  never follows the redirect.

Every probe takes its HTTP gate by injection so the logic is unit-testable offline,
and reaches the target only through :class:`~penny.guardrails.TargetGate` (GET only,
rate-limited, no redirect-following), so it inherits all of active mode's guardrails.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from .feed import EventFeed
from .models import Finding, Location
from .redaction import redact_text

# Shared helpers mirror penny.active so payload encoding and body-shape comparison
# behave identically across the injection probes. This top-level import is safe
# because active.py imports this module only lazily (inside run_active_probes), so
# active is always fully initialized before injection is first imported — there is
# no import cycle for the load order the package actually uses.
from .active import _header, _normalized_body, _with_param


# --- A016: NoSQL injection -------------------------------------------------

# Operator-injection payloads for Mongo-style backends. `param[$ne]=x` is parsed by
# many body/query parsers into `{"param": {"$ne": "x"}}`; against a lookup that means
# "not equal to x" — typically always-true — while the FALSE control stays a literal.
# All read-only: they only change which documents a SELECT-equivalent returns.
# Both sides of every pair carry the *same* value (or empty), so an endpoint that
# merely reflects the value cannot trip the differential — only a backend that
# actually evaluates the operator diverges. (A `$regex` pair with different patterns
# was deliberately dropped: its two sides carry different literal values, so any
# value-reflecting endpoint would false-positive.)
_NOSQL_TRUE_FALSE = (
    # (true_suffix, false_suffix) appended to the *parameter name* portion.
    ("[$ne]=penny_nomatch_xq9", "[$eq]=penny_nomatch_xq9"),
    ("[$gt]=", "[$lt]="),
)
# JSON-style injection strings some endpoints accept as the raw value.
_NOSQL_VALUE_PAYLOADS = (
    ('{"$ne": null}', '{"$eq": "penny_nomatch_xq9"}'),
    ('{"$gt": ""}', '{"$lt": ""}'),
)
_NOSQL_ERROR_RE = re.compile(
    r"(MongoError|MongoServerError|BSONError|\$where|\$ne|cast to .* failed for value|"
    r"unknown operator|CastError|E11000|mongoose)",
    re.I,
)


def _nosql_param_injection(path: str, param: str, suffix: str) -> str:
    """Build `path?param[$ne]=x` — the operator is injected into the parameter name."""
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{param}{suffix}"


def probe_nosql_injection(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect NoSQL operator injection via a TRUE/FALSE differential or DB error.

    A document-store query built from raw request input parses ``param[$ne]=x`` as
    the operator ``{"$ne": "x"}``. The TRUE operator (``$ne`` against a value that
    never matches) widens the result set; the FALSE control (``$eq`` against the same
    value) narrows it. Divergence — or a leaked Mongo/Mongoose error — confirms the
    parameter reaches the query layer unsanitized. Read-only.
    """
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path, param in endpoints:
        try:
            baseline = gate.request("GET", _with_param(path, param, "penny_baseline_xq9"))
        except Exception:  # noqa: BLE001 - a probe must never crash the scan
            continue
        baseline_body = _normalized_body(baseline.text)
        confirmed = _nosql_endpoint_hit(gate, path, param, baseline, baseline_body)
        if confirmed:
            hits.append(confirmed)
            if feed:
                feed.emit("red", f"Confirmed NoSQL injection at {path}?{param} ({confirmed['method']})")
        elif feed:
            feed.emit("red", f"No NoSQL injection at {path}?{param}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="NoSQL injection confirmed (operator injection reaches the query layer)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A016",
            owasp=["A03:2021-Injection", "WSTG-INPV-05"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) accepted NoSQL query operators as input.",
            evidence={
                "dynamic_probe": {
                    "probe": "nosql_injection",
                    "status": "confirmed",
                    "hits": hits,
                    "stored_response": "endpoint, parameter, method, and status codes only",
                },
                "attack_path": "Request input is interpolated into a document-store query, so an attacker can inject operators ($ne/$gt/$regex/$where) to bypass authentication, exfiltrate documents, or change which records a query returns.",
            },
            impact="NoSQL injection lets an attacker bypass authentication and read or alter database documents with crafted query operators.",
            remediation="Validate and cast request input to the expected scalar type before querying; reject objects/operators in user-controlled fields and use a schema/ODM that coerces types.",
        )
    )
    return findings


def _nosql_endpoint_hit(gate, path: str, param: str, baseline, baseline_body: str) -> dict[str, Any] | None:
    # Error-based first: a leaked Mongo/Mongoose error is the clearest signal.
    if not _NOSQL_ERROR_RE.search(baseline.text):
        for true_suffix, _ in _NOSQL_TRUE_FALSE:
            try:
                response = gate.request("GET", _nosql_param_injection(path, param, true_suffix))
            except Exception:  # noqa: BLE001
                continue
            error = _NOSQL_ERROR_RE.search(response.text)
            if error:
                return {
                    "endpoint": path,
                    "parameter": param,
                    "method": "error-based",
                    "payload": f"{param}{true_suffix}",
                    "response_status": response.status_code,
                    "error_signature": redact_text(error.group(0)),
                }
    # Differential: TRUE operator should change the result vs the FALSE control.
    for true_suffix, false_suffix in _NOSQL_TRUE_FALSE:
        try:
            true_resp = gate.request("GET", _nosql_param_injection(path, param, true_suffix))
            false_resp = gate.request("GET", _nosql_param_injection(path, param, false_suffix))
        except Exception:  # noqa: BLE001
            continue
        true_body = _normalized_body(true_resp.text)
        false_body = _normalized_body(false_resp.text)
        # The TRUE operator must diverge from BOTH the false control and the literal
        # baseline; otherwise the endpoint ignores the operator (no injection).
        if true_body != false_body and true_body != baseline_body and true_resp.status_code < 500:
            return {
                "endpoint": path,
                "parameter": param,
                "method": "operator differential",
                "payload": f"{param}{true_suffix}",
                "true_status": true_resp.status_code,
                "false_status": false_resp.status_code,
                "differential": "operator query changed the result set vs the literal control",
            }
    return None


# --- A017: Server-Side Template Injection ----------------------------------

# A benign arithmetic canary across the common template syntaxes. We pick two large
# coprime-ish factors so the product is long and unlikely to appear in the page by
# coincidence, and so it cannot be confused with the literal payload echoing back.
_SSTI_FACTOR_A = 1337
_SSTI_FACTOR_B = 7331
_SSTI_PRODUCT = str(_SSTI_FACTOR_A * _SSTI_FACTOR_B)  # 9,801,547 — distinctive
_SSTI_EXPR = f"{_SSTI_FACTOR_A}*{_SSTI_FACTOR_B}"
# Each entry is a payload that, if the engine evaluates it, renders _SSTI_PRODUCT.
# We cover Jinja2/Twig (`{{ }}`), ERB/EJS (`<%= %>`), Freemarker (`${ }`), and
# Smarty/Velocity-style `#{ }`. Arithmetic only — never a command or file read.
_SSTI_PAYLOADS = (
    f"{{{{{_SSTI_EXPR}}}}}",      # {{1337*7331}}
    f"${{{_SSTI_EXPR}}}",         # ${1337*7331}
    f"<%= {_SSTI_EXPR} %>",       # <%= 1337*7331 %>
    f"#{{{_SSTI_EXPR}}}",         # #{1337*7331}
    f"{{{_SSTI_EXPR}}}",          # {1337*7331}
)


def probe_ssti(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect server-side template injection with a safe arithmetic canary.

    We send ``{{1337*7331}}`` (and equivalents for other engines). If the *product*
    ``9801547`` appears in the response — while the raw expression itself does not —
    the template engine evaluated attacker input, which is one step from RCE on most
    engines. Detection only: the payload is pure arithmetic, never a command.
    """
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path, param in endpoints:
        hit = _ssti_endpoint_hit(gate, path, param)
        if hit:
            hits.append(hit)
            if feed:
                feed.emit("red", f"Confirmed SSTI at {path}?{param}")
        elif feed:
            feed.emit("red", f"No SSTI at {path}?{param}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="Server-side template injection confirmed (engine evaluated injected expression)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A017",
            owasp=["A03:2021-Injection", "WSTG-INPV-18"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) had an injected template expression evaluated server-side.",
            evidence={
                "dynamic_probe": {
                    "probe": "ssti",
                    "status": "confirmed",
                    "hits": hits,
                    "marker_product": _SSTI_PRODUCT,
                    "stored_response": "endpoint, parameter, payload, and status only",
                },
                "attack_path": "User input is rendered as part of a server-side template, so an attacker-supplied template expression executes on the server — typically escalatable to remote code execution.",
            },
            impact="Server-side template injection commonly leads to remote code execution and full server compromise.",
            remediation="Never render user input as a template. Pass user data only as template *variables*, use a logic-less or sandboxed engine, and disable expression evaluation on untrusted input.",
        )
    )
    return findings


def _ssti_endpoint_hit(gate, path: str, param: str) -> dict[str, Any] | None:
    for payload in _SSTI_PAYLOADS:
        try:
            response = gate.request("GET", _with_param(path, param, payload))
        except Exception:  # noqa: BLE001
            continue
        # The product must appear AND the raw expression must NOT — otherwise the page
        # merely echoed our literal payload back (reflection, not evaluation).
        if _SSTI_PRODUCT in response.text and _SSTI_EXPR not in response.text:
            return {
                "endpoint": path,
                "parameter": param,
                "payload": payload,
                "evaluated_to": _SSTI_PRODUCT,
                "response_status": response.status_code,
            }
    return None


# --- A018: Path traversal --------------------------------------------------

# (payload, signature) pairs. The signature is the canonical content of a host file
# that only exists if traversal escaped the intended directory. We try POSIX and
# Windows targets with raw, encoded, and double-encoded separators.
_TRAVERSAL_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.M)
_TRAVERSAL_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I)
_TRAVERSAL_PAYLOADS = (
    ("../../../../etc/passwd", _TRAVERSAL_PASSWD_RE, "/etc/passwd"),
    ("....//....//....//etc/passwd", _TRAVERSAL_PASSWD_RE, "/etc/passwd"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", _TRAVERSAL_PASSWD_RE, "/etc/passwd"),
    ("..%252f..%252f..%252fetc%252fpasswd", _TRAVERSAL_PASSWD_RE, "/etc/passwd"),
    ("../../../../windows/win.ini", _TRAVERSAL_WININI_RE, "windows/win.ini"),
    ("..\\..\\..\\..\\windows\\win.ini", _TRAVERSAL_WININI_RE, "windows/win.ini"),
)


def probe_path_traversal(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect directory traversal by reading well-known host files via ``../``.

    For each parameter we request ``/etc/passwd`` and ``win.ini`` through traversal
    sequences (raw, URL-encoded, double-encoded, and the ``....//`` filter-bypass
    form). A response containing the file's canonical signature (``root:x:0:0`` /
    the ``[fonts]`` section) proves the parameter is used to build a filesystem path
    without containment. Read-only — we only read what the server returns.
    """
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path, param in endpoints:
        hit = _traversal_endpoint_hit(gate, path, param)
        if hit:
            hits.append(hit)
            if feed:
                feed.emit("red", f"Confirmed path traversal at {path}?{param} -> {hit['target_file']}")
        elif feed:
            feed.emit("red", f"No path traversal at {path}?{param}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="Path traversal confirmed (request read a file outside the intended directory)",
            severity="High",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A018",
            owasp=["A01:2021-Broken Access Control", "A03:2021-Injection", "WSTG-ATHZ-01"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) returned host file contents via ../ traversal.",
            evidence={
                "dynamic_probe": {
                    "probe": "path_traversal",
                    "status": "confirmed",
                    "hits": hits,
                    "stored_response": "endpoint, parameter, target file, and matched signature only — file contents are NOT stored",
                },
                "attack_path": "The parameter is used to build a filesystem path without containment, so an attacker can read arbitrary files on the server (credentials, source, configuration) by walking out of the intended directory.",
            },
            impact="Path traversal exposes arbitrary server files — secrets, source code, and configuration — and can escalate to full compromise.",
            remediation="Never build filesystem paths from raw request input. Resolve the canonical path and confirm it stays within an allowed base directory, or map user input to an allow-listed set of files.",
        )
    )
    return findings


def _traversal_endpoint_hit(gate, path: str, param: str) -> dict[str, Any] | None:
    for payload, signature_re, target_file in _TRAVERSAL_PAYLOADS:
        try:
            response = gate.request("GET", _with_param(path, param, payload))
        except Exception:  # noqa: BLE001
            continue
        match = signature_re.search(response.text)
        if response.status_code == 200 and match:
            return {
                "endpoint": path,
                "parameter": param,
                "payload": payload,
                "target_file": target_file,
                "response_status": response.status_code,
                "matched_signature": redact_text(match.group(0))[:60],
            }
    return None


# --- A019: OS command injection (time-based) -------------------------------

_CMDI_DELAY_SECONDS = 5.0
# A real hit must exceed the control by at least the injected delay minus this slack.
_CMDI_SLACK_SECONDS = 2.0
# Each payload uses a different shell separator so we cover command chaining on POSIX
# (`;`, `&&`, `|`, `$()`, backticks) and Windows (`& ping`/`timeout`). The injected
# command is a pure delay — no read, no write, no network — so the only observable is
# latency, exactly like the time-based SQLi probe.
_CMDI_PAYLOADS = (
    f"; sleep {int(_CMDI_DELAY_SECONDS)}",
    f"& sleep {int(_CMDI_DELAY_SECONDS)}",
    f"&& sleep {int(_CMDI_DELAY_SECONDS)}",
    f"| sleep {int(_CMDI_DELAY_SECONDS)}",
    f"$(sleep {int(_CMDI_DELAY_SECONDS)})",
    f"`sleep {int(_CMDI_DELAY_SECONDS)}`",
    f"& ping -n {int(_CMDI_DELAY_SECONDS) + 1} 127.0.0.1",  # Windows: ping loopback to delay
)


def probe_command_injection(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    feed: EventFeed | None = None,
    max_endpoints: int = 6,
    now=None,
) -> list[Finding]:
    """Detect OS command injection by latency: an injected ``sleep`` that delays.

    Like the time-based blind SQLi probe, we time a no-op control then time a payload
    that appends a shell ``sleep``. If the payload response is slower than the control
    by ~the injected delay, the parameter reaches a shell. The injected command only
    sleeps — it never reads, writes, or exfiltrates — so the sole observable is the
    delay we asked for.
    """
    now = now or time.monotonic
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    checked = 0
    for path, param in endpoints:
        if checked >= max_endpoints:
            break
        checked += 1
        hit = _cmdi_endpoint_hit(gate, path, param, now=now)
        if hit:
            hits.append(hit)
            if feed:
                feed.emit("red", f"Confirmed command injection at {path}?{param}")
        elif feed:
            feed.emit("red", f"No command injection at {path}?{param}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="OS command injection confirmed (injected shell delay observed)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A019",
            owasp=["A03:2021-Injection", "WSTG-INPV-12"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) delayed by an injected shell sleep.",
            evidence={
                "dynamic_probe": {
                    "probe": "command_injection",
                    "status": "confirmed",
                    "hits": hits,
                    "injected_delay_seconds": _CMDI_DELAY_SECONDS,
                    "stored_response": "endpoint, parameter, payload, and timings only",
                },
                "attack_path": "The parameter is passed to a shell, so an attacker can chain arbitrary OS commands (read/write files, install tooling, pivot) with the privileges of the web process.",
            },
            impact="OS command injection is remote code execution: an attacker runs arbitrary commands on the server.",
            remediation="Never pass request input to a shell. Use APIs that take an argument array (no shell), validate against a strict allow-list, and drop shell metacharacters.",
        )
    )
    return findings


def _cmdi_endpoint_hit(gate, path: str, param: str, *, now) -> dict[str, Any] | None:
    try:
        control_start = now()
        gate.request("GET", _with_param(path, param, "penny_control"))
        control_elapsed = now() - control_start
    except Exception:  # noqa: BLE001
        return None
    for payload in _CMDI_PAYLOADS:
        try:
            start = now()
            response = gate.request("GET", _with_param(path, param, "penny_control" + payload))
            elapsed = now() - start
        except Exception:  # noqa: BLE001
            continue
        if elapsed - control_elapsed >= _CMDI_DELAY_SECONDS - _CMDI_SLACK_SECONDS:
            return {
                "endpoint": path,
                "parameter": param,
                "payload": payload,
                "response_status": response.status_code,
                "control_seconds": round(control_elapsed, 2),
                "injected_seconds": round(elapsed, 2),
            }
    return None


# --- A020: Open redirect ---------------------------------------------------

# An off-site canary host the application has no reason to redirect to. If a 3xx
# Location lands here (or on its scheme-relative / backslash-confusion variants),
# the redirect target is attacker-controlled.
_REDIRECT_CANARY_HOST = "penny-redirect.example"
_REDIRECT_PAYLOADS = (
    f"https://{_REDIRECT_CANARY_HOST}/",
    f"//{_REDIRECT_CANARY_HOST}/",            # scheme-relative
    f"/\\{_REDIRECT_CANARY_HOST}/",           # backslash confusion
    f"https:{_REDIRECT_CANARY_HOST}/",        # missing-slash confusion
)


def probe_open_redirect(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    target: str,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect unvalidated redirects by pointing redirect params off-site.

    For each parameter we set the value to an off-site canary URL (and its
    scheme-relative / backslash-confusion variants) and inspect the ``Location`` of
    any 3xx response. If the resolved redirect leaves the target's origin and lands
    on the canary host, the endpoint redirects to attacker-controlled destinations.
    The gate never follows the redirect, so nothing off-site is contacted.
    """
    target_host = (urlparse(target).hostname or "").lower()
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path, param in endpoints:
        hit = _open_redirect_endpoint_hit(gate, path, param, target_host)
        if hit:
            hits.append(hit)
            if feed:
                feed.emit("red", f"Confirmed open redirect at {path}?{param}")
        elif feed:
            feed.emit("red", f"No open redirect at {path}?{param}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="Open redirect confirmed (server redirects to an attacker-controlled host)",
            severity="Medium",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A020",
            owasp=["A01:2021-Broken Access Control", "WSTG-CLNT-04"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) redirected off-site to a controlled host.",
            evidence={
                "dynamic_probe": {
                    "probe": "open_redirect",
                    "status": "confirmed",
                    "hits": hits,
                    "canary_host": _REDIRECT_CANARY_HOST,
                    "stored_response": "endpoint, parameter, and redacted Location host only",
                },
                "attack_path": "The redirect destination is taken from request input without validation, so an attacker can craft a link on the trusted domain that bounces victims to a phishing or malware site.",
            },
            impact="Open redirects enable convincing phishing, OAuth/token theft via redirect_uri abuse, and bypass of allow-list-based navigation controls.",
            remediation="Redirect only to a server-side allow-list of paths/hosts, or to relative paths. Reject absolute URLs, scheme-relative (//) and backslash variants in redirect parameters.",
        )
    )
    return findings


def _open_redirect_endpoint_hit(gate, path: str, param: str, target_host: str) -> dict[str, Any] | None:
    for payload in _REDIRECT_PAYLOADS:
        try:
            response = gate.request("GET", _with_param(path, param, payload))
        except Exception:  # noqa: BLE001 - the gate blocks a redirect that escapes the host; that's a non-hit
            continue
        if not 300 <= response.status_code < 400:
            continue
        location = _header(response, "location")
        if not location:
            continue
        resolved = urlparse(urljoin(f"https://{target_host}/", location))
        dest_host = (resolved.hostname or "").lower()
        if dest_host and dest_host == _REDIRECT_CANARY_HOST and dest_host != target_host:
            return {
                "endpoint": path,
                "parameter": param,
                "payload": payload,
                "response_status": response.status_code,
                "redirect_host": redact_text(dest_host),
            }
    return None
