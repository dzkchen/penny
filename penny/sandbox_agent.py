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
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

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
    "on the approved target host. Do NOT attempt denial-of-service (no floods) and do NOT issue "
    "destructive bulk-delete operations.\n"
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
        self.request_count = 0
        self._last_request = 0.0

    def build_url(self, path: str) -> str:
        candidate = urljoin(f"{self.base_url}/", str(path).lstrip("/"))
        parsed = urlparse(candidate)
        # Host-pin: the uncensored model cannot redirect firepower off the approved host.
        if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").lower() != self.host:
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

    def _pace(self) -> None:
        if self.request_count >= self.max_requests:
            raise GateError("request cap reached")
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)
        self._last_request = time.monotonic()
        self.request_count += 1

    def execute(self, method: str, path: str, headers, body, *, timeout: float = 12.0) -> dict:
        m = self.check_method(method)
        url = self.build_url(path)
        self._pace()
        data = None
        send_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        if body is not None and m in {"POST", "PUT", "PATCH"}:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                send_headers.setdefault("Content-Type", "application/json")
            else:
                data = str(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=m, headers=send_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(4096)
                return {"status": int(response.status), "body": raw.decode("utf-8", "replace"),
                        "content_type": response.headers.get("content-type", "")}
        except urllib.error.HTTPError as error:
            raw = error.read(4096)
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


def run_loop(gate: RemoteGate, endpoint: str, model: str, *, max_turns: int = 24, system: str = SYSTEM_PROMPT) -> int:
    """Drive the model→gate→execute loop. Returns the number of findings emitted."""
    baseline = compute_baseline(gate)
    real_hits: dict[str, bool] = {}   # normalized path -> True if it returned a NON-baseline response
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
    transcript: list = [{"role": "user", "content": f"Target root: {gate.base_url}{baseline_note}\nPropose your first probe."}]
    findings = 0
    consecutive_model_errors = 0
    for turn in range(max_turns):
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
            emit({"event": "no_action", "msg": "model returned no valid JSON action"})
            break
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
    parser.add_argument("--max-requests", type=int, default=60)
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--allow-destructive", action="store_true", help="permit DELETE (off by default)")
    # Operator focus for this run, base64-encoded (avoids shell-quoting arbitrary text). Appended
    # to the system prompt so you can steer WHAT it tests, e.g. "focus on SQLi in /search and
    # JWT tampering; ignore IDOR".
    parser.add_argument("--instructions-b64", default="", help="base64-encoded operator focus appended to the system prompt")
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
    run_loop(gate, args.endpoint, args.model, max_turns=args.max_turns, system=system)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
