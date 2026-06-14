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


def ask_model(endpoint: str, model: str, transcript: list, *, timeout: float = 120.0) -> str:
    """Call the local vLLM OpenAI-compatible endpoint; return the reply text."""
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + transcript,
        # Thinking models spend tokens on a <think> block before the JSON answer, so give
        # plenty of headroom or the actual action gets truncated away (we store only compact
        # actions in the transcript, so the context stays free for reasoning).
        "max_tokens": 4096,
        # Qwen3-Thinking's recommended sampling. Don't drop temperature much below this —
        # thinking models degrade (repetition, worse reasoning) at near-greedy temps.
        "temperature": 0.6,
        "top_p": 0.95,
        "top_k": 20,
    }
    request = urllib.request.Request(
        endpoint, data=json.dumps(payload).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8", "replace"))
    return body["choices"][0]["message"]["content"]


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


def run_loop(gate: RemoteGate, endpoint: str, model: str, *, max_turns: int = 24) -> int:
    """Drive the model→gate→execute loop. Returns the number of findings emitted."""
    transcript: list = [{"role": "user", "content": f"Target root: {gate.base_url}\nPropose your first probe."}]
    findings = 0
    for turn in range(max_turns):
        try:
            reply = ask_model(endpoint, model, transcript)
        except Exception as error:  # noqa: BLE001
            emit({"event": "model_error", "msg": str(error)[:200]})
            break
        decision = _extract_json(reply)
        if not decision:
            emit({"event": "no_action", "msg": "model returned no valid JSON action"})
            break
        action = decision.get("action")

        if action == "finish":
            emit({"event": "finish", "msg": str(decision.get("summary", ""))[:500]})
            break

        if action == "finding":
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

        emit({"event": "response", "status": result["status"], "bytes": len(result["body"])})
        result_summary = {"status": result["status"], "content_type": result["content_type"],
                          "body_preview": result["body"][:600]}
        transcript.append({"role": "assistant", "content": reply})
        transcript.append({"role": "user", "content": f"Result: {json.dumps(result_summary)}\n"
                                                      "If this proves a real flaw, emit a finding; else propose the next probe or finish."})
    emit({"event": "done", "findings": findings, "requests": gate.request_count})
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Penny sandbox active-exploitation agent (runs on the box)")
    parser.add_argument("target", help="approved target root URL (host-pinned)")
    parser.add_argument("--endpoint", default=MODEL_ENDPOINT_DEFAULT, help="local vLLM OpenAI-compatible endpoint")
    parser.add_argument("--model", default="heretic", help="served model name (vLLM --served-model-name)")
    parser.add_argument("--max-requests", type=int, default=60)
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--allow-destructive", action="store_true", help="permit DELETE (off by default)")
    args = parser.parse_args(argv)
    try:
        gate = RemoteGate(args.target, max_requests=args.max_requests, allow_destructive=args.allow_destructive)
    except GateError as error:
        emit({"event": "fatal", "msg": str(error)})
        return 2
    run_loop(gate, args.endpoint, args.model, max_turns=args.max_turns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
