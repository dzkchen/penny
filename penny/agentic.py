"""Agentic URL-walking: Claude drives read-only probes against any app.

This is the "penetrate any app" loop. Instead of hardcoded planted-app routes, Claude
proposes the next read-only probe (path + headers), Python validates it through the same
TargetGate guardrails, executes it, and feeds the redacted result back to Claude to decide
the next step. Bounded by request caps and a max number of agent turns.

Safety: every probe goes through TargetGate (read-only methods only, request cap, no host
escape, no redirects off-host). Claude can only PROPOSE; Python decides. Public targets
still require a matching DNS TXT proof record.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .llm import _api_key, _model
from .models import Finding, Location
from .redaction import redact_text
from .repo import SourceFile


# ---------------------------------------------------------------------------
# Supabase auto-detection: make probes adapt to ANY app, not just the planted one
# ---------------------------------------------------------------------------

SUPABASE_URL_RE = re.compile(r"https://([a-z0-9]{16,30})\.supabase\.co", re.I)
TABLE_HINT_RE = re.compile(r"\.from\(\s*['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*\)")
REST_TABLE_RE = re.compile(r"/rest/v1/([a-zA-Z_][a-zA-Z0-9_]*)")


def detect_supabase(files: list[SourceFile]) -> dict[str, Any]:
    """Pull a Supabase project URL and candidate table names out of scanned source."""
    urls: set[str] = set()
    tables: set[str] = set()
    for file in files:
        for match in SUPABASE_URL_RE.finditer(file.text):
            urls.add(match.group(0))
        for match in TABLE_HINT_RE.finditer(file.text):
            tables.add(match.group(1))
        for match in REST_TABLE_RE.finditer(file.text):
            tables.add(match.group(1))
    return {"urls": sorted(urls), "tables": sorted(tables)}


# ---------------------------------------------------------------------------
# Agentic probe loop
# ---------------------------------------------------------------------------

_AGENT_SYSTEM = (
    "You are Penny's Red-Team probe planner for a CONSENTED, read-only security audit. "
    "You decide the next single read-only HTTP probe to run against the target to investigate "
    "possible broken access control (IDOR/BOLA), exposed data, or misconfiguration. "
    "You may ONLY use GET, HEAD, or OPTIONS. You cannot write, delete, or send bodies. "
    "Stay on the approved target host. "
    "Respond with STRICT JSON only, no prose, in one of these forms:\n"
    '{"action":"probe","method":"GET","path":"/api/orders/1002","headers":{"x-user-id":"user-a"},"reason":"try cross-user id"}\n'
    '{"action":"finish","summary":"what you concluded"}\n'
    "Prefer probing object-id endpoints with substituted IDs, common API routes, and Supabase "
    "REST paths like /rest/v1/<table>. Keep paths relative to the target root."
)


def _safe_json(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def run_agentic_probe(
    target: str,
    *,
    hints: dict[str, Any] | None = None,
    feed: EventFeed,
    max_turns: int = 6,
    max_requests: int = 20,
) -> list[Finding]:
    """Let Claude drive read-only probes against the target. Returns any findings raised."""
    findings: list[Finding] = []
    if _api_key() is None:
        feed.emit("red", "Agentic probe needs an Anthropic key; skipping (deterministic probes still ran)")
        return findings
    try:
        import anthropic
    except Exception:
        feed.emit("red", "anthropic SDK not available; skipping agentic probe")
        return findings

    try:
        gate = TargetGate(target, max_requests=max_requests)
    except GuardrailError as error:
        feed.emit("gate", f"Agentic probe target blocked: {error}")
        return findings

    feed.emit("red", f"Agentic probe loop started on {target} (read-only, max {max_turns} turns)")
    client = anthropic.Anthropic(api_key=_api_key())
    transcript: list[dict[str, str]] = []
    hint_text = ""
    if hints:
        hint_text = f"Detected hints from source code: {json.dumps(hints)}\n"
    transcript.append({"role": "user", "content": f"{hint_text}Target root: {target}\nPropose your first probe."})

    for turn in range(max_turns):
        try:
            response = client.messages.create(
                model=_model(),
                max_tokens=400,
                system=_AGENT_SYSTEM,
                messages=transcript,
            )
            reply = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
        except Exception as error:
            feed.emit("red", f"Agentic probe stopped: {error}")
            break

        decision = _safe_json(reply)
        if not decision:
            feed.emit("red", "Agent returned no valid action; ending loop")
            break
        if decision.get("action") == "finish":
            feed.emit("red", f"Agent concluded: {redact_text(decision.get('summary', ''))}")
            break

        method = str(decision.get("method", "GET")).upper()
        path = str(decision.get("path", "/"))
        headers = decision.get("headers") or {}
        reason = redact_text(str(decision.get("reason", "")))
        feed.emit("red", f"Agent probe: {method} {path} ({reason})")

        try:
            gate.validate_method(method)
            resp = gate.request(method, path, headers=headers if isinstance(headers, dict) else {})
        except GuardrailError as error:
            feed.emit("gate", f"Blocked: {error}")
            transcript.append({"role": "assistant", "content": reply})
            transcript.append({"role": "user", "content": f"That probe was blocked by guardrails: {error}. Propose a different read-only probe or finish."})
            continue
        except Exception as error:
            transcript.append({"role": "assistant", "content": reply})
            transcript.append({"role": "user", "content": f"Probe errored: {error}. Try another or finish."})
            continue

        # Feed a redacted, truncated result back to the agent.
        result_summary = {
            "status": resp.status_code,
            "body_preview": redact_text(resp.text[:500]),
            "content_type": resp.headers.get("content-type", ""),
        }
        feed.emit("red", f"  -> status {resp.status_code}, {len(resp.text)} bytes")
        transcript.append({"role": "assistant", "content": reply})
        transcript.append({"role": "user", "content": f"Probe result: {json.dumps(result_summary)}\nPropose the next probe or finish."})

    return findings


def run_agentic_probe_from_files(
    files: list[SourceFile],
    target: str,
    *,
    feed: EventFeed,
) -> list[Finding]:
    """Convenience wrapper: auto-detect Supabase hints from source, then run the loop."""
    hints = detect_supabase(files)
    if hints["urls"] or hints["tables"]:
        feed.emit("red", f"Auto-detected Supabase hints: {len(hints['urls'])} url(s), {len(hints['tables'])} table(s)")
    return run_agentic_probe(target, hints=hints, feed=feed)
