"""AI-assisted vulnerability detection.

The deterministic detectors catch known shapes (secrets, RLS, CORS, vulnerable
deps, dangerous sinks). This pass hands bounded, line-numbered source to Claude
to surface issues regex can't reason about — broken auth/authorization flows,
business-logic bugs, injection through indirect data flow, unsafe redirects,
and the like — and folds the results into the same Finding pipeline.

It is opt-in (``--ai``): unlike the rest of Penny it sends source code to the
model, so callers must ask for it. Output is constrained to a JSON schema, and
each finding's snippet is rebuilt from the real source line (then redacted) so
the model can never smuggle an unredacted secret into persisted output.
"""

from __future__ import annotations

import json

from . import llm
from .detectors import CODE_EXTENSIONS
from .feed import EventFeed
from .models import Finding, Location
from .redaction import redact_text
from .repo import SourceFile

MAX_FILES = 40
MAX_TOTAL_CHARS = 60_000
_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_CONFIDENCES = {"high", "medium", "low"}

AI_SYSTEM = (
    "You are a senior application-security reviewer auditing an AI-built app. "
    "Review the provided source files and report concrete, high-confidence vulnerabilities: "
    "broken authentication or authorization (IDOR/BOLA, missing ownership checks), injection "
    "(SQL/command/template), SSRF, unsafe deserialization, path traversal, insecure secret "
    "handling, unsafe redirects, and similar real risks. "
    "Trace authorization across files: follow each route or handler through its middleware to "
    "the data access, and flag any state-changing or data-returning endpoint that does not bind "
    "the requested object to the authenticated caller (missing ownership checks / broken access "
    "control), even when each individual line looks fine. "
    "Because this is an AI-built app, also audit any LLM integration for the OWASP LLM Top 10: "
    "prompt injection (untrusted input concatenated into prompts or system messages), insecure "
    "output handling (model output flowing into SQL/shell/eval/HTML or an authorization decision), "
    "tool/function-calling without authorization checks, SSRF or data exfiltration via model tool "
    "use, system-prompt or secret leakage, and a model API key shipped to client-side code. "
    "Pay special attention to the client/server trust boundary. If the app performs "
    "authentication, authorization, or state-changing/data operations directly from "
    "client-side code — direct database/BaaS calls (Supabase, Firebase) or client-issued "
    "POST/PUT/PATCH/DELETE requests — with no trusted server-side layer enforcing access "
    "control, report a single Critical or High finding for that missing backend / "
    "trusted-client design: the browser is fully attacker-controllable, so any access control "
    "implemented there can be bypassed. Cite the most representative file and line. "
    "Only report issues you can point to a specific file and line for. Do not report style "
    "nits, TODOs, or speculative concerns. Prefer precision over recall — a wrong finding is "
    "worse than a missed one. Return your answer using the required JSON schema."
)

# Filenames/paths most likely to hold the trust-boundary, authz, and LLM-integration
# logic worth spending the bounded char budget on. Files matching these are bundled
# first so large repos don't truncate the security-relevant code away (see backlog).
_PRIORITY_MARKERS = (
    "auth", "login", "session", "middleware", "permission", "role", "acl",
    "api", "route", "router", "handler", "endpoint", "controller", "server",
    "db", "database", "query", "model", "supabase", "firebase", "firestore",
    "prompt", "llm", "agent", "chat", "openai", "anthropic", "completion", "tool",
)


def _priority(file: SourceFile) -> int:
    """Lower sorts first. Security-relevant files lead the bundle."""
    lowered = file.relative_path.lower()
    return 0 if any(marker in lowered for marker in _PRIORITY_MARKERS) else 1

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "category": {"type": "string"},
                    "owasp": {"type": "string"},
                    "impact": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": ["title", "severity", "confidence", "file", "line", "category", "owasp", "impact", "remediation"],
            },
        }
    },
    "required": ["findings"],
}


def _build_bundle(files: list[SourceFile]) -> tuple[str, set[str]]:
    chunks: list[str] = []
    included: set[str] = set()
    budget = MAX_TOTAL_CHARS
    for file in files:
        numbered = "\n".join(f"{i:>4}  {line}" for i, line in enumerate(file.text.splitlines(), start=1))
        block = f"=== FILE: {file.relative_path} ===\n{numbered}\n"
        if len(block) > budget and chunks:
            break
        chunks.append(block)
        included.add(file.relative_path)
        budget -= len(block)
        if budget <= 0:
            break
    return "\n".join(chunks), included


def _snippet_for(file: SourceFile | None, line: int) -> str:
    if file is None:
        return ""
    lines = file.text.splitlines()
    if 1 <= line <= len(lines):
        return redact_text(lines[line - 1].strip())
    return ""


def _parse(raw: str, by_path: dict[str, SourceFile]) -> list[Finding]:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    findings: list[Finding] = []
    for item in data.get("findings", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("file", "")).strip()
        source_file = by_path.get(path)
        try:
            line = int(item.get("line", 1))
        except (TypeError, ValueError):
            line = 1
        line = max(line, 1)
        severity = item.get("severity") if item.get("severity") in _SEVERITIES else "Medium"
        confidence = item.get("confidence") if item.get("confidence") in _CONFIDENCES else "medium"
        owasp = str(item.get("owasp", "")).strip()
        findings.append(
            Finding(
                title=str(item.get("title", "AI-identified issue")).strip() or "AI-identified issue",
                severity=severity,
                confidence=confidence,
                status="suspected",
                source="ai",
                detector_id="AI001",
                owasp=[owasp] if owasp else [],
                location=Location(file=path or "unknown", line=line, column=1),
                snippet=_snippet_for(source_file, line),
                evidence={
                    "reason": str(item.get("category", "")).strip() or "AI-identified security issue.",
                    "ai_generated": True,
                    "model": llm.deep_model(),
                },
                impact=str(item.get("impact", "")).strip() or "An AI reviewer flagged this as a security risk.",
                remediation=str(item.get("remediation", "")).strip() or "Review the flagged code and apply the appropriate fix.",
            )
        )
    return findings


def ai_review(files: list[SourceFile], *, feed: EventFeed | None = None) -> list[Finding]:
    """Return AI-discovered findings, or ``[]`` if unavailable/unproductive."""
    if not llm.available():
        if feed:
            feed.emit("ai", "AI review skipped (no ANTHROPIC_API_KEY)")
        return []
    code_files = [file for file in files if file.path.suffix.lower() in CODE_EXTENSIONS]
    # Stable sort keeps original order within each priority band.
    code_files = sorted(code_files, key=_priority)[:MAX_FILES]
    if not code_files:
        return []
    bundle, included = _build_bundle(code_files)
    if feed:
        feed.emit("ai", f"AI review sending {len(included)} source file(s) to {llm.deep_model()}")
    prompt = (
        "Audit these source files for security vulnerabilities. Cite the exact file path and line "
        "for each finding.\n\n" + bundle
    )
    # A structured-output findings list needs real headroom, and a 60K-char bundle
    # on a deep model can take well over the old 30s default — both starved the call
    # and produced an empty "no usable response". feed surfaces the specific reason.
    raw = llm.complete(
        prompt,
        system=AI_SYSTEM,
        deep=True,
        max_tokens=8192,
        timeout=120.0,
        response_schema=RESPONSE_SCHEMA,
        feed=feed,
    )
    if not raw:
        if feed:
            feed.emit("ai", "AI review produced no findings (see the reason above)")
        return []
    by_path = {file.relative_path: file for file in code_files}
    findings = _parse(raw, by_path)
    if feed:
        feed.emit("ai", f"AI review surfaced {len(findings)} finding(s)")
    return findings


TRIAGE_SYSTEM = (
    "You triage candidate secret detections from a static scanner. Each candidate is a "
    "high-entropy token flagged in source. Decide, for each, whether it is a REAL leaked "
    "credential (API key, password, private token, connection string) or a BENIGN high-entropy "
    "value (a hash/digest, content fingerprint, git SHA, UUID, public identifier, test fixture, "
    "example/placeholder, or minified asset). Judge from the variable name and surrounding code, "
    "not the token text (it is redacted). When genuinely unsure, treat it as a real secret. "
    "Return your answer using the required JSON schema."
)

TRIAGE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer"},
                    "is_secret": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["index", "is_secret", "reason"],
            },
        }
    },
    "required": ["verdicts"],
}


def _context_lines(file: SourceFile | None, line: int, *, radius: int = 2) -> str:
    if file is None:
        return ""
    lines = file.text.splitlines()
    start = max(line - radius, 1)
    end = min(line + radius, len(lines))
    return "\n".join(redact_text(lines[i - 1]) for i in range(start, end + 1))


def triage_secret_findings(
    findings: list[Finding], files: list[SourceFile], *, feed: EventFeed | None = None
) -> list[Finding]:
    """Drop high-entropy ``D002`` findings a fast model judges to be benign.

    Targets only the heuristic (confidence ``medium``) high-entropy hits — the
    false-positive-prone ones — never the known-prefix secrets. Degrades to a
    no-op when the LLM is unavailable, so it never weakens offline behavior.
    """
    if not llm.available():
        return findings
    candidates = [
        (index, finding)
        for index, finding in enumerate(findings)
        if finding.detector_id == "D002" and finding.confidence == "medium"
    ]
    if not candidates:
        return findings
    by_path = {file.relative_path: file for file in files}
    blocks = []
    for ordinal, (_, finding) in enumerate(candidates):
        context = _context_lines(by_path.get(finding.location.file), finding.location.line)
        blocks.append(f"[{ordinal}] {finding.location.file}:{finding.location.line}\n{context}")
    if feed:
        feed.emit("ai", f"Triaging {len(candidates)} high-entropy token(s) with {llm.fast_model()}")
    prompt = (
        "Classify each candidate below as a real secret or benign. Use the bracketed index.\n\n"
        + "\n\n".join(blocks)
    )
    raw = llm.complete(prompt, system=TRIAGE_SYSTEM, deep=False, max_tokens=1024, response_schema=TRIAGE_SCHEMA)
    if not raw:
        return findings
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return findings
    benign_ordinals: set[int] = set()
    for verdict in data.get("verdicts", []) if isinstance(data, dict) else []:
        if isinstance(verdict, dict) and verdict.get("is_secret") is False:
            try:
                benign_ordinals.add(int(verdict["index"]))
            except (KeyError, TypeError, ValueError):
                continue
    drop = {candidates[ordinal][0] for ordinal in benign_ordinals if 0 <= ordinal < len(candidates)}
    if not drop:
        return findings
    if feed:
        feed.emit("ai", f"Secret triage dismissed {len(drop)} false-positive high-entropy token(s)")
    return [finding for index, finding in enumerate(findings) if index not in drop]
