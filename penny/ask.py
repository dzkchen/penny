from __future__ import annotations

import json
import re
from pathlib import Path

from .guardrails import GuardrailError, TargetGate
from .llm import available as llm_available
from .llm import complete as llm_complete
from .mongo import MongoMirror
from .reporting import load_findings

SYSTEM_PROMPT = (
    "You are Penny, a local-first purple-team security assistant for AI-built apps. "
    "Answer the developer's question using only the scan findings supplied as JSON context. "
    "The findings are already redacted, so never invent secrets, CVEs, or findings that are "
    "not present, and do not claim something is exploitable unless a finding's status is "
    "'confirmed'. Be concise and concrete: cite finding IDs like F-001, name the OWASP "
    "category when relevant, and end with the single most important remediation step. If the "
    "findings do not answer the question, say so plainly."
)


def answer_question(
    question: str,
    *,
    findings_path: Path,
    target: str | None = None,
    i_own_this: bool = False,
    use_llm: bool = False,
) -> str:
    payload = load_findings(findings_path)
    findings = payload.get("findings", [])
    target_note = _target_note(target, i_own_this)

    if use_llm and llm_available():
        answer = _llm_answer(question, payload, findings)
        if answer:
            return f"{answer}{target_note}"

    return f"{_static_answer(question, payload, findings, findings_path)}{target_note}"


def _target_note(target: str | None, i_own_this: bool) -> str:
    if not target:
        return ""
    try:
        TargetGate(target, i_own_this=i_own_this, max_requests=5)
        return f"\n\nProbe gate: `{target}` is allowed for read-only checks."
    except GuardrailError as error:
        return f"\n\nProbe gate: blocked. {error}"


def _findings_context(payload: dict, findings: list[dict]) -> str:
    compact = {
        "summary": payload.get("summary", {}),
        "scan": {
            key: payload.get("scan", {}).get(key)
            for key in ("source", "static_only", "file_count")
        },
        "findings": [
            {
                "id": finding.get("id"),
                "detector_id": finding.get("detector_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "status": finding.get("status"),
                "confidence": finding.get("confidence"),
                "owasp": finding.get("owasp"),
                "location": finding.get("location"),
                "impact": finding.get("impact"),
                "remediation": finding.get("remediation"),
                "evidence_reason": finding.get("evidence", {}).get("reason"),
            }
            for finding in findings
        ],
    }
    return json.dumps(compact, indent=2, default=str)


def _rag_context(question: str) -> str:
    """Retrieve semantically-similar patterns from the Mongo vector KB (true RAG)."""
    retrieved, _ = MongoMirror().search_patterns(question, limit=3)
    if not retrieved:
        return ""
    lines = [
        f"- [{item.get('detector_id', '?')}] {item.get('title', '')}: {item.get('remediation', '')}"
        for item in retrieved
    ]
    return "RETRIEVED KNOWLEDGE-BASE PATTERNS (MongoDB vector search, background only):\n" + "\n".join(lines) + "\n\n"


def _llm_answer(question: str, payload: dict, findings: list[dict]) -> str | None:
    context = _findings_context(payload, findings)
    rag = _rag_context(question)
    prompt = f"{rag}Scan findings (JSON):\n{context}\n\nDeveloper question: {question}"
    return llm_complete(prompt, system=SYSTEM_PROMPT, deep=True, max_tokens=1024)


def _static_answer(
    question: str,
    payload: dict,
    findings: list[dict],
    findings_path: Path,
) -> str:
    normalized = question.lower()

    id_match = re.search(r"\bF-\d{3}\b", question, re.I)
    if id_match:
        finding_id = id_match.group(0).upper()
        finding = next((item for item in findings if item["id"] == finding_id), None)
        if not finding:
            return f"I could not find `{finding_id}` in `{findings_path}`."
        evidence = finding.get("evidence", {})
        return (
            f"{finding_id} is `{finding['severity']}` because {finding['impact']} "
            f"Its status is `{finding['status']}` with `{finding['confidence']}` confidence. "
            f"Blue should fix it by: {finding['remediation']} "
            f"Evidence summary: {evidence}."
        )

    if "what did red" in normalized or "confirm" in normalized:
        confirmed = [finding for finding in findings if finding["status"] == "confirmed"]
        if confirmed:
            lines = [
                f"- {finding['id']}: {finding['title']} ({finding['severity']})"
                for finding in confirmed
            ]
            first_fix = confirmed[0]["remediation"]
            return "Red confirmed:\n" + "\n".join(lines) + f"\n\nBlue should fix first: {first_fix}"
        return (
            "Red did not dynamically confirm any finding. The suspected findings should still "
            "be reviewed before release."
        )

    if "fix" in normalized or "blue" in normalized:
        ordered = sorted(
            findings,
            key=lambda item: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item["severity"], 9),
        )
        lines = [f"- {finding['id']}: {finding['remediation']}" for finding in ordered[:5]]
        return "Blue fix queue:\n" + "\n".join(lines)

    if "attack" in normalized or "path" in normalized:
        paths = []
        for finding in findings:
            evidence = finding.get("evidence", {})
            if evidence.get("attack_path"):
                paths.append(f"- {finding['id']}: {evidence['attack_path']}")
        if not paths:
            return "No confirmed attack path is present in the findings file."
        return "Attack path:\n" + "\n".join(paths)

    total = payload.get("summary", {}).get("total", len(findings))
    critical = payload.get("summary", {}).get("critical_count", 0)
    high = payload.get("summary", {}).get("high_count", 0)
    return (
        f"This scan has {total} finding(s): {critical} critical and {high} high. "
        "Ask about a finding ID, the confirmed attack path, or the Blue fix queue for a more specific answer."
    )
