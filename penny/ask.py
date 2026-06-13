from __future__ import annotations

import json
import re
from pathlib import Path

from .guardrails import GuardrailError, TargetGate
from .llm import llm_answer
from .reporting import load_findings


def answer_question(
    question: str,
    *,
    findings_path: Path,
    target: str | None = None,
    i_own_this: bool = False,
) -> str:
    payload = load_findings(findings_path)
    findings = payload.get("findings", [])
    normalized = question.lower()
    target_note = ""
    if target:
        try:
            TargetGate(target, i_own_this=i_own_this, max_requests=5)
            target_note = f"\n\nProbe gate: `{target}` is allowed for read-only checks."
        except GuardrailError as error:
            target_note = f"\n\nProbe gate: blocked. {error}"

    deterministic = _deterministic_answer(question, normalized, payload, findings, findings_path, target_note)
    # Augment with a live Claude explanation when a key is configured; otherwise return
    # the deterministic answer unchanged. The LLM only ever sees redacted findings.
    findings_json = json.dumps({"summary": payload.get("summary", {}), "findings": findings}, indent=2)
    return llm_answer(question, findings_json, deterministic=deterministic)


def _deterministic_answer(question, normalized, payload, findings, findings_path, target_note) -> str:

    id_match = re.search(r"\bF-\d{3}\b", question, re.I)
    if id_match:
        finding_id = id_match.group(0).upper()
        finding = next((item for item in findings if item["id"] == finding_id), None)
        if not finding:
            return f"I could not find `{finding_id}` in `{findings_path}`.{target_note}"
        evidence = finding.get("evidence", {})
        return (
            f"{finding_id} is `{finding['severity']}` because {finding['impact']} "
            f"Its status is `{finding['status']}` with `{finding['confidence']}` confidence. "
            f"Blue should fix it by: {finding['remediation']} "
            f"Evidence summary: {evidence}."
            f"{target_note}"
        )

    if "what did red" in normalized or "confirm" in normalized:
        confirmed = [finding for finding in findings if finding["status"] == "confirmed"]
        if confirmed:
            lines = [
                f"- {finding['id']}: {finding['title']} ({finding['severity']})"
                for finding in confirmed
            ]
            first_fix = confirmed[0]["remediation"]
            return "Red confirmed:\n" + "\n".join(lines) + f"\n\nBlue should fix first: {first_fix}{target_note}"
        return f"Red did not dynamically confirm any finding. The suspected findings should still be reviewed before release.{target_note}"

    if "fix" in normalized or "blue" in normalized:
        ordered = sorted(findings, key=lambda item: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item["severity"], 9))
        lines = [f"- {finding['id']}: {finding['remediation']}" for finding in ordered[:5]]
        return "Blue fix queue:\n" + "\n".join(lines) + target_note

    if "attack" in normalized or "path" in normalized:
        paths = []
        for finding in findings:
            evidence = finding.get("evidence", {})
            if evidence.get("attack_path"):
                paths.append(f"- {finding['id']}: {evidence['attack_path']}")
        if not paths:
            return f"No confirmed attack path is present in the findings file.{target_note}"
        return "Attack path:\n" + "\n".join(paths) + target_note

    total = payload.get("summary", {}).get("total", len(findings))
    critical = payload.get("summary", {}).get("critical_count", 0)
    high = payload.get("summary", {}).get("high_count", 0)
    return (
        f"This scan has {total} finding(s): {critical} critical and {high} high. "
        "Ask about a finding ID, the confirmed attack path, or the Blue fix queue for a more specific answer."
        f"{target_note}"
    )
