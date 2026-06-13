"""Interactive agentic fix mode: Claude-Code / Cursor style remediation with approval.

Walks the confirmed/suspected findings, and for each flagged source file asks Claude to
produce a corrected version, shows a unified diff, and asks the user to approve before
writing anything. This is the "change code with user approval" loop.

Safety:
- Only operates on the user's LOCAL repo path they explicitly point at.
- Never writes a file without an explicit yes (unless --yes is passed for non-interactive demo).
- Falls back to the deterministic planted-app patches when no LLM key is configured.
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from .feed import EventFeed
from .llm import llm_available, llm_fix_file
from .patches import apply_patch_plans, build_patch_plans


def _colored_diff(relative: str, original: str, updated: str) -> str:
    lines = difflib.unified_diff(
        original.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{relative}",
        tofile=f"b/{relative}",
    )
    out: list[str] = []
    for line in lines:
        stripped = line.rstrip("\n")
        if line.startswith("+") and not line.startswith("+++"):
            out.append(f"[green]{stripped}[/green]")
        elif line.startswith("-") and not line.startswith("---"):
            out.append(f"[red]{stripped}[/red]")
        elif line.startswith("@@"):
            out.append(f"[cyan]{stripped}[/cyan]")
        else:
            out.append(stripped)
    return "\n".join(out)


def _findings_by_file(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in payload.get("findings", []):
        location = finding.get("location", {})
        file_path = location.get("file", "")
        # Skip dynamic findings whose "file" is a synthetic route, not a real file.
        if not file_path or file_path.startswith("dynamic:"):
            continue
        grouped[file_path].append(finding)
    return grouped


def _default_approver(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def run_agent_fix(
    payload: dict[str, Any],
    repo_root: Path,
    *,
    feed: EventFeed,
    auto_yes: bool = False,
    approver: Callable[[str], bool] | None = None,
) -> list[Path]:
    """Interactively propose and (on approval) apply per-file fixes. Returns changed paths."""
    repo_root = repo_root.resolve()
    approve = approver or _default_approver
    changed: list[Path] = []

    if not llm_available():
        # No live model: fall back to the deterministic planted-app patches, still gated.
        feed.emit("blue", "No LLM key configured; using deterministic patch plans")
        plans = build_patch_plans(payload, repo_root)
        if not plans:
            feed.emit("blue", "No applicable deterministic fixes for this repo")
            return changed
        for plan in plans:
            relative = plan.path.relative_to(repo_root).as_posix()
            feed.emit("blue", f"Proposed fix for {relative}:")
            feed._console.print(_colored_diff(relative, plan.original, plan.updated)) if feed._console else print(
                _colored_diff(relative, plan.original, plan.updated)
            )
            if auto_yes or approve(f"Apply fix to {relative}?"):
                plan.path.write_text(plan.updated, encoding="utf-8")
                changed.append(plan.path)
                feed.emit("blue", f"Applied fix to {relative}")
            else:
                feed.emit("blue", f"Skipped {relative}")
        return changed

    grouped = _findings_by_file(payload)
    if not grouped:
        feed.emit("blue", "No file-located findings to fix")
        return changed

    for relative, findings in grouped.items():
        target = (repo_root / relative).resolve()
        # Path-safety: never write outside the repo root.
        if repo_root not in target.parents and target != repo_root:
            feed.emit("blue", f"Skipped {relative}: outside repo root")
            continue
        if not target.exists():
            feed.emit("blue", f"Skipped {relative}: file not found in repo")
            continue

        feed.emit("blue", f"Generating fix for {relative} ({len(findings)} finding(s))...")
        original = target.read_text(encoding="utf-8")
        findings_summary = "\n".join(
            f"- {f.get('detector_id')}: {f.get('title')} (line {f.get('location', {}).get('line', '?')}) — {f.get('remediation', '')}"
            for f in findings
        )
        fixed = llm_fix_file(relative, original, findings_summary)
        if not fixed or fixed == original:
            feed.emit("blue", f"No change proposed for {relative}")
            continue

        feed.emit("blue", f"Proposed fix for {relative}:")
        diff_text = _colored_diff(relative, original, fixed)
        if feed._console is not None:
            feed._console.print(diff_text)
        else:
            print(diff_text)

        if auto_yes or approve(f"Apply this fix to {relative}?"):
            target.write_text(fixed, encoding="utf-8")
            changed.append(target)
            feed.emit("blue", f"Applied fix to {relative}")
        else:
            feed.emit("blue", f"Skipped {relative}")

    return changed
