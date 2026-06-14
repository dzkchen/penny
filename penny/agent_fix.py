"""Compatibility wrapper for the old fix entry point.

Penny no longer sends source files to Claude to rewrite them. The fix flow now
creates a remediation handoff for a local coding agent such as Codex or Claude
Code, then lets that agent make changes in the user's workspace.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .feed import EventFeed
from .handoff import create_fix_handoff


def run_agent_fix(
    payload: dict[str, Any],
    repo_root: Path,
    *,
    feed: EventFeed,
    auto_yes: bool = False,
    approver: Callable[[str], bool] | None = None,
) -> list[Path]:
    """Create a remediation handoff and return no changed files.

    The signature is kept so older integrations fail soft instead of importing a
    removed symbol. ``auto_yes`` and ``approver`` are ignored because this path
    never writes source files.
    """
    del auto_yes, approver
    result = create_fix_handoff(payload, repo_root)
    feed.emit("blue", f"Wrote remediation handoff {result.path}")
    feed.emit("blue", "No source files were changed; open the handoff in Codex or Claude Code to apply fixes.")
    return []
