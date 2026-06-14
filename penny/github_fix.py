"""Clone -> scan -> handoff round trip for a GitHub repository.

Unlike `scan <url>` (which clones to a temp dir, scans, and deletes), this clones to a
working directory you keep, scans it, and creates a remediation handoff for Codex,
Claude Code, or another local coding agent.

Safety:
- Penny does not send source files to Claude for rewriting.
- Penny does not modify source files or commit generated code in this workflow.
- The handoff lands in the persistent clone so the user can review and apply fixes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .feed import EventFeed
from .handoff import create_fix_handoff
from .reporting import load_findings
from .scanner import run_scan
from .sources import _split_ref


def _run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _normalize_clone_url(source: str) -> tuple[str, str | None]:
    from .sources import GIT_HOST_RE

    url, ref = _split_ref(source)
    if GIT_HOST_RE.match(source) and not url.endswith(".git"):
        url = url + ".git"
    return url, ref


def github_fix_roundtrip(
    source: str,
    *,
    workdir: Path,
    branch: str = "penny/fixes",
    auto_yes: bool = False,
    push: bool = False,
    feed: EventFeed,
) -> dict[str, object]:
    """Clone source into workdir, scan, and create a coding-agent handoff."""
    url, ref = _normalize_clone_url(source)
    workdir = workdir.resolve()
    clone_dir = workdir / "repo"

    if clone_dir.exists():
        feed.emit("blue", f"Reusing existing clone at {clone_dir}")
    else:
        feed.emit("blue", f"Cloning {url} into {clone_dir}")
        workdir.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", url, str(clone_dir)])
        if ref:
            _run_git(["checkout", ref], cwd=clone_dir)

    # Scan the persistent clone (static only; user can re-run with a target separately).
    feed.emit("scan", f"Scanning cloned repo {clone_dir}")
    result = run_scan(clone_dir, static_only=True, out_dir=workdir, feed=feed, source_label=source)
    payload = load_findings(result.findings_path)

    # New branch so we never touch the default branch.
    try:
        _run_git(["checkout", "-b", branch], cwd=clone_dir)
    except subprocess.CalledProcessError:
        _run_git(["checkout", branch], cwd=clone_dir)
    feed.emit("blue", f"Working on branch {branch}")

    if auto_yes:
        feed.emit("blue", "--yes is ignored: Penny now creates a handoff instead of editing files directly")
    handoff = create_fix_handoff(payload, clone_dir, agent="codex")
    feed.emit("blue", f"Wrote remediation handoff {handoff.path}")
    feed.emit("blue", "No source files were changed; open the clone in Codex or Claude Code to apply fixes.")

    if push:
        feed.emit("blue", "--push is ignored because no fix commit was created")

    return {
        "clone_dir": str(clone_dir),
        "changed": [],
        "committed": False,
        "pushed": False,
        "branch": branch,
        "handoff": str(handoff.path),
        "scan_payload": result.payload,
    }
