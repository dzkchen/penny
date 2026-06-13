"""Clone -> scan -> fix -> push round trip for a GitHub repository.

Unlike `scan <url>` (which clones to a temp dir, scans, and deletes), this clones to a
working directory you keep, scans it, applies LLM fixes with approval, commits to a new
branch, and optionally pushes so you can open a PR. This is the "change the repo itself"
workflow.

Safety:
- Fixes go through the same approval-gated agent_fix loop.
- Changes land on a NEW branch (penny/fixes), never directly on the default branch.
- Push is explicit (--push) and never force-pushes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .agent_fix import run_agent_fix
from .feed import EventFeed
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
    """Clone source into workdir, scan, fix with approval, commit to a branch, optional push."""
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

    changed = run_agent_fix(payload, clone_dir, feed=feed, auto_yes=auto_yes)
    if not changed:
        feed.emit("blue", "No fixes applied; nothing to commit")
        return {"clone_dir": str(clone_dir), "changed": [], "committed": False, "pushed": False}

    # Stage and commit on the fix branch.
    _run_git(["add", "-A"], cwd=clone_dir)
    _run_git(["commit", "-m", "Apply Penny security fixes"], cwd=clone_dir)
    feed.emit("blue", f"Committed {len(changed)} fix(es) on {branch}")

    pushed = False
    if push:
        try:
            _run_git(["push", "-u", "origin", branch], cwd=clone_dir)
            pushed = True
            feed.emit("blue", f"Pushed {branch} to origin. Open a PR to review the fixes.")
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or str(error)).strip()
            feed.emit("blue", f"Push failed (commit is local on {branch}): {detail}")

    return {
        "clone_dir": str(clone_dir),
        "changed": [str(path) for path in changed],
        "committed": True,
        "pushed": pushed,
        "branch": branch,
    }
