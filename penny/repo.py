from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IGNORES = {
    ".git",
    ".hg",
    ".svn",
    ".astro",
    ".cache",
    ".next",
    ".nuxt",
    ".parcel-cache",
    ".svelte-kit",
    ".turbo",
    ".vite",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".penny",
}

DEFAULT_IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "next-env.d.ts",
}

GENERATED_FILE_PATTERNS = (
    "_client-reference-manifest.js",
    "_build-manifest.js",
    "_ssg-manifest.js",
    ".hot-update.js",
)

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sql",
    ".env",
    ".json",
    ".rules",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".md",
    ".txt",
}


@dataclass
class SourceFile:
    path: Path
    relative_path: str
    text: str


def _git_ignored_paths(root: Path, candidates: list[Path]) -> set[Path]:
    """Return the subset of candidates that git ignores.

    Used so a gitignored local ``.env`` (the recommended place to keep secrets)
    is not flagged as a committed secret, while a ``.env`` that is actually
    tracked by git still gets scanned. ``git check-ignore`` treats tracked files
    as not-ignored by default, which is exactly the behaviour we want. When the
    scan path is not inside a git work tree (or git is unavailable) no filtering
    is applied and the walker keeps its previous behaviour.
    """
    if not candidates:
        return set()
    try:
        inside = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return set()
    stdin = "\0".join(str(path) for path in candidates)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    # check-ignore exit status: 0 = at least one path ignored, 1 = none ignored,
    # anything else (e.g. 128) is an error we treat as "ignore nothing".
    if result.returncode not in (0, 1):
        return set()
    return {Path(token) for token in result.stdout.split("\0") if token}


def changed_files(root: Path, base_ref: str) -> set[Path] | None:
    """Return absolute paths changed versus ``base_ref`` (committed, staged, unstaged, untracked).

    Used by ``--diff`` to scan only what a PR touches. Returns ``None`` (meaning
    "could not determine — scan everything") when the path is not a git work tree,
    git is unavailable, or ``base_ref`` does not resolve. Never raises.
    """
    root = root.resolve()
    git_root = root if root.is_dir() else root.parent
    try:
        inside = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return None
    names: set[str] = set()
    commands = [
        ["git", "-C", str(git_root), "diff", "--name-only", f"{base_ref}...HEAD"],
        ["git", "-C", str(git_root), "diff", "--name-only"],
        ["git", "-C", str(git_root), "diff", "--name-only", "--cached"],
        ["git", "-C", str(git_root), "ls-files", "--others", "--exclude-standard"],
    ]
    saw_base = False
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        if "...HEAD" in command[-1]:
            saw_base = True
        names.update(line for line in result.stdout.splitlines() if line)
    if not saw_base:
        # base_ref did not resolve; caller should fall back to a full scan.
        return None
    try:
        top = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        repo_top = Path(top.stdout.strip()) if top.returncode == 0 else git_root
    except (OSError, subprocess.SubprocessError):
        repo_top = git_root
    return {(repo_top / name).resolve() for name in names}


def _allowed_file(path: Path, root: Path, max_bytes: int) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        relative_parts = path.parts
    if any(part in DEFAULT_IGNORES for part in relative_parts):
        return False
    if any(part in DEFAULT_IGNORES for part in path.parts):
        return False
    if path.name in DEFAULT_IGNORED_FILES:
        return False
    if any(path.name.endswith(pattern) for pattern in GENERATED_FILE_PATTERNS):
        return False
    if path.name == ".env":
        allowed_extension = True
    else:
        allowed_extension = path.suffix.lower() in DEFAULT_EXTENSIONS
    if not allowed_extension:
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    return path.is_file() and stat.st_size <= max_bytes


def walk_repo(root: Path, max_bytes: int = 512 * 1024) -> list[SourceFile]:
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan path does not exist: {root}")
    if root.name in DEFAULT_IGNORES:
        return []
    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        candidates = [path for path in root.rglob("*") if path.is_file()]
        base = root

    ignored = _git_ignored_paths(base, candidates)

    files: list[SourceFile] = []
    for path in sorted(candidates):
        if path in ignored:
            continue
        if not _allowed_file(path, base, max_bytes):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
        relative = path.relative_to(base).as_posix()
        files.append(SourceFile(path=path, relative_path=relative, text=text))
    return files
