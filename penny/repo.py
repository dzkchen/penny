from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_IGNORES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".penny",
}

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sql",
    ".env",
    ".json",
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


def _allowed_file(path: Path, root: Path, max_bytes: int) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        relative_parts = path.parts
    if any(part in DEFAULT_IGNORES for part in relative_parts):
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
    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        candidates = [path for path in root.rglob("*") if path.is_file()]
        base = root

    files: list[SourceFile] = []
    for path in sorted(candidates):
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
