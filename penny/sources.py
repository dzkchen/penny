from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


GIT_SOURCE_RE = re.compile(r"^(?:https://|git@|ssh://|file://).+\.git(?:#.+)?$|^[^@\s]+@[^:\s]+:.+\.git(?:#.+)?$")


def is_git_source(source: str) -> bool:
    return bool(GIT_SOURCE_RE.match(source))


def _split_ref(source: str) -> tuple[str, str | None]:
    if "#" not in source:
        return source, None
    url, ref = source.rsplit("#", 1)
    return url, ref or None


@contextmanager
def resolved_scan_source(source: str | Path) -> Iterator[Path]:
    source_text = str(source)
    if not is_git_source(source_text):
        yield Path(source_text)
        return

    url, ref = _split_ref(source_text)
    temp_dir = Path(tempfile.mkdtemp(prefix="penny-git-"))
    clone_dir = temp_dir / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(clone_dir)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if ref:
            subprocess.run(
                ["git", "-C", str(clone_dir), "checkout", ref],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        yield clone_dir
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or str(error)).strip()
        raise RuntimeError(f"git source clone failed: {detail}") from error
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
