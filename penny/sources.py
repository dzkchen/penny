from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


GIT_SOURCE_RE = re.compile(r"^(?:https://|git@|ssh://|file://).+\.git(?:#.+)?$|^[^@\s]+@[^:\s]+:.+\.git(?:#.+)?$")
URL_SOURCE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
# Common git hosts: accept a bare repo URL without a trailing .git for convenience,
# e.g. https://github.com/owner/repo or https://gitlab.com/owner/repo[#ref].
GIT_HOST_RE = re.compile(
    r"^https://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)/[^/\s]+/[^/\s#]+(?:#.+)?$",
    re.I,
)


def is_git_source(source: str) -> bool:
    return bool(GIT_SOURCE_RE.match(source)) or bool(GIT_HOST_RE.match(source))


def is_url_source(source: str) -> bool:
    return bool(URL_SOURCE_RE.match(source))


def validate_scan_source(source: str | Path) -> None:
    source_text = str(source)
    if is_url_source(source_text) and not is_git_source(source_text):
        raise ValueError(
            "Penny scans local source folders or git repository URLs ending in .git. "
            "Do not pass a deployed website URL as the scan path. Use a local checkout, "
            "for example: python3 -m penny run ./my-app --target https://example.com"
        )


def _split_ref(source: str) -> tuple[str, str | None]:
    if "#" not in source:
        return source, None
    url, ref = source.rsplit("#", 1)
    return url, ref or None


@contextmanager
def resolved_scan_source(source: str | Path) -> Iterator[Path]:
    source_text = str(source)
    validate_scan_source(source_text)
    if not is_git_source(source_text):
        path = Path(source_text)
        if not path.exists():
            raise FileNotFoundError(f"scan path does not exist: {path}")
        if not path.is_dir() and not path.is_file():
            raise FileNotFoundError(f"scan path is not a file or directory: {path}")
        yield path
        return

    url, ref = _split_ref(source_text)
    # Normalize a bare host URL (no trailing .git) to a clonable URL.
    if GIT_HOST_RE.match(source_text) and not url.endswith(".git"):
        url = url + ".git"
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
