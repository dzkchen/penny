from __future__ import annotations

import subprocess
from pathlib import Path

from penny.sources import is_git_source, resolved_scan_source


def test_is_git_source_detects_common_git_urls() -> None:
    assert is_git_source("https://github.com/example/repo.git")
    assert is_git_source("git@github.com:example/repo.git")
    assert is_git_source("ssh://git@example.com/repo.git#main")
    assert not is_git_source("./planted-app")


def test_resolved_scan_source_passes_local_paths_through(tmp_path) -> None:
    with resolved_scan_source(tmp_path) as resolved:
        assert resolved == tmp_path


def test_resolved_scan_source_clones_local_file_git_repo(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("demo\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=source, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(["git", "add", "README.md"], cwd=source, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.test", "-c", "user.name=Penny Test", "commit", "-m", "init"],
        cwd=source,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    bare = tmp_path / "source.git"
    subprocess.run(["git", "clone", "--bare", str(source), str(bare)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    with resolved_scan_source(f"file://{bare}") as resolved:
        assert isinstance(resolved, Path)
        assert (resolved / "README.md").read_text(encoding="utf-8") == "demo\n"
