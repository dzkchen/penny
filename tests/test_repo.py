from __future__ import annotations

import subprocess

import pytest

from penny.detectors import detect_committed_secrets, run_detectors
from penny.repo import changed_files, walk_repo


def _git(cwd, *args) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def test_walk_repo_ignores_nextjs_generated_output(tmp_path) -> None:
    generated = tmp_path / ".next/dev/server/app/_not-found"
    generated.mkdir(parents=True)
    (generated / "page_client-reference-manifest.js").write_text(
        'self.__RSC_MANIFEST="AbC123xYz987QwErTyUiOpAsDfGhJkLz0123456789";\n',
        encoding="utf-8",
    )
    source = tmp_path / "app/page.tsx"
    source.parent.mkdir(parents=True)
    source.write_text("export default function Page() { return null; }\n", encoding="utf-8")

    files = walk_repo(tmp_path)

    assert [file.relative_path for file in files] == ["app/page.tsx"]
    assert run_detectors(files) == []


def test_walk_repo_ignores_direct_nextjs_root(tmp_path) -> None:
    next_root = tmp_path / ".next"
    generated = next_root / "dev/server/app/_not-found"
    generated.mkdir(parents=True)
    (generated / "page_client-reference-manifest.js").write_text(
        'self.__RSC_MANIFEST="AbC123xYz987QwErTyUiOpAsDfGhJkLz0123456789";\n',
        encoding="utf-8",
    )

    assert walk_repo(next_root) == []


def test_walk_repo_ignores_common_lockfiles(tmp_path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"":{"integrity":"sha512-AbC123xYz987QwErTyUiOpAsDfGhJkLz0123456789"}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"dependencies":{}}\n', encoding="utf-8")

    files = walk_repo(tmp_path)

    assert [file.relative_path for file in files] == ["package.json"]


@pytest.mark.skipif(not _has_git(), reason="git is required for gitignore-aware scanning")
def test_walk_repo_skips_gitignored_env(tmp_path) -> None:
    _git(tmp_path, "init")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / ".env").write_text("STRIPE=sk_live_ABCDEFGH12345678\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    files = walk_repo(tmp_path)
    paths = {file.relative_path for file in files}

    assert ".env" not in paths
    assert "app.py" in paths
    assert detect_committed_secrets(files) == []


@pytest.mark.skipif(not _has_git(), reason="git is required for gitignore-aware scanning")
def test_walk_repo_still_flags_tracked_env(tmp_path) -> None:
    _git(tmp_path, "init")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / ".env").write_text("STRIPE=sk_live_ABCDEFGH12345678\n", encoding="utf-8")
    # A committed .env is tracked, so git check-ignore reports it as NOT ignored
    # and Penny still flags the real secret.
    _git(tmp_path, "add", "-f", ".env")

    files = walk_repo(tmp_path)
    assert ".env" in {file.relative_path for file in files}
    findings = detect_committed_secrets(files)
    assert any(finding.detector_id == "D002" for finding in findings)


def test_changed_files_returns_none_outside_git(tmp_path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert changed_files(tmp_path, "main") is None


@pytest.mark.skipif(not _has_git(), reason="git is required for --diff")
def test_changed_files_lists_changes_versus_base(tmp_path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "base.py").write_text("print('base')\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "base")
    _git(tmp_path, "branch", "base-ref")
    # New committed change plus an untracked file should both be in scope.
    (tmp_path / "feature.py").write_text("print('feature')\n", encoding="utf-8")
    _git(tmp_path, "add", "feature.py")
    _git(tmp_path, "commit", "-m", "feature")
    (tmp_path / "wip.py").write_text("print('wip')\n", encoding="utf-8")

    changed = changed_files(tmp_path, "base-ref")
    assert changed is not None
    names = {path.name for path in changed}
    assert "feature.py" in names
    assert "wip.py" in names
    assert "base.py" not in names


@pytest.mark.skipif(not _has_git(), reason="git is required for --diff")
def test_changed_files_unresolvable_ref_returns_none(tmp_path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "init")
    assert changed_files(tmp_path, "nonexistent-ref") is None
