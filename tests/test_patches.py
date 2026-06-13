from __future__ import annotations

import json
import shutil

from penny.feed import EventFeed
from penny.patches import apply_patch_plans, build_unified_patch, write_patch_file
from penny.scanner import run_scan

from .conftest import PAYMENT_SECRET, ROOT, SERVICE_KEY


def _copy_planted_app(tmp_path):
    target = tmp_path / "planted-app"
    shutil.copytree(ROOT / "planted-app", target)
    return target


def test_patch_preview_is_redacted_and_contains_actionable_diffs(tmp_path, monkeypatch) -> None:
    repo = _copy_planted_app(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(repo, static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))

    patch = build_unified_patch(result.payload, repo)
    patch_path = write_patch_file(result.payload, repo, tmp_path / "penny.patch")

    assert patch_path.read_text(encoding="utf-8") == patch
    assert "frontend/src/supabaseClient.ts" in patch
    assert "policies/private_notes.sql" in patch
    assert "jinja2>=2.10.2" in patch
    assert "lodash" in patch
    assert SERVICE_KEY not in patch
    assert PAYMENT_SECRET not in patch
    assert "[REDACTED:service_key:" in patch


def test_patch_preview_accepts_relative_repo_path(tmp_path, monkeypatch) -> None:
    repo = _copy_planted_app(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(repo, static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))

    patch = build_unified_patch(result.payload, repo.relative_to(tmp_path))

    assert "frontend/src/supabaseClient.ts" in patch
    assert SERVICE_KEY not in patch


def test_patch_apply_updates_local_copy_without_touching_original(tmp_path, monkeypatch) -> None:
    repo = _copy_planted_app(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    result = run_scan(repo, static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))

    changed = apply_patch_plans(result.payload, repo)

    changed_relative = {path.relative_to(repo).as_posix() for path in changed}
    assert {
        "frontend/src/supabaseClient.ts",
        "frontend/src/api.ts",
        "policies/private_notes.sql",
        "server/app.py",
        "requirements.txt",
        "frontend/package.json",
    }.issubset(changed_relative)
    assert SERVICE_KEY not in (repo / "frontend/src/supabaseClient.ts").read_text(encoding="utf-8")
    assert PAYMENT_SECRET not in (repo / "frontend/src/api.ts").read_text(encoding="utf-8")
    assert "using (auth.uid() = user_id);" in (repo / "policies/private_notes.sql").read_text(encoding="utf-8")
    assert 'access-control-allow-origin", "*"' not in (repo / "server/app.py").read_text(encoding="utf-8")
    assert "jinja2>=2.10.2" in (repo / "requirements.txt").read_text(encoding="utf-8")
    package_json = json.loads((repo / "frontend/package.json").read_text(encoding="utf-8"))
    assert package_json["dependencies"]["lodash"] == "4.17.21"
    assert SERVICE_KEY in (ROOT / "planted-app/frontend/src/supabaseClient.ts").read_text(encoding="utf-8")
