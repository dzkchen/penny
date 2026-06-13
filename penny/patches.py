from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .redaction import redact_text


@dataclass
class PatchPlan:
    path: Path
    original: str
    updated: str

    def diff(self, repo_root: Path, *, redact: bool = True) -> str:
        relative = self.path.relative_to(repo_root).as_posix()
        diff = "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.updated.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
        return redact_text(diff) if redact else diff


def _replace_once(text: str, old: str, new: str) -> str:
    if old not in text:
        return text
    return text.replace(old, new, 1)


def _patch_supabase_client(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    updated = original
    updated = _replace_once(updated, 'export const serviceRoleKey = "sb_service_role_PENNY_DEMO_SUPER_PRIVATE_DO_NOT_SHIP_2026";\n', "")
    updated = updated.replace("createClient(supabaseUrl, serviceRoleKey)", "createClient(supabaseUrl, anonKey)")
    if updated == original:
        return None
    return PatchPlan(path=path, original=original, updated=updated)


def _patch_frontend_api(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    updated = _replace_once(original, 'export const STRIPE_SECRET = "sk_live_penny_demo_51NnDemoSecretValueThatShouldNotShip";\n', "")
    if updated == original:
        return None
    return PatchPlan(path=path, original=original, updated=updated)


def _patch_policy(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    updated = original.replace('create policy "public can read private notes"', 'create policy "users can read their own private notes"')
    updated = updated.replace("using (true);", "using (auth.uid() = user_id);")
    if updated == original:
        return None
    return PatchPlan(path=path, original=original, updated=updated)


def _patch_server(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    updated = _replace_once(original, '        self.send_header("access-control-allow-origin", "*")\n', "")
    updated = _replace_once(
        updated,
        '            self._json(200, order)\n            return\n',
        '            if order.get("user_id") != self.headers.get("x-user-id"):\n                self._json(404, {"error": "not found"})\n                return\n            self._json(200, order)\n            return\n',
    )
    if updated == original:
        return None
    return PatchPlan(path=path, original=original, updated=updated)


def _patch_requirements(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    updated = original.replace("jinja2==2.10.1", "jinja2>=2.10.2")
    if updated == original:
        return None
    return PatchPlan(path=path, original=original, updated=updated)


def _patch_package_json(path: Path) -> PatchPlan | None:
    if not path.exists():
        return None
    original = path.read_text(encoding="utf-8")
    try:
        package_json: dict[str, Any] = json.loads(original)
    except json.JSONDecodeError:
        return None
    dependencies = package_json.get("dependencies")
    if not isinstance(dependencies, dict) or dependencies.get("lodash") != "4.17.20":
        return None
    dependencies["lodash"] = "4.17.21"
    updated = json.dumps(package_json, indent=2, sort_keys=False) + "\n"
    return PatchPlan(path=path, original=original, updated=updated)


def build_patch_plans(findings_payload: dict[str, Any], repo_root: Path) -> list[PatchPlan]:
    repo_root = repo_root.resolve()
    detector_ids = {finding.get("detector_id") for finding in findings_payload.get("findings", [])}
    candidates: list[PatchPlan | None] = []
    if "D001" in detector_ids:
        candidates.append(_patch_supabase_client(repo_root / "frontend/src/supabaseClient.ts"))
    if "D002" in detector_ids:
        candidates.append(_patch_frontend_api(repo_root / "frontend/src/api.ts"))
    if "D003" in detector_ids:
        candidates.append(_patch_policy(repo_root / "policies/private_notes.sql"))
    if "D004" in detector_ids or "D006" in detector_ids:
        candidates.append(_patch_server(repo_root / "server/app.py"))
    if "D005" in detector_ids:
        candidates.append(_patch_requirements(repo_root / "requirements.txt"))
        candidates.append(_patch_package_json(repo_root / "frontend/package.json"))
    return [candidate for candidate in candidates if candidate is not None]


def build_unified_patch(findings_payload: dict[str, Any], repo_root: Path, *, redact: bool = True) -> str:
    repo_root = repo_root.resolve()
    plans = build_patch_plans(findings_payload, repo_root)
    return "\n".join(plan.diff(repo_root, redact=redact).rstrip() for plan in plans if plan.diff(repo_root, redact=redact).strip()).rstrip() + "\n"


def write_patch_file(findings_payload: dict[str, Any], repo_root: Path, out_path: Path) -> Path:
    repo_root = repo_root.resolve()
    patch_text = build_unified_patch(findings_payload, repo_root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(patch_text, encoding="utf-8")
    return out_path


def apply_patch_plans(findings_payload: dict[str, Any], repo_root: Path) -> list[Path]:
    plans = build_patch_plans(findings_payload, repo_root)
    changed: list[Path] = []
    for plan in plans:
        plan.path.write_text(plan.updated, encoding="utf-8")
        changed.append(plan.path)
    return changed
