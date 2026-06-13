from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .active import run_active_probes
from .advisories import lookup as osv_lookup
from .ai_review import ai_review, triage_secret_findings
from .detectors import detect_dependencies_via_advisories, run_detectors
from .feed import EventFeed
from .models import assign_finding_ids, dedupe_cross_detector, now_session_id
from .mongo import MongoMirror
from .probes import confirm_bola_order_access, confirm_cors_policy, confirm_service_key_read
from .repo import changed_files, walk_repo
from .store import FindingsStore


@dataclass
class ScanResult:
    session_id: str
    findings_path: Path
    payload: dict


def run_scan(
    repo_path: Path,
    *,
    target: str | None = None,
    static_only: bool = False,
    out_dir: Path = Path("."),
    i_own_this: bool = False,
    agentic: bool = False,
    brute: bool = False,
    browser: bool = False,
    wordlist: str | None = None,
    pages: int = 8,
    feed: EventFeed | None = None,
    source_label: str | None = None,
    use_osv: bool = False,
    use_ai: bool = False,
    use_active: bool = False,
    diff_base: str | None = None,
    endpoints: list[str] | None = None,
) -> ScanResult:
    feed = feed or EventFeed()
    session_id = now_session_id()
    repo_path = repo_path.resolve()
    if not repo_path.exists():
        raise FileNotFoundError(f"scan path does not exist: {repo_path}")
    feed.emit("scan", f"Walking {repo_path}")
    files = walk_repo(repo_path)
    if diff_base:
        changed = changed_files(repo_path, diff_base)
        if changed is None:
            feed.emit("scan", f"--diff: could not resolve '{diff_base}' (not a git tree or bad ref); scanning all files")
        else:
            files = [file for file in files if file.path.resolve() in changed]
            feed.emit("scan", f"--diff {diff_base}: {len(files)} changed file(s) in scope")
    feed.emit("scan", f"Loaded {len(files)} source file(s)")
    mongo = MongoMirror()
    knowledge_query = " ".join(file.relative_path for file in files[:50])
    patterns, knowledge_message = mongo.search_patterns(knowledge_query, limit=3)
    if knowledge_message:
        feed.emit("mongo", knowledge_message)
    elif patterns:
        feed.emit("mongo", f"Knowledge search returned {len(patterns)} generic pattern(s)")
    findings = run_detectors(files)
    if use_osv:
        advisory_findings = detect_dependencies_via_advisories(files, osv_lookup)
        findings = [finding for finding in findings if finding.detector_id != "D005"] + advisory_findings
        package_count = advisory_findings[0].evidence.get("package_count", 0) if advisory_findings else 0
        feed.emit("osv", f"OSV review: {package_count} vulnerable dependency package(s)")
    if use_ai:
        findings.extend(ai_review(files, feed=feed))
        findings = triage_secret_findings(findings, files, feed=feed)
        before = len(findings)
        findings = dedupe_cross_detector(findings)
        merged = before - len(findings)
        if merged:
            feed.emit("ai", f"Merged {merged} AI finding(s) duplicating deterministic detectors")
    for finding in findings:
        feed.emit("red", f"{finding.detector_id} hit in {finding.location.file}:{finding.location.line}")
    if target and not static_only:
        confirm_service_key_read(findings, target, i_own_this=i_own_this, feed=feed)
        confirm_bola_order_access(findings, target, i_own_this=i_own_this, feed=feed)
        confirm_cors_policy(findings, target, i_own_this=i_own_this, feed=feed)
        if agentic:
            from .agentic import run_agentic_probe_from_files

            findings.extend(run_agentic_probe_from_files(files, target, i_own_this=i_own_this, feed=feed))
    elif target and static_only:
        feed.emit("gate", "Static-only mode: skipped dynamic probes")
    if use_active:
        findings.extend(run_active_probes(files, target, i_own_this=i_own_this, feed=feed, extra_endpoints=endpoints))
    if target and not static_only and brute:
        from .bruteforce import run_brute_force

        findings.extend(run_brute_force(target, i_own_this=i_own_this, wordlist=wordlist, feed=feed))
    if target and not static_only and browser:
        from .browser import run_browser_probe

        findings.extend(run_browser_probe(target, i_own_this=i_own_this, max_pages=pages, feed=feed))
    findings = assign_finding_ids(findings)
    store = FindingsStore(out_dir)
    payload, findings_path = store.write_findings(
        session_id,
        findings,
        scan={
            "source": source_label or str(repo_path),
            "resolved_path": str(repo_path),
            "static_only": static_only,
            "file_count": len(files),
            "coverage": {
                "osv": use_osv,
                "ai": use_ai,
                "active": use_active,
                "target": bool(target),
            },
        },
    )
    feed.emit("store", f"Wrote {findings_path}")
    mirror_result = mongo.mirror(payload)
    if mirror_result:
        feed.emit("mongo", mirror_result)
    return ScanResult(session_id=session_id, findings_path=findings_path, payload=payload)
