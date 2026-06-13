from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .detectors import run_detectors
from .feed import EventFeed
from .models import assign_finding_ids, now_session_id
from .mongo import MongoMirror
from .probes import confirm_bola_order_access, confirm_cors_policy, confirm_service_key_read
from .repo import walk_repo
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
    feed: EventFeed | None = None,
    source_label: str | None = None,
) -> ScanResult:
    feed = feed or EventFeed()
    session_id = now_session_id()
    repo_path = repo_path.resolve()
    if not repo_path.exists():
        raise FileNotFoundError(f"scan path does not exist: {repo_path}")
    feed.emit("scan", f"Walking {repo_path}")
    files = walk_repo(repo_path)
    feed.emit("scan", f"Loaded {len(files)} source file(s)")
    mongo = MongoMirror()
    knowledge_query = " ".join(file.relative_path for file in files[:50])
    patterns, knowledge_message = mongo.search_patterns(knowledge_query, limit=3)
    if knowledge_message:
        feed.emit("mongo", knowledge_message)
    elif patterns:
        feed.emit("mongo", f"Knowledge search returned {len(patterns)} generic pattern(s)")
    findings = run_detectors(files)
    for finding in findings:
        feed.emit("red", f"{finding.detector_id} hit in {finding.location.file}:{finding.location.line}")
    if target and not static_only:
        confirm_service_key_read(findings, target, i_own_this=i_own_this, feed=feed)
        confirm_bola_order_access(findings, target, i_own_this=i_own_this, feed=feed)
        confirm_cors_policy(findings, target, i_own_this=i_own_this, feed=feed)
    elif target and static_only:
        feed.emit("gate", "Static-only mode: skipped dynamic probes")
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
        },
    )
    feed.emit("store", f"Wrote {findings_path}")
    mirror_result = mongo.mirror(payload)
    if mirror_result:
        feed.emit("mongo", mirror_result)
    return ScanResult(session_id=session_id, findings_path=findings_path, payload=payload)
