from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .feed import EventFeed
from .models import Finding, Location
from .reporting import generate_report
from .store import FindingsStore, build_findings_payload


def _default_findings() -> list[Finding]:
    return [
        Finding(
            id="F-001",
            fingerprint="replay-service-key",
            title="Client-visible service-role credential",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="static+dynamic",
            detector_id="D001",
            owasp=["A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures"],
            location=Location(file="frontend/src/supabaseClient.ts", line=4),
            snippet='export const serviceRoleKey = "[REDACTED:service_key:replay]";',
            evidence={
                "dynamic_probe": {
                    "probe": "service_key_table_read",
                    "status": "confirmed",
                    "anon_status": 403,
                    "anon_row_count": 0,
                    "service_status": 200,
                    "service_row_count": 3,
                    "stored_response": "row counts and status codes only",
                },
                "attack_path": "Anon access was blocked or empty, while the leaked service credential read protected rows.",
            },
            impact="A service-role key in browser-shipped code can bypass row-level access controls.",
            remediation="Move service credentials to a server-only environment and expose only least-privilege API routes to clients.",
        )
    ]


def run_demo_replay(*, recording: Path | None = None, out_dir: Path = Path("."), feed: EventFeed | None = None) -> tuple[Path, Path]:
    feed = feed or EventFeed()
    feed.emit("replay", "Loading known-good Penny session")
    if recording:
        payload: dict[str, Any] = json.loads(recording.read_text(encoding="utf-8"))
        session_id = payload.get("session_id", "replay")
    else:
        session_id = "replay"
        payload = build_findings_payload(session_id, _default_findings())
    for event in (
        ("scan", "Walking ./planted-app"),
        ("red", "D001 hit in frontend/src/supabaseClient.ts"),
        ("gate", "Target http://127.0.0.1:8787 allowed"),
        ("red", "Confirmed: anon blocked, service key returned 3 redacted rows"),
        ("blue", "Writing fix: move service key server-side and tighten policy"),
        ("purple", "Verdict: critical client-exposed service credential confirmed"),
    ):
        feed.emit(*event)
    store = FindingsStore(out_dir)
    run_dir = store.run_dir(session_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.json"
    findings_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest_dir = store.latest_dir()
    latest_dir.mkdir(parents=True, exist_ok=True)
    (latest_dir / "findings.json").write_text(findings_path.read_text(encoding="utf-8"), encoding="utf-8")
    report_path = store.write_report(session_id, generate_report(payload))
    feed.emit("report", f"Wrote {report_path}")
    return findings_path, report_path
