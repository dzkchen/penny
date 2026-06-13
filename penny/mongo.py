from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


class MongoMirror:
    def __init__(self) -> None:
        load_dotenv()
        self.uri = None if os.environ.get("PENNY_DISABLE_MONGO") == "1" else os.environ.get("MONGODB_URI")
        self.database_name = os.environ.get("PENNY_MONGODB_DB", "penny")

    def enabled(self) -> bool:
        return bool(self.uri)

    def mirror(self, payload: dict[str, Any]) -> str | None:
        if not self.enabled():
            return None
        try:
            from pymongo import MongoClient
        except Exception:
            return "pymongo is not installed; skipped Mongo mirror"

        client = MongoClient(self.uri, serverSelectionTimeoutMS=1500)
        db = client[self.database_name]
        summary = payload.get("summary", {})
        now = datetime.now(UTC)
        scan_history = {
            "created_at": now,
            "schema_version": payload.get("schema_version"),
            "total_findings": summary.get("total", 0),
            "critical_count": summary.get("critical_count", 0),
            "high_count": summary.get("high_count", 0),
            "confirmed_count": summary.get("confirmed_count", 0),
            "by_severity": summary.get("by_severity", {}),
            "by_status": summary.get("by_status", {}),
            "by_detector": summary.get("by_detector", {}),
        }
        db.scan_history.insert_one(scan_history)
        for finding in payload.get("findings", []):
            pattern_doc = {
                "detector_id": finding["detector_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "owasp": finding.get("owasp", []),
                "remediation": finding["remediation"],
                "pattern_text": f"{finding['title']} {finding['impact']} {finding['remediation']}",
                "updated_at": now,
            }
            db.vuln_patterns.update_one(
                {"detector_id": finding["detector_id"], "title": finding["title"]},
                {"$set": pattern_doc, "$inc": {"observation_count": 1}, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
        client.close()
        return "mirrored redacted stats and generic patterns to Mongo"
