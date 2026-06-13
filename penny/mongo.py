from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from hashlib import sha256
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
        now = datetime.now(UTC)
        db.scan_history.insert_one(scan_history_doc(payload, now=now))
        for finding in payload.get("findings", []):
            pattern_doc = vuln_pattern_doc(finding, now=now)
            db.vuln_patterns.update_one(
                {"detector_id": finding["detector_id"], "title": finding["title"]},
                {"$set": pattern_doc, "$inc": {"observation_count": 1}, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
        client.close()
        return "mirrored redacted stats and generic patterns to Mongo"


def scan_history_doc(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    summary = payload.get("summary", {})
    return {
        "created_at": now or datetime.now(UTC),
        "schema_version": payload.get("schema_version"),
        "total_findings": summary.get("total", 0),
        "critical_count": summary.get("critical_count", 0),
        "high_count": summary.get("high_count", 0),
        "confirmed_count": summary.get("confirmed_count", 0),
        "by_severity": summary.get("by_severity", {}),
        "by_status": summary.get("by_status", {}),
        "by_detector": summary.get("by_detector", {}),
    }


def vuln_pattern_doc(finding: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    pattern_text = f"{finding['title']} {finding['impact']} {finding['remediation']}"
    return {
        "detector_id": finding["detector_id"],
        "title": finding["title"],
        "severity": finding["severity"],
        "owasp": finding.get("owasp", []),
        "remediation": finding["remediation"],
        "pattern_text": pattern_text,
        "embedding_text": pattern_text,
        "embedding_model": "penny-hash-v1",
        "embedding": hashed_embedding(pattern_text),
        "updated_at": now or datetime.now(UTC),
    }


def hashed_embedding(text: str, dimensions: int = 64) -> list[float]:
    vector = [0.0] * dimensions
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    if not tokens:
        return vector
    for token in tokens:
        digest = sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:2], "big") % dimensions
        sign = 1.0 if digest[2] % 2 == 0 else -1.0
        vector[index] += sign
    magnitude = sum(value * value for value in vector) ** 0.5
    if not magnitude:
        return vector
    return [round(value / magnitude, 6) for value in vector]
