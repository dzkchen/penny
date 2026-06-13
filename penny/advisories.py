"""Real vulnerability-advisory lookups via the public OSV.dev API.

Penny ships with a tiny curated list of known-bad package/version pairs so the
offline demo is deterministic. When the OSV feed is enabled (``--osv``) Penny
also queries https://osv.dev for every parsed dependency, giving genuine CVE
coverage instead of three hard-coded packages. Only package names and versions
(public information) leave the machine, and every failure degrades to an empty
result so the curated detector remains the safety net.
"""

from __future__ import annotations

from dataclasses import dataclass

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Penny's internal ecosystem tags mapped to OSV's canonical names.
ECOSYSTEM_MAP = {"npm": "npm", "pypi": "PyPI"}

_SEVERITY_WORDS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    cve: str
    severity: str
    summary: str
    fixed_version: str


def _pick_cve(vuln: dict) -> str:
    aliases = vuln.get("aliases") or []
    cve = next((alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")), "")
    return cve or str(vuln.get("id", ""))


def _pick_severity(vuln: dict) -> str:
    database_specific = vuln.get("database_specific") or {}
    word = str(database_specific.get("severity", "")).upper()
    if word in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word]
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score", "")).upper()
        for needle, label in _SEVERITY_WORDS.items():
            if needle in score:
                return label
    # A published advisory with no severity metadata is still worth surfacing.
    return "High"


def _pick_fixed_version(vuln: dict) -> str:
    for affected in vuln.get("affected") or []:
        for ranges in affected.get("ranges") or []:
            for event in ranges.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return ""


def _advisory_from_vuln(vuln: dict) -> Advisory:
    return Advisory(
        advisory_id=str(vuln.get("id", "")),
        cve=_pick_cve(vuln),
        severity=_pick_severity(vuln),
        summary=str(vuln.get("summary") or vuln.get("details") or "").strip()[:300],
        fixed_version=_pick_fixed_version(vuln),
    )


def lookup(ecosystem: str, package: str, version: str, *, timeout: float = 15.0) -> list[Advisory]:
    """Return advisories affecting ``package==version``; ``[]`` on any failure."""
    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_ecosystem or not package or not version:
        return []
    try:
        import httpx
    except ImportError:
        return []
    try:
        response = httpx.post(
            OSV_QUERY_URL,
            json={"version": version, "package": {"ecosystem": osv_ecosystem, "name": package}},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    return [_advisory_from_vuln(vuln) for vuln in data.get("vulns", []) if isinstance(vuln, dict)]
