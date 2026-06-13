from __future__ import annotations

from pathlib import Path

from penny.advisories import Advisory, _advisory_from_vuln
from penny.detectors import (
    detect_dependencies_via_advisories,
    detect_vulnerable_dependencies,
)
from penny.repo import SourceFile


def _requirements(text: str) -> SourceFile:
    return SourceFile(path=Path("requirements.txt"), relative_path="requirements.txt", text=text)


def test_advisory_parsing_from_osv_vuln() -> None:
    vuln = {
        "id": "GHSA-jf85-cpcp-j695",
        "aliases": ["CVE-2019-10906", "SNYK-PYTHON-JINJA2-174126"],
        "summary": "Sandbox escape in Jinja2",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.2"}]}]}],
    }

    advisory = _advisory_from_vuln(vuln)

    assert advisory.cve == "CVE-2019-10906"
    assert advisory.severity == "High"
    assert advisory.fixed_version == "2.10.2"
    assert "jinja2" in advisory.summary.lower()


def test_advisory_severity_defaults_to_high_without_metadata() -> None:
    advisory = _advisory_from_vuln({"id": "OSV-1"})

    assert advisory.severity == "High"
    assert advisory.fixed_version == ""


def test_advisories_collapse_into_one_grouped_finding() -> None:
    files = [_requirements("jinja2==2.10.1\nflask==0.12.0\n")]

    def fake_lookup(ecosystem, package, version):
        if package == "jinja2":
            return [
                Advisory("GHSA-1", "CVE-2019-10906", "High", "sandbox escape", "2.10.2"),
                Advisory("GHSA-2", "CVE-2020-28493", "Medium", "ReDoS", "2.11.3"),
            ]
        return []  # flask falls back to the curated list

    findings = detect_dependencies_via_advisories(files, fake_lookup)

    assert len(findings) == 1  # one finding for the whole project
    finding = findings[0]
    assert finding.detector_id == "D005"
    assert finding.severity == "High"  # max across all advisories
    evidence = finding.evidence
    assert evidence["package_count"] == 2
    assert evidence["advisory_count"] == 3  # 2 jinja2 + 1 curated flask
    listed = {entry["package"]: entry for entry in evidence["vulnerable_dependencies"]}
    assert set(listed) == {"jinja2", "flask"}
    assert listed["jinja2"]["recommended_version"] == "2.11.3"  # highest fixed version
    assert "CVE-2019-10906" in listed["jinja2"]["cves"]


def test_offline_falls_back_to_curated_single_finding() -> None:
    files = [_requirements("jinja2==2.10.1\n")]

    online = detect_dependencies_via_advisories(files, lambda *_: [])  # OSV down → curated
    offline = detect_vulnerable_dependencies(files)

    assert len(online) == len(offline) == 1
    assert online[0].evidence["vulnerable_dependencies"][0]["package"] == "jinja2"
    assert online[0].evidence["source"] == "curated"


def test_no_findings_when_dependencies_are_clean() -> None:
    files = [_requirements("requests==2.32.0\n")]

    assert detect_vulnerable_dependencies(files) == []
    assert detect_dependencies_via_advisories(files, lambda *_: []) == []
