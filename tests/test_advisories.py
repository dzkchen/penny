from __future__ import annotations

from pathlib import Path

from penny.advisories import Advisory, _advisory_from_vuln
from penny.detectors import (
    detect_dependencies_via_advisories,
    detect_vulnerable_dependencies,
    merge_dependency_findings,
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


def test_detect_dependencies_via_advisories_uses_injected_lookup() -> None:
    files = [_requirements("jinja2==2.10.1\n")]

    def fake_lookup(ecosystem, package, version):
        if (ecosystem, package, version) == ("pypi", "jinja2", "2.10.1"):
            return [Advisory("GHSA-1", "CVE-2019-10906", "High", "sandbox escape", "2.10.2")]
        return []

    findings = detect_dependencies_via_advisories(files, fake_lookup)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "D005"
    assert finding.evidence["cve"] == "CVE-2019-10906"
    assert finding.evidence["source"] == "osv.dev"
    assert "2.10.2" in finding.remediation


def test_merge_prefers_advisory_findings_and_drops_curated_duplicate() -> None:
    files = [_requirements("jinja2==2.10.1\n")]
    curated = detect_vulnerable_dependencies(files)
    advisory = detect_dependencies_via_advisories(
        files,
        lambda *_: [Advisory("GHSA-1", "CVE-2019-10906", "High", "sandbox escape", "2.10.2")],
    )

    merged = merge_dependency_findings(curated, advisory)

    assert len(curated) == 1  # curated knows jinja2
    assert len(merged) == 1  # but the duplicate is dropped in favour of OSV
    assert merged[0].evidence.get("source") == "osv.dev"


def test_merge_keeps_curated_when_advisories_empty() -> None:
    files = [_requirements("jinja2==2.10.1\n")]
    curated = detect_vulnerable_dependencies(files)

    merged = merge_dependency_findings(curated, [])

    assert merged == curated
