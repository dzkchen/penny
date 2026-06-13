from __future__ import annotations

from collections import Counter

from penny.detectors import run_detectors
from penny.models import assign_finding_ids
from penny.repo import walk_repo

from .conftest import ROOT, SERVICE_KEY


def test_planted_app_fires_the_three_hero_detectors() -> None:
    files = walk_repo(ROOT / "planted-app")
    findings = assign_finding_ids(run_detectors(files))
    counts = Counter(finding.detector_id for finding in findings)

    assert counts == {"D001": 1, "D002": 1, "D003": 1}
    service_finding = next(finding for finding in findings if finding.detector_id == "D001")
    assert service_finding.id == "F-001"
    assert service_finding.secret_value == SERVICE_KEY
    assert SERVICE_KEY not in service_finding.snippet
    assert service_finding.status == "suspected"
