from __future__ import annotations

from collections import Counter

from penny.detectors import (
    detect_committed_secrets,
    run_detectors,
)
from penny.models import assign_finding_ids
from penny.repo import SourceFile, walk_repo

from .conftest import ROOT, SERVICE_KEY


def _source(name: str, text: str) -> SourceFile:
    from pathlib import Path

    return SourceFile(path=Path(name), relative_path=name, text=text)


def test_planted_app_fires_the_three_hero_detectors() -> None:
    files = walk_repo(ROOT / "planted-app")
    findings = assign_finding_ids(run_detectors(files))
    counts = Counter(finding.detector_id for finding in findings)

    assert counts == {"D001": 1, "D002": 1, "D003": 1, "D005": 1, "D006": 1}
    service_finding = next(finding for finding in findings if finding.detector_id == "D001")
    assert service_finding.id == "F-001"
    assert service_finding.secret_value == SERVICE_KEY
    assert SERVICE_KEY not in service_finding.snippet
    assert service_finding.status == "suspected"


def test_p1_static_detectors_include_dependencies_and_cors() -> None:
    files = walk_repo(ROOT / "planted-app")
    findings = run_detectors(files)

    dependency_findings = [finding for finding in findings if finding.detector_id == "D005"]
    assert len(dependency_findings) == 1  # all vulnerable deps collapse into one finding
    listed = dependency_findings[0].evidence["vulnerable_dependencies"]
    assert {entry["package"] for entry in listed} == {"jinja2", "lodash"}
    assert all(entry.get("recommended_version") for entry in listed)

    cors_finding = next(finding for finding in findings if finding.detector_id == "D006")
    assert cors_finding.title == "Permissive CORS policy"
    assert cors_finding.status == "suspected"


def test_new_code_detectors_fire_on_vulnerable_python() -> None:
    files = [
        _source(
            "src/app.py",
            "\n".join(
                [
                    "import os, subprocess, pickle, requests",
                    "os.system('rm -rf ' + user_path)",
                    "subprocess.run(cmd, shell=True)",
                    "pickle.loads(blob)",
                    "cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")",
                    "requests.get(url, verify=False)",
                    "app.run(host='0.0.0.0', debug=True)",
                ]
            ),
        ),
        _source(
            "deploy/id_rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        ),
    ]

    detector_ids = {finding.detector_id for finding in run_detectors(files)}

    assert {"D007", "D008", "D009", "D010", "D011"} <= detector_ids


def test_docs_do_not_produce_high_entropy_noise() -> None:
    readme = _source(
        "README.md",
        "\n".join(
            [
                "![build](https://img.shields.io/badge/build-passing-brightgreen)",
                "Install with integrity "
                'sha512-AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCdEfGhIjKlMn0pQrStUvWx==',
                "Commit 9f8c1b2a3d4e5f60718293a4b5c6d7e8f9012345 documents the change.",
            ]
        ),
    )

    assert detect_committed_secrets([readme]) == []


def test_known_secret_prefix_still_flagged_in_docs() -> None:
    readme = _source("README.md", "Example token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")

    findings = detect_committed_secrets([readme])

    assert [finding.detector_id for finding in findings] == ["D002"]


def test_integrity_hashes_are_not_flagged_in_source() -> None:
    manifest = _source(
        "src/lockfile.json",
        '{"integrity": "sha512-AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCdEfGhIjKlMn0pQrStUvWx=="}\n',
    )

    assert detect_committed_secrets([manifest]) == []


def test_high_entropy_token_inside_url_is_not_flagged() -> None:
    # A Google Docs / Drive share id is part of a URL, not a credential.
    source = _source(
        "src/pages/Settings.tsx",
        "const HELP = 'https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789?usp=sharing';\n",
    )

    assert detect_committed_secrets([source]) == []


def test_client_side_db_write_flagged_and_server_excluded() -> None:
    client = _source(
        "src/lib/orders.ts",
        "await supabase.from('orders').insert({ amount, userId });\n",
    )
    firestore = _source(
        "src/hooks/useProfile.tsx",
        "await updateDoc(doc(db, 'users', uid), { balance });\n",
    )
    server = _source(
        "src/app/api/orders/route.ts",
        "await supabase.from('orders').insert({ amount, userId });\n",
    )

    findings = run_detectors([client, firestore, server])
    d012 = [f for f in findings if f.detector_id == "D012"]

    assert {f.location.file for f in d012} == {"src/lib/orders.ts", "src/hooks/useProfile.tsx"}
    assert all(f.severity == "High" for f in d012)
