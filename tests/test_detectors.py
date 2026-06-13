from __future__ import annotations

from collections import Counter

from penny.detectors import (
    detect_committed_secrets,
    run_detectors,
)
from penny.models import Finding, Location, assign_finding_ids, dedupe_cross_detector
from penny.repo import SourceFile, walk_repo

from .conftest import ROOT, SERVICE_KEY


def _finding(detector_id: str, source: str, file: str, line: int) -> Finding:
    return Finding(
        title=f"{detector_id} finding",
        severity="High",
        confidence="high",
        status="suspected",
        source=source,
        detector_id=detector_id,
        owasp=[],
        location=Location(file=file, line=line),
        snippet="",
        evidence={},
        impact="",
        remediation="",
    )


def test_dedupe_drops_ai_finding_colliding_with_detector() -> None:
    findings = [
        _finding("D001", "static", "client.ts", 5),
        _finding("AI001", "ai", "client.ts", 5),
        _finding("AI001", "ai", "other.ts", 9),
    ]
    kept = dedupe_cross_detector(findings)
    ids = [(f.detector_id, f.source, f.location.file) for f in kept]
    assert ("D001", "static", "client.ts") in ids
    assert ("AI001", "ai", "client.ts") not in ids  # deduped
    assert ("AI001", "ai", "other.ts") in ids  # unique AI finding survives


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
    # No security rules ship in these files, so Penny cannot confirm the writes are
    # unguarded: severity stays Medium with a low-confidence "rules not assessable" caveat
    # rather than asserting High blindly.
    assert all(f.severity == "Medium" for f in d012)
    assert all(f.confidence == "low" for f in d012)
    assert all("No Firestore/RLS" in f.evidence["rules_posture"] for f in d012)


def test_client_side_db_write_collapses_per_file_and_counts_occurrences() -> None:
    client = _source(
        "src/lib/orders.ts",
        "await supabase.from('orders').insert({ a });\n"
        "await supabase.from('orders').update({ b });\n"
        "await supabase.from('orders').delete();\n",
    )

    d012 = [f for f in run_detectors([client]) if f.detector_id == "D012"]

    # Three offending lines, but a single collapsed finding that records all of them.
    assert len(d012) == 1
    assert d012[0].evidence["occurrences"] == 3
    assert d012[0].evidence["lines"] == [1, 2, 3]


def test_client_side_db_write_high_when_permissive_rule_present() -> None:
    client = _source("src/lib/orders.ts", "await supabase.from('orders').insert({ a });\n")
    open_rule = _source(
        "firestore.rules",
        "match /databases/{db}/documents {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n",
    )

    d012 = [f for f in run_detectors([client, open_rule]) if f.detector_id == "D012"]

    # A permissive rule is visible in the repo, so the client write is confirmed unguarded.
    assert len(d012) == 1
    assert d012[0].severity == "High"
    assert d012[0].confidence == "high"


def test_dataflow_detectors_fire_on_request_derived_sinks() -> None:
    server = _source(
        "server/app.py",
        "\n".join(
            [
                "import requests",
                "r = requests.get(request.args['url'])",
                "data = open(request.args.get('f')).read()",
                "return redirect(request.args.get('next'))",
                "system_prompt = f'You are a bot. {request.args[\"q\"]}'",
            ]
        ),
    )
    by_id = {f.detector_id: f for f in run_detectors([server])}

    assert "D014" in by_id  # SSRF
    assert "D015" in by_id  # path traversal
    assert "D019" in by_id  # open redirect
    assert "D023" in by_id  # prompt injection
    assert by_id["D023"].severity == "High"  # system-prompt build is High


def test_dataflow_detectors_quiet_without_request_input() -> None:
    # Constant / function-param sinks must not fire (precision over recall).
    benign = _source(
        "src/api.ts",
        "\n".join(
            [
                "const r = await fetch(`/api/orders/${orderId}`);",
                "const data = open('config.json');",
                "res.redirect('/dashboard');",
                "const prompt = `Summarize: ${doc.body}`;",
            ]
        ),
    )

    ids = {f.detector_id for f in run_detectors([benign])}
    assert not ({"D014", "D015", "D019", "D023"} & ids)


def test_insecure_jwt_and_crypto_detectors() -> None:
    source = _source(
        "server/auth.py",
        "\n".join(
            [
                "claims = jwt.decode(token, verify=False)",
                "opts = {'algorithms': ['none']}",
                "import hashlib",
                "pw_hash = hashlib.md5(password.encode())",
                "cipher = AES.new(key, AES.MODE_ECB)",
            ]
        ),
    )
    findings = run_detectors([source])
    d016 = {f.severity for f in findings if f.detector_id == "D016"}
    d017 = [f for f in findings if f.detector_id == "D017"]

    assert "Critical" in d016  # the 'none' algorithm
    assert any(f.title.startswith("Weak hash") for f in d017)
    assert any("ECB" in f.title for f in d017)


def test_weak_hash_without_security_context_is_not_flagged() -> None:
    # md5 of a non-sensitive value (cache key) is a common benign use.
    source = _source("src/cache.py", "cache_key = hashlib.md5(url.encode()).hexdigest()\n")

    assert [f.detector_id for f in run_detectors([source]) if f.detector_id == "D017"] == []


def test_client_exposed_secret_gate_is_critical() -> None:
    source = _source(
        "src/pages/Admin.tsx",
        "if (resetPassword === import.meta.env.VITE_FRASERPAY_RESET_PASSWORD) {\n  grant();\n}\n",
    )

    d020 = [f for f in run_detectors([source]) if f.detector_id == "D020"]

    assert len(d020) == 1
    assert d020[0].severity == "Critical"
    assert d020[0].evidence["env_var"] == "VITE_FRASERPAY_RESET_PASSWORD"


def test_client_exposed_secret_plain_read_is_high() -> None:
    source = _source(
        "src/lib/mailer.ts",
        "const pass = process.env.NEXT_PUBLIC_EMAIL_PASS;\n",
    )

    d020 = [f for f in run_detectors([source]) if f.detector_id == "D020"]

    assert len(d020) == 1
    assert d020[0].severity == "High"


def test_public_api_key_is_not_flagged_as_exposed_secret() -> None:
    # Firebase web API keys are public by design — name-based filtering must not flag them.
    source = _source(
        "src/integrations/firebase/client.ts",
        "const cfg = { apiKey: import.meta.env.VITE_FIREBASE_API_KEY, projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID };\n",
    )

    assert [f for f in run_detectors([source]) if f.detector_id == "D020"] == []


def test_xss_sink_skips_static_markup() -> None:
    source = _source(
        "src/render.tsx",
        "\n".join(
            [
                "el.innerHTML = userBio;",
                "container.innerHTML = '';",
                "card.innerHTML = '<hr>';",
            ]
        ),
    )
    d018 = [f for f in run_detectors([source]) if f.detector_id == "D018"]

    # Only the dynamic assignment is flagged; empty and static-literal markup are not.
    assert [f.location.line for f in d018] == [1]


def test_xss_sink_skips_static_multiline_template() -> None:
    # A multi-line static template (no ${...}) must not be flagged just because the
    # opening line is a lone backtick.
    static_tpl = _source(
        "src/error.tsx",
        "\n".join(
            [
                "el.innerHTML = `",
                "  <div>Something went wrong</div>",
                "  <button>Reload</button>",
                "`;",
            ]
        ),
    )
    dynamic_tpl = _source(
        "src/render.tsx",
        "\n".join(
            [
                "el.innerHTML = `",
                "  <p>Hello ${userName}</p>",
                "`;",
            ]
        ),
    )

    assert [f for f in run_detectors([static_tpl]) if f.detector_id == "D018"] == []
    dynamic = [f for f in run_detectors([dynamic_tpl]) if f.detector_id == "D018"]
    assert [f.location.line for f in dynamic] == [1]


def test_jwt_verify_false_is_not_also_a_tls_finding() -> None:
    source = _source("server/auth.py", "claims = jwt.decode(token, verify=False)\n")
    ids = {f.detector_id for f in run_detectors([source])}

    assert "D016" in ids
    assert "D010" not in ids
