from __future__ import annotations

import json

from penny.models import Finding, Location, validate_findings_payload
from penny.store import build_findings_payload

from .conftest import SERVICE_KEY


def test_findings_payload_schema_excludes_private_secret_field() -> None:
    finding = Finding(
        title="Client-visible service-role credential",
        severity="Critical",
        confidence="high",
        status="suspected",
        source="static",
        detector_id="D001",
        owasp=["A01:2021-Broken Access Control"],
        location=Location(file="frontend/src/supabaseClient.ts", line=5),
        snippet=f'const serviceRoleKey = "{SERVICE_KEY}"',
        evidence={"reason": f"found {SERVICE_KEY}"},
        impact="Privileged access can bypass row-level controls.",
        remediation="Move the key server-side.",
        secret_value=SERVICE_KEY,
    )

    payload = build_findings_payload("test-session", [finding], scan={"source": "/tmp/demo", "resolved_path": "/tmp/demo", "file_count": 1})
    encoded = json.dumps(payload)

    validate_findings_payload(payload)
    assert payload["scan"]["source"] == "/tmp/demo"
    assert "secret_value" not in encoded
    assert SERVICE_KEY not in encoded
    assert "[REDACTED:service_key:" in encoded
