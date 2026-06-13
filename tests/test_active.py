from __future__ import annotations

from pathlib import Path

from penny.active import (
    discover_firebase_databases,
    discover_query_endpoints,
    parse_endpoint_specs,
    probe_sql_injection,
    run_firebase_open_rules_probe,
)
from penny.guardrails import SafeResponse
from penny.repo import SourceFile

SQL_ERROR_BODY = "You have an error in your SQL syntax; check the manual near \"'\" at line 1"


class FakeGate:
    """Stands in for TargetGate so probe logic is tested without the network."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, headers=None):
        self.calls.append((method, path))
        return self.handler(method, path)


def test_sql_injection_probe_confirms_on_error_signature() -> None:
    def handler(method, path):
        # The injected quote (url-encoded %27) trips a database error.
        if "%27" in path:
            return SafeResponse(500, SQL_ERROR_BODY, {})
        return SafeResponse(200, '{"ok": true}', {})

    gate = FakeGate(handler)
    findings = probe_sql_injection(gate, [("/api/items", "id")])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "A001"
    assert finding.severity == "Critical"
    assert finding.status == "confirmed"
    assert finding.evidence["dynamic_probe"]["parameter"] == "id"


def test_sql_injection_probe_clean_endpoint_returns_nothing() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(200, '{"ok": true}', {}))

    assert probe_sql_injection(gate, [("/api/items", "id")]) == []


def test_sql_injection_probe_ignores_endpoints_that_always_error() -> None:
    # If the baseline already shows a SQL error, we cannot attribute it to injection.
    gate = FakeGate(lambda method, path: SafeResponse(500, SQL_ERROR_BODY, {}))

    assert probe_sql_injection(gate, [("/api/items", "id")]) == []


def test_firebase_probe_flags_open_database() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(200, '{"users": true, "transactions": true}', {}))

    findings = run_firebase_open_rules_probe(gate, "https://demo-default-rtdb.firebaseio.com")

    assert len(findings) == 1
    assert findings[0].detector_id == "A002"
    assert findings[0].severity == "Critical"
    assert findings[0].evidence["dynamic_probe"]["top_level_keys"] == 2


def test_firebase_probe_respects_locked_rules() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(401, '{"error": "Permission denied"}', {}))

    assert run_firebase_open_rules_probe(gate, "https://demo-default-rtdb.firebaseio.com") == []


def test_discovery_finds_firebase_url_and_query_endpoint() -> None:
    files = [
        SourceFile(Path("src/firebase.ts"), "src/firebase.ts", "const databaseURL = 'https://fp-default-rtdb.firebaseio.com';\n"),
        SourceFile(Path("src/api.ts"), "src/api.ts", "fetch('/api/search?q=' + term)\n"),
    ]

    assert discover_firebase_databases(files) == ["https://fp-default-rtdb.firebaseio.com"]
    assert ("/api/search", "q") in discover_query_endpoints(files)


def test_parse_endpoint_specs_handles_variants() -> None:
    pairs = parse_endpoint_specs(["/api/users?id=1", "/search?q", "/multi?a=1&b=2", "", "/noquery"])
    assert ("/api/users", "id") in pairs
    assert ("/search", "q") in pairs
    assert ("/multi", "a") in pairs
    assert ("/multi", "b") in pairs
    # No-query and blank specs are ignored (nothing to inject into).
    assert all(path != "/noquery" for path, _ in pairs)
