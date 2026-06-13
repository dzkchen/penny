from __future__ import annotations

from pathlib import Path

from penny.active import (
    discover_firebase_databases,
    discover_query_endpoints,
    parse_endpoint_specs,
    probe_cache_controls,
    probe_checklist_baseline,
    probe_cookie_attributes,
    probe_cors_preflight,
    probe_directory_listing,
    probe_exposed_paths,
    probe_http_methods,
    probe_security_headers,
    probe_sql_injection,
    probe_verbose_errors,
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


def test_security_header_probe_flags_missing_hardening_headers() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(200, "<html>Hello</html>", {"server": "Werkzeug/3.0"}))

    findings = probe_security_headers(gate, "https://app.example.test")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "A003"
    assert finding.severity == "Medium"
    missing = finding.evidence["dynamic_probe"]["missing_or_weak_headers"]
    assert any(issue["header"] == "Content-Security-Policy" for issue in missing)
    assert finding.evidence["dynamic_probe"]["exposed_technology_headers"]["server"] == "Werkzeug/3.0"


def test_cookie_attribute_probe_flags_weak_session_cookie() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(200, "ok", {"set-cookie": "sessionid=abc123; Path=/"}))

    findings = probe_cookie_attributes(gate, "https://app.example.test")

    assert len(findings) == 1
    assert findings[0].detector_id == "A004"
    assert findings[0].evidence["dynamic_probe"]["cookie_issues"][0]["missing"] == ["HttpOnly", "Secure", "SameSite"]


def test_http_method_probe_flags_advertised_trace() -> None:
    def handler(method, path):
        if method == "OPTIONS":
            return SafeResponse(204, "", {"allow": "GET, POST, TRACE"})
        return SafeResponse(404, "missing", {})

    findings = probe_http_methods(FakeGate(handler), ["/"])

    assert len(findings) == 1
    assert findings[0].detector_id == "A005"
    assert findings[0].severity == "High"
    assert findings[0].evidence["dynamic_probe"]["advertised_methods"][0]["methods"] == ["TRACE"]


def test_http_method_probe_flags_state_changing_methods_high() -> None:
    def handler(method, path):
        return SafeResponse(204, "", {"allow": "GET, OPTIONS, PUT, DELETE, MKCOL"})

    findings = probe_http_methods(FakeGate(handler), ["/"])

    assert findings[0].severity == "High"
    high = set(findings[0].evidence["dynamic_probe"]["high_risk_methods"])
    assert {"PUT", "DELETE", "MKCOL"} <= high


def test_http_method_probe_readonly_webdav_is_medium() -> None:
    # PROPFIND alone is a read-only WebDAV verb: noteworthy but not state-changing.
    def handler(method, path):
        return SafeResponse(207, "", {"allow": "GET, OPTIONS, PROPFIND"})

    findings = probe_http_methods(FakeGate(handler), ["/"])

    assert findings[0].severity == "Medium"
    assert findings[0].evidence["dynamic_probe"]["advertised_methods"][0]["methods"] == ["PROPFIND"]
    assert findings[0].evidence["dynamic_probe"]["high_risk_methods"] == []


def test_exposed_path_probe_flags_environment_file() -> None:
    def handler(method, path):
        if path == "/.env":
            return SafeResponse(200, "SECRET_KEY=not-for-clients\nDATABASE_URL=postgres://db\n", {"content-type": "text/plain"})
        return SafeResponse(404, "not found", {})

    findings = probe_exposed_paths(FakeGate(handler))

    assert len(findings) == 1
    assert findings[0].detector_id == "A006"
    assert findings[0].severity == "High"
    exposure = findings[0].evidence["dynamic_probe"]["exposures"][0]
    assert exposure["path"] == "/.env"
    assert exposure["type"] == "environment file"


def test_directory_listing_probe_flags_index_page() -> None:
    def handler(method, path):
        if path == "/uploads/":
            return SafeResponse(200, "<title>Index of /uploads/</title><a href=\"file.txt\">file</a>", {})
        return SafeResponse(404, "not found", {})

    findings = probe_directory_listing(FakeGate(handler))

    assert len(findings) == 1
    assert findings[0].detector_id == "A007"
    assert findings[0].evidence["dynamic_probe"]["listings"][0]["path"] == "/uploads/"


def test_verbose_error_probe_flags_stack_trace() -> None:
    gate = FakeGate(
        lambda method, path: SafeResponse(
            500,
            'Traceback (most recent call last):\n  File "/srv/app.py", line 7, in route\nException: boom',
            {},
        )
    )

    findings = probe_verbose_errors(gate)

    assert len(findings) == 1
    assert findings[0].detector_id == "A008"
    assert findings[0].evidence["dynamic_probe"]["error_signature"] == "Python traceback"


def test_cors_preflight_probe_flags_credentialed_untrusted_origin() -> None:
    def handler(method, path):
        if method == "OPTIONS":
            return SafeResponse(
                204,
                "",
                {
                    "access-control-allow-origin": "https://attacker.example",
                    "access-control-allow-credentials": "true",
                    "access-control-allow-methods": "GET, DELETE",
                    "access-control-allow-headers": "authorization,content-type",
                },
            )
        return SafeResponse(404, "not found", {})

    findings = probe_cors_preflight(FakeGate(handler), ["/api"])

    assert len(findings) == 1
    assert findings[0].detector_id == "A009"
    assert findings[0].severity == "High"
    issue = findings[0].evidence["dynamic_probe"]["issues"][0]
    assert issue["risky_methods"] == ["DELETE"]
    assert issue["allows_authorization_header"] is True


def test_cache_control_probe_flags_sensitive_json_without_no_store() -> None:
    def handler(method, path):
        if path == "/api/me":
            return SafeResponse(200, '{"email":"a@example.test","user_id":"u1"}', {"content-type": "application/json"})
        return SafeResponse(404, "missing", {})

    findings = probe_cache_controls(FakeGate(handler), ["/api/me"])

    assert len(findings) == 1
    assert findings[0].detector_id == "A010"
    cached = findings[0].evidence["dynamic_probe"]["cacheable_sensitive_responses"][0]
    assert cached["path"] == "/api/me"
    assert cached["cache_control"] == "<missing>"


def test_checklist_baseline_runs_multiple_live_probes() -> None:
    def handler(method, path):
        if method == "OPTIONS":
            return SafeResponse(204, "", {"allow": "GET, TRACE"})
        if path == "/.env":
            return SafeResponse(200, "SECRET_KEY=not-for-clients\n", {})
        if path == "/__penny_probe_error_surface__":
            return SafeResponse(500, "Traceback (most recent call last):\nFile \"app.py\", line 1", {})
        return SafeResponse(404, "missing", {})

    findings = probe_checklist_baseline(FakeGate(handler), "http://127.0.0.1:8787", [])
    detector_ids = {finding.detector_id for finding in findings}

    assert {"A003", "A005", "A006", "A008"} <= detector_ids
