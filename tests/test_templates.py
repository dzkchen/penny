from __future__ import annotations

from penny.guardrails import SafeResponse
from penny.templates import run_template_checks


class FakeGate:
    def __init__(self, handler) -> None:
        self.handler = handler

    def request(self, method, path, headers=None):
        return self.handler(method, path)


def test_template_check_flags_spring_actuator_env() -> None:
    def handler(method, path):
        if path == "/actuator/env":
            return SafeResponse(200, '{"propertySources": [{"name": "systemEnvironment"}]}', {})
        return SafeResponse(404, "not found", {})

    findings = run_template_checks(FakeGate(handler))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "A013"
    assert finding.severity == "High"
    matches = finding.evidence["dynamic_probe"]["matches"]
    assert any(match["id"] == "spring-actuator-env" for match in matches)


def test_template_check_matches_on_header_for_heapdump() -> None:
    def handler(method, path):
        if path == "/actuator/heapdump":
            return SafeResponse(200, "\x00\x00binary", {"content-type": "application/octet-stream"})
        return SafeResponse(404, "missing", {})

    findings = run_template_checks(FakeGate(handler))

    assert len(findings) == 1
    assert findings[0].severity == "Critical"  # heapdump is Critical
    assert findings[0].evidence["dynamic_probe"]["matches"][0]["id"] == "spring-actuator-heapdump"


def test_template_check_clean_target_returns_nothing() -> None:
    findings = run_template_checks(FakeGate(lambda method, path: SafeResponse(404, "not found", {})))
    assert findings == []


def test_template_check_ignores_catch_all_responder() -> None:
    # SPA/wildcard server returns the same 200 page for everything — no real match.
    page = "<html><body>app shell</body></html>"
    findings = run_template_checks(FakeGate(lambda method, path: SafeResponse(200, page, {})))
    assert findings == []
