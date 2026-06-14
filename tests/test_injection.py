from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlparse

from penny.guardrails import SafeResponse
from penny.injection import (
    probe_command_injection,
    probe_nosql_injection,
    probe_open_redirect,
    probe_path_traversal,
    probe_ssti,
)


class FakeGate:
    """Stands in for TargetGate so probe logic is tested without the network."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, headers=None):
        self.calls.append((method, path))
        return self.handler(method, path)


# --- A016: NoSQL injection -------------------------------------------------


def test_nosql_injection_confirms_on_operator_differential() -> None:
    def handler(method, path):
        decoded = unquote(path)
        if "[$ne]" in decoded or "$ne" in decoded:  # TRUE operator widens the result set
            return SafeResponse(200, "user: alice\nuser: bob\nuser: carol", {})
        if "[$eq]" in decoded or "$eq" in decoded:  # FALSE control matches nothing
            return SafeResponse(200, "user: (none)", {})
        return SafeResponse(200, "user: requested-literal", {})  # literal baseline

    findings = probe_nosql_injection(FakeGate(handler), [("/api/users", "name")])

    assert len(findings) == 1
    assert findings[0].detector_id == "A016"
    assert findings[0].severity == "Critical"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["parameter"] == "name"


def test_nosql_injection_confirms_on_db_error() -> None:
    def handler(method, path):
        if "$ne" in unquote(path) or "%24ne" in path:
            return SafeResponse(500, "MongoServerError: unknown operator: $ne", {})
        return SafeResponse(200, "ok literal", {})

    findings = probe_nosql_injection(FakeGate(handler), [("/api/users", "name")])

    assert len(findings) == 1
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["method"] == "error-based"


def test_nosql_injection_clean_endpoint_returns_nothing() -> None:
    # The endpoint ignores operators: every response is identical to the baseline.
    gate = FakeGate(lambda method, path: SafeResponse(200, "always the same body", {}))
    assert probe_nosql_injection(gate, [("/api/users", "name")]) == []


def test_nosql_injection_no_false_positive_on_reflecting_endpoint() -> None:
    # A benign endpoint that simply reflects the parameter VALUE returns different
    # bodies for different values — but the $ne/$eq and $gt/$lt pairs carry the same
    # value on both sides, so reflection alone must not trip the differential.
    def handler(method, path):
        value = (parse_qs(urlparse(path).query).get("name") or [""])[0]
        return SafeResponse(200, f"<p>You searched for: {value}</p>", {})

    assert probe_nosql_injection(FakeGate(handler), [("/search", "name")]) == []


# --- A017: SSTI ------------------------------------------------------------


def test_ssti_confirms_when_expression_is_evaluated() -> None:
    def handler(method, path):
        value = (parse_qs(urlparse(path).query).get("name") or [""])[0]
        # A template engine would evaluate {{1337*7331}} to its product.
        if "1337*7331" in value:
            return SafeResponse(200, "<html>Hello 9801547</html>", {})
        return SafeResponse(200, f"<html>Hello {value}</html>", {})

    findings = probe_ssti(FakeGate(handler), [("/greet", "name")])

    assert len(findings) == 1
    assert findings[0].detector_id == "A017"
    assert findings[0].severity == "Critical"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["evaluated_to"] == "9801547"


def test_ssti_ignores_reflected_but_unevaluated_payload() -> None:
    def handler(method, path):
        value = (parse_qs(urlparse(path).query).get("name") or [""])[0]
        # The payload echoes verbatim (reflection) but is NOT evaluated.
        return SafeResponse(200, f"<html>Hello {value}</html>", {})

    assert probe_ssti(FakeGate(handler), [("/greet", "name")]) == []


# --- A018: Path traversal --------------------------------------------------


def test_path_traversal_confirms_on_passwd_signature() -> None:
    def handler(method, path):
        if "etc" in unquote(path).lower() and "passwd" in unquote(path).lower():
            return SafeResponse(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", {})
        return SafeResponse(200, "normal content", {})

    findings = probe_path_traversal(FakeGate(handler), [("/download", "file")])

    assert len(findings) == 1
    assert findings[0].detector_id == "A018"
    assert findings[0].severity == "High"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["target_file"] == "/etc/passwd"


def test_path_traversal_confirms_on_windows_ini() -> None:
    def handler(method, path):
        if "win.ini" in unquote(path).lower():
            return SafeResponse(200, "; for 16-bit app support\n[fonts]\n[extensions]\n", {})
        return SafeResponse(404, "missing", {})

    findings = probe_path_traversal(FakeGate(handler), [("/download", "file")])

    assert len(findings) == 1
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["target_file"] == "windows/win.ini"


def test_path_traversal_clean_endpoint_returns_nothing() -> None:
    gate = FakeGate(lambda method, path: SafeResponse(404, "not found", {}))
    assert probe_path_traversal(gate, [("/download", "file")]) == []


# --- A019: Command injection (time-based) ----------------------------------


def test_command_injection_confirms_on_injected_delay() -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.t = 0.0

        def now(self) -> float:
            return self.t

    clock = FakeClock()

    def handler(method, path):
        # Inspect only the parameter *value*, not the path (which itself may contain
        # a word like "ping"). A shell-delay command in the value runs the delay.
        value = (parse_qs(urlparse(path).query).get("host") or [""])[0]
        if "sleep" in value or "ping" in value:  # the injected delay command runs
            clock.t += 5.3
        return SafeResponse(200, "done", {})

    findings = probe_command_injection(FakeGate(handler), [("/api/lookup", "host")], now=clock.now)

    assert len(findings) == 1
    assert findings[0].detector_id == "A019"
    assert findings[0].severity == "Critical"


def test_command_injection_no_delay_returns_nothing() -> None:
    class FakeClock:
        t = 0.0

        def now(self):
            return self.t

    # The clock never advances: no command runs, so no delay, so no finding.
    gate = FakeGate(lambda method, path: SafeResponse(200, "done", {}))
    assert probe_command_injection(gate, [("/api/lookup", "host")], now=FakeClock().now) == []


# --- A020: Open redirect ---------------------------------------------------


def test_open_redirect_confirms_offsite_location() -> None:
    def handler(method, path):
        value = (parse_qs(urlparse(path).query).get("next") or [""])[0]
        if "penny-redirect.example" in value:
            return SafeResponse(302, "", {"location": "https://penny-redirect.example/"})
        return SafeResponse(200, "home", {})

    findings = probe_open_redirect(FakeGate(handler), [("/login", "next")], target="http://app.local")

    assert len(findings) == 1
    assert findings[0].detector_id == "A020"
    assert findings[0].severity == "Medium"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["parameter"] == "next"


def test_open_redirect_ignores_same_host_redirect() -> None:
    def handler(method, path):
        # The app redirects, but only to its own host: not an open redirect.
        return SafeResponse(302, "", {"location": "https://app.local/dashboard"})

    assert probe_open_redirect(FakeGate(handler), [("/login", "next")], target="http://app.local") == []
