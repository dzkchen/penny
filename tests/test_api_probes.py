from __future__ import annotations

from penny.api_probes import probe_graphql_introspection, probe_jwt_tampering
from penny.guardrails import SafeResponse


class FakeGate:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method, path, headers=None):
        self.calls.append((method, path, headers))
        return self.handler(method, path, headers)


# --- A021: JWT tampering ---------------------------------------------------


def test_jwt_tampering_flags_accepted_forged_token() -> None:
    def handler(method, path, headers):
        auth = (headers or {}).get("Authorization", "")
        if auth.startswith("Bearer "):  # any forged token is accepted -> sig not verified
            return SafeResponse(200, '{"role":"admin"}', {})
        return SafeResponse(401, "unauthorized", {})

    findings = probe_jwt_tampering(FakeGate(handler), paths=["/api/me"])

    assert len(findings) == 1
    assert findings[0].detector_id == "A021"
    assert findings[0].severity == "Critical"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["path"] == "/api/me"


def test_jwt_tampering_respects_real_verification() -> None:
    # The server rejects every forged token (no token and forged token both 401).
    gate = FakeGate(lambda method, path, headers: SafeResponse(401, "unauthorized", {}))
    assert probe_jwt_tampering(gate, paths=["/api/me"]) == []


def test_jwt_tampering_skips_public_endpoints() -> None:
    # A 200 with no token means the endpoint is public; not an auth-bypass signal.
    gate = FakeGate(lambda method, path, headers: SafeResponse(200, "public", {}))
    assert probe_jwt_tampering(gate, paths=["/api/me"]) == []


# --- A022: GraphQL introspection -------------------------------------------


def test_graphql_introspection_flags_open_schema() -> None:
    def handler(method, path, headers):
        if path.startswith("/graphql"):
            return SafeResponse(
                200,
                '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}',
                {"content-type": "application/json"},
            )
        return SafeResponse(404, "not found", {})

    findings = probe_graphql_introspection(FakeGate(handler), paths=["/graphql"])

    assert len(findings) == 1
    assert findings[0].detector_id == "A022"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["path"] == "/graphql"


def test_graphql_introspection_quiet_when_disabled() -> None:
    gate = FakeGate(lambda method, path, headers: SafeResponse(400, '{"errors":["introspection disabled"]}', {}))
    assert probe_graphql_introspection(gate, paths=["/graphql"]) == []
