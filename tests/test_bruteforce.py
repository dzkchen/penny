from __future__ import annotations

from penny.bruteforce import _PATH_CATEGORY, COMMON_PATHS, LOGIN_PATHS, _brute_force_with_gate
from penny.feed import EventFeed
from penny.guardrails import SafeResponse

# A typical SPA dev-server index shell; served verbatim for every route.
SPA_INDEX = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"


class FakeGate:
    """Stands in for TargetGate; the handler may branch on method/path/headers."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, headers=None):
        self.calls.append((method, path))
        return self.handler(method, path, headers or {})


def _run(handler) -> list:
    return _brute_force_with_gate(FakeGate(handler), "http://localhost:8081", list(COMMON_PATHS), feed=EventFeed())


def test_spa_catch_all_yields_no_findings() -> None:
    # Every path (random probes, sensitive paths, login routes) returns the same
    # 200 index.html — the classic Vite/React dev-server behavior that used to make
    # every path "exposed" and every credential "accepted".
    findings = _run(lambda method, path, headers: SafeResponse(200, SPA_INDEX, {}))

    assert [f.detector_id for f in findings] == []


def test_real_exposed_path_is_flagged_against_catch_all() -> None:
    # Server still serves a catch-all page, but /.env returns genuinely distinct
    # content, so it must survive the baseline suppression.
    def handler(method, path, headers):
        if path == "/.env":
            return SafeResponse(200, "SECRET_KEY=not-for-clients\nDATABASE_URL=postgres://db\n", {})
        return SafeResponse(200, SPA_INDEX, {})

    findings = _run(handler)
    d020 = [f for f in findings if f.detector_id == "D020"]

    assert len(d020) == 1
    assert d020[0].evidence["dynamic_probe"]["exposed_paths"] == ["/.env"]
    # The SPA login routes returning the shared page must NOT register as weak creds.
    assert [f for f in findings if f.detector_id == "D021"] == []


def test_real_404s_preserve_original_behavior() -> None:
    # No catch-all (random probes 404), so a 200 on a sensitive path is trusted.
    def handler(method, path, headers):
        if path == "/admin":
            return SafeResponse(200, "<h1>Admin Console</h1>", {})
        return SafeResponse(404, "not found", {})

    d020 = [f for f in _run(handler) if f.detector_id == "D020"]

    assert len(d020) == 1
    assert d020[0].evidence["dynamic_probe"]["exposed_paths"] == ["/admin"]


def test_weak_login_flagged_only_when_credential_discriminates() -> None:
    # A real Basic-auth endpoint: wrong creds -> 401, admin:admin -> 200.
    def handler(method, path, headers):
        if path not in LOGIN_PATHS:
            return SafeResponse(404, "not found", {})
        auth = headers.get("authorization", "")
        # admin:admin base64 == YWRtaW46YWRtaW4=
        if "YWRtaW46YWRtaW4=" in auth:
            return SafeResponse(200, '{"token": "ok"}', {})
        return SafeResponse(401, "unauthorized", {})

    d021 = [f for f in _run(handler) if f.detector_id == "D021"]

    assert len(d021) == 1
    weak = d021[0].evidence["dynamic_probe"]["weak_endpoints"]
    assert all("admin:****" in entry for entry in weak)
    assert all("root:****" not in entry for entry in weak)


def test_wordlist_is_expanded_and_categorized() -> None:
    # The flat list grew well past the original 12 and carries backup permutations.
    assert len(COMMON_PATHS) > 50
    assert "/.env.bak" in COMMON_PATHS  # editor/backup-file permutation of a base
    assert _PATH_CATEGORY["/.env"] == "secrets"
    assert _PATH_CATEGORY["/.git/config"] == "version-control"
    assert _PATH_CATEGORY["/.env.bak"] == "backup"
    assert _PATH_CATEGORY["/admin"] == "admin"


def test_critical_category_path_escalates_severity() -> None:
    # No catch-all (real 404s), so a distinct 200 on a VCS file is trusted and,
    # because version-control is a critical category, the finding is Critical.
    def handler(method, path, headers):
        if path == "/.git/config":
            return SafeResponse(200, "[core]\n\trepositoryformatversion = 0\n", {})
        return SafeResponse(404, "not found", {})

    d020 = [f for f in _run(handler) if f.detector_id == "D020"]

    assert len(d020) == 1
    assert d020[0].severity == "Critical"
    categories = d020[0].evidence["dynamic_probe"]["exposed_by_category"]
    assert categories["version-control"] == ["/.git/config"]


def test_non_critical_path_stays_high() -> None:
    def handler(method, path, headers):
        if path == "/admin":
            return SafeResponse(200, "<h1>Admin Console</h1>", {})
        return SafeResponse(404, "not found", {})

    d020 = [f for f in _run(handler) if f.detector_id == "D020"]

    assert d020[0].severity == "High"
    assert "admin" in d020[0].evidence["dynamic_probe"]["exposed_by_category"]
