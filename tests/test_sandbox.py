from __future__ import annotations

import pytest

from penny import guardrails, sandbox
from penny import sandbox_agent as agent
from penny.feed import EventFeed
from penny.sandbox_agent import GateError, RemoteGate
from penny.vultr import Box


class _FakeGate:
    """Stand-in for RemoteGate: returns a catch-all page for unknown paths, JSON for `real_paths`."""

    def __init__(self, real_paths=()):
        self.base_url = "http://target"
        self.request_count = 0
        self.allow_destructive = False
        self.extra_hosts = set()
        self._real = set(real_paths)

    def allow_backend_host(self, host):
        self.extra_hosts.add((host or "").lower())

    def execute(self, method, path, headers=None, body=None, *, timeout=12.0, pace=True):
        self.request_count += 1
        if path in self._real:
            return {"status": 200, "body": '{"id": 1, "amount": 99}', "content_type": "application/json"}
        return {"status": 200, "body": "<html>generic catch-all page</html>", "content_type": "text/html"}


def _feed() -> EventFeed:
    return EventFeed(quiet=True)


def _box() -> Box:
    return Box(id="box-1", ip="", region="ord", plan="vcg-a16-6c-64g-16vram",
               created_at=0.0, kill_by=1800.0, label="penny-sandbox")


# ---------------------------------------------------------------------------
# RemoteGate — the box's minimal active-exploitation guardrail
# ---------------------------------------------------------------------------

def test_remote_gate_host_pin_blocks_off_host() -> None:
    gate = RemoteGate("http://127.0.0.1:8787")
    # A relative path stays on the approved host.
    assert gate.build_url("/api/orders/1").startswith("http://127.0.0.1:8787/")
    # An absolute URL to another host is rejected (no pivoting).
    with pytest.raises(GateError):
        gate.build_url("http://evil.example/steal")


def test_remote_gate_destructive_verb_floor() -> None:
    gate = RemoteGate("http://127.0.0.1:8787")
    with pytest.raises(GateError):
        gate.check_method("DELETE")
    # POST/PUT/PATCH are permitted (active exploitation tier).
    for method in ("GET", "POST", "PUT", "PATCH"):
        assert gate.check_method(method) == method
    # CONNECT/TRACE are always blocked.
    with pytest.raises(GateError):
        gate.check_method("CONNECT")


def test_remote_gate_allow_destructive_opt_in() -> None:
    gate = RemoteGate("http://127.0.0.1:8787", allow_destructive=True)
    assert gate.check_method("DELETE") == "DELETE"


def test_remote_gate_request_cap() -> None:
    gate = RemoteGate("http://127.0.0.1:8787", max_requests=2)
    gate.min_interval_seconds = 0.0
    gate._pace()
    gate._pace()
    with pytest.raises(GateError):
        gate._pace()


# ---------------------------------------------------------------------------
# Strict TXT gate — sandbox-test never honors PENNY_DISABLE_TXT_PROOF
# ---------------------------------------------------------------------------

def test_strict_txt_ignores_disable_bypass(monkeypatch) -> None:
    monkeypatch.setattr(guardrails, "_is_private_or_loopback_host", lambda h: False)
    monkeypatch.setattr(guardrails, "_has_matching_txt_record", lambda h: False)
    monkeypatch.setenv("PENNY_DISABLE_TXT_PROOF", "1")
    # Non-strict path honors the bypass...
    assert guardrails.host_authorization_error("app.example.com") is None
    # ...but the strict path still demands a real TXT record.
    assert guardrails.host_authorization_error("app.example.com", strict_txt=True) is not None


def test_strict_txt_passes_with_record(monkeypatch) -> None:
    monkeypatch.setattr(guardrails, "_is_private_or_loopback_host", lambda h: False)
    monkeypatch.setattr(guardrails, "_has_matching_txt_record", lambda h: True)
    assert guardrails.host_authorization_error("app.example.com", strict_txt=True) is None


# ---------------------------------------------------------------------------
# Orchestrator: gate-before-spend, JSONL parsing, ephemeral teardown
# ---------------------------------------------------------------------------

def test_sandbox_test_blocks_before_provision(monkeypatch) -> None:
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)

    def _boom(*args, **kwargs):  # provision must never run for an unowned host
        raise AssertionError("provision called despite failed gate")

    monkeypatch.setattr(sandbox.vultr, "provision", _boom)
    monkeypatch.setattr(sandbox, "snapshot_id", lambda: "snap-x")
    findings = sandbox.sandbox_test("http://8.8.8.8", feed=_feed())
    assert findings == []


def test_parse_agent_output_builds_findings() -> None:
    out = "\n".join([
        '{"event": "request", "method": "GET", "path": "/api/orders/2", "reason": "idor"}',
        '{"event": "response", "status": 200, "bytes": 120}',
        '{"finding": {"title": "IDOR on orders", "severity": "Critical", "confidence": "high",'
        ' "owasp": ["A01:2021-Broken Access Control"], "path": "/api/orders/2",'
        ' "snippet": "read another user order", "impact": "data breach", "remediation": "scope by owner",'
        ' "evidence": {"status": 200}}}',
        '{"event": "done", "findings": 1, "requests": 3}',
    ])
    findings = sandbox._parse_agent_output(out, "http://127.0.0.1:8787", _feed())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_id == "H001"
    assert finding.severity == "Critical"
    assert finding.status == "confirmed"
    assert finding.evidence["dynamic_probe"]["probe"] == "heretic_sandbox"


def _wire_happy_path(monkeypatch, destroyed: list, *, output: str = "", stream_raises: Exception | None = None) -> None:
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)
    monkeypatch.setattr(sandbox, "_reusable_box", lambda: None)
    monkeypatch.setattr(sandbox, "snapshot_id", lambda: "snap-x")
    monkeypatch.setattr(sandbox.vultr, "provision", lambda **kwargs: _box())
    monkeypatch.setattr(sandbox.vultr, "wait_for_ip", lambda box, **kw: "1.2.3.4")
    monkeypatch.setattr(sandbox.vultr, "wait_for_ssh", lambda ip, **kw: True)
    monkeypatch.setattr(sandbox, "_ensure_model_up", lambda ip, feed, **kw: True)

    def _ssh_stream(ip, cmd, *, timeout=0.0, on_line=None):
        if stream_raises is not None:
            raise stream_raises
        for line in output.splitlines():
            if on_line is not None:
                on_line(line)
        return 0, output

    monkeypatch.setattr(sandbox.vultr, "ssh_stream", _ssh_stream)
    monkeypatch.setattr(sandbox.vultr, "ssh_run", lambda *a, **k: (0, "", ""))
    monkeypatch.setattr(sandbox.vultr, "destroy", lambda box_id: destroyed.append(box_id))


def test_sandbox_test_runs_and_destroys(monkeypatch) -> None:
    destroyed: list[str] = []
    jsonl = ('{"finding": {"title": "Auth bypass", "severity": "High", "owasp": ["A07"],'
             ' "path": "/admin", "snippet": "got in", "impact": "x", "remediation": "y", "evidence": {}}}\n'
             '{"event": "done", "findings": 1}')
    _wire_happy_path(monkeypatch, destroyed, output=jsonl)
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed())
    assert len(findings) == 1
    assert findings[0].detector_id == "H001"
    assert destroyed == ["box-1"]  # ephemeral: box destroyed after the run


def test_sandbox_test_destroys_on_error(monkeypatch) -> None:
    destroyed: list[str] = []
    _wire_happy_path(monkeypatch, destroyed, stream_raises=RuntimeError("ssh blew up mid-attack"))
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed())
    assert findings == []
    assert destroyed == ["box-1"]  # teardown still runs in finally


def test_sandbox_test_keep_alive_skips_destroy(monkeypatch) -> None:
    destroyed: list[str] = []
    _wire_happy_path(monkeypatch, destroyed, output='{"event": "done", "findings": 0}')
    sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed(), keep_alive=True)
    assert destroyed == []


def test_sandbox_test_reuses_kept_box(monkeypatch) -> None:
    destroyed: list[str] = []
    kept = _box()
    kept.ip = "9.9.9.9"
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)
    monkeypatch.setattr(sandbox, "_reusable_box", lambda: kept)

    def _no_provision(**kwargs):  # reuse must skip provisioning entirely (no restore)
        raise AssertionError("provision called despite a reusable box")

    monkeypatch.setattr(sandbox.vultr, "provision", _no_provision)
    monkeypatch.setattr(sandbox.vultr, "wait_for_ssh", lambda ip, **kw: True)
    monkeypatch.setattr(sandbox, "_ensure_model_up", lambda ip, feed, **kw: True)
    monkeypatch.setattr(sandbox.vultr, "destroy", lambda box_id: destroyed.append(box_id))

    def _ssh_stream(ip, cmd, *, timeout=0.0, on_line=None):
        assert ip == "9.9.9.9"  # talks to the reused box
        for line in '{"event": "done", "findings": 0}'.splitlines():
            if on_line is not None:
                on_line(line)
        return 0, ""

    monkeypatch.setattr(sandbox.vultr, "ssh_stream", _ssh_stream)
    sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed(), keep_alive=True)
    assert destroyed == []  # kept alive for the next run


def test_sandbox_test_destroys_unhealable_reused_box(monkeypatch) -> None:
    # A reused box whose model can't be healed must be destroyed even under --keep-alive, so the
    # next run restores fresh instead of reusing the same broken box forever.
    destroyed: list[str] = []
    kept = _box()
    kept.ip = "9.9.9.9"
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)
    monkeypatch.setattr(sandbox, "_reusable_box", lambda: kept)
    monkeypatch.setattr(sandbox.vultr, "wait_for_ssh", lambda ip, **kw: True)
    monkeypatch.setattr(sandbox, "_ensure_model_up", lambda ip, feed, **kw: False)
    monkeypatch.setattr(sandbox, "_dump_vllm_logs", lambda ip, feed: None)
    monkeypatch.setattr(sandbox.vultr, "destroy", lambda box_id: destroyed.append(box_id))

    def _no_stream(*a, **k):
        raise AssertionError("attack launched despite a dead model")

    monkeypatch.setattr(sandbox.vultr, "ssh_stream", _no_stream)
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed(), keep_alive=True)
    assert findings == []
    assert destroyed == ["box-1"]  # poisoned box torn down despite keep_alive


def _wire_for_breach(monkeypatch, ssh_stream) -> None:
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)
    monkeypatch.setattr(sandbox, "_reusable_box", lambda: None)
    monkeypatch.setattr(sandbox, "snapshot_id", lambda: "snap-x")
    monkeypatch.setattr(sandbox.vultr, "provision", lambda **kw: _box())
    monkeypatch.setattr(sandbox.vultr, "wait_for_ip", lambda box, **kw: "1.2.3.4")
    monkeypatch.setattr(sandbox.vultr, "wait_for_ssh", lambda ip, **kw: True)
    monkeypatch.setattr(sandbox, "_ensure_model_up", lambda ip, feed, **kw: True)
    monkeypatch.setattr(sandbox.vultr, "ssh_run", lambda *a, **k: (0, "", ""))
    monkeypatch.setattr(sandbox.vultr, "destroy", lambda box_id: None)
    monkeypatch.setattr(sandbox.vultr, "ssh_stream", ssh_stream)


def test_sandbox_test_passes_instructions_to_agent(monkeypatch) -> None:
    import base64

    captured: dict[str, str] = {}

    def _ssh_stream(ip, cmd, *, timeout=0.0, on_line=None):
        captured["cmd"] = cmd
        return 0, ""

    _wire_for_breach(monkeypatch, _ssh_stream)
    sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed(),
                         instructions="focus on SQLi in /search")
    assert "--instructions-b64" in captured["cmd"]
    b64 = captured["cmd"].split("--instructions-b64", 1)[1].split()[0]
    assert "focus on SQLi in /search" in base64.b64decode(b64).decode("utf-8")


def test_sandbox_test_parallel_workers_dedup(monkeypatch) -> None:
    calls: list[str] = []
    dup = ('{"finding": {"title": "IDOR", "severity": "High", "owasp": ["A01"], "path": "/api/orders/1",'
           ' "snippet": "s", "impact": "i", "remediation": "r", "evidence": {}}}')

    def _ssh_stream(ip, cmd, *, timeout=0.0, on_line=None):
        calls.append(cmd)
        if on_line is not None:
            on_line(dup)  # every worker reports the same finding
        return 0, dup

    _wire_for_breach(monkeypatch, _ssh_stream)
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", feed=_feed(), workers=3)
    assert len(calls) == 3       # one stream per worker
    assert len(findings) == 1    # identical findings deduped across workers


# ---------------------------------------------------------------------------
# Anti-hallucination: catch-all (SPA) responders must not yield phantom findings
# ---------------------------------------------------------------------------

def test_matches_baseline_distinguishes_json_from_catch_all() -> None:
    baseline = [{"status": 200, "ct": "html", "len": 30, "hash": agent._body_hash("<html>x</html>")}]
    # Identical body -> matches the catch-all.
    assert agent.matches_baseline({"status": 200, "body": "<html>x</html>", "content_type": "text/html"}, baseline)
    # A real JSON API response never matches an html baseline.
    assert not agent.matches_baseline({"status": 200, "body": '{"id":1}', "content_type": "application/json"}, baseline)


def test_validate_finding_rejects_on_pure_catch_all() -> None:
    baseline = [{"status": 200, "ct": "html", "len": 30, "hash": "abc"}]
    ok, reason = agent._validate_finding("/api/invoices/1", {"/api/invoices/1": False}, baseline)
    assert not ok and "catch-all" in reason


def test_validate_finding_accepts_real_hit() -> None:
    baseline = [{"status": 200, "ct": "html", "len": 30, "hash": "abc"}]
    assert agent._validate_finding("/api/invoices/1", {"/api/invoices/1": True}, baseline)[0]
    # an id-style finding is backed by a real sibling probe
    assert agent._validate_finding("/api/invoices/{id}", {"/api/invoices/7": True}, baseline)[0]


def _run_agent(monkeypatch, gate, replies):
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    it = iter(replies)
    monkeypatch.setattr(agent, "ask_model", lambda *a, **k: next(it))
    count = agent.run_loop(gate, "ep", "m", max_turns=6)
    return count, emitted


def test_run_loop_rejects_phantom_finding_on_catch_all(monkeypatch) -> None:
    # Every path returns the catch-all page, so the IDOR "finding" is a hallucination.
    replies = [
        '{"action":"request","method":"GET","path":"/api/invoices/1","reason":"idor"}',
        '{"action":"finding","title":"IDOR","severity":"High","owasp":["A01"],"path":"/api/invoices/1",'
        '"snippet":"s","impact":"i","remediation":"r","evidence":{}}',
        '{"action":"finish","summary":"done"}',
    ]
    count, emitted = _run_agent(monkeypatch, _FakeGate(), replies)
    assert count == 0
    assert any(e.get("event") == "finding_rejected" for e in emitted)
    assert not any("finding" in e and "event" not in e for e in emitted)  # no finding emitted


def test_run_loop_accepts_finding_on_real_json_endpoint(monkeypatch) -> None:
    # /api/invoices/1 returns JSON (differs from the html catch-all) -> a real, accepted finding.
    replies = [
        '{"action":"request","method":"GET","path":"/api/invoices/1","reason":"idor"}',
        '{"action":"finding","title":"IDOR","severity":"High","owasp":["A01"],"path":"/api/invoices/1",'
        '"snippet":"s","impact":"i","remediation":"r","evidence":{}}',
        '{"action":"finish","summary":"done"}',
    ]
    count, emitted = _run_agent(monkeypatch, _FakeGate(real_paths={"/api/invoices/1"}), replies)
    assert count == 1
    assert any("finding" in e and "event" not in e for e in emitted)


# ---------------------------------------------------------------------------
# Client-side recon + backend (Firebase/Supabase) probing
# ---------------------------------------------------------------------------

class _ReconGate:
    """Serves an index that references a bundle; the bundle leaks a Firebase RTDB URL; the RTDB
    is world-readable. Tracks which backend hosts were allow-listed."""

    INDEX = '<html><script src="/assets/app.js"></script></html>'
    BUNDLE = ('const cfg={projectId:"penny-demo",databaseURL:"https://penny-demo-default-rtdb.firebaseio.com"};'
              'fetch("/api/orders/1");')

    def __init__(self):
        self.base_url = "http://target"
        self.host = "target"
        self.request_count = 0
        self.allow_destructive = False
        self.extra_hosts = set()

    def allow_backend_host(self, host):
        if host:
            self.extra_hosts.add(host.lower())

    def execute(self, method, path, headers=None, body=None, *, timeout=12.0, pace=True):
        self.request_count += 1
        if path == "/":
            return {"status": 200, "body": self.INDEX, "content_type": "text/html"}
        if path == "/assets/app.js":
            return {"status": 200, "body": self.BUNDLE, "content_type": "application/javascript"}
        if "firebaseio.com" in path:
            host = path.split("/")[2]
            if host not in self.extra_hosts:  # host-pin would have blocked it
                raise GateError("host-pin")
            return {"status": 200, "body": '{"users":{"u1":{"email":"a@b.c"}}}', "content_type": "application/json"}
        return {"status": 200, "body": "<html>catch-all</html>", "content_type": "text/html"}


def test_recon_extracts_endpoints_and_firebase(monkeypatch) -> None:
    monkeypatch.setattr(agent, "emit", lambda obj: None)
    info = agent.recon(_ReconGate())
    assert "/api/orders/1" in info["endpoints"]
    assert "penny-demo" in info["project_ids"]
    assert any("penny-demo-default-rtdb.firebaseio.com" in u for u in info["rtdb"])


def test_probe_firebase_flags_open_rules_and_allows_backend_host(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    gate = _ReconGate()
    info = agent.recon(gate)
    found = agent.probe_firebase(gate, info)
    assert found >= 1
    # the firebaseio.com backend host had to be allow-listed for the probe to reach it
    assert any("firebaseio.com" in h for h in gate.extra_hosts)
    fb = [e["finding"] for e in emitted if "finding" in e]
    assert fb and fb[0]["severity"] == "Critical" and "Firebase" in fb[0]["title"]


class _FirestoreGate:
    """Firestore is open only for the 'sac_authorized_users' collection; everything else 403/locked."""

    def __init__(self):
        self.base_url = "http://target"
        self.host = "target"
        self.request_count = 0
        self.allow_destructive = False
        self.extra_hosts = set()

    def allow_backend_host(self, host):
        self.extra_hosts.add((host or "").lower())

    def execute(self, method, path, headers=None, body=None, *, timeout=12.0, pace=True):
        self.request_count += 1
        if "firestore.googleapis.com" in path:
            if "/documents/sac_authorized_users" in path:
                return {"status": 200, "body": '{"documents":[{"name":"x","fields":{"email":{}}}]}',
                        "content_type": "application/json"}
            return {"status": 403, "body": '{"error":{"status":"PERMISSION_DENIED"}}', "content_type": "application/json"}
        if "firebaseio.com" in path:
            return {"status": 401, "body": '{"error":"Permission denied"}', "content_type": "application/json"}
        return {"status": 200, "body": "<html>catch</html>", "content_type": "text/html"}


def test_probe_firestore_flags_named_collection(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    gate = _FirestoreGate()
    info = {"endpoints": set(), "rtdb": set(), "project_ids": {"penny-demo"},
            "supabase_urls": set(), "supabase_keys": set()}
    found = agent.probe_firebase(gate, info)
    assert found >= 1
    fb = [e["finding"] for e in emitted if "finding" in e]
    assert any("sac_authorized_users" in f["title"] for f in fb)
    assert any("firestore.googleapis.com" in h for h in gate.extra_hosts)


def test_remote_gate_allows_discovered_backend_host() -> None:
    gate = RemoteGate("https://app.example")
    with pytest.raises(GateError):
        gate.build_url("https://app-default-rtdb.firebaseio.com/.json")  # blocked until discovered
    gate.allow_backend_host("app-default-rtdb.firebaseio.com")
    assert gate.build_url("https://app-default-rtdb.firebaseio.com/.json").endswith("/.json")


# ---------------------------------------------------------------------------
# Deterministic active probes: rate-limit, SQL injection, writes
# ---------------------------------------------------------------------------

class _ProbeGate:
    """Configurable fake gate: per-(method,path-substring) responses; everything else catch-all."""

    def __init__(self, rules=None):
        self.base_url = "http://target"
        self.host = "target"
        self.request_count = 0
        self.extra_hosts = set()
        self.allow_destructive = True
        self._rules = rules or []  # list of (method, substr, response_dict)
        self.calls = []

    def allow_backend_host(self, host):
        self.extra_hosts.add((host or "").lower())

    def execute(self, method, path, headers=None, body=None, *, timeout=12.0, pace=True):
        self.request_count += 1
        self.calls.append((method, path))
        for m, sub, resp in self._rules:
            if m == method and sub in path:
                return dict(resp)
        return {"status": 200, "body": "<html>catch-all</html>", "content_type": "text/html"}


_BASE = [{"status": 200, "ct": "html", "len": len("<html>catch-all</html>"),
          "hash": agent._body_hash("<html>catch-all</html>")}]


def test_probe_rate_limit_flags_missing_throttle(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    # /api/orders returns JSON (live, never throttled)
    gate = _ProbeGate([("GET", "/api/orders", {"status": 200, "body": '{"ok":1}', "content_type": "application/json"})])
    info = {"endpoints": {"/api/orders"}, "rtdb": set(), "project_ids": set(), "supabase_urls": set(), "supabase_keys": set()}
    found = agent.probe_rate_limit(gate, info, _BASE)
    assert found == 1
    titles = [e["finding"]["title"] for e in emitted if "finding" in e]
    assert any("rate limiting" in t.lower() for t in titles)


def test_probe_injection_flags_sql_error(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    gate = _ProbeGate([
        ("GET", "id=", {"status": 500, "body": "ERROR: syntax error at or near \"'\"", "content_type": "text/plain"}),
        ("GET", "/api/search", {"status": 200, "body": '{"results":[]}', "content_type": "application/json"}),
    ])
    info = {"endpoints": {"/api/search"}, "rtdb": set(), "project_ids": set(), "supabase_urls": set(), "supabase_keys": set()}
    found = agent.probe_injection(gate, info, _BASE)
    assert found == 1
    assert any("sql injection" in e["finding"]["title"].lower() for e in emitted if "finding" in e)


def test_probe_writes_flags_mass_assignment(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    gate = _ProbeGate([
        ("GET", "/api/users", {"status": 200, "body": '{"users":[]}', "content_type": "application/json"}),
        ("POST", "/api/users", {"status": 201, "body": '{"id":"9","role":"admin","isAdmin":true}', "content_type": "application/json"}),
        ("DELETE", "/api/users/9", {"status": 204, "body": "", "content_type": ""}),
    ])
    info = {"endpoints": {"/api/users"}, "rtdb": set(), "project_ids": set(), "supabase_urls": set(), "supabase_keys": set()}
    found = agent.probe_writes(gate, info, _BASE, allow_destructive=True)
    titles = [e["finding"]["title"] for e in emitted if "finding" in e]
    assert any("mass assignment" in t.lower() for t in titles)
    assert any("delete" in t.lower() for t in titles)  # cleaned up our record + flagged open DELETE


def test_run_loop_stops_on_time_budget(monkeypatch) -> None:
    # With max_seconds=0 the loop should stop on the very first time check (no model turns at all).
    monkeypatch.setattr(agent, "emit", lambda obj: None)
    calls = {"n": 0}

    def _ask(*a, **k):
        calls["n"] += 1
        return '{"action":"request","method":"GET","path":"/x","reason":"r"}'

    monkeypatch.setattr(agent, "ask_model", _ask)
    # max_seconds=0.0 trips on the first check (elapsed >= 0) before any model call
    count = agent.run_loop(_FakeGate(), "ep", "m", deterministic=False, max_seconds=0.0, max_turns=99)
    assert calls["n"] == 0


def test_probe_writes_no_delete_without_optin(monkeypatch) -> None:
    emitted: list = []
    monkeypatch.setattr(agent, "emit", lambda obj: emitted.append(obj))
    gate = _ProbeGate([
        ("GET", "/api/users", {"status": 200, "body": '{"users":[]}', "content_type": "application/json"}),
        ("POST", "/api/users", {"status": 201, "body": '{"id":"9"}', "content_type": "application/json"}),
    ])
    info = {"endpoints": {"/api/users"}, "rtdb": set(), "project_ids": set(), "supabase_urls": set(), "supabase_keys": set()}
    agent.probe_writes(gate, info, _BASE, allow_destructive=False)
    assert not any(m == "DELETE" for m, _ in gate.calls)  # DELETE only with --allow-destructive
