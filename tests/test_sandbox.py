from __future__ import annotations

import pytest

from penny import guardrails, sandbox
from penny.feed import EventFeed
from penny.sandbox_agent import GateError, RemoteGate
from penny.vultr import Box


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
    assert guardrails.host_authorization_error("app.example.com", True) is None
    # ...but the strict path still demands a real TXT record.
    assert guardrails.host_authorization_error("app.example.com", True, strict_txt=True) is not None


def test_strict_txt_passes_with_record(monkeypatch) -> None:
    monkeypatch.setattr(guardrails, "_is_private_or_loopback_host", lambda h: False)
    monkeypatch.setattr(guardrails, "_has_matching_txt_record", lambda h: True)
    assert guardrails.host_authorization_error("app.example.com", True, strict_txt=True) is None


# ---------------------------------------------------------------------------
# Orchestrator: gate-before-spend, JSONL parsing, ephemeral teardown
# ---------------------------------------------------------------------------

def test_sandbox_test_blocks_before_provision(monkeypatch) -> None:
    monkeypatch.setattr(sandbox.vultr, "available", lambda: True)

    def _boom(*args, **kwargs):  # provision must never run for an unowned host
        raise AssertionError("provision called despite failed gate")

    monkeypatch.setattr(sandbox.vultr, "provision", _boom)
    monkeypatch.setattr(sandbox, "snapshot_id", lambda: "snap-x")
    findings = sandbox.sandbox_test("http://8.8.8.8", i_own_this=False, feed=_feed())
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
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", i_own_this=False, feed=_feed())
    assert len(findings) == 1
    assert findings[0].detector_id == "H001"
    assert destroyed == ["box-1"]  # ephemeral: box destroyed after the run


def test_sandbox_test_destroys_on_error(monkeypatch) -> None:
    destroyed: list[str] = []
    _wire_happy_path(monkeypatch, destroyed, stream_raises=RuntimeError("ssh blew up mid-attack"))
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", i_own_this=False, feed=_feed())
    assert findings == []
    assert destroyed == ["box-1"]  # teardown still runs in finally


def test_sandbox_test_keep_alive_skips_destroy(monkeypatch) -> None:
    destroyed: list[str] = []
    _wire_happy_path(monkeypatch, destroyed, output='{"event": "done", "findings": 0}')
    sandbox.sandbox_test("http://127.0.0.1:8787", i_own_this=False, feed=_feed(), keep_alive=True)
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
    sandbox.sandbox_test("http://127.0.0.1:8787", i_own_this=False, feed=_feed(), keep_alive=True)
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
    findings = sandbox.sandbox_test("http://127.0.0.1:8787", i_own_this=False, feed=_feed(), keep_alive=True)
    assert findings == []
    assert destroyed == ["box-1"]  # poisoned box torn down despite keep_alive
