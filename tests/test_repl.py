from __future__ import annotations

import penny.repl as repl_module
from penny.feed import EventFeed
from penny.repl import Session
from penny.scanner import run_scan

from .conftest import ROOT


def _session(tmp_path, monkeypatch):
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    project = tmp_path / "app"
    project.mkdir()
    (project / "client.ts").write_text(
        'export const serviceRoleKey = "sb_service_role_PENNY_DEMO_SUPER_PRIVATE";\n',
        encoding="utf-8",
    )
    run_scan(project, static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    captured: list[str] = []
    session = Session(out_dir=tmp_path, printer=captured.append)
    session.use_ai = False  # keep tests offline/deterministic
    return session, captured


def test_session_autoloads_last_findings(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    assert session.payload is not None
    assert session.payload["summary"]["total"] >= 1


def test_help_lists_commands(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    assert session.handle("/help") is True
    text = "\n".join(captured)
    assert "/scan" in text and "/exit" in text


def test_greet_shows_recommended_prompt_without_loaded_state(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    session.greet()
    text = "\n".join(captured)
    assert "How To Use" in text
    assert "Run a full audit on ./file_path" in text
    assert "/help" in text
    assert "loaded" not in text
    assert "Commands" not in text


def test_findings_table_and_show(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    session.handle("/findings")
    session.handle("/show F-001")
    text = "\n".join(captured)
    assert "F-001" in text
    assert "Severity" in text  # table header
    assert "Impact:" in text  # detail panel
    assert "Client-visible service-role credential" in text


def test_plain_text_is_a_deterministic_question(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    session.handle("what should blue fix first?")
    assert "Blue fix queue" in "\n".join(captured)


def test_fix_prints_mcp_config_for_claude_code(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    assert session.findings_path is not None
    report_path = session.findings_path.parent / "report.md"
    report_path.write_text("# Report\n\nFix the issue.\n", encoding="utf-8")

    session.handle("/fix --agent cc")

    text = "\n".join(captured)
    assert "Penny remediation MCP server" in text
    assert '"command": "penny"' in text
    assert '"mcp"' in text
    assert "Smoke test command: penny mcp" in text
    assert str(session.findings_path) in text
    assert str(report_path) in text
    assert "claude-code" in text


def test_exit_command_ends_session(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    assert session.handle("/exit") is False
    assert session.handle("") is True  # blank line is a no-op


def test_natural_language_audit_forwards_target_flag(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    captured: dict[str, object] = {}
    session._scan = lambda args, force=None: captured.update(args=args, target=session.target)
    session._report = lambda args, **kwargs: None  # _audit now passes announce_path=...

    handled = session._route_intent("run full audit on ../app --target http://localhost:8081 and AI/OSV scan")

    assert handled is True
    assert session.target == "http://localhost:8081"  # flag survives NL routing
    assert captured["args"] == ["../app"]


def test_natural_language_scan_forwards_flags(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    captured: dict[str, object] = {}
    session._scan = lambda args, force=None: captured.update(args=args)

    session._route_intent("scan ./proj --target http://127.0.0.1:8787 --active")

    assert captured["args"] == ["./proj", "--target", "http://127.0.0.1:8787", "--active"]


def test_scan_command_loads_and_summarizes(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")

    session.handle(f"/scan {project}")

    text = "\n".join(captured)
    assert "Scan summary" in text or "finding(s)" in text
    assert any(f["detector_id"] == "D008" for f in session.payload["findings"])
