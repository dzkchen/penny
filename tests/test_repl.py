from __future__ import annotations

import penny.repl as repl_module
from penny.feed import EventFeed
from penny.repl import Session
from penny.scanner import run_scan

from .conftest import ROOT


def _session(tmp_path, monkeypatch):
    monkeypatch.setenv("PENNY_DISABLE_MONGO", "1")
    run_scan(ROOT / "planted-app", static_only=True, out_dir=tmp_path, feed=EventFeed(quiet=True))
    captured: list[str] = []
    session = Session(out_dir=tmp_path, printer=captured.append)
    session.use_ai = False  # keep tests offline/deterministic
    return session, captured


def test_session_autoloads_last_findings(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    assert session.payload is not None
    assert session.payload["summary"]["total"] == 6


def test_help_lists_commands(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    assert session.handle("/help") is True
    text = "\n".join(captured)
    assert "/scan" in text and "/exit" in text


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


def test_exit_command_ends_session(tmp_path, monkeypatch) -> None:
    session, _ = _session(tmp_path, monkeypatch)
    assert session.handle("/exit") is False
    assert session.handle("") is True  # blank line is a no-op


def test_scan_command_loads_and_summarizes(tmp_path, monkeypatch) -> None:
    session, captured = _session(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")

    session.handle(f"/scan {project}")

    text = "\n".join(captured)
    assert "Scan summary" in text
    assert any(f["detector_id"] == "D008" for f in session.payload["findings"])
