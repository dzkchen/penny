from __future__ import annotations

from pathlib import Path

from penny.handoff import create_fix_handoff, render_handoff


def _payload() -> dict:
    return {
        "session_id": "session/demo",
        "scan": {"source": "./app"},
        "findings": [
            {
                "id": "F-001",
                "detector_id": "D002",
                "severity": "High",
                "status": "confirmed",
                "title": "Committed secret",
                "impact": "An attacker can use the exposed token.",
                "remediation": "Rotate the key and move it to server-side configuration.",
                "location": {"file": "app.py", "line": 12},
                "evidence": {"token": "sk_live_penny_demo_51NnDemoSecretValueThatShouldNotShip"},
            },
            {
                "id": "F-002",
                "detector_id": "A004",
                "severity": "Medium",
                "status": "confirmed",
                "title": "Permissive CORS",
                "remediation": "Restrict CORS to trusted origins.",
                "location": {"file": "dynamic:/api/orders"},
                "evidence": {"header": "access-control-allow-origin: *"},
            },
        ],
    }


def test_render_handoff_groups_file_and_runtime_findings(tmp_path: Path) -> None:
    text = render_handoff(_payload(), tmp_path, agent="claude-code")

    assert "# Penny Remediation Handoff" in text
    assert "Intended agent: `claude-code`" in text
    assert "### `app.py`" in text
    assert "[F-001] High confirmed D002" in text
    assert "## Runtime Or Route Findings" in text
    assert "[F-002] Medium confirmed A004" in text
    assert "sk_live_penny_demo" not in text
    assert "[REDACTED:secret:" in text


def test_create_fix_handoff_writes_default_path(tmp_path: Path) -> None:
    result = create_fix_handoff(_payload(), tmp_path, agent="codex")

    assert result.path == tmp_path / ".penny" / "handoffs" / "session-demo-remediation.md"
    assert result.finding_count == 2
    assert result.file_count == 1
    assert result.path.exists()
