from __future__ import annotations

import json
from pathlib import Path

from penny.mcp import build_context, handle_request


def test_mcp_lists_create_handoff_tool() -> None:
    response = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert response is not None
    tools = response["result"]["tools"]
    assert tools[0]["name"] == "create_handoff"
    assert "inputSchema" in tools[0]


def test_mcp_create_handoff_tool_writes_file(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    repo = tmp_path / "repo"
    repo.mkdir()
    findings.write_text(
        json.dumps(
            {
                "session_id": "demo",
                "scan": {"source": str(repo)},
                "findings": [
                    {
                        "id": "F-001",
                        "detector_id": "D001",
                        "severity": "High",
                        "status": "suspected",
                        "title": "Client-side secret",
                        "remediation": "Move the secret server-side.",
                        "location": {"file": "src/app.ts", "line": 4},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "create_handoff",
                "arguments": {
                    "findings_path": str(findings),
                    "repo": str(repo),
                    "out_path": "handoff.md",
                    "agent": "codex",
                },
            },
        },
        cwd=tmp_path,
    )

    assert response is not None
    assert response["result"]["isError"] is False
    summary = json.loads(response["result"]["content"][0]["text"])
    assert summary["finding_count"] == 1
    assert Path(summary["handoff_path"]) == repo / "handoff.md"
    assert (repo / "handoff.md").exists()


def test_mcp_get_remediation_context_uses_startup_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    findings = tmp_path / "findings.json"
    report = tmp_path / "report.md"
    findings.write_text(
        json.dumps(
            {
                "session_id": "demo",
                "scan": {"source": str(repo)},
                "findings": [{"id": "F-001", "title": "Risk", "location": {"file": "app.py"}}],
            }
        ),
        encoding="utf-8",
    )
    report.write_text("# Report\n\nFix F-001.\n", encoding="utf-8")
    context = build_context(repo=repo, findings_path=findings, report_path=report, agent="claude-code")

    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_remediation_context", "arguments": {}},
        },
        cwd=tmp_path,
        context=context,
    )

    assert response is not None
    body = json.loads(response["result"]["content"][0]["text"])
    assert body["repo_root"] == str(repo)
    assert body["findings_path"] == str(findings)
    assert body["report_path"] == str(report)
    assert body["agent"] == "claude-code"
    assert body["report"].startswith("# Report")
