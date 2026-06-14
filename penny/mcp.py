from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .handoff import create_fix_handoff
from .redaction import redact_text, redact_value
from .reporting import load_findings

PROTOCOL_VERSION = "2024-11-05"


@dataclass(frozen=True)
class MCPContext:
    repo: Path
    findings_path: Path
    report_path: Path | None
    agent: str = "codex"


def _resolve_path(value: Path | str | None, *, cwd: Path) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(value)
    return path if path.is_absolute() else cwd / path


def build_context(
    *,
    cwd: Path | None = None,
    repo: Path | str | None = None,
    findings_path: Path | str | None = None,
    report_path: Path | str | None = None,
    agent: str = "codex",
) -> MCPContext:
    cwd = (cwd or Path.cwd()).resolve()
    repo_path = (_resolve_path(repo, cwd=cwd) or cwd).resolve()
    findings = (_resolve_path(findings_path, cwd=cwd) or (cwd / ".penny/runs/latest/findings.json")).resolve()
    report = _resolve_path(report_path, cwd=cwd)
    if report is None:
        candidate = findings.parent / "report.md"
        report = candidate if candidate.exists() else None
    return MCPContext(repo=repo_path, findings_path=findings, report_path=report.resolve() if report else None, agent=agent)


def mcp_command_args(context: MCPContext) -> list[str]:
    args = [
        "mcp",
        "--repo",
        str(context.repo),
        "--findings",
        str(context.findings_path),
        "--agent",
        context.agent,
    ]
    if context.report_path:
        args.extend(["--report", str(context.report_path)])
    return args


def render_client_config(context: MCPContext, *, client: str = "codex") -> str:
    config = {
        "command": "penny",
        "args": mcp_command_args(context),
        "cwd": str(context.repo),
    }
    label = "Claude Code" if client in {"cc", "claude", "claude-code"} else "Codex"
    return (
        f"{label} stdio MCP server config:\n"
        "```json\n"
        f"{json.dumps(config, indent=2)}\n"
        "```\n"
        "The client should start this command as a stdio MCP server."
    )


CREATE_HANDOFF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings_path": {
            "type": "string",
            "description": "Path to a Penny findings.json file. Defaults to .penny/runs/latest/findings.json.",
        },
        "repo": {
            "type": "string",
            "description": "Repository root to write the handoff into. Defaults to the server startup repo.",
        },
        "report_path": {
            "type": "string",
            "description": "Path to report.md. Defaults to the server startup report path when supplied.",
        },
        "out_path": {
            "type": "string",
            "description": "Optional handoff output path. Relative paths are resolved inside repo.",
        },
        "agent": {
            "type": "string",
            "description": "Target coding agent label, for example codex or claude-code.",
            "default": "codex",
        },
    },
    "additionalProperties": False,
}


GET_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings_path": {
            "type": "string",
            "description": "Optional override for the Penny findings.json path.",
        },
        "report_path": {
            "type": "string",
            "description": "Optional override for the Penny report.md path.",
        },
        "repo": {
            "type": "string",
            "description": "Optional override for the repository root.",
        },
    },
    "additionalProperties": False,
}


def _response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tools_list() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "create_handoff",
                "description": "Create a Penny remediation handoff for Codex, Claude Code, or another coding agent.",
                "inputSchema": CREATE_HANDOFF_SCHEMA,
            },
            {
                "name": "get_remediation_context",
                "description": "Return the current Penny findings.json and report.md context for remediation.",
                "inputSchema": GET_CONTEXT_SCHEMA,
            }
        ]
    }


def _context_from_arguments(arguments: dict[str, Any], *, cwd: Path, context: MCPContext) -> MCPContext:
    return build_context(
        cwd=cwd,
        repo=arguments.get("repo") or context.repo,
        findings_path=arguments.get("findings_path") or context.findings_path,
        report_path=arguments.get("report_path") or context.report_path,
        agent=str(arguments.get("agent") or context.agent),
    )


def _call_create_handoff(arguments: dict[str, Any], *, cwd: Path, context: MCPContext) -> dict[str, Any]:
    resolved = _context_from_arguments(arguments, cwd=cwd, context=context)
    out_value = arguments.get("out_path")
    out_path = Path(str(out_value)) if out_value else None

    payload = load_findings(resolved.findings_path)
    result = create_fix_handoff(
        payload,
        resolved.repo,
        out_path=out_path,
        agent=resolved.agent,
        report_path=resolved.report_path,
    )
    summary = {
        "handoff_path": str(result.path),
        "repo_root": str(result.repo_root),
        "findings_path": str(resolved.findings_path),
        "report_path": str(result.report_path) if result.report_path else None,
        "finding_count": result.finding_count,
        "file_count": result.file_count,
        "agent": result.agent,
    }
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(summary, indent=2, sort_keys=True),
            }
        ],
        "isError": False,
    }


def _call_get_remediation_context(arguments: dict[str, Any], *, cwd: Path, context: MCPContext) -> dict[str, Any]:
    resolved = _context_from_arguments(arguments, cwd=cwd, context=context)
    payload = redact_value(load_findings(resolved.findings_path))
    report_text = ""
    if resolved.report_path and resolved.report_path.exists():
        report_text = redact_text(resolved.report_path.read_text(encoding="utf-8"))
    body = {
        "repo_root": str(resolved.repo),
        "findings_path": str(resolved.findings_path),
        "report_path": str(resolved.report_path) if resolved.report_path else None,
        "agent": resolved.agent,
        "findings": payload,
        "report": report_text,
    }
    return {
        "content": [{"type": "text", "text": json.dumps(body, indent=2, sort_keys=True)}],
        "isError": False,
    }


def handle_request(
    request: dict[str, Any],
    *,
    cwd: Path | None = None,
    context: MCPContext | None = None,
) -> dict[str, Any] | None:
    cwd = (cwd or Path.cwd()).resolve()
    context = context or build_context(cwd=cwd)
    request_id = request.get("id")
    method = request.get("method")

    if request_id is None:
        return None
    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "penny", "version": __version__},
            },
        )
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, _tools_list())
    if method == "tools/call":
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return _error(request_id, -32602, "params must be an object")
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _error(request_id, -32602, "arguments must be an object")
        try:
            if name == "create_handoff":
                return _response(request_id, _call_create_handoff(arguments, cwd=cwd, context=context))
            if name == "get_remediation_context":
                return _response(request_id, _call_get_remediation_context(arguments, cwd=cwd, context=context))
            return _error(request_id, -32601, f"unknown tool: {name}")
        except Exception as exc:
            return _response(
                request_id,
                {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            )
    return _error(request_id, -32601, f"unknown method: {method}")


def serve(context: MCPContext | None = None) -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _error(None, -32700, f"parse error: {exc}")
        else:
            if not isinstance(request, dict):
                response = _error(None, -32600, "request must be an object")
            else:
                response = handle_request(request, context=context)
                if response is None:
                    continue
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
