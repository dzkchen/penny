"""Slash-command completions for the Penny REPL.

Keeps the command catalog in one place so the interactive shell can show
Claude-style suggestion lists and Tab-complete ``/commands`` without pulling
in a full prompt library.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SlashCompletion:
    name: str
    template: str
    summary: str
    aliases: tuple[str, ...] = ()


# Keep in sync with ``repl.HELP`` and ``Session._command``.
SLASH_COMPLETIONS: tuple[SlashCompletion, ...] = (
    SlashCompletion("audit", "/audit <path> [--target <url>]", "FULL audit: scan + AI + all probes + report", ("full",)),
    SlashCompletion("scan", "/scan <path> [--osv] [--ai] [--active] [--static-only] [--target <url>]", "scan only (add flags as needed)"),
    SlashCompletion("report", "/report", "write report.md to .penny/runs/"),
    SlashCompletion("fix", "/fix [--yes]", "fix flagged files with approval"),
    SlashCompletion("findings", "/findings", "list the current findings", ("ls",)),
    SlashCompletion("show", "/show <F-001>", "show one finding in detail"),
    SlashCompletion("target", "/target <url|off>", "set or clear the live probe target"),
    SlashCompletion("own", "/own <on|off>", "confirm you own the target (needed for public URLs)"),
    SlashCompletion("ai", "/ai <on|off>", "toggle AI answers and review"),
    SlashCompletion("model", "/model <auto|haiku|sonnet>", "pick the Claude model"),
    SlashCompletion("cloud-attack", "/cloud-attack <type> [target]", "heavy tier on a cloud box", ("cloud",)),
    SlashCompletion("sandbox-bake", "/sandbox-bake", "one-time: build the heretic/gemma-3 GPU snapshot"),
    SlashCompletion("sandbox-test", "/sandbox-test [target] [--workers N] [--focus <text>]", "ephemeral GPU box runs active breach, then self-destructs"),
    SlashCompletion("boxes", "/boxes", "list active cloud boxes", ("attack-status",)),
    SlashCompletion("kill", "/kill", "stop running cloud attacks"),
    SlashCompletion("destroy", "/destroy", "destroy all cloud boxes now"),
    SlashCompletion("knowledge", "/knowledge <query>", "search the optional Mongo knowledge base"),
    SlashCompletion("help", "/help", "show the full command list", ("h", "?")),
    SlashCompletion("clear", "/clear", "clear the screen"),
    SlashCompletion("exit", "/exit", "leave Penny", ("quit", "q")),
)

MAX_SUGGESTIONS = 6


def _command_token(buffer: str) -> str | None:
    if not buffer.startswith("/"):
        return None
    rest = buffer[1:]
    if not rest:
        return ""
    return rest.split()[0].lower()


def _names(completion: SlashCompletion) -> tuple[str, ...]:
    return (completion.name, *completion.aliases)


def completions_for_buffer(buffer: str) -> list[SlashCompletion]:
    """Return slash-command matches for the current input buffer."""
    if not buffer.startswith("/"):
        return []
    rest = buffer[1:]
    if " " in rest:
        return []
    token = _command_token(buffer)
    if token is None:
        return []
    if token == "":
        return list(SLASH_COMPLETIONS)
    matched = [item for item in SLASH_COMPLETIONS if any(name.startswith(token) for name in _names(item))]
    matched.sort(key=lambda item: (item.name != token, item.name))
    return matched


def ghost_suffix(buffer: str, matches: list[SlashCompletion], *, selected: int = 0) -> str:
    """Dim inline completion for the command word only (not the full template)."""
    if not matches or not buffer.startswith("/") or " " in buffer[1:]:
        return ""
    choice = matches[min(selected, len(matches) - 1)]
    command = f"/{choice.name}"
    if command.startswith(buffer) and len(command) > len(buffer):
        suffix = command[len(buffer) :]
        return suffix + (" " if len(matches) == 1 else "")
    return ""


def apply_tab_completion(buffer: str, matches: list[SlashCompletion], *, selected: int = 0) -> str:
    """Apply Tab to the buffer using the highlighted match."""
    if not matches:
        return buffer
    choice = matches[min(selected, len(matches) - 1)]
    token = _command_token(buffer) or ""
    names = _names(choice)
    if token and any(name == token for name in names):
        return f"/{choice.name} "
    if len(matches) == 1:
        completed = f"/{choice.name}"
        if buffer == completed or buffer.startswith(completed + " "):
            return buffer if buffer.endswith(" ") else buffer + " "
        return completed + " "
    prefix = _common_name_prefix(matches)
    if len(prefix) > len(token):
        return "/" + prefix
    return f"/{choice.name} "


def _common_name_prefix(matches: list[SlashCompletion]) -> str:
    names = sorted({name for item in matches for name in _names(item)})
    if not names:
        return ""
    prefix = names[0]
    for name in names[1:]:
        while prefix and not name.startswith(prefix):
            prefix = prefix[:-1]
    return prefix


def suggestion_lines(matches: list[SlashCompletion], *, selected: int = 0, width: int = 100) -> list[str]:
    """Render the Claude-style suggestion list shown under the prompt."""
    if not matches:
        return []
    lines: list[str] = []
    for index, item in enumerate(matches[:MAX_SUGGESTIONS]):
        marker = "›" if index == selected else " "
        text = f"{marker} {item.template}"
        summary = item.summary
        room = max(12, width - len(text) - 3)
        if room >= 8:
            text = f"{text:<{width - room - 1}} {summary[: room - 1]}"
        lines.append(text)
    remaining = len(matches) - MAX_SUGGESTIONS
    if remaining > 0:
        lines.append(f"  … {remaining} more — keep typing to narrow")
    return lines
