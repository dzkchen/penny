"""Interactive REPL input with slash-command autocomplete.

Uses ``prompt_toolkit`` for reliable in-place completion menus and Tab
autocomplete across Windows/macOS/Linux terminals (including VS Code/Cursor).
Falls back to plain ``input()`` when stdin is not a TTY, autocomplete is
disabled, or ``prompt_toolkit`` is unavailable.
"""

from __future__ import annotations

import os
import sys

from . import completions as slash

os.environ.setdefault("PROMPT_TOOLKIT_NO_CPR", "1")

_PROMPT_STYLE = None
_SESSION = None
_WARNED = False

try:
    from prompt_toolkit.completion import Completer as _CompleterBase
    from prompt_toolkit.completion import Completion
except ImportError:
    _CompleterBase = None  # type: ignore[misc, assignment]
    Completion = None  # type: ignore[misc, assignment]


def autocomplete_enabled() -> bool:
    if os.environ.get("PENNY_NO_AUTOCOMPLETE"):
        return False
    if _CompleterBase is None:
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _plain_prompt() -> str:
    return "penny > "


def _completion_parts(buffer: str, item: slash.SlashCompletion) -> tuple[str, int] | None:
    template = item.template
    command = f"/{item.name}"

    if template.startswith(buffer):
        return template[len(buffer) :], 0
    if command.startswith(buffer):
        return command[len(buffer) :] + (" " if len(command) > len(buffer) else ""), 0

    token = buffer[1:].split()[0] if len(buffer) > 1 else ""
    if not token:
        return template[1:], 0

    names = slash._names(item)
    if any(name.startswith(token) for name in names):
        return command[1:] + " ", -len(token)
    return None


if _CompleterBase is not None:

    class SlashCommandCompleter(_CompleterBase):
        def get_completions(self, document, complete_event):  # noqa: ANN001
            buffer = document.text_before_cursor
            if not buffer.startswith("/"):
                return
            for item in slash.completions_for_buffer(buffer):
                parts = _completion_parts(buffer, item)
                if parts is None or Completion is None:
                    continue
                insert, start_position = parts
                yield Completion(
                    insert,
                    start_position=start_position,
                    display=item.template,
                    display_meta=item.summary,
                )

else:

    class SlashCommandCompleter:  # pragma: no cover - no prompt_toolkit installed
        pass


def _make_completer() -> SlashCommandCompleter:
    return SlashCommandCompleter()


def _prompt_style():
    global _PROMPT_STYLE
    if _PROMPT_STYLE is not None:
        return _PROMPT_STYLE
    from prompt_toolkit.styles import Style

    _PROMPT_STYLE = Style.from_dict(
        {
            "prompt": "bold ansicyan",
            "completion-menu.border": "ansibrightblack",
            "completion-menu": "bg:ansiblack ansigray",
            "completion-menu.completion": "ansiwhite",
            "completion-menu.completion.current": "bold ansibrightcyan",
            "completion-menu.meta.completion": "ansigray italic",
            "completion-menu.meta.completion.current": "italic ansigray",
            "": "",
        }
    )
    return _PROMPT_STYLE


def _prompt_session():
    global _SESSION
    if _SESSION is not None:
        return _SESSION
    from prompt_toolkit import PromptSession
    from prompt_toolkit.shortcuts import CompleteStyle

    _SESSION = PromptSession(
        completer=_make_completer(),
        complete_while_typing=True,
        complete_style=CompleteStyle.COLUMN,
        reserve_space_for_menu=8,
        style=_prompt_style(),
    )
    return _SESSION


def _warn_fallback(reason: str) -> None:
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    print(f"[penny] autocomplete disabled: {reason}", file=sys.stderr)


def read_line(prompt: str) -> str:
    del prompt  # prompt_toolkit uses a fixed styled prompt
    if not autocomplete_enabled():
        return input(_plain_prompt())
    try:
        return _prompt_session().prompt("penny > ", refresh_interval=0.15)
    except EOFError:
        raise
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        _warn_fallback(str(exc))
        return input(_plain_prompt())


def clear_screen() -> None:
    """Clear the terminal and home the cursor.

    ``run_repl`` runs the loop inside ``prompt_toolkit``'s ``patch_stdout``,
    whose proxy renders screen-control escapes literally — so a plain
    ``print("\\x1b[2J")`` shows up as ``?[2J`` instead of clearing. Write
    through the *real* stdout (bypassing the proxy), preferring
    ``prompt_toolkit``'s output for cross-platform handling and falling back
    to raw ANSI.
    """
    real = sys.__stdout__ or sys.stdout
    if _CompleterBase is not None:
        try:
            from prompt_toolkit.output import create_output

            output = create_output(stdout=real)
            output.erase_screen()
            output.cursor_goto(0, 0)
            output.flush()
            return
        except Exception:
            pass
    try:
        real.write("\x1b[2J\x1b[H")
        real.flush()
    except Exception:
        pass
