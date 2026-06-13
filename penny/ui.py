"""Dependency-free terminal styling for Penny's interactive UI.

Penny only requires the standard library, so this module renders colour, boxed
panels, and aligned tables with raw ANSI + Unicode. Colour auto-disables when
output is not a TTY (or ``NO_COLOR`` is set), so piped/captured output stays
plain and test-friendly. Markdown is rendered through ``rich`` when it happens
to be installed, otherwise the raw (already readable) text is returned.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_RESET = "\x1b[0m"
_CODES = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "bright_black": "90",
    "bright_red": "91",
    "bright_green": "92",
    "bright_yellow": "93",
    "bright_blue": "94",
    "bright_magenta": "95",
    "bright_cyan": "96",
}

SEVERITY_STYLE = {
    "Critical": ("bright_red", "bold"),
    "High": ("red",),
    "Medium": ("yellow",),
    "Low": ("blue",),
    "Info": ("bright_black",),
}

CHANNEL_STYLE = {
    "scan": ("🔍", "cyan"),
    "mongo": ("🍃", "green"),
    "osv": ("📦", "bright_magenta"),
    "ai": ("🤖", "bright_blue"),
    "attack": ("💥", "bright_red"),
    "red": ("›", "bright_red"),
    "gate": ("⛔", "bright_yellow"),
    "store": ("💾", "bright_black"),
    "blue": ("🛠", "bright_green"),
    "purple": ("◆", "bright_magenta"),
    "report": ("📄", "bright_cyan"),
    "error": ("✖", "bright_red"),
}


def color_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("PENNY_FORCE_COLOR"):
        return True
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def style(text: str, *names: str) -> str:
    if not names or not color_enabled():
        return text
    codes = ";".join(_CODES[name] for name in names if name in _CODES)
    return f"\x1b[{codes}m{text}{_RESET}" if codes else text


def dim(text: str) -> str:
    return style(text, "dim")


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - visible_len(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def severity_badge(severity: str) -> str:
    return style(f"{severity:<8}", *SEVERITY_STYLE.get(severity, ("white",)))


def _term_width(default: int = 100) -> int:
    return shutil.get_terminal_size((default, 24)).columns


def _wrap(line: str, width: int) -> list[str]:
    """Word-wrap to ``width`` visible columns, leaving ANSI codes intact."""
    if visible_len(line) <= width:
        return [line]
    wrapped: list[str] = []
    current = ""
    current_len = 0
    for word in line.split(" "):
        word_len = visible_len(word)
        if current and current_len + 1 + word_len > width:
            wrapped.append(current)
            current, current_len = word, word_len
        elif current:
            current += " " + word
            current_len += 1 + word_len
        else:
            current, current_len = word, word_len
    if current or not wrapped:
        wrapped.append(current)
    return wrapped


def panel(body: str, *, title: str | None = None, color: str = "cyan") -> str:
    raw = body.split("\n")
    if title:
        raw = [style(title, "bold")] + ([""] if body else []) + raw
    width = max(24, min(max((visible_len(line) for line in raw), default=0), _term_width() - 4))
    lines: list[str] = []
    for line in raw:
        lines.extend(_wrap(line, width))
    inner = min(max((visible_len(line) for line in lines), default=0), width)
    top = style("╭" + "─" * (inner + 2) + "╮", color)
    bottom = style("╰" + "─" * (inner + 2) + "╯", color)
    bar = style("│", color)
    rows = [top]
    for line in lines:
        rows.append(f"{bar} {_pad(line, inner)} {bar}")
    rows.append(bottom)
    return "\n".join(rows)


def table(headers: list[str], rows: list[list[str]], aligns: list[str] | None = None) -> str:
    cols = len(headers)
    aligns = aligns or ["left"] * cols
    widths = [visible_len(headers[i]) for i in range(cols)]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], visible_len(str(row[i])))
    out = ["  ".join(_pad(style(headers[i], "bold"), widths[i], aligns[i]) for i in range(cols))]
    out.append(dim("  ".join("─" * widths[i] for i in range(cols))))
    for row in rows:
        out.append("  ".join(_pad(str(row[i]), widths[i], aligns[i]) for i in range(cols)))
    return "\n".join(out)


_LOGO = r"""
 ____
|  _ \ ___ _ __  _ __  _   _
| |_) / _ \ '_ \| '_ \| | | |
|  __/  __/ | | | | | | |_| |
|_|   \___|_| |_|_| |_|\__, |
                       |___/
""".strip("\n")


def banner() -> str:
    return style(_LOGO, "bright_magenta", "bold")


def prompt() -> str:
    return style("penny", "bold", "cyan") + style(" › ", "dim")


def channel_line(channel: str, message: str) -> str:
    icon, color = CHANNEL_STYLE.get(channel, ("•", "white"))
    return f"  {icon} {style(message, color)}"


def render_markdown(text: str) -> str:
    try:
        import io

        from rich.console import Console
        from rich.markdown import Markdown

        buffer = io.StringIO()
        Console(file=buffer, force_terminal=color_enabled(), width=_term_width()).print(Markdown(text))
        return buffer.getvalue().rstrip("\n")
    except Exception:
        return text
