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


def _hard_chunk(line: str, width: int) -> list[str]:
    """Break a single line into <= width visible-column chunks, splitting even
    unbroken runs (e.g. long file paths with no spaces). ANSI codes are carried
    along as zero-width so colour survives the break."""
    if width <= 0:
        return [line]
    chunks: list[str] = []
    current = ""
    current_len = 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        if not part:
            continue
        if _ANSI_RE.fullmatch(part):
            current += part  # zero-width: never forces a break
            continue
        for char in part:
            if current_len >= width:
                chunks.append(current)
                current, current_len = "", 0
            current += char
            current_len += 1
    if current or not chunks:
        chunks.append(current)
    return chunks


def _wrap_cell(text: str, width: int) -> list[str]:
    """Wrap a table cell to ``width`` visible columns: word-wrap first, then
    hard-break any word still too long (paths, hashes). Returns >= 1 line."""
    if width <= 0 or visible_len(text) <= width:
        return [text]
    lines: list[str] = []
    for line in _wrap(text, width):
        lines.extend(_hard_chunk(line, width) if visible_len(line) > width else [line])
    return lines


def panel(body: str, *, title: str | None = None, subtitle: str | None = None, color: str = "cyan") -> str:
    raw = [line for line in body.split("\n") if line or not title]
    if subtitle:
        raw = [dim(subtitle)] + ([""] if raw else []) + raw
    width = max(24, min(max((visible_len(line) for line in raw), default=0), _term_width() - 4))
    lines: list[str] = []
    for line in raw:
        lines.extend(_wrap(line, width))
    inner = min(max((visible_len(line) for line in lines), default=0), width)
    if title:
        title_text = f" {title} "
        if visible_len(title_text) > inner:
            title_text = f" {title[: max(0, inner - 2)]} "
        top = style("╭─", color) + style(title_text, "bold", color) + style("─" * max(0, inner - visible_len(title_text)) + "╮", color)
    else:
        top = style("╭" + "─" * (inner + 2) + "╮", color)
    bottom = style("╰" + "─" * (inner + 2) + "╯", color)
    bar = style("│", color)
    rows = [top]
    for line in lines:
        rows.append(f"{bar} {_pad(line, inner)} {bar}")
    rows.append(bottom)
    return "\n".join(rows)


def tagline(text: str) -> str:
    return dim(text.center(max(visible_len(_LOGO.splitlines()[0]), visible_len(text))))


def kv(label: str, value: str) -> str:
    return f"{style(f'{label:<8}', 'bright_black')} {value}"


def command_chip(command: str) -> str:
    return style(command, "bold", "bright_cyan")


def status_on() -> str:
    return style("●", "bright_green") + dim(" on")


def status_off() -> str:
    return style("○", "bright_black") + dim(" off")


def field(label: str, value: str) -> str:
    return f"{style(label + ':', 'bold', 'bright_black')}  {value}"


def severity_strip(by_severity: dict[str, int]) -> str:
    parts = [
        f"{severity_badge(severity).strip()}{dim(f' {by_severity[severity]}')}"
        for severity in ("Critical", "High", "Medium", "Low", "Info")
        if by_severity.get(severity)
    ]
    return "   ".join(parts)


def rule(width: int | None = None) -> str:
    span = min((width or _term_width()) - 4, 72)
    return dim("─" * max(span, 12))


def table(
    headers: list[str],
    rows: list[list[str]],
    aligns: list[str] | None = None,
    *,
    max_width: int | None = None,
    min_widths: list[int] | None = None,
    gap: int = 2,
    column_divider: str | None = None,
    row_dividers: bool = False,
) -> str:
    cols = len(headers)
    aligns = aligns or ["left"] * cols
    min_widths = min_widths or [6] * cols
    widths = [visible_len(headers[i]) for i in range(cols)]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], visible_len(str(row[i])))

    # Keep the table inside the terminal. Without this the widest columns (file
    # paths, titles) run past the right edge and the terminal soft-wraps them
    # mid-cell, mangling every column. Instead, shave the widest column(s) down
    # until the row fits, then wrap the overflowing cells onto continuation lines.
    divider_width = visible_len(column_divider) if column_divider else 0
    budget = (max_width if max_width is not None else _term_width()) - gap
    available = budget - gap * (cols - 1) - (divider_width * (cols - 1) if column_divider else 0)
    min_col = min(min_widths) if min_widths else 6
    while sum(widths) > available and max(widths) > min_col:
        shrinkable = [i for i in range(cols) if widths[i] > min_widths[i]]
        if not shrinkable:
            break
        widest = max(shrinkable, key=lambda i: widths[i])
        widths[widest] -= 1

    def render_row(cells: list[str]) -> list[str]:
        wrapped = [_wrap_cell(str(cells[i]), widths[i]) for i in range(cols)]
        height = max((len(cell) for cell in wrapped), default=1)
        lines = []
        for line_index in range(height):
            pieces = [
                _pad(wrapped[i][line_index] if line_index < len(wrapped[i]) else "", widths[i], aligns[i])
                for i in range(cols)
            ]
            if column_divider:
                joiner = (" " * gap) + column_divider + (" " * gap)
            else:
                joiner = " " * gap
            lines.append(joiner.join(pieces))
        return lines

    if column_divider:
        divider_joiner = (" " * gap) + style(column_divider, "bright_black") + (" " * gap)
        rule_cells = [style("─" * widths[i], "bright_black") for i in range(cols)]
        header_rule = divider_joiner.join(rule_cells)
    else:
        header_rule = dim((" " * gap).join("─" * widths[i] for i in range(cols)))

    out = render_row([style(headers[i], "bold") for i in range(cols)])
    out.append(header_rule)
    for index, row in enumerate(rows):
        out.extend(render_row(list(row)))
        if row_dividers and index != len(rows) - 1:
            out.append(header_rule)
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
    return style("◆ ", "bright_magenta") + style("penny", "bold", "cyan") + style(" › ", "dim")


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
