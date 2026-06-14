"""Live, Claude-Code-style scan UI: a spinner, collapsing finding groups, and a
ctrl-O toggle to expand into detailed finding rows.

The one-shot CLI previously printed one line per finding (``D012 hit in …`` ×15,
then ``D020 hit in …`` …), which buried the signal. :class:`LiveScanFeed` is an
:class:`~penny.feed.EventFeed` that, on an interactive terminal, renders a single
animated panel: a spinner + current activity, the last few status lines, and a
collapsed ``● D012  15 hits`` tally per detector. Press **ctrl-O** to expand the
tally into full finding rows (and again to collapse). When stdout is not a TTY
(CI, pipes) it degrades to plain line output with the per-finding spam suppressed
— the full list still prints in the final summary.

After the live phase, :func:`print_scan_summary` renders the durable summary:
a severity rollup, a per-detector table, and the full findings table (the
always-available "expanded" view). ``--verbose`` additionally prints every
``file:line`` grouped by detector.
"""

from __future__ import annotations

import re
import sys
import threading
from pathlib import Path
from typing import Any

from . import ui
from .feed import Event, EventFeed
from .models import SEVERITY_ORDER

# Per-finding lines look like "D012 hit in src/foo.ts:170" — collapse these.
_HIT_RE = re.compile(r"^(\w+) hit in (.+)$")
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_CTRL_O = "\x0f"

# Detector-family colours for the live tally (rich-compatible names).
_FAMILY_COLOR = {"AI": "bright_blue", "A": "bright_red", "D": "cyan", "N": "magenta"}


def _family_color(detector: str) -> str:
    family = "AI" if detector.startswith("AI") else (detector[:1] or "")
    return _FAMILY_COLOR.get(family, "white")


def _indent(block: str, spaces: int = 2) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in block.split("\n"))


class LiveScanFeed(EventFeed):
    """EventFeed that renders an animated, collapsing live panel on a TTY."""

    def __init__(self) -> None:
        super().__init__(quiet=True)
        self._lock = threading.Lock()
        self._dets: dict[str, list[str]] = {}
        self._finding_rows: dict[str, dict[str, str]] = {}
        self._log: list[tuple[str, str]] = []
        self._activity = "initializing"
        self._expanded = False
        self._tick = 0
        self._interactive = False
        self._ctrlo = False
        self._live = None
        self._stop = threading.Event()
        self._restore = None
        self._key_thread: threading.Thread | None = None

    # ---- event intake -----------------------------------------------------
    def emit(self, channel: str, message: str) -> None:
        self.events.append(Event(channel=channel, message=message))
        if channel == "scan" and message.startswith("Walking "):
            return
        hit = _HIT_RE.match(message) if channel == "red" else None
        with self._lock:
            if hit:
                self._dets.setdefault(hit.group(1), []).append(hit.group(2))
            else:
                if channel != "red":
                    self._activity = message
                self._log.append((channel, message))
                if len(self._log) > 7:
                    self._log = self._log[-7:]
        # Plain mode (non-interactive, or before/after the live panel): print
        # everything except the collapsed per-finding hits.
        if self._live is None and hit is None:
            try:
                print(ui.channel_line(channel, message))
            except Exception:  # noqa: BLE001 - never let rendering crash a scan
                print(f"[{channel}] {message}")

    def record_finding(self, finding: dict[str, Any]) -> None:
        fingerprint = str(finding.get("fingerprint", "")).strip()
        if not fingerprint:
            fingerprint = "|".join(
                [
                    str(finding.get("detector_id", "")),
                    str(finding.get("location", "")),
                    str(finding.get("title", "")),
                ]
            )
        row = {
            "id": str(finding.get("id", "")).strip() or "…",
            "severity": str(finding.get("severity", "")).strip() or "Info",
            "detector_id": str(finding.get("detector_id", "")).strip() or "?",
            "location": str(finding.get("location", "")).strip(),
            "title": str(finding.get("title", "")).strip(),
        }
        with self._lock:
            current = self._finding_rows.get(fingerprint, {})
            current.update(row)
            self._finding_rows[fingerprint] = current

    # ---- live rendering ---------------------------------------------------
    def __rich__(self):  # noqa: D401 - rich protocol
        from rich.console import Group
        from rich.panel import Panel
        from rich.text import Text

        with self._lock:
            self._tick += 1
            frame = _SPINNER_FRAMES[self._tick % len(_SPINNER_FRAMES)]
            activity = self._activity
            log = list(self._log[-6:])
            dets = {key: list(value) for key, value in self._dets.items()}
            finding_rows = sorted(
                self._finding_rows.values(),
                key=lambda row: (
                    SEVERITY_ORDER.get(row.get("severity", ""), 9),
                    row.get("detector_id", ""),
                    row.get("location", ""),
                    row.get("id", ""),
                ),
            )
            expanded = self._expanded

        header = Text()
        header.append("penny ", style="bold magenta")
        header.append("─" * max(8, ui._term_width() - 8), style="magenta")
        lines = []
        activity_row = Text()
        activity_row.append(f"{frame} ", style="bold cyan")
        activity_row.append(activity, style="white")
        lines.append(activity_row)

        for channel, message in log:
            icon, color = ui.CHANNEL_STYLE.get(channel, ("•", "white"))
            row = Text(f"  {icon} ", style=color)
            row.append(message, style=color)
            lines.append(row)

        if dets:
            total = sum(len(v) for v in dets.values())
            lines.append(Text(""))
            lines.append(Text(f"  findings {total}", style="bold white"))
            if expanded and finding_rows:
                table = ui.table(
                    ["ID", "Severity", "Detector", "Location", "Title"],
                    [
                        [
                            row["id"],
                            ui.severity_badge(row["severity"]),
                            row["detector_id"],
                            row["location"],
                            row["title"],
                        ]
                        for row in finding_rows
                    ],
                    min_widths=[5, 8, 8, 22, 26],
                    gap=2,
                    column_divider="│",
                    row_dividers=True,
                    max_width=max(68, ui._term_width() - 12),
                )
                for line in table.splitlines():
                    lines.append(Text.from_ansi(f"  {line}"))
            else:
                for detector in sorted(dets):
                    locations = dets[detector]
                    row = Text(f"    ● {detector}", style=f"bold {_family_color(detector)}")
                    row.append(f"   {len(locations)} hit(s)", style="dim")
                    lines.append(row)

        if self._ctrlo:
            hint = "ctrl-o collapse" if expanded else "ctrl-o expand"
            lines.append(Text(""))
            lines.append(Text(f"  {hint}  ·  ctrl-c cancel", style="dim italic"))

        return Group(
            header,
            Panel(Group(*lines), border_style="magenta", padding=(0, 1)),
        )

    # ---- ctrl-O key handling (Unix TTY, best-effort) ----------------------
    def _start_keys(self) -> None:
        if not sys.stdin.isatty():
            return
        try:
            import select
            import termios
            import tty
        except ImportError:
            return
        try:
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
        except Exception:  # noqa: BLE001
            return
        # Register the restore BEFORE touching the terminal: if setcbreak or the
        # echo-disable below half-applies and then raises, __exit__ must still put
        # the terminal back — otherwise a failed setup leaves the shell in cbreak
        # with echo off (keystrokes vanish, the terminal looks "broken").
        self._restore = lambda: termios.tcsetattr(fd, termios.TCSADRAIN, old)
        try:
            tty.setcbreak(fd)
            # cbreak leaves ECHO, IEXTEN, and IXON enabled — each breaks a ctrl-o
            # hotkey in its own way:
            #   * ECHO would print "^O" over the live panel.
            #   * IEXTEN makes the line discipline treat ctrl-o as VDISCARD
            #     ("discard terminal output", default ^O on macOS/Linux): it
            #     swallows the keystroke *and* freezes the screen until toggled
            #     again — so the hotkey both does nothing and looks like a hang.
            #   * IXON lets a stray ctrl-s flow-control the tty into a freeze too.
            # Clear all three so ctrl-o reaches our reader and output never stalls.
            attrs = termios.tcgetattr(fd)
            attrs[0] &= ~termios.IXON  # c_iflag
            attrs[3] &= ~(termios.ECHO | termios.IEXTEN)  # c_lflag
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:  # noqa: BLE001
            return
        self._ctrlo = True

        def loop() -> None:
            try:
                while not self._stop.is_set():
                    ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if ready:
                        char = sys.stdin.read(1)
                        if char == _CTRL_O:
                            with self._lock:
                                self._expanded = not self._expanded
            except Exception:  # noqa: BLE001 - a flaky stdin must never crash the scan
                pass

        self._key_thread = threading.Thread(target=loop, daemon=True)
        self._key_thread.start()

    # ---- context manager --------------------------------------------------
    def __enter__(self) -> "LiveScanFeed":
        self._interactive = ui.color_enabled() and sys.stdout.isatty()
        if not self._interactive:
            return self
        try:
            from rich.console import Console
            from rich.live import Live

            self._live = Live(self, console=Console(), refresh_per_second=12, transient=True)
            self._live.__enter__()
            self._start_keys()
        except Exception:  # noqa: BLE001 - fall back to plain mode on any rich/term failure
            self._live = None
        return self

    def __exit__(self, *exc_info) -> bool:
        self._stop.set()
        if self._restore is not None:
            try:
                self._restore()
            except Exception:  # noqa: BLE001
                pass
            self._restore = None
        if self._live is not None:
            try:
                self._live.__exit__(*exc_info)
            except Exception:  # noqa: BLE001
                pass
            self._live = None
        return False


def _findings_table(findings: list[dict]) -> str:
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["detector_id"], f["location"]["file"]),
    )
    rows = [
        [
            finding["id"],
            ui.severity_badge(finding["severity"]),
            f"{finding['location']['file']}:{finding['location']['line']}",
            finding["title"],
        ]
        for finding in ordered
    ]
    return ui.table(
        ["ID", "Severity", "Location", "Title"],
        rows,
        min_widths=[5, 8, 28, 36],
        gap=4,
    )


def _detector_rollup(findings: list[dict]) -> str:
    by_detector: dict[str, list[dict]] = {}
    for finding in findings:
        by_detector.setdefault(finding["detector_id"], []).append(finding)
    rows = []
    for detector in sorted(by_detector, key=lambda d: (min(SEVERITY_ORDER.get(f["severity"], 9) for f in by_detector[d]), d)):
        group = by_detector[detector]
        worst = min(group, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))["severity"]
        rows.append([detector, str(len(group)), ui.severity_badge(worst), group[0]["title"]])
    return ui.table(
        ["Detector", "Hits", "Worst", "What"],
        rows,
        aligns=["left", "right", "left", "left"],
        min_widths=[8, 4, 8, 34],
        gap=4,
    )


def render_scan_summary(payload: dict, out_dir: Path, *, verbose: bool = False) -> str:
    """Build the durable post-scan summary (rollup + tables)."""
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    by_severity = summary.get("by_severity", {})
    total = summary.get("total", len(findings))

    if not total:
        return ui.style("  ✓ No findings — clean scan.", "bright_green", "bold")

    parts = []
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        count = by_severity.get(severity, 0)
        if count:
            # Single-width "●" (not an emoji) so the dependency-free panel border
            # stays aligned — wide emoji throw off the column math.
            parts.append(ui.style(f"● {count} {severity}", *ui.SEVERITY_STYLE.get(severity, ("white",))))
    confirmed = summary.get("confirmed_count", 0)
    rollup = f"{ui.style(str(total), 'bold')} finding(s)    " + "    ".join(parts)
    if confirmed:
        rollup += "\n" + ui.style(f"✓ {confirmed} dynamically confirmed", "bright_green", "bold")
    # Box only the short rollup; print the wide tables unboxed so they self-align
    # (wrapping a table inside the dependency-free panel ruins the border).
    blocks = [
        ui.panel(rollup, title="Scan complete", color="magenta"),
        _indent(_detector_rollup(findings)),
        _indent(_findings_table(findings)),
    ]

    if verbose:
        detail_lines = [ui.style("  Expanded detail (every hit):", "bold")]
        by_detector: dict[str, list[dict]] = {}
        for finding in findings:
            by_detector.setdefault(finding["detector_id"], []).append(finding)
        for detector in sorted(by_detector):
            detail_lines.append(ui.style(f"  ● {detector}", "bold", _family_color(detector)))
            for finding in by_detector[detector]:
                loc = finding["location"]
                detail_lines.append(ui.dim(f"      {loc['file']}:{loc['line']}"))
        blocks.append("\n".join(detail_lines))
    return "\n\n".join(blocks)


def print_scan_summary(payload: dict, out_dir: Path, *, verbose: bool = False) -> None:
    """Render the durable post-scan summary (rollup + tables) to stdout."""
    print()
    print(render_scan_summary(payload, out_dir, verbose=verbose))
