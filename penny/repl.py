"""Interactive Penny shell.

Launching ``penny`` with no subcommand drops you into this session: type a
question to ask the assistant about the current findings, or a ``/command`` to
scan, report, and inspect. It reuses the same scanner/ask/report code paths as
the one-shot CLI, so behaviour (and the opt-in AI/OSV egress) is identical.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__, llm, ui
from .ask import answer_question
from .exports import write_exports
from .feed import Event, EventFeed
from .reporting import generate_report, load_findings
from .scanner import run_scan
from .sources import resolved_scan_source
from .store import FindingsStore, copy_report_to_findings_dir

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

HELP = """\
/scan <path> [--osv] [--ai] [--static-only] [--target <url>]   scan a repo or .git URL
/report [--export]                                            write report.md (+ html/csv)
/findings                                                     list the current findings
/show <F-001>                                                 show one finding in detail
/target <url|off>                                             set the dynamic-probe target
/ai <on|off>                                                  toggle AI answers/review
/clear                                                        clear the screen
/help                                                         show this help
/exit                                                         leave

Type anything else to ask the assistant about the loaded findings."""


class PrettyFeed(EventFeed):
    """Feed that renders scan progress as styled lines (skips per-finding spam)."""

    def __init__(self, printer: Callable[[str], None]) -> None:
        super().__init__(quiet=True)
        self._printer = printer

    def emit(self, channel: str, message: str) -> None:
        self.events.append(Event(channel=channel, message=message))
        if channel == "red":  # one event per finding — summarised in the table instead
            return
        self._printer(ui.channel_line(channel, message))


class Session:
    def __init__(self, out_dir: Path | str = Path("."), printer: Callable[[str], None] | None = None) -> None:
        self.out_dir = Path(out_dir)
        self.printer = printer or (lambda text="": print(text))
        self.payload: dict[str, Any] | None = None
        self.findings_path: Path | None = None
        self.target: str | None = None
        self.i_own_this = False
        self.use_ai = llm.available()
        self._autoload()

    # ---- output helpers ---------------------------------------------------
    def out(self, text: str = "") -> None:
        self.printer(text)

    def _warn(self, text: str) -> None:
        self.out(ui.style(text, "yellow"))

    def _error(self, text: str) -> None:
        self.out(ui.style(text, "red"))

    # ---- state ------------------------------------------------------------
    def _autoload(self) -> None:
        for candidate in (
            self.out_dir / ".penny" / "runs" / "latest" / "findings.json",
            self.out_dir / "findings.json",
        ):
            if candidate.exists():
                try:
                    self.payload = load_findings(candidate)
                    self.findings_path = candidate
                    return
                except (OSError, ValueError):
                    continue

    def _findings_list(self) -> list[dict[str, Any]]:
        return (self.payload or {}).get("findings", [])

    # ---- greeting / help --------------------------------------------------
    def greet(self) -> None:
        self.out(ui.banner())
        self.out()
        lines = [
            f"{ui.dim('version')} {__version__}    {ui.dim('cwd')} {os.getcwd()}",
            f"{ui.dim('AI')} " + (f"on · {llm.deep_model()}" if self.use_ai else "off (set ANTHROPIC_API_KEY)"),
        ]
        if self.payload:
            total = self.payload.get("summary", {}).get("total", 0)
            lines.append(f"{ui.dim('loaded')} {total} finding(s) from {self.findings_path}")
        else:
            lines.append(ui.dim("no findings yet — run /scan <path>"))
        lines.append("")
        lines.append(ui.dim("Ask a question, or type /help for commands."))
        self.out(ui.panel("\n".join(lines), title="Penny — purple-team assistant for AI-built apps", color="magenta"))
        self.out()

    def _help(self) -> None:
        self.out(ui.panel(HELP, title="Commands", color="cyan"))

    # ---- dispatch ---------------------------------------------------------
    def handle(self, line: str) -> bool:
        """Process one input line. Returns False to end the session."""
        line = line.strip()
        if not line:
            return True
        if line.startswith("/"):
            return self._command(line[1:])
        self._ask(line)
        return True

    def _command(self, rest: str) -> bool:
        parts = rest.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:]
        if cmd in ("exit", "quit", "q"):
            return False
        if cmd in ("help", "h", "?"):
            self._help()
        elif cmd == "clear":
            self.out("\x1b[2J\x1b[H")
        elif cmd == "scan":
            self._scan(args)
        elif cmd == "report":
            self._report(args)
        elif cmd in ("findings", "ls"):
            self._findings()
        elif cmd == "show":
            self._show(args)
        elif cmd == "ai":
            self._toggle_ai(args)
        elif cmd == "target":
            self._set_target(args)
        else:
            self._error(f"Unknown command: /{cmd}") if cmd else None
            self.out(ui.dim("Try /help."))
        return True

    # ---- commands ---------------------------------------------------------
    def _scan(self, args: list[str]) -> None:
        path: str | None = None
        use_osv = use_ai = static_only = False
        target = self.target
        tokens = iter(args)
        for token in tokens:
            if token == "--osv":
                use_osv = True
            elif token == "--ai":
                use_ai = True
            elif token == "--static-only":
                static_only = True
            elif token == "--target":
                target = next(tokens, None)
            elif not token.startswith("-") and path is None:
                path = token
        if not path:
            self._warn("Usage: /scan <path> [--osv] [--ai] [--static-only] [--target <url>]")
            return

        self.out(ui.dim(f"Scanning {path}…"))
        feed = PrettyFeed(self.printer)
        try:
            with resolved_scan_source(path) as resolved:
                result = run_scan(
                    resolved,
                    target=target,
                    static_only=static_only,
                    out_dir=self.out_dir,
                    i_own_this=self.i_own_this,
                    feed=feed,
                    source_label=path,
                    use_osv=use_osv,
                    use_ai=use_ai,
                )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            self._error(f"Scan failed: {error}")
            return
        self.payload = result.payload
        self.findings_path = result.findings_path
        self.out()
        self._summary()
        self._findings()

    def _summary(self) -> None:
        summary = (self.payload or {}).get("summary", {})
        by_sev = summary.get("by_severity", {})
        parts = [
            ui.severity_badge(sev).strip() + ui.dim(f" {by_sev[sev]}")
            for sev in ("Critical", "High", "Medium", "Low", "Info")
            if by_sev.get(sev)
        ]
        confirmed = summary.get("confirmed_count", 0)
        body = (
            f"{summary.get('total', 0)} finding(s)   " + "   ".join(parts)
            + (f"\n{ui.style(str(confirmed) + ' dynamically confirmed', 'bright_green')}" if confirmed else "")
        )
        self.out(ui.panel(body, title="Scan summary", color="green"))

    def _findings(self) -> None:
        findings = self._findings_list()
        if not findings:
            self._warn("No findings loaded. Run /scan <path> first.")
            return
        ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        rows = [
            [
                f["id"],
                ui.severity_badge(f["severity"]),
                f["detector_id"],
                f"{f['location']['file']}:{f['location']['line']}",
                f["title"][:48],
                f["status"],
            ]
            for f in ordered
        ]
        self.out(ui.table(["ID", "Severity", "Det", "Location", "Title", "Status"], rows))
        self.out(ui.dim("Use /show <id> for details, or ask a question."))

    def _show(self, args: list[str]) -> None:
        if not args:
            self._warn("Usage: /show <F-001>")
            return
        target_id = args[0].upper()
        finding = next((f for f in self._findings_list() if f["id"] == target_id), None)
        if not finding:
            self._warn(f"No finding {target_id} in the current scan.")
            return
        location = finding["location"]
        body = "\n".join(
            [
                f"{ui.severity_badge(finding['severity'])}  {finding['detector_id']}  {ui.dim(finding['status'])}",
                f"{ui.dim('where')}  {location['file']}:{location['line']}",
                f"{ui.dim('owasp')}  {', '.join(finding.get('owasp', [])) or '—'}",
                "",
                ui.dim("snippet"),
                finding.get("snippet", ""),
                "",
                f"{ui.style('Impact:', 'bold')} {finding['impact']}",
                f"{ui.style('Fix:', 'bold')} {finding['remediation']}",
            ]
        )
        self.out(ui.panel(body, title=f"{finding['id']} — {finding['title']}", color="magenta"))

    def _report(self, args: list[str]) -> None:
        if not self.findings_path or not self.payload:
            self._warn("No findings loaded. Run /scan <path> first.")
            return
        payload = self.payload
        report = generate_report(payload)
        store = FindingsStore(self.out_dir)
        report_path = store.write_report(payload.get("session_id", "manual-report"), report)
        copy_report_to_findings_dir(report_path, self.findings_path)
        self.out(ui.style(f"📄 report.md → {report_path}", "green"))
        if "--export" in args:
            paths = write_exports(payload, report, self.out_dir)
            self.out(ui.style(f"📄 report.html → {paths['html']}", "green"))
            self.out(ui.style(f"📊 findings.csv → {paths['csv']}", "green"))

    def _toggle_ai(self, args: list[str]) -> None:
        want = args[0].lower() if args else ("off" if self.use_ai else "on")
        if want == "on":
            if not llm.available():
                self._warn("AI unavailable — set ANTHROPIC_API_KEY (or add it to .env).")
                return
            self.use_ai = True
            self.out(ui.style(f"AI on · {llm.deep_model()}", "green"))
        else:
            self.use_ai = False
            self.out(ui.dim("AI off — answers are deterministic."))

    def _set_target(self, args: list[str]) -> None:
        if not args or args[0].lower() == "off":
            self.target = None
            self.out(ui.dim("Probe target cleared."))
            return
        self.target = args[0]
        self.out(ui.style(f"Probe target set: {self.target}", "green"))

    def _ask(self, question: str) -> None:
        if not self.findings_path:
            self._warn("No findings loaded yet. Run /scan <path> first.")
            return
        if self.use_ai:
            self.out(ui.dim("thinking…"))
        answer = answer_question(
            question,
            findings_path=self.findings_path,
            target=self.target,
            i_own_this=self.i_own_this,
            use_llm=self.use_ai,
        )
        self.out(ui.style("🤖 penny", "bold", "bright_blue"))
        self.out(ui.render_markdown(answer))
        self.out()


def run_repl(out_dir: Path | str = Path(".")) -> None:
    session = Session(out_dir=out_dir)
    session.greet()
    while True:
        try:
            line = input(ui.prompt())
        except EOFError:
            session.out()
            break
        except KeyboardInterrupt:
            session.out(ui.dim("\n(^C — type /exit to quit)"))
            continue
        if not session.handle(line):
            break
    session.out(ui.dim("bye 👋"))
