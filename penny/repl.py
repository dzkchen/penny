"""Interactive Penny shell.

Launching ``penny`` with no subcommand drops you into this session: type a
question to ask the assistant about the current findings, or a ``/command`` to
scan, report, and inspect. It reuses the same scanner/ask/report code paths as
the one-shot CLI, so behaviour (and the opt-in AI/OSV egress) is identical.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from . import __version__, llm, ui
from .ask import answer_question
from .feed import Event, EventFeed
from .live import LiveScanFeed, print_scan_summary, render_scan_summary
from .reporting import generate_report, load_findings
from .scanner import run_scan
from .sources import resolved_scan_source
from .repl_input import autocomplete_enabled, clear_screen, read_line
from .store import FindingsStore, copy_report_to_findings_dir

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

HELP = """\
/audit <path> [--target <url>]    FULL audit: scan + AI + all probes + report
/full  <path> [--target <url>]    alias for /audit
/scan  <path> [--osv] [--ai] [--active] [--agentic] [--brute] [--browser] [--netscan] [--load-test] [--i-accept] [--static-only] [--target <url>]
/report                           write report.md to .penny/runs/
/fix [--agent codex|claude-code]  set up the remediation MCP server
/findings                         list the current findings
/show <F-001>                     show one finding in detail
/target <url|off>                 set the live target to attack/probe
/ai <on|off>                      toggle AI answers/review
/model <auto|haiku|sonnet>        pick the Claude model (auto = Haiku chat + Sonnet work)
/cloud-attack <type> [target]     heavy tier on a Vultr box (e.g. load) — auto-destroys
/sandbox-bake                     one-time: build the heretic/gemma-3 GPU snapshot (~$0.70)
/sandbox-test [target] [--workers N] [--timing N] [--focus <text>]   ephemeral GPU box runs heretic/gemma-3 active breach (steer with --focus; parallel with --workers; --timing N = run the model N minutes), then self-destructs
/boxes                            list active cloud boxes + auto-destroy timers
/kill                             stop running cloud attacks (keep boxes)
/destroy                          destroy all cloud boxes now
/clear   /help   /exit

scan/audit flags:  --target <url>  --active  --brute  --browser  --agentic
                   --netscan  --load-test  --i-accept  --osv  --ai  --static-only
  --load-test   bounded ramp-to-failure capacity test (owned targets; read-only, abortable)
  --i-accept    safe write-path probe — POST-only marked test records (owned targets; no PUT/PATCH/DELETE)

Natural language works too: "pentest this app", "audit ./planted-app", "fix the issues",
or just ask a question. For a live site you own:  /target <url>   /audit ."""

STARTER_EXAMPLE = """\
1. Set a target (optional)     {target}
2. Run a scan or full audit   {audit}
3. Review, ask, and hand off  {review}

Example
"Run a full audit on ./file_path --target https://your-app.example --active --osv --ai"

Type {slash} for autocomplete · {help} for every command · {exit} to leave"""


def _quick_start_text() -> str:
    return STARTER_EXAMPLE.format(
        target=ui.command_chip("/target <url>"),
        audit=ui.command_chip("/audit <path>"),
        review=f"{ui.command_chip('/findings')}  {ui.command_chip('/report')}  {ui.command_chip('/fix')}",
        slash=ui.command_chip("/"),
        help=ui.command_chip("/help"),
        exit=ui.command_chip("/exit"),
    )


class PrettyFeed(EventFeed):
    """Feed that renders scan progress as styled lines (skips per-finding spam)."""

    def __init__(self, printer: Callable[[str], None]) -> None:
        super().__init__(quiet=True)
        self._printer = printer

    def emit(self, channel: str, message: str) -> None:
        self.events.append(Event(channel=channel, message=message))
        if channel == "scan" and message.startswith("Walking "):
            return
        if channel == "red":  # one event per finding — summarised in the table instead
            return
        self._printer(ui.channel_line(channel, message))


class Session:
    def __init__(self, out_dir: Path | str = Path("."), printer: Callable[[str], None] | None = None) -> None:
        self.out_dir = Path(out_dir)
        self.printer = printer or (lambda text="": print(text))
        self._interactive_shell = printer is None
        self.payload: dict[str, Any] | None = None
        self.findings_path: Path | None = None
        self.target: str | None = None
        llm._load_dotenv()
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

    def _make_scan_feed(self) -> tuple[EventFeed, bool]:
        if self._interactive_shell:
            return LiveScanFeed(), True
        return PrettyFeed(self.printer), False

    # ---- greeting / help --------------------------------------------------
    def greet(self) -> None:
        self.out(ui.banner())
        self.out(ui.tagline("purple-team assistant for AI-built apps"))
        self.out()

        status_lines = [
            ui.kv("version", __version__),
            ui.kv("cwd", os.getcwd()),
            ui.kv(
                "AI",
                (ui.status_on() + ui.dim(f"  {llm.deep_model()}") if self.use_ai else ui.status_off() + ui.dim("  set ANTHROPIC_API_KEY")),
            ),
        ]
        if self.payload:
            total = self.payload.get("summary", {}).get("total", 0)
            status_lines.append(ui.kv("session", ui.style(f"{total} finding(s) ready", "bright_green")))
        if self.target:
            status_lines.append(ui.kv("target", self.target))

        self.out(ui.panel("\n".join(status_lines), title="Session", color="magenta"))
        self.out()
        self.out(ui.panel(_quick_start_text(), title="How To Use", color="cyan"))
        self.out(ui.dim("Natural language works too — just ask a question or say \"audit ./app\""))
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
        # Natural-language routing: let users say "pentest this app" / "audit ./x".
        if self._route_intent(line):
            return True
        self._ask(line)
        return True

    def _route_intent(self, line: str) -> bool:
        """Map plain-English requests to actions. Returns True if it handled the line.

        Lets the user drive everything in natural language so slash-commands are optional.
        Order matters: more specific intents are checked before broad ones.
        """
        low = line.lower()
        path = self._extract_path(line)
        url = self._extract_url(line)
        finding_id = self._extract_finding_id(line)

        # --- model selection ---
        if "model" in low:
            for mode in ("auto", "haiku", "sonnet"):
                if mode in low:
                    self._set_model([mode])
                    return True
            self._set_model([])
            return True

        # --- set target from a sentence ---
        if url and ("target" in low or "set" in low or "use" in low) and not any(w in low for w in ("audit", "pentest", "scan", "attack", "test")):
            self._set_target([url])
            return True

        # --- show a specific finding ---
        if finding_id and ("show" in low or "explain" in low or "what is" in low or "detail" in low or "tell me about" in low):
            self._show([finding_id])
            return True

        # --- list findings ---
        if any(w in low for w in ("list findings", "show findings", "what did you find", "what's wrong", "whats wrong", "show me the findings", "findings")):
            self._findings()
            return True

        # Questions (start with a question word or end with '?') are NEVER actions —
        # they go to ask-mode so "what should blue fix first?" stays a question.
        is_question = low.strip().endswith("?") or low.split()[:1] and low.split()[0] in (
            "what", "why", "how", "is", "are", "should", "can", "does", "do", "which", "who", "when", "where",
        )

        # --- fix (imperative only) ---
        if not is_question and ("fix the" in low or "fix it" in low or "fix them" in low or low.strip() in ("fix", "apply fixes", "fix everything")):
            self._fix([])
            return True

        # --- report / export ---
        if not is_question and ("report" in low or "export" in low):
            self._report(["--export"] if "export" in low else [])
            return True

        # --- knowledge base / RAG lookup ---
        if not is_question and ("knowledge base" in low or "similar findings" in low):
            self._knowledge([line])
            return True

        # --- full audit (broad, imperative only) ---
        flags = self._extract_flags(line) if hasattr(self, "_extract_flags") else []
        audit_words = ("pentest", "pen test", "audit", "full scan", "run everything", "test this", "attack", "hack")
        if not is_question and any(word in low for word in audit_words):
            if url:
                self._set_target([url])
            self._audit(([path] if path else []) + flags)
            return True

        # --- plain scan ---
        if not is_question and ("scan" in low or "check" in low) and (path or url):
            if url:
                self._set_target([url])
            self._scan(([path] if path else []) + flags)
            return True

        # bare keywords
        if low.strip() in ("full", "audit"):
            self._audit([])
            return True
        return False

    def _extract_url(self, line: str) -> str | None:
        for token in line.split():
            if token.startswith("http://") or token.startswith("https://"):
                return token.rstrip(".,;")
        return None

    def _extract_finding_id(self, line: str) -> str | None:
        import re

        match = re.search(r"\b([FA]-?\d{1,3}|F\d{3})\b", line, re.I)
        if not match:
            return None
        token = match.group(0).upper().replace(" ", "")
        if "-" not in token and len(token) >= 2:
            token = token[0] + "-" + token[1:]
        return token

    def _extract_path(self, line: str) -> str | None:
        """Pull a local path or repo URL token out of a sentence."""
        for token in line.split():
            if token.startswith("./") or token.startswith("/") or token.endswith(".git") or "github.com" in token or "/" in token and not token.startswith("--"):
                return token
        return None

    def _extract_flags(self, line: str) -> list[str]:
        """Pull explicit ``--flags`` (and the value following ``--target``) out of a
        sentence so natural-language audits honour them the same as /commands."""
        tokens = line.split()
        flags: list[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.startswith("--"):
                flags.append(token)
                if token == "--target" and index + 1 < len(tokens):
                    flags.append(tokens[index + 1])
                    index += 1
            index += 1
        return flags

    def _command(self, rest: str) -> bool:
        parts = rest.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:]
        if cmd in ("exit", "quit", "q"):
            return False
        if cmd in ("help", "h", "?"):
            self._help()
        elif cmd == "clear":
            clear_screen()
        elif cmd in ("audit", "full"):
            self._audit(args)
        elif cmd == "scan":
            self._scan(args)
        elif cmd == "fix":
            self._fix(args)
        elif cmd == "report":
            self._report(args)
        elif cmd == "knowledge":
            self._knowledge(args)
        elif cmd in ("findings", "ls"):
            self._findings()
        elif cmd == "show":
            self._show(args)
        elif cmd == "ai":
            self._toggle_ai(args)
        elif cmd == "model":
            self._set_model(args)
        elif cmd == "target":
            self._set_target(args)
        elif cmd in ("cloud", "cloud-attack"):
            self._cloud_attack(args)
        elif cmd == "sandbox-bake":
            self._sandbox_bake(args)
        elif cmd == "sandbox-test":
            self._sandbox_test(args)
        elif cmd in ("boxes", "attack-status"):
            self._cloud_status()
        elif cmd == "kill":
            self._cloud_kill()
        elif cmd == "destroy":
            self._cloud_destroy()
        else:
            self._error(f"Unknown command: /{cmd}") if cmd else None
            self.out(ui.dim("Try /help."))
        return True

    # ---- commands ---------------------------------------------------------
    def _scan(self, args: list[str], *, force: dict[str, bool] | None = None) -> None:
        path: str | None = None
        use_osv = use_ai = use_active = static_only = False
        agentic = brute = browser = netscan = load_test = i_accept = False
        target = self.target
        tokens = iter(args)
        for token in tokens:
            if token == "--osv":
                use_osv = True
            elif token == "--ai":
                use_ai = True
            elif token == "--active":
                use_active = True
            elif token == "--agentic":
                agentic = True
            elif token == "--brute":
                brute = True
            elif token == "--browser":
                browser = True
            elif token == "--netscan":
                netscan = True
            elif token == "--load-test":
                load_test = True
            elif token == "--i-accept":
                i_accept = True
            elif token == "--static-only":
                static_only = True
            elif token == "--target":
                target = next(tokens, None)
            elif not token.startswith("-") and path is None:
                path = token
        if force:
            use_osv = force.get("osv", use_osv)
            use_ai = force.get("ai", use_ai)
            use_active = force.get("active", use_active)
            agentic = force.get("agentic", agentic)
            brute = force.get("brute", brute)
            browser = force.get("browser", browser)
            netscan = force.get("netscan", netscan)
            load_test = force.get("load_test", load_test)
            i_accept = force.get("i_accept", i_accept)
        if not path:
            self._warn("Usage: /scan <path> [--osv] [--ai] [--active] [--agentic] [--brute] [--browser] [--netscan] [--load-test] [--i-accept] [--static-only] [--target <url>]")
            return

        feed, live_dashboard = self._make_scan_feed()
        feed_scope = feed if live_dashboard else nullcontext(feed)
        try:
            with feed_scope:
                with resolved_scan_source(path) as resolved:
                    result = run_scan(
                        resolved,
                        target=target,
                        static_only=static_only,
                        out_dir=self.out_dir,
                        agentic=agentic,
                        brute=brute,
                        browser=browser,
                        netscan=netscan,
                        load_test=load_test,
                        i_accept=i_accept,
                        feed=feed,
                        source_label=path,
                        use_osv=use_osv,
                        use_ai=use_ai,
                        use_active=use_active,
                    )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            self._error(f"Scan failed: {error}")
            return
        self.payload = result.payload
        self.findings_path = result.findings_path
        if live_dashboard:
            print_scan_summary(result.payload, self.out_dir)
        else:
            self.out()
            for line in render_scan_summary(result.payload, self.out_dir).splitlines():
                self.out(line)

    def _audit(self, args: list[str]) -> None:
        """Full pipeline: scan + AI + every probe + report, in one command."""
        path = next((t for t in args if not t.startswith("-")), None)
        if not path and self.findings_path:
            path = (self.payload or {}).get("scan", {}).get("source")
        if not path:
            self._warn("Usage: /audit <path> [--target <url>]   (e.g. /audit ./planted-app --target http://127.0.0.1:8787)")
            return
        # honor an inline --target, else the session target
        if "--target" in args:
            self.target = args[args.index("--target") + 1] if args.index("--target") + 1 < len(args) else self.target
        self.out(ui.style(f"🔎 Running FULL audit on {path}…", "bold", "magenta"))
        # Read-only/bounded probes run automatically; write-path testing (--i-accept)
        # creates records, so it stays opt-in even inside a full audit.
        forced = {"ai": True, "osv": True, "active": True, "agentic": True, "brute": True, "browser": True, "netscan": True, "load_test": True}
        if "--i-accept" in args:
            forced["i_accept"] = True
            self.out(ui.dim("--i-accept: including safe write-path probe (POST-only marked test records)."))
        self._scan([path], force=forced)
        if self.payload:
            self._report([], announce_path=False)
        self.out(ui.style("✅ Full audit complete — findings + report.md written.", "bright_green"))

    def _fix(self, args: list[str]) -> None:
        if not self.findings_path or not self.payload:
            self._warn("No findings loaded. Run /scan or /audit first.")
            return
        from .mcp import build_context, mcp_command_args, render_client_config

        repo = (self.payload or {}).get("scan", {}).get("resolved_path") or "."
        agent = "codex"
        if "--agent" in args:
            index = args.index("--agent")
            if index + 1 >= len(args):
                self._warn("Usage: /fix [--agent <codex|claude-code>]")
                return
            agent = args[index + 1]
        elif args and args[0] in {"codex", "cc", "claude", "claude-code"}:
            agent = args[0]
        if agent in {"cc", "claude"}:
            agent = "claude-code"
        if agent not in {"codex", "claude-code"}:
            self._warn("Usage: /fix [--agent <codex|claude-code>]")
            return
        if "--yes" in args:
            self.out(ui.dim("--yes is ignored: /fix now sets up an MCP server for your coding agent."))

        report_path = self.findings_path.parent / "report.md"
        context = build_context(
            repo=Path(repo),
            findings_path=self.findings_path,
            report_path=report_path if report_path.exists() else None,
            agent=agent,
        )
        command = "penny " + " ".join(mcp_command_args(context))
        self.out(ui.style("🔧 Penny remediation MCP server", "bold", "cyan"))
        self.out(ui.dim(f"Findings: {context.findings_path}"))
        if context.report_path:
            self.out(ui.dim(f"Report:   {context.report_path}"))
        else:
            self.out(ui.dim("Report:   not found yet; run /report to include report.md context."))
        self.out()
        self.out(render_client_config(context, client=agent))
        self.out()
        self.out(ui.dim(f"Smoke test command: {command}"))

    def _summary(self) -> None:
        summary = (self.payload or {}).get("summary", {})
        by_sev = summary.get("by_severity", {})
        confirmed = summary.get("confirmed_count", 0)
        body_lines = [
            ui.style(f"{summary.get('total', 0)} finding(s)", "bold", "white"),
            ui.severity_strip(by_sev),
        ]
        if confirmed:
            body_lines.append(ui.style(f"✓ {confirmed} dynamically confirmed", "bright_green"))
        self.out(ui.panel("\n".join(body_lines), title="Scan summary", color="green"))

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
                f"{f['location']['file']}:{f['location']['line']}",
                f["title"],
                f["status"],
            ]
            for f in ordered
        ]
        self.out(
            ui.table(
                ["ID", "Severity", "Location", "Title", "Status"],
                rows,
                min_widths=[5, 8, 28, 36, 9],
                gap=4,
            )
        )

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
                f"{ui.severity_badge(finding['severity'])}  {ui.style(finding['detector_id'], 'bold', 'cyan')}  {ui.dim(finding['status'])}",
                ui.field("where", f"{location['file']}:{location['line']}"),
                ui.field("owasp", ", ".join(finding.get("owasp", [])) or "—"),
                "",
                ui.style("snippet", "bold", "bright_black"),
                ui.dim(finding.get("snippet", "")),
                "",
                ui.field("Impact", finding["impact"]),
                ui.field("Fix", finding["remediation"]),
            ]
        )
        self.out(ui.panel(body, title=f"{finding['id']} — {finding['title']}", color="magenta"))

    def _report(self, args: list[str], *, announce_path: bool = True) -> None:
        if not self.findings_path or not self.payload:
            self._warn("No findings loaded. Run /scan <path> first.")
            return
        payload = self.payload
        report = generate_report(payload, use_llm=self.use_ai)
        store = FindingsStore(self.out_dir)
        report_path = store.write_report(payload.get("session_id", "manual-report"), report)
        copy_report_to_findings_dir(report_path, self.findings_path)
        if announce_path:
            self.out(ui.style(f"📄 report.md → {report_path}", "green"))

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

    def _set_model(self, args: list[str]) -> None:
        if not args:
            self.out(ui.dim(llm.describe_model_mode()))
            self.out(ui.dim("Usage: /model <auto|haiku|sonnet>"))
            self.out(ui.dim("  auto   — Haiku for quick chat, Sonnet for AI review/agentic probes (recommended)"))
            self.out(ui.dim("  haiku  — fast + cheap for everything"))
            self.out(ui.dim("  sonnet — deep + accurate for everything"))
            return
        try:
            mode = llm.set_model_mode(args[0])
        except ValueError as error:
            self._warn(str(error))
            return
        self.out(ui.style(f"✓ {llm.describe_model_mode()}", "green"))

    def _set_target(self, args: list[str]) -> None:
        if not args or args[0].lower() == "off":
            self.target = None
            self.out(ui.dim("Probe target cleared."))
            return
        self.target = args[0]
        self.out(ui.style(f"Probe target set: {self.target}", "green"))

    # ---- cloud (Vultr) tier ----------------------------------------------
    def _cloud_attack(self, args: list[str]) -> None:
        from .cloud import cloud_attack
        from .cloud_attacks import available_attacks

        attack_type = args[0] if args else None
        target = self.target
        kwargs: dict[str, str] = {}
        tokens = iter(args[1:])
        for a in tokens:
            if a == "--key":
                kwargs["apikey"] = next(tokens, "")
            elif a == "--tables":
                kwargs["tables"] = next(tokens, "")
            elif a == "--supabase-url":
                kwargs["supabase_url"] = next(tokens, "")
            elif a == "--login-url":
                kwargs["login_url"] = next(tokens, "")
            elif a == "--creds":
                kwargs["creds"] = next(tokens, "")
            elif a == "--template":
                kwargs["template"] = next(tokens, "")
            elif a == "--start":
                kwargs["start"] = next(tokens, "1")
            elif a == "--end":
                kwargs["end"] = next(tokens, "200")
            elif a == "--header":
                kwargs["header"] = next(tokens, "")
            elif a == "--max-rows":
                kwargs["max_rows"] = next(tokens, "5000")
            elif not a.startswith("-"):
                target = a
        if not attack_type:
            self.out(ui.dim(f"Usage: /cloud-attack <type> [target] [opts]   types: {', '.join(available_attacks())}"))
            self.out(ui.dim("  supabase-dump opts: --supabase-url <url> --key <anon/service key> --tables a,b,c"))
            self.out(ui.dim("  cred-stuffing opts: --login-url <url> --creds user:pass,user:pass"))
            return
        if not target:
            self._warn("No target set. Use /target <url> first.")
            return
        feed = PrettyFeed(self.printer)
        findings = cloud_attack(
            attack_type, target,
            feed=feed,
            keep_alive="--destroy" not in args,
            **kwargs,
        )
        if findings:
            self.out(ui.style(f"Cloud attack produced {len(findings)} finding(s).", "bright_green"))

    # ---- sandbox-test (heretic/gemma-3 GPU breach) -----------------------
    def _sandbox_bake(self, args: list[str]) -> None:
        from .sandbox import sandbox_bake

        feed = PrettyFeed(self.printer)
        self.out(ui.dim("Building the one-time heretic/gemma-3 GPU snapshot (~$0.70, ~1h)."))
        snap = sandbox_bake(feed=feed, auto_confirm="--yes" in args)
        if snap:
            self.out(ui.style(f"Sandbox snapshot ready: {snap}", "bright_green"))

    def _sandbox_test(self, args: list[str]) -> None:
        from .sandbox import sandbox_test

        keep_alive = "--keep-alive" in args
        allow_destructive = "--allow-destructive" in args
        # Drop boolean flags, then pull --workers N, then treat everything after --focus/
        # --instructions as the free-text focus (so the user needn't quote it).
        toks = [a for a in args if a not in ("--keep-alive", "--allow-destructive")]

        def _take_number(flag: str, default: float) -> float | None:
            # Supports "--flag 5" and the glued "--flag-5" form.
            nonlocal toks
            if flag in toks:
                i = toks.index(flag)
                try:
                    val = float(toks[i + 1])
                except (IndexError, ValueError):
                    self._warn(f"{flag} needs a number, e.g. {flag} 5")
                    return None
                del toks[i:i + 2]
                return val
            for t in list(toks):  # glued form: --workers-3 / --timing-5
                if t.startswith(flag + "-"):
                    try:
                        val = float(t[len(flag) + 1:])
                    except ValueError:
                        continue
                    toks.remove(t)
                    return val
            return default

        workers = _take_number("--workers", 1)
        if workers is None:
            return
        timing_minutes = _take_number("--timing", 0.0)
        if timing_minutes is None:
            return
        instructions = ""
        for flag in ("--focus", "--instructions"):
            if flag in toks:
                i = toks.index(flag)
                instructions = " ".join(toks[i + 1:]).strip()
                toks = toks[:i]
                break
        target = next((a for a in toks if not a.startswith("-")), None) or self.target
        if not target:
            self._warn("No target set. Use /target <url> first, or /sandbox-test <url> [--workers N] [--timing N] [--focus <text>].")
            return
        feed = PrettyFeed(self.printer)
        findings = sandbox_test(
            target,
            feed=feed,
            keep_alive=keep_alive,
            allow_destructive=allow_destructive,
            instructions=instructions, workers=max(1, int(workers)), timing_minutes=timing_minutes,
        )
        # Always persist + write a report, even with 0 findings, so the run leaves an artifact.
        self._persist_findings(findings, target, source="sandbox-test")
        color = "bright_green" if findings else "yellow"
        self.out(ui.style(f"Sandbox breach produced {len(findings)} finding(s).", color))
        self._report([])
        if findings:
            self.out(ui.dim("/findings to view, /show <id> for detail."))

    def _persist_findings(self, findings: list, target: str, *, source: str) -> None:
        """Write attack-tier findings into the run store so /findings, /show, /report work."""
        from .models import assign_finding_ids, now_session_id

        ordered = assign_finding_ids(list(findings))
        store = FindingsStore(self.out_dir)
        session_id = now_session_id()
        payload, run_path = store.write_findings(session_id, ordered, scan={"source": source, "target": target})
        self.payload = payload
        self.findings_path = run_path

    def _cloud_status(self) -> None:
        from .cloud import status
        status(PrettyFeed(self.printer))

    def _cloud_kill(self) -> None:
        from .cloud import kill_all
        kill_all(PrettyFeed(self.printer))

    def _cloud_destroy(self) -> None:
        from .cloud import destroy_all
        destroy_all(PrettyFeed(self.printer))

    def _knowledge(self, args: list[str]) -> None:
        from .mongo import MongoMirror

        query = " ".join(args).strip() or "common vulnerabilities"
        patterns, message = MongoMirror().search_patterns(query, limit=5)
        if message:
            self.out(ui.dim(message))
        if not patterns:
            self.out(ui.dim("No matching patterns in the knowledge base yet (run a scan to populate it)."))
            return
        for p in patterns:
            self.out(ui.dim(f"• {p.get('detector_id','?')} {p.get('title','')} — {p.get('remediation','')}"))

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
            use_llm=self.use_ai,
        )
        self.out(ui.style("🤖 penny", "bold", "bright_blue"))
        self.out(ui.render_markdown(answer))
        self.out()


def run_repl(out_dir: Path | str = Path(".")) -> None:
    session = Session(out_dir=out_dir)
    session.greet()

    def _loop() -> None:
        while True:
            try:
                line = read_line(ui.prompt())
            except EOFError:
                session.out()
                break
            except KeyboardInterrupt:
                session.out(ui.dim("\n(^C — type /exit to quit)"))
                continue
            if not session.handle(line):
                break

    if autocomplete_enabled():
        from prompt_toolkit.patch_stdout import patch_stdout

        with patch_stdout():
            _loop()
    else:
        _loop()
    session.out(ui.dim("bye"))
