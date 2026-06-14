from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, List, Optional

from . import llm
from .agent_fix import run_agent_fix
from .ask import answer_question
from .models import SEVERITY_ORDER
from .feed import EventFeed
from .live import LiveScanFeed, print_scan_summary
from .mongo import MongoMirror
from .patches import apply_patch_plans, write_patch_file
from .reporting import generate_report, load_findings
from .replay import run_demo_replay
from .scanner import run_scan
from .sources import resolved_scan_source
from .store import FindingsStore, copy_report_to_findings_dir


def _resolve_findings_path(findings: Path | None, out_dir: Path) -> Path:
    """Resolve which findings file `report` should read.

    When `--findings` is not given explicitly, read the latest run under `--out`
    (`<out>/.penny/runs/latest/findings.json`) so `scan --out X` followed by
    `report --out X` reports the same run.
    """
    if findings is not None:
        return findings
    return out_dir / ".penny" / "runs" / "latest" / "findings.json"


def _run_scan_command(
    path: str,
    *,
    target: str | None,
    static_only: bool,
    out: Path,
    i_own_this: bool,
    osv: bool,
    ai: bool,
    active: bool,
    fail_on: str | None,
    diff: str | None,
    endpoint: list[str] | None,
    agentic: bool,
    brute: bool,
    browser: bool,
    netscan: bool,
    load_test: bool,
    i_accept: bool,
    wordlist: str | None,
    pages: int,
    verbose: bool,
) -> tuple[Any, LiveScanFeed]:
    feed = LiveScanFeed()
    with feed:
        with resolved_scan_source(path) as resolved:
            result = run_scan(
                resolved,
                target=target,
                static_only=static_only,
                out_dir=out,
                i_own_this=i_own_this,
                feed=feed,
                source_label=path,
                use_osv=osv,
                use_ai=ai,
                use_active=active,
                diff_base=diff,
                endpoints=endpoint,
                agentic=agentic,
                brute=brute,
                browser=browser,
                netscan=netscan,
                load_test=load_test,
                i_accept=i_accept,
                wordlist=wordlist,
                pages=pages,
            )
    print_scan_summary(result.payload, out, verbose=verbose)
    _enforce_fail_on(result.payload, fail_on, feed)
    return result, feed


def _report_command(
    findings: Path,
    out_dir: Path,
    feed: EventFeed,
    *,
    use_llm: bool = False,
    announce: bool = True,
) -> Path:
    payload = load_findings(findings)
    session_id = payload.get("session_id", "manual-report")
    if announce:
        feed.emit("blue", "Writing report with concrete fixes")
    report = generate_report(payload, use_llm=use_llm)
    report_path = FindingsStore(out_dir).write_report(session_id, report)
    copy_report_to_findings_dir(report_path, findings)
    if announce:
        verdict = report.split("## 2. Executive Summary", 1)[0].split("## 1. Purple-Team Verdict", 1)[1].strip()
        feed.emit("purple", f"Verdict: {verdict}")
        feed.emit("report", f"Wrote {report_path}")
    return report_path


def _fail(message: str) -> None:
    print(f"[error] {message}", file=sys.stderr)
    raise SystemExit(2)


def _enforce_fail_on(payload: dict, threshold: str | None, feed: EventFeed) -> None:
    """Exit non-zero (code 1) if any finding meets/exceeds the severity threshold.

    Lets Penny gate CI/PRs: `penny scan . --fail-on high`. Usage/scan errors stay
    on exit code 2 (raised by `_fail`); the gate uses 1 so callers can tell them apart.
    """
    if not threshold:
        return
    threshold = threshold.capitalize()
    if threshold not in SEVERITY_ORDER:
        _fail(f"--fail-on must be one of: {', '.join(SEVERITY_ORDER)}")
    limit = SEVERITY_ORDER[threshold]
    tripped = [
        finding
        for finding in payload.get("findings", [])
        if SEVERITY_ORDER.get(finding.get("severity", ""), 99) <= limit
    ]
    if tripped:
        feed.emit("gate", f"{len(tripped)} finding(s) at or above {threshold}; failing (--fail-on {threshold})")
        raise SystemExit(1)
    feed.emit("gate", f"No findings at or above {threshold}; passing (--fail-on {threshold})")


def _ask_loop(
    findings: Path,
    target: str | None,
    i_own_this: bool,
    feed: EventFeed,
    use_llm: bool = False,
) -> None:
    feed.emit("purple", "Interactive ask mode. Type 'exit' or 'quit' to stop.")
    if use_llm:
        feed.emit("purple", llm.describe())
    while True:
        try:
            question = input("penny> ").strip()
        except EOFError:
            break
        if not question:
            continue
        if question.lower() in {"exit", "quit", ":q"}:
            break
        feed.emit(
            "purple",
            answer_question(
                question,
                findings_path=findings,
                target=target,
                i_own_this=i_own_this,
                use_llm=use_llm,
            ),
        )


def _patch_command(findings: Path, repo: Path, out: Path, apply: bool, feed: EventFeed) -> None:
    payload = load_findings(findings)
    patch_path = write_patch_file(payload, repo, out)
    feed.emit("blue", f"Wrote redacted patch preview {patch_path}")
    if apply:
        changed = apply_patch_plans(payload, repo)
        if changed:
            for path in changed:
                feed.emit("blue", f"Applied fix to {path}")
        else:
            feed.emit("blue", "No applicable source changes found")


def _fix_command(findings: Path, repo: Path, auto_yes: bool, feed: EventFeed) -> None:
    payload = load_findings(findings)
    feed.emit("blue", f"Interactive fix mode on {repo} (LLM-driven, approval required)")
    changed = run_agent_fix(payload, repo, feed=feed, auto_yes=auto_yes)
    if changed:
        feed.emit("blue", f"Applied {len(changed)} fix(es). Review with `git diff` before committing.")
    else:
        feed.emit("blue", "No fixes applied")


def _github_fix_command(source: str, workdir: Path, branch: str, auto_yes: bool, push: bool, feed: EventFeed) -> None:
    from .github_fix import github_fix_roundtrip

    try:
        live_feed = LiveScanFeed()
        with live_feed:
            result = github_fix_roundtrip(source, workdir=workdir, branch=branch, auto_yes=auto_yes, push=push, feed=live_feed)
    except Exception as error:
        _fail(str(error))
    payload = result.get("scan_payload")
    if isinstance(payload, dict):
        print_scan_summary(payload, workdir)


def _build_typer_app():
    import typer

    app = typer.Typer(no_args_is_help=True, help="Penny: local-first security assistant for AI-built apps.")

    @app.command()
    def scan(
        path: str,
        target: Optional[str] = typer.Option(None, "--target"),
        static_only: bool = typer.Option(False, "--static-only"),
        out: Path = typer.Option(Path("."), "--out"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
        osv: bool = typer.Option(False, "--osv", help="Query OSV.dev for real dependency advisories (sends package names + versions)."),
        ai: bool = typer.Option(False, "--ai", help="Run an AI vulnerability review (sends source code to the Claude model)."),
        active: bool = typer.Option(False, "--active", help="Send active read-only probes: SQLi, Firebase open rules, headers, cookies, HTTP methods, exposed paths, errors, CORS, and cache checks. Public targets need --i-own-this plus a matching DNS TXT proof record."),
        fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit non-zero if any finding is at or above this severity (Critical/High/Medium/Low/Info)."),
        diff: Optional[str] = typer.Option(None, "--diff", help="Only scan files changed versus this git ref, e.g. main."),
        endpoint: Optional[List[str]] = typer.Option(None, "--endpoint", help="Add an endpoint for active SQLi probing, e.g. /api/users?id=1 (repeatable)."),
        agentic: bool = typer.Option(False, "--agentic", help="Let Claude drive extra read-only probes (any app)."),
        brute: bool = typer.Option(False, "--brute", help="Run a wordlist brute-force of paths/logins (owned targets only)."),
        browser: bool = typer.Option(False, "--browser", help="Drive a real browser (Playwright) to crawl and probe the live site."),
        netscan: bool = typer.Option(False, "--netscan", help="Run a read-only TCP-connect port scan of the target host for exposed services (owned targets only)."),
        load_test: bool = typer.Option(False, "--load-test", help="Run a bounded, abortable ramp-to-failure load test of the target to find its capacity knee (owned targets only; read-only GET)."),
        i_accept: bool = typer.Option(False, "--i-accept", help="Consent to safe write-path testing: POST-only benign marked test records to detect unauthenticated writes / mass assignment (owned targets only; never PUT/PATCH/DELETE)."),
        wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Path to a custom brute-force wordlist (one path per line)."),
        pages: int = typer.Option(8, "--pages", help="Max pages for the browser crawl."),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="After the scan, print every finding location grouped by detector (the non-interactive form of ctrl-o expand)."),
    ) -> None:
        try:
            _run_scan_command(
                path,
                target=target,
                static_only=static_only,
                out=out,
                i_own_this=i_own_this,
                osv=osv,
                ai=ai,
                active=active,
                fail_on=fail_on,
                diff=diff,
                endpoint=endpoint,
                agentic=agentic,
                brute=brute,
                browser=browser,
                netscan=netscan,
                load_test=load_test,
                i_accept=i_accept,
                wordlist=wordlist,
                pages=pages,
                verbose=verbose,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))

    @app.command()
    def report(
        findings: Optional[Path] = typer.Option(None, "--findings", help="Defaults to the latest run under --out."),
        out: Path = typer.Option(Path("."), "--out"),
        ai: bool = typer.Option(False, "--ai", help="Write the purple-team verdict with the Claude model instead of the deterministic one-liner (sends redacted findings to the API)."),
    ) -> None:
        _report_command(_resolve_findings_path(findings, out), out, EventFeed(), use_llm=ai)

    @app.command()
    def ask(
        question: str,
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        target: Optional[str] = typer.Option(None, "--target"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
        no_ai: bool = typer.Option(False, "--no-ai", help="Answer with deterministic logic instead of the Claude model."),
    ) -> None:
        feed = EventFeed()
        use_llm = not no_ai
        if use_llm:
            feed.emit("purple", llm.describe())
        feed.emit(
            "purple",
            answer_question(question, findings_path=findings, target=target, i_own_this=i_own_this, use_llm=use_llm),
        )

    @app.command()
    def model(
        mode: Optional[str] = typer.Argument(None, help="auto | haiku | sonnet (omit to show current)"),
    ) -> None:
        feed = EventFeed()
        if not mode:
            feed.emit("purple", llm.describe_model_mode())
            feed.emit("purple", "Set with: penny model <auto|haiku|sonnet>")
            return
        try:
            llm.set_model_mode(mode)
        except ValueError as error:
            _fail(str(error))
        feed.emit("purple", llm.describe_model_mode())
        feed.emit("purple", "Tip: add PENNY_MODEL_MODE=<mode> to .env to make it permanent.")

    @app.command("ask-loop")
    def ask_loop(
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        target: Optional[str] = typer.Option(None, "--target"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
        no_ai: bool = typer.Option(False, "--no-ai", help="Answer with deterministic logic instead of the Claude model."),
    ) -> None:
        _ask_loop(findings, target, i_own_this, EventFeed(), use_llm=not no_ai)

    @app.command()
    def patch(
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        repo: Path = typer.Option(Path("."), "--repo"),
        out: Path = typer.Option(Path("penny.patch"), "--out"),
        apply: bool = typer.Option(False, "--apply", help="Apply generated fixes to the local repo."),
    ) -> None:
        _patch_command(findings, repo, out, apply, EventFeed())

    @app.command()
    def fix(
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        repo: Path = typer.Option(Path("."), "--repo"),
        yes: bool = typer.Option(False, "--yes", help="Apply all proposed fixes without prompting (demo/non-interactive)."),
    ) -> None:
        _fix_command(findings, repo, yes, EventFeed())

    @app.command("github-fix")
    def github_fix(
        source: str,
        workdir: Path = typer.Option(Path("penny-workdir"), "--workdir"),
        branch: str = typer.Option("penny/fixes", "--branch"),
        yes: bool = typer.Option(False, "--yes", help="Apply all fixes without prompting."),
        push: bool = typer.Option(False, "--push", help="Push the fix branch to origin."),
    ) -> None:
        _github_fix_command(source, workdir, branch, yes, push, EventFeed())

    @app.command()
    def knowledge(
        query: str,
        limit: int = typer.Option(5, "--limit"),
    ) -> None:
        feed = EventFeed()
        patterns, message = MongoMirror().search_patterns(query, limit=limit)
        if message:
            feed.emit("mongo", message)
        if not patterns:
            feed.emit("mongo", "No Mongo knowledge patterns returned")
            return
        for pattern in patterns:
            feed.emit("mongo", f"{pattern['detector_id']} {pattern['title']} - {pattern['remediation']}")

    @app.command()
    def trends(
        days: int = typer.Option(7, "--days"),
        limit: int = typer.Option(10, "--limit"),
    ) -> None:
        feed = EventFeed()
        rows, message = MongoMirror().trends(days=days, limit=limit)
        if message:
            feed.emit("mongo", message)
        if not rows:
            feed.emit("mongo", "No Mongo scan-history trends returned")
            return
        for row in rows:
            feed.emit(
                "mongo",
                f"{row['detector_id']}: {row['count']} finding(s), critical={row['critical_count']}, high={row['high_count']}",
            )

    @app.command()
    def run(
        path: str,
        target: str = typer.Option(..., "--target"),
        out: Path = typer.Option(Path("."), "--out"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
        osv: bool = typer.Option(False, "--osv", help="Query OSV.dev for real dependency advisories (sends package names + versions)."),
        ai: bool = typer.Option(False, "--ai", help="Run an AI vulnerability review (sends source code to the Claude model)."),
        active: bool = typer.Option(False, "--active", help="Send active read-only probes: SQLi, Firebase open rules, headers, cookies, HTTP methods, exposed paths, errors, CORS, and cache checks. Public targets need --i-own-this plus a matching DNS TXT proof record."),
        fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit non-zero if any finding is at or above this severity (Critical/High/Medium/Low/Info)."),
        diff: Optional[str] = typer.Option(None, "--diff", help="Only scan files changed versus this git ref, e.g. main."),
        endpoint: Optional[List[str]] = typer.Option(None, "--endpoint", help="Add an endpoint for active SQLi probing, e.g. /api/users?id=1 (repeatable)."),
        agentic: bool = typer.Option(False, "--agentic", help="Let Claude drive extra read-only probes (any app)."),
        brute: bool = typer.Option(False, "--brute", help="Run a wordlist brute-force of paths/logins (owned targets only)."),
        browser: bool = typer.Option(False, "--browser", help="Drive a real browser (Playwright) to crawl and probe the live site."),
        netscan: bool = typer.Option(False, "--netscan", help="Run a read-only TCP-connect port scan of the target host for exposed services (owned targets only)."),
        load_test: bool = typer.Option(False, "--load-test", help="Run a bounded, abortable ramp-to-failure load test of the target to find its capacity knee (owned targets only; read-only GET)."),
        i_accept: bool = typer.Option(False, "--i-accept", help="Consent to safe write-path testing: POST-only benign marked test records to detect unauthenticated writes / mass assignment (owned targets only; never PUT/PATCH/DELETE)."),
        wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Path to a custom brute-force wordlist (one path per line)."),
        pages: int = typer.Option(8, "--pages", help="Max pages for the browser crawl."),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="After the scan, print every finding location grouped by detector (the non-interactive form of ctrl-o expand)."),
    ) -> None:
        try:
            result, feed = _run_scan_command(
                path,
                target=target,
                static_only=False,
                out=out,
                i_own_this=i_own_this,
                osv=osv,
                ai=ai,
                active=active,
                fail_on=fail_on,
                diff=diff,
                endpoint=endpoint,
                agentic=agentic,
                brute=brute,
                browser=browser,
                netscan=netscan,
                load_test=load_test,
                i_accept=i_accept,
                wordlist=wordlist,
                pages=pages,
                verbose=verbose,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
        _report_command(result.findings_path, out, feed, use_llm=ai, announce=False)
        print("Full audit complete — findings + report.md written.")

    @app.command("demo-replay")
    def demo_replay(
        recording: Optional[Path] = typer.Option(None, "--recording"),
        out: Path = typer.Option(Path("."), "--out"),
    ) -> None:
        run_demo_replay(recording=recording, out_dir=out, feed=EventFeed())

    return app


def _fallback_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="penny")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--target")
    scan_parser.add_argument("--static-only", action="store_true")
    scan_parser.add_argument("--out", type=Path, default=Path("."))
    scan_parser.add_argument("--i-own-this", action="store_true")
    scan_parser.add_argument("--osv", action="store_true")
    scan_parser.add_argument("--ai", action="store_true")
    scan_parser.add_argument("--active", action="store_true")
    scan_parser.add_argument("--fail-on", default=None)
    scan_parser.add_argument("--diff", default=None)
    scan_parser.add_argument("--endpoint", action="append", default=None)
    scan_parser.add_argument("--agentic", action="store_true")
    scan_parser.add_argument("--brute", action="store_true")
    scan_parser.add_argument("--browser", action="store_true")
    scan_parser.add_argument("--netscan", action="store_true")
    scan_parser.add_argument("--load-test", action="store_true")
    scan_parser.add_argument("--i-accept", action="store_true")
    scan_parser.add_argument("--wordlist", default=None)
    scan_parser.add_argument("--pages", type=int, default=8)
    scan_parser.add_argument("--verbose", "-v", action="store_true")

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--findings", type=Path, default=None)
    report_parser.add_argument("--out", type=Path, default=Path("."))
    report_parser.add_argument("--ai", action="store_true")

    ask_parser = sub.add_parser("ask")
    ask_parser.add_argument("question")
    ask_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    ask_parser.add_argument("--target")
    ask_parser.add_argument("--i-own-this", action="store_true")
    ask_parser.add_argument("--no-ai", action="store_true")

    ask_loop_parser = sub.add_parser("ask-loop")
    ask_loop_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    ask_loop_parser.add_argument("--target")
    ask_loop_parser.add_argument("--i-own-this", action="store_true")
    ask_loop_parser.add_argument("--no-ai", action="store_true")

    model_parser = sub.add_parser("model")
    model_parser.add_argument("mode", nargs="?", default=None)

    patch_parser = sub.add_parser("patch")
    patch_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    patch_parser.add_argument("--repo", type=Path, default=Path("."))
    patch_parser.add_argument("--out", type=Path, default=Path("penny.patch"))
    patch_parser.add_argument("--apply", action="store_true")

    fix_parser = sub.add_parser("fix")
    fix_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    fix_parser.add_argument("--repo", type=Path, default=Path("."))
    fix_parser.add_argument("--yes", action="store_true")

    github_fix_parser = sub.add_parser("github-fix")
    github_fix_parser.add_argument("source")
    github_fix_parser.add_argument("--workdir", type=Path, default=Path("penny-workdir"))
    github_fix_parser.add_argument("--branch", default="penny/fixes")
    github_fix_parser.add_argument("--yes", action="store_true")
    github_fix_parser.add_argument("--push", action="store_true")

    knowledge_parser = sub.add_parser("knowledge")
    knowledge_parser.add_argument("query")
    knowledge_parser.add_argument("--limit", type=int, default=5)

    trends_parser = sub.add_parser("trends")
    trends_parser.add_argument("--days", type=int, default=7)
    trends_parser.add_argument("--limit", type=int, default=10)

    run_parser = sub.add_parser("run")
    run_parser.add_argument("path")
    run_parser.add_argument("--target", required=True)
    run_parser.add_argument("--out", type=Path, default=Path("."))
    run_parser.add_argument("--i-own-this", action="store_true")
    run_parser.add_argument("--osv", action="store_true")
    run_parser.add_argument("--ai", action="store_true")
    run_parser.add_argument("--active", action="store_true")
    run_parser.add_argument("--fail-on", default=None)
    run_parser.add_argument("--diff", default=None)
    run_parser.add_argument("--endpoint", action="append", default=None)
    run_parser.add_argument("--agentic", action="store_true")
    run_parser.add_argument("--brute", action="store_true")
    run_parser.add_argument("--browser", action="store_true")
    run_parser.add_argument("--netscan", action="store_true")
    run_parser.add_argument("--load-test", action="store_true")
    run_parser.add_argument("--i-accept", action="store_true")
    run_parser.add_argument("--wordlist", default=None)
    run_parser.add_argument("--pages", type=int, default=8)
    run_parser.add_argument("--verbose", "-v", action="store_true")

    replay_parser = sub.add_parser("demo-replay")
    replay_parser.add_argument("--recording", type=Path)
    replay_parser.add_argument("--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    feed = EventFeed()
    if args.command == "scan":
        try:
            _run_scan_command(
                args.path,
                target=args.target,
                static_only=args.static_only,
                out=args.out,
                i_own_this=args.i_own_this,
                osv=args.osv,
                ai=args.ai,
                active=args.active,
                fail_on=args.fail_on,
                diff=args.diff,
                endpoint=args.endpoint,
                agentic=args.agentic,
                brute=args.brute,
                browser=args.browser,
                netscan=args.netscan,
                load_test=args.load_test,
                i_accept=args.i_accept,
                wordlist=args.wordlist,
                pages=args.pages,
                verbose=args.verbose,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
    elif args.command == "report":
        _report_command(_resolve_findings_path(args.findings, args.out), args.out, feed, use_llm=args.ai)
    elif args.command == "ask":
        use_llm = not args.no_ai
        if use_llm:
            feed.emit("purple", llm.describe())
        feed.emit(
            "purple",
            answer_question(args.question, findings_path=args.findings, target=args.target, i_own_this=args.i_own_this, use_llm=use_llm),
        )
    elif args.command == "ask-loop":
        _ask_loop(args.findings, args.target, args.i_own_this, feed, use_llm=not args.no_ai)
    elif args.command == "model":
        if not args.mode:
            feed.emit("purple", llm.describe_model_mode())
        else:
            try:
                llm.set_model_mode(args.mode)
                feed.emit("purple", llm.describe_model_mode())
            except ValueError as error:
                _fail(str(error))
    elif args.command == "patch":
        _patch_command(args.findings, args.repo, args.out, args.apply, feed)
    elif args.command == "fix":
        _fix_command(args.findings, args.repo, args.yes, feed)
    elif args.command == "github-fix":
        _github_fix_command(args.source, args.workdir, args.branch, args.yes, args.push, feed)
    elif args.command == "knowledge":
        patterns, message = MongoMirror().search_patterns(args.query, limit=args.limit)
        if message:
            feed.emit("mongo", message)
        if not patterns:
            feed.emit("mongo", "No Mongo knowledge patterns returned")
        for pattern in patterns:
            feed.emit("mongo", f"{pattern['detector_id']} {pattern['title']} - {pattern['remediation']}")
    elif args.command == "trends":
        rows, message = MongoMirror().trends(days=args.days, limit=args.limit)
        if message:
            feed.emit("mongo", message)
        if not rows:
            feed.emit("mongo", "No Mongo scan-history trends returned")
        for row in rows:
            feed.emit(
                "mongo",
                f"{row['detector_id']}: {row['count']} finding(s), critical={row['critical_count']}, high={row['high_count']}",
            )
    elif args.command == "run":
        try:
            result, feed = _run_scan_command(
                args.path,
                target=args.target,
                static_only=False,
                out=args.out,
                i_own_this=args.i_own_this,
                osv=args.osv,
                ai=args.ai,
                active=args.active,
                fail_on=args.fail_on,
                diff=args.diff,
                endpoint=args.endpoint,
                agentic=args.agentic,
                brute=args.brute,
                browser=args.browser,
                netscan=args.netscan,
                load_test=args.load_test,
                i_accept=args.i_accept,
                wordlist=args.wordlist,
                pages=args.pages,
                verbose=args.verbose,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
        _report_command(result.findings_path, args.out, feed, use_llm=args.ai, announce=False)
        print("Full audit complete — findings + report.md written.")
    elif args.command == "demo-replay":
        run_demo_replay(recording=args.recording, out_dir=args.out, feed=feed)


def main() -> None:
    argv = sys.argv[1:]
    if not argv or argv[0] in ("repl", "shell"):
        from .repl import run_repl

        run_repl()
        return
    try:
        app = _build_typer_app()
    except Exception:
        _fallback_main()
        return
    app()
