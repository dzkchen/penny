from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from . import llm
from .ask import answer_question
from .exports import write_exports
from .feed import EventFeed
from .mongo import MongoMirror
from .patches import apply_patch_plans, write_patch_file
from .reporting import generate_report, load_findings
from .replay import run_demo_replay
from .scanner import run_scan
from .sources import resolved_scan_source
from .store import FindingsStore, copy_report_to_findings_dir


def _resolve_findings_path(findings: Path | None, out_dir: Path) -> Path:
    """Resolve which findings file `report` should read.

    When `--findings` is not given explicitly, look inside the `--out` run tree
    first (`<out>/.penny/runs/latest/findings.json`, then `<out>/findings.json`)
    so `scan --out X` followed by `report --out X` reports the same run. Falls
    back to `findings.json` in the current directory for backwards compatibility.
    """
    if findings is not None:
        return findings
    candidates = [
        out_dir / ".penny" / "runs" / "latest" / "findings.json",
        out_dir / "findings.json",
        Path("findings.json"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _report_command(findings: Path, out_dir: Path, feed: EventFeed, *, export: bool = False) -> Path:
    payload = load_findings(findings)
    session_id = payload.get("session_id", "manual-report")
    feed.emit("blue", "Writing report with concrete fixes")
    report = generate_report(payload)
    report_path = FindingsStore(out_dir).write_report(session_id, report)
    copy_report_to_findings_dir(report_path, findings)
    verdict = report.split("## 2. Executive Summary", 1)[0].split("## 1. Purple-Team Verdict", 1)[1].strip()
    feed.emit("purple", f"Verdict: {verdict}")
    feed.emit("report", f"Wrote {report_path}")
    if export:
        paths = write_exports(payload, report, out_dir)
        feed.emit("report", f"Wrote {paths['html']}")
        feed.emit("report", f"Wrote {paths['csv']}")
    return report_path


def _fail(message: str) -> None:
    print(f"[error] {message}", file=sys.stderr)
    raise SystemExit(2)


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
        active: bool = typer.Option(False, "--active", help="Send active (non-destructive) probes: SQLi payloads and Firebase open-rules checks. Public targets need --i-own-this."),
    ) -> None:
        try:
            with resolved_scan_source(path) as resolved:
                run_scan(resolved, target=target, static_only=static_only, out_dir=out, i_own_this=i_own_this, feed=EventFeed(), source_label=path, use_osv=osv, use_ai=ai, use_active=active)
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))

    @app.command()
    def report(
        findings: Optional[Path] = typer.Option(None, "--findings", help="Defaults to the latest run under --out."),
        out: Path = typer.Option(Path("."), "--out"),
        export: bool = typer.Option(False, "--export", help="Also write report.html and findings.csv."),
    ) -> None:
        _report_command(_resolve_findings_path(findings, out), out, EventFeed(), export=export)

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
        active: bool = typer.Option(False, "--active", help="Send active (non-destructive) probes: SQLi payloads and Firebase open-rules checks. Public targets need --i-own-this."),
    ) -> None:
        feed = EventFeed()
        try:
            with resolved_scan_source(path) as resolved:
                result = run_scan(resolved, target=target, out_dir=out, i_own_this=i_own_this, feed=feed, source_label=path, use_osv=osv, use_ai=ai, use_active=active)
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
        _report_command(result.findings_path, out, feed)

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

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--findings", type=Path, default=None)
    report_parser.add_argument("--out", type=Path, default=Path("."))
    report_parser.add_argument("--export", action="store_true")

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

    patch_parser = sub.add_parser("patch")
    patch_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    patch_parser.add_argument("--repo", type=Path, default=Path("."))
    patch_parser.add_argument("--out", type=Path, default=Path("penny.patch"))
    patch_parser.add_argument("--apply", action="store_true")

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

    replay_parser = sub.add_parser("demo-replay")
    replay_parser.add_argument("--recording", type=Path)
    replay_parser.add_argument("--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    feed = EventFeed()
    if args.command == "scan":
        try:
            with resolved_scan_source(args.path) as resolved:
                run_scan(resolved, target=args.target, static_only=args.static_only, out_dir=args.out, i_own_this=args.i_own_this, feed=feed, source_label=args.path, use_osv=args.osv, use_ai=args.ai, use_active=args.active)
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
    elif args.command == "report":
        _report_command(_resolve_findings_path(args.findings, args.out), args.out, feed, export=args.export)
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
    elif args.command == "patch":
        _patch_command(args.findings, args.repo, args.out, args.apply, feed)
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
            with resolved_scan_source(args.path) as resolved:
                result = run_scan(resolved, target=args.target, out_dir=args.out, i_own_this=args.i_own_this, feed=feed, source_label=args.path, use_osv=args.osv, use_ai=args.ai, use_active=args.active)
        except (FileNotFoundError, ValueError, RuntimeError) as error:
            _fail(str(error))
        _report_command(result.findings_path, args.out, feed)
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
