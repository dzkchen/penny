from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .ask import answer_question
from .exports import write_exports
from .feed import EventFeed
from .patches import apply_patch_plans, write_patch_file
from .reporting import generate_report, load_findings
from .replay import run_demo_replay
from .scanner import run_scan
from .sources import resolved_scan_source
from .store import FindingsStore, copy_report_to_findings_dir


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


def _ask_loop(findings: Path, target: str | None, i_own_this: bool, feed: EventFeed) -> None:
    feed.emit("purple", "Interactive ask mode. Type 'exit' or 'quit' to stop.")
    while True:
        try:
            question = input("penny> ").strip()
        except EOFError:
            break
        if not question:
            continue
        if question.lower() in {"exit", "quit", ":q"}:
            break
        feed.emit("purple", answer_question(question, findings_path=findings, target=target, i_own_this=i_own_this))


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
    ) -> None:
        with resolved_scan_source(path) as resolved:
            run_scan(resolved, target=target, static_only=static_only, out_dir=out, i_own_this=i_own_this, feed=EventFeed())

    @app.command()
    def report(
        findings: Path = typer.Option(Path("findings.json"), "--findings"),
        out: Path = typer.Option(Path("."), "--out"),
        export: bool = typer.Option(False, "--export", help="Also write report.html and findings.csv."),
    ) -> None:
        _report_command(findings, out, EventFeed(), export=export)

    @app.command()
    def ask(
        question: str,
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        target: Optional[str] = typer.Option(None, "--target"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        feed = EventFeed()
        feed.emit("purple", answer_question(question, findings_path=findings, target=target, i_own_this=i_own_this))

    @app.command("ask-loop")
    def ask_loop(
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        target: Optional[str] = typer.Option(None, "--target"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        _ask_loop(findings, target, i_own_this, EventFeed())

    @app.command()
    def patch(
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        repo: Path = typer.Option(Path("."), "--repo"),
        out: Path = typer.Option(Path("penny.patch"), "--out"),
        apply: bool = typer.Option(False, "--apply", help="Apply generated fixes to the local repo."),
    ) -> None:
        _patch_command(findings, repo, out, apply, EventFeed())

    @app.command()
    def run(
        path: str,
        target: str = typer.Option(..., "--target"),
        out: Path = typer.Option(Path("."), "--out"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        feed = EventFeed()
        with resolved_scan_source(path) as resolved:
            result = run_scan(resolved, target=target, out_dir=out, i_own_this=i_own_this, feed=feed)
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

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--findings", type=Path, default=Path("findings.json"))
    report_parser.add_argument("--out", type=Path, default=Path("."))
    report_parser.add_argument("--export", action="store_true")

    ask_parser = sub.add_parser("ask")
    ask_parser.add_argument("question")
    ask_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    ask_parser.add_argument("--target")
    ask_parser.add_argument("--i-own-this", action="store_true")

    ask_loop_parser = sub.add_parser("ask-loop")
    ask_loop_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    ask_loop_parser.add_argument("--target")
    ask_loop_parser.add_argument("--i-own-this", action="store_true")

    patch_parser = sub.add_parser("patch")
    patch_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    patch_parser.add_argument("--repo", type=Path, default=Path("."))
    patch_parser.add_argument("--out", type=Path, default=Path("penny.patch"))
    patch_parser.add_argument("--apply", action="store_true")

    run_parser = sub.add_parser("run")
    run_parser.add_argument("path")
    run_parser.add_argument("--target", required=True)
    run_parser.add_argument("--out", type=Path, default=Path("."))
    run_parser.add_argument("--i-own-this", action="store_true")

    replay_parser = sub.add_parser("demo-replay")
    replay_parser.add_argument("--recording", type=Path)
    replay_parser.add_argument("--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    feed = EventFeed()
    if args.command == "scan":
        with resolved_scan_source(args.path) as resolved:
            run_scan(resolved, target=args.target, static_only=args.static_only, out_dir=args.out, i_own_this=args.i_own_this, feed=feed)
    elif args.command == "report":
        _report_command(args.findings, args.out, feed, export=args.export)
    elif args.command == "ask":
        feed.emit("purple", answer_question(args.question, findings_path=args.findings, target=args.target, i_own_this=args.i_own_this))
    elif args.command == "ask-loop":
        _ask_loop(args.findings, args.target, args.i_own_this, feed)
    elif args.command == "patch":
        _patch_command(args.findings, args.repo, args.out, args.apply, feed)
    elif args.command == "run":
        with resolved_scan_source(args.path) as resolved:
            result = run_scan(resolved, target=args.target, out_dir=args.out, i_own_this=args.i_own_this, feed=feed)
        _report_command(result.findings_path, args.out, feed)
    elif args.command == "demo-replay":
        run_demo_replay(recording=args.recording, out_dir=args.out, feed=feed)


def main() -> None:
    try:
        app = _build_typer_app()
    except Exception:
        _fallback_main()
        return
    app()
