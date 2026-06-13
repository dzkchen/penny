from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .ask import answer_question
from .feed import EventFeed
from .reporting import generate_report, load_findings
from .replay import run_demo_replay
from .scanner import run_scan
from .store import FindingsStore, copy_report_to_findings_dir


def _report_command(findings: Path, out_dir: Path, feed: EventFeed) -> Path:
    payload = load_findings(findings)
    session_id = payload.get("session_id", "manual-report")
    report = generate_report(payload)
    report_path = FindingsStore(out_dir).write_report(session_id, report)
    copy_report_to_findings_dir(report_path, findings)
    feed.emit("report", f"Wrote {report_path}")
    return report_path


def _build_typer_app():
    import typer

    app = typer.Typer(no_args_is_help=True, help="Penny: local-first security assistant for AI-built apps.")

    @app.command()
    def scan(
        path: Path,
        target: Optional[str] = typer.Option(None, "--target"),
        static_only: bool = typer.Option(False, "--static-only"),
        out: Path = typer.Option(Path("."), "--out"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        run_scan(path, target=target, static_only=static_only, out_dir=out, i_own_this=i_own_this, feed=EventFeed())

    @app.command()
    def report(
        findings: Path = typer.Option(Path("findings.json"), "--findings"),
        out: Path = typer.Option(Path("."), "--out"),
    ) -> None:
        _report_command(findings, out, EventFeed())

    @app.command()
    def ask(
        question: str,
        findings: Path = typer.Option(Path(".penny/runs/latest/findings.json"), "--findings"),
        target: Optional[str] = typer.Option(None, "--target"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        feed = EventFeed()
        feed.emit("purple", answer_question(question, findings_path=findings, target=target, i_own_this=i_own_this))

    @app.command()
    def run(
        path: Path,
        target: str = typer.Option(..., "--target"),
        out: Path = typer.Option(Path("."), "--out"),
        i_own_this: bool = typer.Option(False, "--i-own-this"),
    ) -> None:
        feed = EventFeed()
        result = run_scan(path, target=target, out_dir=out, i_own_this=i_own_this, feed=feed)
        _report_command(result.findings_path, out, feed)
        feed.emit("purple", "Verdict: " + generate_report(result.payload).split("## 2. Executive Summary", 1)[0].split("## 1. Purple-Team Verdict", 1)[1].strip())

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
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--target")
    scan_parser.add_argument("--static-only", action="store_true")
    scan_parser.add_argument("--out", type=Path, default=Path("."))
    scan_parser.add_argument("--i-own-this", action="store_true")

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--findings", type=Path, default=Path("findings.json"))
    report_parser.add_argument("--out", type=Path, default=Path("."))

    ask_parser = sub.add_parser("ask")
    ask_parser.add_argument("question")
    ask_parser.add_argument("--findings", type=Path, default=Path(".penny/runs/latest/findings.json"))
    ask_parser.add_argument("--target")
    ask_parser.add_argument("--i-own-this", action="store_true")

    run_parser = sub.add_parser("run")
    run_parser.add_argument("path", type=Path)
    run_parser.add_argument("--target", required=True)
    run_parser.add_argument("--out", type=Path, default=Path("."))
    run_parser.add_argument("--i-own-this", action="store_true")

    replay_parser = sub.add_parser("demo-replay")
    replay_parser.add_argument("--recording", type=Path)
    replay_parser.add_argument("--out", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    feed = EventFeed()
    if args.command == "scan":
        run_scan(args.path, target=args.target, static_only=args.static_only, out_dir=args.out, i_own_this=args.i_own_this, feed=feed)
    elif args.command == "report":
        _report_command(args.findings, args.out, feed)
    elif args.command == "ask":
        feed.emit("purple", answer_question(args.question, findings_path=args.findings, target=args.target, i_own_this=args.i_own_this))
    elif args.command == "run":
        result = run_scan(args.path, target=args.target, out_dir=args.out, i_own_this=args.i_own_this, feed=feed)
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
