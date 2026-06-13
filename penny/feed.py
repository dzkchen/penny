from __future__ import annotations

import sys
from dataclasses import dataclass


def _ensure_utf8_stdout() -> None:
    # On Windows the default console encoding (cp1252) mangles characters that the
    # LLM emits (em-dashes, emoji). Reconfigure stdout/stderr to UTF-8 when possible.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_ensure_utf8_stdout()


@dataclass
class Event:
    channel: str
    message: str


class EventFeed:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.events: list[Event] = []
        try:
            from rich.console import Console

            self._console = Console()
        except Exception:
            self._console = None

    def emit(self, channel: str, message: str) -> None:
        event = Event(channel=channel, message=message)
        self.events.append(event)
        if self.quiet:
            return
        text = f"[{channel}] {message}"
        if self._console is not None:
            self._console.print(text)
        else:
            print(text)
