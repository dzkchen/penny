from __future__ import annotations

from dataclasses import dataclass


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
