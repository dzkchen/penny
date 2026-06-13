from __future__ import annotations

from penny.feed import EventFeed
from penny.scanner import _clean_target


def _feed() -> EventFeed:
    return EventFeed(quiet=True)


def test_clean_target_passes_through_clean_url() -> None:
    assert _clean_target("http://localhost:8081/", _feed()) == "http://localhost:8081/"
    assert _clean_target(None, _feed()) is None


def test_clean_target_recovers_url_from_glued_flag() -> None:
    # A regular-space glued flag (what the user hit) collapses to the URL.
    assert _clean_target("http://localhost:8081/ --ai", _feed()) == "http://localhost:8081/"
    # A non-breaking space (the copy-paste artifact the shell did not split) too.
    nbsp = chr(0xA0)
    assert _clean_target(f"http://localhost:8081/{nbsp}--ai", _feed()) == "http://localhost:8081/"


def test_clean_target_warns_on_whitespace() -> None:
    feed = _feed()
    _clean_target("http://localhost:8081/ --ai --osv", feed)
    assert any("whitespace" in event.message for event in feed.events)
