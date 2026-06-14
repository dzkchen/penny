from __future__ import annotations

from penny.feed import EventFeed
from penny.writes import PENNY_WRITE_MARKER, WriteResponse, run_safe_write_probe


def _feed() -> EventFeed:
    return EventFeed(quiet=True)


def test_write_probe_requires_i_accept() -> None:
    calls: list[str] = []

    def client(url, body, headers, timeout):
        calls.append(url)
        return WriteResponse(201, "{}", {})

    findings = run_safe_write_probe(
        "http://127.0.0.1:8000", i_accept=False, feed=_feed(), client=client
    )
    assert findings == []
    assert calls == []  # nothing was POSTed without consent


def test_write_probe_blocks_public_host() -> None:
    findings = run_safe_write_probe(
        "http://8.8.8.8", i_accept=True, feed=_feed(),
        client=lambda url, body, headers, timeout: WriteResponse(201, "{}", {}),
    )
    assert findings == []


def test_write_probe_flags_unauthenticated_create_and_mass_assignment() -> None:
    def client(url, body, headers, timeout):
        if url.endswith("/api/items"):
            # Accepts the create AND echoes back the unexpected field => mass assignment.
            return WriteResponse(201, f'{{"id":1,"penny_unexpected_field":"{PENNY_WRITE_MARKER}"}}', {})
        return WriteResponse(401, "unauthorized", {})

    findings = run_safe_write_probe(
        "http://127.0.0.1:8000", i_accept=True, feed=_feed(),
        endpoints=["/api/items?ignored=1"], client=client,
    )

    detector_ids = {f.detector_id for f in findings}
    titles = {f.title for f in findings}
    assert detector_ids == {"A015"}
    assert "Write endpoint accepts unauthenticated creates" in titles
    assert "Mass assignment: endpoint binds unexpected request fields" in titles


def test_write_probe_ignores_catch_all_acceptor() -> None:
    # SPA/wildcard server that "accepts" any POST identically — must not be read as
    # a real create on every candidate endpoint (the SPA catch-all FP class).
    def client(url, body, headers, timeout):
        return WriteResponse(201, "OK", {})

    findings = run_safe_write_probe(
        "http://127.0.0.1:8000", i_accept=True, feed=_feed(),
        client=client,
    )
    assert findings == []


def test_write_probe_confirm_hook_can_decline_every_write() -> None:
    calls: list[str] = []

    def client(url, body, headers, timeout):
        calls.append(url)
        return WriteResponse(201, "{}", {})

    findings = run_safe_write_probe(
        "http://127.0.0.1:8000", i_accept=True, feed=_feed(),
        client=client, confirm=lambda url: False,
    )
    assert findings == []
    assert calls == []  # confirm hook vetoed every POST
