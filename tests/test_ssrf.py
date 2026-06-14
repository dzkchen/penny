from __future__ import annotations

import re

from penny.guardrails import SafeResponse
from penny.ssrf import probe_ssrf


class FakeListener:
    """A self-contained stand-in for the HTTP callback listener (no sockets)."""

    def __init__(self) -> None:
        self.port = 54321
        self.registered: set[str] = set()
        self.hits: set[str] = set()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def register(self, nonce: str) -> None:
        self.registered.add(nonce)

    # Test helper: simulate the target calling back with this nonce.
    def deliver(self, nonce: str) -> None:
        self.hits.add(nonce)

    def was_hit(self, nonce: str) -> bool:
        return nonce in self.hits


_NONCE_RE = re.compile(r"penny-ssrf-\d+-\d+")


def _make_gate(listener: FakeListener, *, vulnerable: bool):
    """A gate that, for a vulnerable target, 'delivers' the callback nonce it is asked
    to fetch — emulating the server-side fetch that proves SSRF."""

    class FakeGate:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def request(self, method, path, headers=None):
            self.calls.append(path)
            if vulnerable:
                match = _NONCE_RE.search(path)
                if match:
                    listener.deliver(match.group(0))
            return SafeResponse(200, "ok", {})

    return FakeGate()


def test_ssrf_confirms_when_callback_is_received() -> None:
    listener = FakeListener()
    gate = _make_gate(listener, vulnerable=True)

    findings = probe_ssrf(
        gate,
        [("/fetch", "url")],
        target="http://app.local",
        listener_factory=lambda: listener,
        reachable_address=lambda host: "127.0.0.1",
        settle=lambda seconds: None,
    )

    assert len(findings) == 1
    assert findings[0].detector_id == "A023"
    assert findings[0].severity == "High"
    assert findings[0].evidence["dynamic_probe"]["hits"][0]["parameter"] == "url"


def test_ssrf_quiet_when_no_callback() -> None:
    listener = FakeListener()
    gate = _make_gate(listener, vulnerable=False)

    findings = probe_ssrf(
        gate,
        [("/fetch", "url")],
        target="http://app.local",
        listener_factory=lambda: listener,
        reachable_address=lambda host: "127.0.0.1",
        settle=lambda seconds: None,
    )

    assert findings == []


def test_ssrf_only_tests_url_style_parameters() -> None:
    listener = FakeListener()
    gate = _make_gate(listener, vulnerable=True)

    # `id` is not a URL-style sink, so the probe should not test it (and find nothing).
    findings = probe_ssrf(
        gate,
        [("/api/items", "id")],
        target="http://app.local",
        listener_factory=lambda: listener,
        reachable_address=lambda host: "127.0.0.1",
        settle=lambda seconds: None,
    )

    assert findings == []
    assert gate.calls == []  # no request issued for a non-URL parameter
