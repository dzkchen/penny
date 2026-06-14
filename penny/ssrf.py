"""Server-Side Request Forgery probe with a self-hosted callback listener (A023).

SSRF is invisible from the response alone: when an attacker makes the server fetch
an internal URL, the proof is that *the server made a request it should not have*,
not anything echoed back. The only reliable, low-false-positive way to confirm it is
out-of-band — make the target fetch a URL that points at a listener we control and
watch for the callback.

This probe does exactly that, self-contained and with no new dependencies:

* It starts a tiny :mod:`http.server` on an ephemeral port bound to all interfaces,
  in a daemon thread, and records the path of any request it receives.
* For each candidate URL-style parameter it asks the target (via the gate, GET only)
  to fetch ``http://<our-address>/<nonce>``. The address is whichever local interface
  the target can route back to: ``127.0.0.1`` for a loopback target, otherwise the
  source IP the OS would use to reach the target host.
* If the listener receives a request carrying the unique nonce, the target fetched
  our URL — SSRF is confirmed, attributed to the exact parameter whose nonce came
  back. No nonce, no finding: the listener cannot be hit by accident.

The listener only ever *reads* the inbound request line; it serves a fixed empty
204 and stores nothing but the matched nonce. It is bound for the duration of the
probe and torn down immediately after. Authorization is the same gate every other
probe uses — localhost/private by default, public targets require a matching DNS TXT proof record.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

from .feed import EventFeed
from .models import Finding, Location

# Each injected callback URL carries a per-parameter nonce so a received request is
# attributable to exactly one (path, param). The marker keeps nonces easy to scan for.
_NONCE_MARKER = "penny-ssrf"
# Params worth pointing at the listener: anything that names a URL/host/destination,
# i.e. the classic SSRF sinks (fetchers, webhooks, image/url proxies, callbacks).
_SSRF_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "dest", "destination", "target",
    "redirect", "next", "return", "callback", "webhook", "image", "img", "fetch",
    "proxy", "host", "domain", "feed", "rss", "endpoint", "remote", "load", "file",
)
# How long, after the last request is sent, to wait for a slow server-side fetch to
# call back before giving up. Kept short so the probe stays quick.
_CALLBACK_GRACE_SECONDS = 2.0


class _CallbackHandler(BaseHTTPRequestHandler):
    # Set per-server below; collects nonces seen in inbound request paths.
    received: set[str]

    def _record(self) -> None:
        path = self.path or ""
        for nonce in list(type(self).received):
            if nonce in path:
                type(self).received.add(f"__hit__{nonce}")
        self.send_response(204)
        self.end_headers()

    # Any method that reaches us is a callback; record and answer empty.
    do_GET = _record
    do_POST = _record
    do_HEAD = _record

    def log_message(self, *args: Any) -> None:  # noqa: D401 - silence default stderr logging
        return


class _CallbackListener:
    """An ephemeral local HTTP server that records callback nonces."""

    def __init__(self) -> None:
        handler = type("_BoundHandler", (_CallbackHandler,), {"received": set()})
        self._handler = handler
        self._server = HTTPServer(("0.0.0.0", 0), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "_CallbackListener":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()

    def register(self, nonce: str) -> None:
        self._handler.received.add(nonce)

    def was_hit(self, nonce: str) -> bool:
        return f"__hit__{nonce}" in self._handler.received


def _reachable_address(target_host: str) -> str:
    """The address the target can call back to: loopback for local, else our source IP.

    The listener binds IPv4 (``0.0.0.0``), so this returns an IPv4 address. An
    IPv6-only target therefore cannot be confirmed by this probe — that is a known
    limitation (callers should surface it), not a silent pass: no callback simply
    means no finding, never a false "secure" claim.
    """
    lowered = (target_host or "").lower().strip("[]")
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return "127.0.0.1"
    # Ask the OS which local interface it would use to reach the target, without
    # sending anything (UDP connect just sets the socket's route).
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((lowered or "127.0.0.1", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def _ssrf_candidate_params(endpoints: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Keep only (path, param) pairs whose param name looks like a URL/host sink."""
    candidates: dict[tuple[str, str], None] = {}
    for path, param in endpoints:
        if any(hint in param.lower() for hint in _SSRF_PARAM_HINTS):
            candidates[(path, param)] = None
    return list(candidates)


def probe_ssrf(
    gate,
    endpoints: Iterable[tuple[str, str]],
    *,
    target: str,
    feed: EventFeed | None = None,
    listener_factory=_CallbackListener,
    reachable_address=None,
    settle=None,
) -> list[Finding]:
    """Confirm SSRF out-of-band by making the target fetch a self-hosted callback URL.

    For each URL-style parameter we inject ``http://<our-address>:<port>/<nonce>`` and
    watch a local listener for the nonce. A received nonce proves the server fetched
    our URL — SSRF — and attributes it to that exact parameter. Nonces are unique, so
    the listener cannot be triggered by accident; no nonce means no finding.
    """
    from .active import _with_param

    candidates = _ssrf_candidate_params(endpoints)
    if not candidates:
        if feed:
            feed.emit("red", "SSRF probe found no URL-style parameters to test")
        return []

    target_host = (urlparse(target).hostname or "").lower()
    address_for = reachable_address or _reachable_address
    settle = settle or _default_settle
    hits: list[dict[str, Any]] = []

    with listener_factory() as listener:
        callback_host = address_for(target_host)
        pending: list[tuple[str, str, str]] = []  # (path, param, nonce)
        for index, (path, param) in enumerate(candidates):
            nonce = f"{_NONCE_MARKER}-{index}-{listener.port}"
            listener.register(nonce)
            callback_url = f"http://{callback_host}:{listener.port}/{nonce}"
            try:
                gate.request("GET", _with_param(path, param, callback_url))
            except Exception:  # noqa: BLE001 - a blocked/failed request is simply a non-hit
                continue
            pending.append((path, param, nonce))

        # Give slow server-side fetches a moment to land before we read results.
        settle(_CALLBACK_GRACE_SECONDS)

        for path, param, nonce in pending:
            if listener.was_hit(nonce):
                hits.append({"endpoint": path, "parameter": param, "callback_host": callback_host})
                if feed:
                    feed.emit("red", f"Confirmed SSRF at {path}?{param} (callback received)")
            elif feed:
                feed.emit("red", f"No SSRF callback for {path}?{param}")

    if not hits:
        return []
    return [
        Finding(
            title="Server-Side Request Forgery confirmed (target fetched a controlled callback URL)",
            severity="High",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A023",
            owasp=["A10:2021-Server-Side Request Forgery", "WSTG-INPV-19"],
            location=Location(file=f"dynamic:{hits[0]['endpoint']}", line=1, column=1),
            snippet=f"{len(hits)} parameter(s) made the server fetch an attacker-supplied URL.",
            evidence={
                "dynamic_probe": {
                    "probe": "ssrf",
                    "status": "confirmed",
                    "hits": hits,
                    "method": "out-of-band callback to a self-hosted listener",
                    "stored_response": "endpoint, parameter, and callback host only",
                },
                "attack_path": "The server fetches a URL taken from request input, so an attacker can make it reach internal services, cloud metadata endpoints (169.254.169.254), or other hosts behind the firewall — pivoting into the internal network.",
            },
            impact="SSRF lets an attacker reach internal-only services and cloud metadata (often leaking credentials), bypassing network boundaries via the server.",
            remediation="Validate and allow-list outbound URLs (scheme, host, port); block private/link-local ranges and metadata IPs; resolve and re-check the host after DNS; and disable unused URL-fetching features.",
        )
    ]


def _default_settle(seconds: float) -> None:
    import time

    time.sleep(seconds)
