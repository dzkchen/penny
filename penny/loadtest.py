"""Bounded load / capacity test for owned targets (detector A014).

This answers the resilience question — *does my app survive load, and where does
it start to fail?* — without being a denial-of-service tool. The difference is
deliberate and enforced:

* It is **finite and abortable**. Every run is hard-capped on total requests,
  wall-clock duration, *and* peak concurrency (see the ``CEILING_*`` constants).
  It ramps concurrency up a ladder and **stops at the first "knee"** — the point
  where error rate or latency degrades — so it gathers the resilience signal and
  then halts rather than sustaining a flood.
* It is **read-only**: GET requests to the target only, no payloads.
* It obeys the same authorization gate as every other probe via
  :func:`penny.guardrails.host_allowed` — localhost/private by default, public
  hosts require ``i_own_this``.

A dumb flood would tell you less (just "it fell over") while being a reusable
weapon; the ramp reports the *capacity knee*, which is the number you actually
want before shipping to prod. The HTTP layer is injected (``fetch``) so the
ladder/aggregation logic is unit-tested offline without real traffic.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import host_authorization_error
from .models import Finding, Location

# Hard ceilings. Inputs are clamped to these no matter what the caller passes, so
# the tool cannot be turned into an unbounded flood.
CEILING_CONCURRENCY = 200
CEILING_DURATION_SECONDS = 120.0
CEILING_TOTAL_REQUESTS = 50_000
# Per-stage request count is concurrency * this, capped, so each rung is a short burst.
REQUESTS_PER_WORKER = 20
MAX_REQUESTS_PER_STAGE = 1_000
# Concurrency ladder. Truncated at the requested max_concurrency.
CONCURRENCY_LADDER = (1, 2, 5, 10, 25, 50, 100, 150, 200)
# "Knee" thresholds: stop when ≥10% of requests fail, or p95 latency balloons to
# 8× the single-request baseline (and is meaningfully slow in absolute terms).
ERROR_RATE_KNEE = 0.10
LATENCY_KNEE_FACTOR = 8.0
LATENCY_KNEE_FLOOR_SECONDS = 1.0
# A target that already degrades at or below this concurrency is genuinely fragile.
FRAGILE_CONCURRENCY = 10

FetchResult = tuple[int, float]
# fetch(url, timeout) -> (status_code, elapsed_seconds); raises on transport error.
Fetch = Callable[[str, float], FetchResult]


def _default_fetch(url: str, timeout: float) -> FetchResult:
    start = time.monotonic()
    try:
        import httpx

        response = httpx.get(url, timeout=timeout, follow_redirects=False)
        return response.status_code, time.monotonic() - start
    except ImportError:
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        try:
            with urlopen(Request(url, method="GET"), timeout=timeout) as response:
                return int(response.status), time.monotonic() - start
        except HTTPError as error:
            return int(error.code), time.monotonic() - start


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def _run_stage(fetch: Fetch, url: str, concurrency: int, count: int, timeout: float) -> dict:
    latencies: list[float] = []
    errors = 0
    server_errors = 0
    statuses: dict[int, int] = {}

    def one() -> None:
        nonlocal errors, server_errors
        try:
            status, elapsed = fetch(url, timeout)
        except Exception:  # noqa: BLE001 - a failed request is a load signal, not a crash
            errors += 1
            return
        latencies.append(elapsed)
        statuses[status] = statuses.get(status, 0) + 1
        if status >= 500:
            server_errors += 1

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one) for _ in range(count)]
        for future in as_completed(futures):
            future.result()

    failed = errors + server_errors
    return {
        "concurrency": concurrency,
        "requests": count,
        "failed": failed,
        "error_rate": round(failed / count, 4) if count else 0.0,
        "p50_seconds": round(_percentile(latencies, 50), 4),
        "p95_seconds": round(_percentile(latencies, 95), 4),
        "statuses": {str(code): n for code, n in sorted(statuses.items())},
    }


def run_load_test(
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    max_concurrency: int = 50,
    max_total_requests: int = 5_000,
    max_duration_seconds: float = 20.0,
    timeout_seconds: float = 5.0,
    fetch: Fetch | None = None,
    now: Callable[[], float] | None = None,
) -> list[Finding]:
    """Ramp load against ``target`` until the failure knee, then stop. Bounded."""
    host = urlparse(target).hostname or target
    authorization_error = host_authorization_error(host, i_own_this)
    if authorization_error:
        feed.emit("gate", f"Load test blocked for {host}: {authorization_error}")
        return []

    fetch = fetch or _default_fetch
    now = now or time.monotonic
    # Clamp every knob to its ceiling — this is what keeps a "load test" from
    # becoming an unbounded flood.
    max_concurrency = max(1, min(max_concurrency, CEILING_CONCURRENCY))
    max_total_requests = max(1, min(max_total_requests, CEILING_TOTAL_REQUESTS))
    max_duration_seconds = min(max_duration_seconds, CEILING_DURATION_SECONDS)
    url = target if urlparse(target).scheme else f"http://{target}"

    feed.emit(
        "attack",
        f"Bounded load test on {host} (≤{max_concurrency} concurrency, ≤{max_total_requests} reqs, ≤{max_duration_seconds:.0f}s, read-only GET)",
    )

    # Baseline single-request latency to anchor the latency-knee check.
    try:
        _, baseline_latency = fetch(url, timeout_seconds)
    except Exception:  # noqa: BLE001
        baseline_latency = 0.0

    stages: list[dict] = []
    total_requests = 1
    knee: dict | None = None
    started = now()
    aborted = False

    try:
        for concurrency in CONCURRENCY_LADDER:
            if concurrency > max_concurrency:
                break
            if now() - started >= max_duration_seconds:
                feed.emit("attack", "Load test reached its time cap; stopping ramp")
                break
            remaining = max_total_requests - total_requests
            if remaining <= 0:
                feed.emit("attack", "Load test reached its request cap; stopping ramp")
                break
            count = min(concurrency * REQUESTS_PER_WORKER, MAX_REQUESTS_PER_STAGE, remaining)
            if count <= 0:
                break
            stage = _run_stage(fetch, url, concurrency, count, timeout_seconds)
            total_requests += count
            stages.append(stage)
            feed.emit(
                "red",
                f"  c={concurrency:>3}  reqs={count:>4}  errors={stage['error_rate']*100:.0f}%  p95={stage['p95_seconds']:.2f}s",
            )
            latency_knee = (
                baseline_latency > 0
                and stage["p95_seconds"] >= max(baseline_latency * LATENCY_KNEE_FACTOR, LATENCY_KNEE_FLOOR_SECONDS)
            )
            if stage["error_rate"] >= ERROR_RATE_KNEE or latency_knee:
                knee = stage
                reason = "error rate" if stage["error_rate"] >= ERROR_RATE_KNEE else "latency"
                feed.emit("attack", f"Capacity knee at concurrency {concurrency} ({reason}); stopping ramp")
                break
    except KeyboardInterrupt:
        aborted = True
        feed.emit("attack", "Load test aborted by user (Ctrl-C)")

    return _build_load_findings(
        host,
        stages,
        knee=knee,
        baseline_latency=baseline_latency,
        total_requests=total_requests,
        aborted=aborted,
    )


def _build_load_findings(
    host: str,
    stages: list[dict],
    *,
    knee: dict | None,
    baseline_latency: float,
    total_requests: int,
    aborted: bool,
) -> list[Finding]:
    if not stages:
        return []
    max_ok_concurrency = max((s["concurrency"] for s in stages if s["error_rate"] < ERROR_RATE_KNEE), default=0)
    knee_concurrency = knee["concurrency"] if knee else None
    fragile = knee_concurrency is not None and knee_concurrency <= FRAGILE_CONCURRENCY

    if fragile:
        severity, status = "Medium", "confirmed"
        title = "Limited load capacity — service degrades under light concurrency"
        snippet = f"Target degraded at only {knee_concurrency} concurrent client(s)."
        impact = (
            "The service starts erroring or stalling under modest concurrency, so a small traffic spike — "
            "or a single noisy client — can cause a self-inflicted denial of service in production."
        )
    else:
        severity, status = "Info", "informational"
        title = "Load capacity profile"
        snippet = (
            f"Sustained ~{max_ok_concurrency} concurrent client(s) cleanly"
            + (f"; degraded at {knee_concurrency}." if knee_concurrency else " across the tested range.")
        )
        impact = "Capacity baseline for the target; use it to size rate limits, autoscaling, and timeouts before launch."

    return [
        Finding(
            title=title,
            severity=severity,
            confidence="medium",
            status=status,
            source="dynamic",
            detector_id="A014",
            owasp=["A04:2021-Insecure Design", "API4:2023-Unrestricted Resource Consumption", "WSTG-BUSL-01"],
            location=Location(file=f"network:{host}", line=1, column=1),
            snippet=snippet + (" (aborted early)" if aborted else ""),
            evidence={
                "dynamic_probe": {
                    "probe": "load_test",
                    "status": status,
                    "host": host,
                    "baseline_latency_seconds": round(baseline_latency, 4),
                    "max_clean_concurrency": max_ok_concurrency,
                    "knee_concurrency": knee_concurrency,
                    "total_requests": total_requests,
                    "aborted": aborted,
                    "ladder": stages,
                    "stored_response": "per-stage concurrency, error rate, and latency percentiles only",
                },
                "attack_path": "Resource exhaustion: an attacker (or organic spike) drives concurrency past the knee to deny service.",
            },
            impact=impact,
            remediation="Add per-client rate limiting and request timeouts, set sensible connection/worker pools and autoscaling, and load-test in staging before launch.",
        )
    ]
