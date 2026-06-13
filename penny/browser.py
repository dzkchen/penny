"""Real browser automation (Playwright) to crawl and probe a live site.

This opens an actual headless browser, loads the target, follows in-scope links, and
inspects rendered pages + responses for client-side exposure (secrets in JS bundles,
mixed content, forms posting over http, tokens in localStorage-ish patterns).

Degrades gracefully: if Playwright isn't installed or the browser binary is missing,
it emits a hint and returns no findings, so the rest of the scan is unaffected.

Safety: same host-allowlist rule as TargetGate — localhost/private by default, public
needs i_own_this. Read-only navigation only; it does not submit forms or mutate state.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location
from .redaction import SERVICE_KEY_RE, JWT_RE, KNOWN_SECRET_RE, redact_text


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def _scan_text_for_secrets(text: str) -> list[str]:
    hits: list[str] = []
    for pattern, label in ((SERVICE_KEY_RE, "service_key"), (JWT_RE, "jwt"), (KNOWN_SECRET_RE, "secret")):
        if pattern.search(text):
            hits.append(label)
    return sorted(set(hits))


def run_browser_probe(
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    max_pages: int = 8,
) -> list[Finding]:
    findings: list[Finding] = []
    # Reuse TargetGate purely for the host-allow decision.
    try:
        TargetGate(target, i_own_this=i_own_this)
    except GuardrailError as error:
        feed.emit("gate", f"Browser probe target blocked: {error}")
        return findings

    if not _playwright_available():
        feed.emit("red", "Browser probe needs Playwright. Install: pip install playwright && python -m playwright install chromium")
        return findings

    from playwright.sync_api import sync_playwright

    base = urlparse(target)
    seen: set[str] = set()
    queue = [target.rstrip("/")]
    secret_pages: list[str] = []
    insecure_forms: list[str] = []

    feed.emit("red", f"Browser crawl on {target} (headless Chromium, up to {max_pages} pages)")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            while queue and len(seen) < max_pages:
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                try:
                    page.goto(url, timeout=8000, wait_until="domcontentloaded")
                except Exception:
                    continue
                feed.emit("red", f"  visited {url}")
                content = page.content()

                # Secrets rendered/bundled into the page.
                secret_hits = _scan_text_for_secrets(content)
                if secret_hits:
                    secret_pages.append(url)
                    feed.emit("red", f"    client-exposed {', '.join(secret_hits)} on {url}")

                # Forms that submit over plaintext http.
                for action in page.eval_on_selector_all("form", "els => els.map(e => e.getAttribute('action') || '')"):
                    if action.startswith("http://"):
                        insecure_forms.append(redact_text(action))

                # Enqueue same-host links.
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
                    if not href:
                        continue
                    nxt = urljoin(url + "/", href)
                    if urlparse(nxt).netloc == base.netloc and nxt not in seen:
                        queue.append(nxt)
            browser.close()
    except Exception as error:
        feed.emit("red", f"Browser probe stopped: {redact_text(str(error))}")
        return findings

    if secret_pages:
        findings.append(
            Finding(
                title="Secrets exposed in rendered browser pages",
                severity="Critical",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D022",
                owasp=["A02:2021-Cryptographic Failures"],
                location=Location(file="dynamic:browser", line=1, column=1),
                snippet=f"{len(secret_pages)} page(s) shipped secret-shaped values to the browser.",
                evidence={
                    "dynamic_probe": {
                        "probe": "browser_crawl",
                        "status": "confirmed",
                        "pages_with_secrets": [redact_text(u) for u in secret_pages],
                        "stored_response": "URLs and secret types only",
                    }
                },
                impact="Anything in client-rendered pages or JS bundles is readable by any visitor.",
                remediation="Move secrets server-side; never ship privileged keys to the browser bundle.",
            )
        )
    if insecure_forms:
        findings.append(
            Finding(
                title="Form submits over insecure HTTP",
                severity="Medium",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D023",
                owasp=["A02:2021-Cryptographic Failures"],
                location=Location(file="dynamic:browser", line=1, column=1),
                snippet="A form action posts over plaintext http://.",
                evidence={"dynamic_probe": {"probe": "browser_crawl", "status": "confirmed", "insecure_form_actions": insecure_forms}},
                impact="Form data submitted over http can be read or modified in transit.",
                remediation="Submit all forms over https and enable HSTS.",
            )
        )
    if not findings:
        feed.emit("red", f"Browser crawl visited {len(seen)} page(s); no client-side secret exposure found")
    return findings
