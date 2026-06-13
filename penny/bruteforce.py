"""Bounded brute-force probing for owned/consented targets.

Two kinds of brute-force, both small and rate-limited through TargetGate:
1. Path discovery: try a short wordlist of common sensitive paths (.env, /admin,
   /api/debug, etc.) and report any that return 200.
2. Login spray: try a tiny list of weak default credentials against a detected
   login endpoint via GET-style basic-auth checks only (no destructive POST).

Safety: localhost/private targets by default; public targets require i_own_this.
Hard caps on request count. Read-only methods only (GET/HEAD). This is intentionally
small — enough to demonstrate the capability without becoming a real attack tool.
"""

from __future__ import annotations

import base64

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location

COMMON_PATHS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/api/debug",
    "/api/admin",
    "/config.json",
    "/backup.zip",
    "/.aws/credentials",
    "/server-status",
    "/actuator/health",
    "/swagger.json",
    "/api/users",
]

WEAK_LOGINS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
]

LOGIN_PATHS = ["/login", "/api/login", "/auth/login"]


def _load_wordlist(wordlist: str | None) -> list[str]:
    """Load a user-supplied wordlist file (one path per line), else the built-in list."""
    if not wordlist:
        return COMMON_PATHS
    from pathlib import Path

    try:
        lines = Path(wordlist).read_text(encoding="utf-8").splitlines()
    except OSError:
        return COMMON_PATHS
    paths = []
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        paths.append(entry if entry.startswith("/") else "/" + entry)
    return paths or COMMON_PATHS


def run_brute_force(
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    wordlist: str | None = None,
    max_requests: int = 40,
) -> list[Finding]:
    findings: list[Finding] = []
    paths = _load_wordlist(wordlist)
    # Cap requests to fit the wordlist plus the login spray, so a big list isn't truncated.
    needed = len(paths) + len(LOGIN_PATHS) * len(WEAK_LOGINS) + 5
    try:
        gate = TargetGate(target, i_own_this=i_own_this, max_requests=max(max_requests, needed))
    except GuardrailError as error:
        feed.emit("gate", f"Brute-force target blocked: {error}")
        return findings

    feed.emit("red", f"Brute-force path discovery on {target} ({len(paths)} paths, read-only)")
    exposed: list[str] = []
    for path in paths:
        try:
            resp = gate.request("GET", path)
        except GuardrailError as error:
            feed.emit("gate", f"Stopped brute-force: {error}")
            break
        except Exception:
            continue
        if resp.status_code == 200 and resp.text.strip():
            exposed.append(path)
            feed.emit("red", f"  exposed: {path} (200)")
    if exposed:
        findings.append(
            Finding(
                title="Sensitive paths exposed via brute-force discovery",
                severity="High",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D020",
                owasp=["A05:2021-Security Misconfiguration"],
                location=Location(file="dynamic:brute-force", line=1, column=1),
                snippet=f"{len(exposed)} common sensitive path(s) returned 200.",
                evidence={
                    "dynamic_probe": {
                        "probe": "path_brute_force",
                        "status": "confirmed",
                        "exposed_paths": exposed,
                        "stored_response": "paths and status codes only",
                    }
                },
                impact="Exposed sensitive paths can leak configuration, source, or admin surfaces.",
                remediation="Remove or authenticate these paths and ensure deploys never ship config, .git, or backups.",
            )
        )

    # Tiny login spray via basic-auth header (read-only GET; never destructive).
    weak_hits: list[str] = []
    for login_path in LOGIN_PATHS:
        for user, password in WEAK_LOGINS:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            try:
                resp = gate.request("GET", login_path, headers={"authorization": f"Basic {token}"})
            except GuardrailError as error:
                feed.emit("gate", f"Stopped login spray: {error}")
                break
            except Exception:
                continue
            if resp.status_code in {200, 302}:
                weak_hits.append(f"{login_path} ({user}:****)")
                feed.emit("red", f"  weak login accepted at {login_path} for {user}")
    if weak_hits:
        findings.append(
            Finding(
                title="Weak default credentials accepted",
                severity="Critical",
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D021",
                owasp=["A07:2021-Identification and Authentication Failures"],
                location=Location(file="dynamic:login", line=1, column=1),
                snippet="A default/weak credential was accepted by a login endpoint.",
                evidence={
                    "dynamic_probe": {
                        "probe": "login_spray",
                        "status": "confirmed",
                        "weak_endpoints": weak_hits,
                        "stored_response": "endpoint + username only; passwords redacted",
                    }
                },
                impact="Default credentials let anyone authenticate as a privileged user.",
                remediation="Disable default accounts, enforce strong passwords, and add rate limiting / lockout.",
            )
        )

    if not findings:
        feed.emit("red", "Brute-force completed: no exposed paths or weak logins found")
    return findings
