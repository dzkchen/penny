"""Bounded brute-force probing for owned/consented targets.

Two kinds of brute-force, both small and rate-limited through TargetGate:
1. Path discovery: try a categorized wordlist of common sensitive paths (secrets,
   version-control, config, backups, admin, debug, api) plus editor/backup-file
   permutations, and report any that return 200. The category drives severity:
   leaking a secret/VCS/backup file is Critical, other surfaces are High.
2. Login spray: try a tiny list of weak default credentials against a detected
   login endpoint via GET-style basic-auth checks only (no destructive POST).

Safety: localhost/private targets by default; public targets require i_own_this.
Hard caps on request count. Read-only methods only (GET/HEAD). This is intentionally
small — enough to demonstrate the capability without becoming a real attack tool.
"""

from __future__ import annotations

import base64
import re

from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from .models import Finding, Location

# Path wordlist grouped by category. The category drives the severity of a D020
# finding: exposing a secret/credential/VCS path is Critical, everything else is
# High. Keeping the categories here (rather than a flat list) lets the report say
# *why* a path matters instead of dumping an undifferentiated list of 200s.
_PATH_GROUPS: dict[str, list[str]] = {
    "secrets": [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/.env.backup",
        "/.aws/credentials",
        "/.aws/config",
        "/.ssh/id_rsa",
        "/.npmrc",
        "/.netrc",
        "/.docker/config.json",
        "/secrets.json",
        "/credentials.json",
    ],
    "version-control": [
        "/.git/config",
        "/.git/HEAD",
        "/.gitignore",
        "/.svn/entries",
        "/.hg/hgrc",
    ],
    "config": [
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/appsettings.json",
        "/wp-config.php",
        "/web.config",
        "/settings.py",
        "/database.yml",
        "/docker-compose.yml",
        "/Dockerfile",
        "/.gitlab-ci.yml",
    ],
    "backup": [
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/db.sqlite",
    ],
    "admin": [
        "/admin",
        "/administrator",
        "/wp-admin/",
        "/manage",
        "/dashboard",
        "/api/admin",
    ],
    "debug": [
        "/api/debug",
        "/debug",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/metrics",
        "/.well-known/security.txt",
    ],
    "api": [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/graphql",
        "/api/users",
    ],
}

# Categories whose exposure is severe enough to make the whole finding Critical.
_CRITICAL_CATEGORIES = {"secrets", "version-control", "backup"}

# Base files worth checking for editor/leftover backup copies, and the suffixes
# that commonly leak source (editor swap files, `cp x x.bak`, etc.).
_BACKUP_BASES = ("/index.php", "/config.php", "/config.json", "/wp-config.php", "/.env")
_BACKUP_SUFFIXES = ("~", ".bak", ".old", ".save", ".orig", ".swp")


def _build_path_index() -> dict[str, str]:
    """Map every built-in path to its category (backup permutations included)."""
    index: dict[str, str] = {}
    for category, paths in _PATH_GROUPS.items():
        for path in paths:
            index.setdefault(path, category)
    for base in _BACKUP_BASES:
        for suffix in _BACKUP_SUFFIXES:
            index.setdefault(f"{base}{suffix}", "backup")
    return index


_PATH_CATEGORY = _build_path_index()
COMMON_PATHS = list(_PATH_CATEGORY)

WEAK_LOGINS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
]

LOGIN_PATHS = ["/login", "/api/login", "/auth/login"]

# Random paths that should not exist on any real server. If the target answers
# these with an identical 200 page, it has a catch-all responder (SPA history
# fallback, Vite/CRA dev server, wildcard route) and a bare 200 proves nothing.
_RANDOM_PROBE_PATHS = ("/__penny_probe_missing_a1b2__", "/__penny_probe_missing_c3d4__/x.y")
# A credential that must never be valid; the login spray only trusts a "success"
# response if it differs from how this deliberately-wrong credential is handled.
_BOGUS_LOGIN = base64.b64encode(b"penny-nonexistent-user:penny-definitely-wrong-pw").decode()


def _normalized_body(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())[:512]


def _catch_all_body(gate) -> str | None:
    """Return the shared body of a wildcard/catch-all responder, else ``None``.

    Probes a couple of paths that cannot legitimately exist. If they all return an
    identical, non-empty 200, the server serves the same page for everything, so a
    200 on a "sensitive" path is meaningless. ``None`` means the server actually
    distinguishes missing resources (e.g. real 404s), so a 200 is informative.
    """
    bodies: list[str] = []
    for path in _RANDOM_PROBE_PATHS:
        try:
            resp = gate.request("GET", path)
        except Exception:  # noqa: BLE001 - best-effort baseline; fall back to "no catch-all"
            return None
        if resp.status_code != 200 or not resp.text.strip():
            return None
        bodies.append(_normalized_body(resp.text))
    if len(bodies) == len(_RANDOM_PROBE_PATHS) and len(set(bodies)) == 1:
        return bodies[0]
    return None


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
    paths = _load_wordlist(wordlist)
    # Cap requests to fit the catch-all baseline, the wordlist, and the login spray
    # (one wrong-credential baseline per login path), so a big list isn't truncated.
    needed = len(_RANDOM_PROBE_PATHS) + len(paths) + len(LOGIN_PATHS) * (len(WEAK_LOGINS) + 1) + 5
    try:
        gate = TargetGate(target, i_own_this=i_own_this, max_requests=max(max_requests, needed))
    except GuardrailError as error:
        feed.emit("gate", f"Brute-force target blocked: {error}")
        return []
    return _brute_force_with_gate(gate, target, paths, feed=feed)


def _brute_force_with_gate(gate, target: str, paths: list[str], *, feed: EventFeed) -> list[Finding]:
    findings: list[Finding] = []

    # Detect a catch-all responder first. Against an SPA dev server every path
    # returns the same index.html with a 200, which previously made every path and
    # every credential look "exposed"/"accepted". When that's the case we require a
    # response to be *distinct* from that page before trusting it.
    catch_all = _catch_all_body(gate)
    if catch_all is not None:
        feed.emit(
            "red",
            "Target returns a catch-all 200 (SPA/wildcard route); a bare 200 does not confirm a "
            "path — requiring content distinct from the catch-all page",
        )

    feed.emit("red", f"Brute-force path discovery on {target} ({len(paths)} paths, read-only)")
    exposed: list[str] = []
    by_category: dict[str, list[str]] = {}
    for path in paths:
        try:
            resp = gate.request("GET", path)
        except GuardrailError as error:
            feed.emit("gate", f"Stopped brute-force: {error}")
            break
        except Exception:
            continue
        if resp.status_code != 200 or not resp.text.strip():
            continue
        if catch_all is not None and _normalized_body(resp.text) == catch_all:
            continue  # same page the server serves for everything → not a real exposure
        category = _PATH_CATEGORY.get(path, "custom")
        exposed.append(path)
        by_category.setdefault(category, []).append(path)
        feed.emit("red", f"  exposed: {path} (200, {category})")
    if exposed:
        critical = sorted(_CRITICAL_CATEGORIES & by_category.keys())
        severity = "Critical" if critical else "High"
        findings.append(
            Finding(
                title="Sensitive paths exposed via brute-force discovery",
                severity=severity,
                confidence="high",
                status="confirmed",
                source="dynamic",
                detector_id="D020",
                owasp=["A05:2021-Security Misconfiguration"],
                location=Location(file="dynamic:brute-force", line=1, column=1),
                snippet=f"{len(exposed)} sensitive path(s) returned 200"
                + (f" (incl. {', '.join(critical)})" if critical else "")
                + ".",
                evidence={
                    "dynamic_probe": {
                        "probe": "path_brute_force",
                        "status": "confirmed",
                        "exposed_paths": exposed,
                        "exposed_by_category": by_category,
                        "stored_response": "paths and status codes only",
                    }
                },
                impact="Exposed sensitive paths can leak configuration, source, credentials, or admin surfaces."
                + (" Secret/credential/source-control or backup files were reachable." if critical else ""),
                remediation="Remove or authenticate these paths and ensure deploys never ship config, .git, secrets, or backups.",
            )
        )

    # Tiny login spray via basic-auth header (read-only GET; never destructive).
    weak_hits: list[str] = []
    for login_path in LOGIN_PATHS:
        # Baseline with a credential that must never be valid. If the endpoint
        # treats a wrong credential the same as a weak one (e.g. an SPA route that
        # just renders the page on any request), the credential never mattered.
        try:
            baseline = gate.request("GET", login_path, headers={"authorization": f"Basic {_BOGUS_LOGIN}"})
        except GuardrailError as error:
            feed.emit("gate", f"Stopped login spray: {error}")
            break
        except Exception:
            continue
        baseline_body = _normalized_body(baseline.text)
        for user, password in WEAK_LOGINS:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            try:
                resp = gate.request("GET", login_path, headers={"authorization": f"Basic {token}"})
            except GuardrailError as error:
                feed.emit("gate", f"Stopped login spray: {error}")
                break
            except Exception:
                continue
            # Only a real signal when the weak credential behaves *differently*
            # from a known-bad one: the bad credential was rejected, or the weak
            # credential produced a materially different response.
            accepted = resp.status_code in {200, 302} and (
                baseline.status_code in {401, 403, 404}
                or _normalized_body(resp.text) != baseline_body
            )
            if accepted:
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
