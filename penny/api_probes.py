"""Active API-layer probes: JWT tampering (A021) and GraphQL introspection (A022).

These target weaknesses specific to token-based auth and GraphQL APIs rather than
generic input handling:

* ``probe_jwt_tampering`` (A021) — checks whether a protected endpoint accepts a
  forged JSON Web Token. We synthesize structurally-valid but **unsigned** tokens —
  an ``alg:none`` token and an ``alg:HS256`` token with an empty/garbage signature —
  and compare the response to a no-token baseline. If a forged token is accepted
  where no token is rejected, the server is not verifying the signature, so anyone
  can mint admin tokens. We never use a real secret or a captured token; the forged
  tokens carry only synthetic claims.
* ``probe_graphql_introspection`` (A022) — sends the standard introspection query to
  common GraphQL paths. A production API that answers ``__schema`` hands an attacker
  the full type system, including hidden mutations and fields, which is a significant
  reconnaissance leak and often the first step of a GraphQL attack. Read-only: the
  introspection query reads the schema, it does not run any mutation.

Both reach the target only through :class:`~penny.guardrails.TargetGate`. JWT
tampering rides on GET requests with a forged ``Authorization`` header; introspection
is expressed as a GET with the query in the query string (the spec-supported GET form)
so it stays within the gate's GET/HEAD/OPTIONS allow-list.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

from .feed import EventFeed
from .models import Finding, Location
from .redaction import redact_text

# Endpoints that typically require authentication. A 401/403 here (no token) that
# flips to 200 with a forged token is the tampering signal. Kept curated.
_JWT_PROTECTED_PATHS = (
    "/api/me",
    "/api/user",
    "/api/users",
    "/api/account",
    "/api/profile",
    "/api/admin",
    "/me",
    "/profile",
    "/account",
    "/admin",
    "/api/orders",
    "/api/dashboard",
)
# Statuses we treat as "you are authenticated/authorized".
_AUTH_OK_STATUSES = {200, 201, 204}
# Statuses we treat as "auth required / rejected" — the expected no-token baseline.
_AUTH_DENIED_STATUSES = {401, 403}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _forge_token(header: dict[str, Any], payload: dict[str, Any], signature: str) -> str:
    head = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{head}.{body}.{signature}"


# Synthetic admin-ish claims. No real subject, no captured token — purely fabricated
# to test whether the server validates the signature at all.
_FORGED_CLAIMS = {"sub": "penny-test", "role": "admin", "admin": True, "iat": 1000000000, "exp": 4102444800}
# Two classic signature-bypass forgeries:
#   1. alg:none — the unsigned-JWT attack; a server that honors `none` skips verification.
#   2. alg:HS256 with an empty signature — catches servers that "verify" but accept blanks.
_FORGED_TOKENS = (
    ("alg:none", _forge_token({"alg": "none", "typ": "JWT"}, _FORGED_CLAIMS, "")),
    ("alg:none-cap", _forge_token({"alg": "None", "typ": "JWT"}, _FORGED_CLAIMS, "")),
    ("empty-sig HS256", _forge_token({"alg": "HS256", "typ": "JWT"}, _FORGED_CLAIMS, "")),
    ("garbage-sig HS256", _forge_token({"alg": "HS256", "typ": "JWT"}, _FORGED_CLAIMS, "cGVubnk")),
)


def probe_jwt_tampering(
    gate,
    *,
    paths: Iterable[str] | None = None,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect missing JWT signature verification by sending forged, unsigned tokens.

    For each candidate protected path we first confirm the no-token request is denied
    (401/403). We then replay it with forged ``alg:none`` and empty/garbage-signature
    tokens carrying synthetic admin claims. If a forged token is *accepted* where the
    bare request was *denied*, the server is not verifying the signature — an attacker
    can mint arbitrary tokens. The tokens are fabricated; no real secret or captured
    token is used.
    """
    candidate_paths = list(paths) if paths is not None else list(_JWT_PROTECTED_PATHS)
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path in dict.fromkeys(candidate_paths):
        try:
            baseline = gate.request("GET", path)
        except Exception:  # noqa: BLE001
            continue
        # Only meaningful where the endpoint actually gates on auth: a bare request
        # must be denied. A path that returns 200 with no token is just public.
        if baseline.status_code not in _AUTH_DENIED_STATUSES:
            continue
        hit = _jwt_path_hit(gate, path, baseline)
        if hit:
            hits.append(hit)
            if feed:
                feed.emit("red", f"Forged JWT accepted at {path} ({hit['forgery']})")
        elif feed:
            feed.emit("red", f"JWT verification holds at {path}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="JWT signature not verified (forged token accepted)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A021",
            owasp=[
                "A02:2021-Cryptographic Failures",
                "A07:2021-Identification and Authentication Failures",
                "API2:2023-Broken Authentication",
                "WSTG-SESS-10",
            ],
            location=Location(file=f"dynamic:{hits[0]['path']}", line=1, column=1),
            snippet=f"{len(hits)} protected endpoint(s) accepted an unsigned/forged JWT.",
            evidence={
                "dynamic_probe": {
                    "probe": "jwt_tampering",
                    "status": "confirmed",
                    "hits": hits,
                    "stored_response": "path, forgery type, and status codes only — no real tokens",
                },
                "attack_path": "The server accepts a JWT whose signature it never validated (alg:none or empty signature), so an attacker can forge a token with any identity or role and access protected functionality as any user, including admin.",
            },
            impact="Unverified JWT signatures let an attacker impersonate any user and escalate to admin, fully bypassing authentication.",
            remediation="Verify every token's signature with a fixed, server-side algorithm and key; reject the `none` algorithm, empty signatures, and tokens whose `alg` is attacker-controlled.",
        )
    )
    return findings


def _jwt_path_hit(gate, path: str, baseline) -> dict[str, Any] | None:
    for forgery, token in _FORGED_TOKENS:
        try:
            response = gate.request("GET", path, headers={"Authorization": f"Bearer {token}"})
        except Exception:  # noqa: BLE001
            continue
        # Baseline is already known to be 401/403 (filtered by the caller), so an
        # OK status here means the forged token was accepted → signature not checked.
        if response.status_code in _AUTH_OK_STATUSES:
            return {
                "path": path,
                "forgery": forgery,
                "baseline_status": baseline.status_code,
                "forged_status": response.status_code,
            }
    return None


# --- A022: GraphQL introspection -------------------------------------------

_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql", "/graphql/v1")
# The minimal introspection query. Read-only — it reads the schema, runs no mutation.
_INTROSPECTION_QUERY = "{__schema{queryType{name} types{name kind}}}"
_GRAPHQL_SCHEMA_RE = re.compile(r'"__schema"\s*:\s*\{|"queryType"\s*:\s*\{|"types"\s*:\s*\[')
_GRAPHQL_MUTATION_RE = re.compile(r'"mutationType"\s*:\s*\{[^}]*"name"', re.S)


def probe_graphql_introspection(
    gate,
    *,
    paths: Iterable[str] | None = None,
    feed: EventFeed | None = None,
) -> list[Finding]:
    """Detect an exposed GraphQL schema via introspection on common endpoints.

    We send the standard ``__schema`` introspection query (as a GET, the spec's
    supported form, so it stays inside the gate's allow-list) to common GraphQL
    paths. A response containing the introspection result means the schema — every
    type, query, and hidden mutation — is readable, a significant recon leak that
    should be disabled in production. Read-only.
    """
    candidate_paths = list(paths) if paths is not None else list(_GRAPHQL_PATHS)
    findings: list[Finding] = []
    hits: list[dict[str, Any]] = []
    for path in dict.fromkeys(candidate_paths):
        request_path = f"{path}?query={quote(_INTROSPECTION_QUERY, safe='')}"
        try:
            response = gate.request("GET", request_path)
        except Exception:  # noqa: BLE001
            continue
        if response.status_code == 200 and _GRAPHQL_SCHEMA_RE.search(response.text):
            hits.append(
                {
                    "path": path,
                    "response_status": response.status_code,
                    "exposes_mutations": bool(_GRAPHQL_MUTATION_RE.search(response.text)),
                }
            )
            if feed:
                feed.emit("red", f"GraphQL introspection enabled at {path}")
        elif feed:
            feed.emit("red", f"No GraphQL introspection at {path}")
    if not hits:
        return findings
    findings.append(
        Finding(
            title="GraphQL introspection enabled in production",
            severity="Low",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A022",
            owasp=[
                "A05:2021-Security Misconfiguration",
                "API8:2023-Security Misconfiguration",
                "API9:2023-Improper Inventory Management",
                "WSTG-CONF-05",
            ],
            location=Location(file=f"dynamic:{hits[0]['path']}", line=1, column=1),
            snippet=f"{len(hits)} GraphQL endpoint(s) answered the introspection query.",
            evidence={
                "dynamic_probe": {
                    "probe": "graphql_introspection",
                    "status": "confirmed",
                    "hits": hits,
                    "stored_response": "path, status, and whether mutations are exposed only",
                },
                "attack_path": "Introspection returns the full GraphQL type system, revealing every query, mutation, and field — including ones not used by the front end — which an attacker uses to map and target the API.",
            },
            impact="An exposed schema gives attackers a complete map of the API, including hidden mutations and fields, accelerating targeted attacks.",
            remediation="Disable introspection in production (or restrict it to authenticated/internal callers), and do not rely on schema obscurity for authorization.",
        )
    )
    return findings
