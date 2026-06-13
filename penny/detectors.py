from __future__ import annotations

import re
from collections.abc import Iterable

from .models import Finding, Location
from .redaction import KNOWN_SECRET_RE, SERVICE_KEY_RE, looks_high_entropy, redact_text
from .repo import SourceFile


CLIENT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
SECRET_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{32,}\b")


def _line_column(line: str, value: str) -> int:
    index = line.find(value)
    return index + 1 if index >= 0 else 1


def _is_client_visible(file: SourceFile) -> bool:
    path = file.relative_path.lower()
    return (
        file.path.suffix.lower() in CLIENT_EXTENSIONS
        and any(marker in path for marker in ("client", "frontend", "src", "public"))
    )


def _extract_quoted_secret(line: str) -> str | None:
    for match in re.finditer(r"['\"]([^'\"]{20,})['\"]", line):
        value = match.group(1)
        lowered = value.lower()
        if "service" in lowered and "role" in lowered:
            return value
    return None


def detect_service_role_in_client(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if not _is_client_visible(file):
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            match = SERVICE_KEY_RE.search(line)
            secret = match.group(0) if match else _extract_quoted_secret(line)
            lowered = line.lower()
            if not secret:
                continue
            findings.append(
                Finding(
                    title="Client-visible service-role credential",
                    severity="Critical",
                    confidence="high" if match else "medium",
                    status="suspected",
                    source="static",
                    detector_id="D001",
                    owasp=["A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures"],
                    location=Location(file=file.relative_path, line=line_no, column=_line_column(line, secret)),
                    snippet=redact_text(line.strip()),
                    evidence={
                        "reason": "A service-role style credential appears in client-visible code.",
                        "client_visible": True,
                    },
                    impact="A service-role key in browser-shipped code can bypass row-level access controls.",
                    remediation="Move service credentials to a server-only environment and expose only least-privilege API routes to clients.",
                    secret_value=secret,
                )
            )
    return findings


def detect_committed_secrets(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            service_match = SERVICE_KEY_RE.search(line)
            for match in KNOWN_SECRET_RE.finditer(line):
                value = match.group(0)
                if service_match and service_match.group(0) == value:
                    continue
                findings.append(
                    Finding(
                        title="Committed application secret",
                        severity="High",
                        confidence="high",
                        status="suspected",
                        source="static",
                        detector_id="D002",
                        owasp=["A02:2021-Cryptographic Failures"],
                        location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "Known secret prefix found in source-controlled file."},
                        impact="Committed secrets can be copied from source history and used outside the app.",
                        remediation="Rotate the exposed value, remove it from source, and load it from a server-side secret manager or local .env.",
                    )
                )
            for token_match in SECRET_TOKEN_RE.finditer(line):
                value = token_match.group(0)
                if SERVICE_KEY_RE.fullmatch(value) or KNOWN_SECRET_RE.fullmatch(value):
                    continue
                if not looks_high_entropy(value):
                    continue
                findings.append(
                    Finding(
                        title="High-entropy committed token",
                        severity="High",
                        confidence="medium",
                        status="suspected",
                        source="static",
                        detector_id="D002",
                        owasp=["A02:2021-Cryptographic Failures"],
                        location=Location(file=file.relative_path, line=line_no, column=token_match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "High-entropy token-shaped value found in source-controlled file."},
                        impact="High-entropy tokens in code may represent credentials that need rotation.",
                        remediation="Verify the token, rotate it if real, and replace the committed value with an environment reference.",
                    )
                )
    return findings


def detect_permissive_access_policy(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"\busing\s*\(\s*true\s*\)", re.I), "Policy predicate allows every row."),
        (re.compile(r"\bwith\s+check\s*\(\s*true\s*\)", re.I), "Write-check predicate allows every row."),
        (re.compile(r"\bdisable\s+row\s+level\s+security\b", re.I), "Row-level security is disabled."),
        (re.compile(r"\bpublic\s+bucket\b|\bbucket\s+public\s*=\s*true\b", re.I), "Storage bucket is public."),
    ]
    for file in files:
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            for pattern, reason in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        title="Permissive row-level access policy",
                        severity="High",
                        confidence="high",
                        status="suspected",
                        source="static",
                        detector_id="D003",
                        owasp=["A01:2021-Broken Access Control"],
                        location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": reason},
                        impact="A permissive policy can expose private rows or allow unauthorized writes.",
                        remediation="Require authenticated ownership predicates such as auth.uid() = user_id and enable row-level security.",
                    )
                )
    return findings


def run_detectors(files: list[SourceFile]) -> list[Finding]:
    return [
        *detect_service_role_in_client(files),
        *detect_committed_secrets(files),
        *detect_permissive_access_policy(files),
    ]
