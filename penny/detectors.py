from __future__ import annotations

import re
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Finding, Location
from .redaction import KNOWN_SECRET_RE, SERVICE_KEY_RE, looks_high_entropy, redact_text
from .repo import SourceFile


CLIENT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
SECRET_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{32,}\b")


@dataclass(frozen=True)
class VulnerableDependency:
    ecosystem: str
    package: str
    vulnerable_below: tuple[int, ...]
    safe_version: str
    cve: str
    severity: str
    summary: str


VULNERABLE_DEPENDENCIES = {
    ("npm", "lodash"): VulnerableDependency(
        ecosystem="npm",
        package="lodash",
        vulnerable_below=(4, 17, 21),
        safe_version="4.17.21",
        cve="CVE-2021-23337",
        severity="High",
        summary="lodash before 4.17.21 is vulnerable to command injection through template handling.",
    ),
    ("pypi", "jinja2"): VulnerableDependency(
        ecosystem="pypi",
        package="jinja2",
        vulnerable_below=(2, 10, 2),
        safe_version="2.10.2",
        cve="CVE-2019-10906",
        severity="High",
        summary="Jinja2 before 2.10.2 can expose sandbox escape paths through format_map.",
    ),
    ("pypi", "flask"): VulnerableDependency(
        ecosystem="pypi",
        package="flask",
        vulnerable_below=(0, 12, 3),
        safe_version="0.12.3",
        cve="CVE-2018-1000656",
        severity="High",
        summary="Older Flask releases include a denial-of-service issue in JSON handling.",
    ),
}


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


def _parse_version(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts[:4])


def _version_less_than(found: str, safe: tuple[int, ...]) -> bool:
    parsed = _parse_version(found)
    if not parsed:
        return False
    max_len = max(len(parsed), len(safe))
    return parsed + (0,) * (max_len - len(parsed)) < safe + (0,) * (max_len - len(safe))


def _dependency_finding(
    *,
    file: SourceFile,
    line_no: int,
    column: int,
    package: str,
    version: str,
    vuln: VulnerableDependency,
    line: str,
) -> Finding:
    return Finding(
        title=f"Vulnerable dependency: {package} {version}",
        severity=vuln.severity,
        confidence="high",
        status="suspected",
        source="static",
        detector_id="D005",
        owasp=["A06:2021-Vulnerable and Outdated Components"],
        location=Location(file=file.relative_path, line=line_no, column=column),
        snippet=redact_text(line.strip()),
        evidence={
            "ecosystem": vuln.ecosystem,
            "package": package,
            "detected_version": version,
            "safe_version": vuln.safe_version,
            "cve": vuln.cve,
            "reason": vuln.summary,
        },
        impact="Known-vulnerable dependencies can reintroduce exploitable behavior even when application code looks safe.",
        remediation=f"Upgrade {package} to {vuln.safe_version} or later and rerun dependency tests.",
    )


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


def detect_vulnerable_dependencies(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        lower_path = file.relative_path.lower()
        if lower_path.endswith("package.json"):
            try:
                package_json = json.loads(file.text)
            except json.JSONDecodeError:
                continue
            dependency_blocks = [
                package_json.get("dependencies", {}),
                package_json.get("devDependencies", {}),
            ]
            lines = file.text.splitlines()
            for dependencies in dependency_blocks:
                if not isinstance(dependencies, dict):
                    continue
                for package, raw_version in dependencies.items():
                    key = ("npm", package.lower())
                    vuln = VULNERABLE_DEPENDENCIES.get(key)
                    if not vuln:
                        continue
                    version = str(raw_version).lstrip("^~>=< ")
                    if not _version_less_than(version, vuln.vulnerable_below):
                        continue
                    line_no = next((index for index, line in enumerate(lines, start=1) if f'"{package}"' in line), 1)
                    line = lines[line_no - 1] if lines else ""
                    findings.append(
                        _dependency_finding(
                            file=file,
                            line_no=line_no,
                            column=_line_column(line, package),
                            package=package,
                            version=version,
                            vuln=vuln,
                            line=line,
                        )
                    )
        elif lower_path.endswith("requirements.txt"):
            for line_no, line in enumerate(file.text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                match = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.!+\-]+)", stripped)
                if not match:
                    continue
                package, version = match.group(1), match.group(2)
                vuln = VULNERABLE_DEPENDENCIES.get(("pypi", package.lower()))
                if vuln and _version_less_than(version, vuln.vulnerable_below):
                    findings.append(
                        _dependency_finding(
                            file=file,
                            line_no=line_no,
                            column=_line_column(line, package),
                            package=package,
                            version=version,
                            vuln=vuln,
                            line=line,
                        )
                    )
    return findings


def detect_permissive_cors(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        re.compile(r"access-control-allow-origin['\"]?\s*[:,=]\s*['\"]\*", re.I),
        re.compile(r"access-control-allow-origin['\"]?\s*,\s*['\"]\*", re.I),
        re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", re.I),
        re.compile(r"cors\s*\([^)]*origin\s*:\s*['\"]\*['\"]", re.I),
    ]
    for file in files:
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            for pattern in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        title="Permissive CORS policy",
                        severity="Medium",
                        confidence="high",
                        status="suspected",
                        source="static",
                        detector_id="D006",
                        owasp=["A05:2021-Security Misconfiguration"],
                        location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "The application appears to allow every Origin via CORS."},
                        impact="Permissive CORS can let attacker-controlled web pages read browser-accessible API responses.",
                        remediation="Restrict Access-Control-Allow-Origin to trusted frontend origins and avoid wildcard origins on sensitive APIs.",
                    )
                )
                break
    return findings


def run_detectors(files: list[SourceFile]) -> list[Finding]:
    return [
        *detect_service_role_in_client(files),
        *detect_committed_secrets(files),
        *detect_permissive_access_policy(files),
        *detect_vulnerable_dependencies(files),
        *detect_permissive_cors(files),
    ]
