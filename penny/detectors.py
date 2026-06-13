from __future__ import annotations

import re
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Finding, Location
from .redaction import (
    KNOWN_SECRET_RE,
    PRIVATE_KEY_RE,
    SERVICE_KEY_RE,
    looks_high_entropy,
    redact_text,
)
from .repo import SourceFile


CLIENT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
DOC_EXTENSIONS = {".md", ".txt", ".rst"}
SECRET_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{32,}\b")

# Shapes that are high-entropy but routinely benign in source/config: subresource
# integrity hashes, content hashes / git SHAs, and UUIDs. Suppressing these keeps
# the committed-token detector from flagging README badges, lockfile hashes, and
# asset fingerprints.
_SRI_HASH_RE = re.compile(r"^sha(?:256|384|512)-")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HASH_DIGEST_LENGTHS = {32, 40, 56, 64, 96, 128}


def _is_benign_high_entropy_token(value: str) -> bool:
    if _SRI_HASH_RE.match(value):
        return True
    if _UUID_RE.match(value):
        return True
    if _HEX_RE.match(value) and len(value) in _HASH_DIGEST_LENGTHS:
        return True
    return False


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
        # Known-prefix secrets are flagged everywhere (a leaked `ghp_...` in a
        # README is still a real finding), but the generic high-entropy heuristic
        # produces mostly noise in prose/docs, so it is skipped there.
        is_doc = file.path.suffix.lower() in DOC_EXTENSIONS
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
            if is_doc:
                continue
            for token_match in SECRET_TOKEN_RE.finditer(line):
                value = token_match.group(0)
                if SERVICE_KEY_RE.fullmatch(value) or KNOWN_SECRET_RE.fullmatch(value):
                    continue
                if _is_benign_high_entropy_token(value):
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


@dataclass(frozen=True)
class PatternRule:
    detector_id: str
    title: str
    severity: str
    confidence: str
    owasp: tuple[str, ...]
    impact: str
    remediation: str
    pattern: re.Pattern[str]
    reason: str


# D007: committed private-key material. Scanned in every file type — a PEM header
# in source control is high-signal regardless of where it lands.
PRIVATE_KEY_RULES = (
    PatternRule(
        detector_id="D007",
        title="Committed private key",
        severity="Critical",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="A committed private key lets anyone who can read the repo impersonate the service or decrypt its traffic.",
        remediation="Remove the key from the repository and its history, rotate it immediately, and load private keys from a secret store at runtime.",
        pattern=PRIVATE_KEY_RE,
        reason="A PEM private-key header is present in source-controlled content.",
    ),
)

# D008: dangerous execution sinks. Scoped to code files to keep precision high.
DANGEROUS_SINK_RULES = (
    PatternRule(
        detector_id="D008",
        title="Dangerous command execution",
        severity="High",
        confidence="high",
        owasp=("A03:2021-Injection",),
        impact="Passing untrusted input to a shell enables command injection and remote code execution.",
        remediation="Avoid shell execution; call the program directly with an argument list (e.g. subprocess.run([...]) without shell=True).",
        pattern=re.compile(r"\bos\.system\s*\("),
        reason="os.system() runs its argument through a shell.",
    ),
    PatternRule(
        detector_id="D008",
        title="Dangerous command execution",
        severity="High",
        confidence="high",
        owasp=("A03:2021-Injection",),
        impact="A subprocess launched with shell=True interprets shell metacharacters in interpolated input.",
        remediation="Drop shell=True and pass the command as a list of arguments so user input is never parsed by a shell.",
        pattern=re.compile(r"\bsubprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"),
        reason="A subprocess call uses shell=True.",
    ),
    PatternRule(
        detector_id="D008",
        title="Unsafe deserialization",
        severity="High",
        confidence="high",
        owasp=("A08:2021-Software and Data Integrity Failures",),
        impact="Deserializing attacker-controlled data with pickle can execute arbitrary code.",
        remediation="Never unpickle untrusted data; use a safe format such as JSON for data that crosses a trust boundary.",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        reason="pickle deserialization can instantiate arbitrary objects.",
    ),
    PatternRule(
        detector_id="D008",
        title="Unsafe deserialization",
        severity="High",
        confidence="medium",
        owasp=("A08:2021-Software and Data Integrity Failures",),
        impact="yaml.load() without a safe loader can construct arbitrary Python objects from untrusted input.",
        remediation="Use yaml.safe_load() (or pass Loader=SafeLoader) for any externally supplied YAML.",
        pattern=re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=)"),
        reason="yaml.load() is called without an explicit safe loader.",
    ),
    PatternRule(
        detector_id="D008",
        title="Dynamic code evaluation",
        severity="High",
        confidence="medium",
        owasp=("A03:2021-Injection",),
        impact="Evaluating runtime values as code lets attacker-controlled input run with full program privileges.",
        remediation="Replace eval/exec with explicit parsing or a lookup table; never evaluate user-influenced strings.",
        pattern=re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        reason="A dynamic eval/exec call evaluates a runtime value.",
    ),
    PatternRule(
        detector_id="D008",
        title="Dangerous command execution",
        severity="High",
        confidence="medium",
        owasp=("A03:2021-Injection",),
        impact="child_process.exec() runs its argument through a shell, enabling command injection.",
        remediation="Use child_process.execFile()/spawn() with an argument array instead of exec().",
        pattern=re.compile(r"\bchild_process\.exec\s*\(|\bexec\s*\(\s*`"),
        reason="A shell-based child_process.exec() call is used.",
    ),
)

# D010: transport security explicitly disabled.
TLS_RULES = (
    PatternRule(
        detector_id="D010",
        title="TLS certificate verification disabled",
        severity="High",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="Disabling certificate verification exposes traffic to man-in-the-middle interception.",
        remediation="Keep certificate verification enabled; pin or supply a trusted CA bundle instead of turning verification off.",
        pattern=re.compile(r"\bverify\s*=\s*False\b"),
        reason="An HTTP client call disables certificate verification (verify=False).",
    ),
    PatternRule(
        detector_id="D010",
        title="TLS certificate verification disabled",
        severity="High",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="rejectUnauthorized: false accepts any certificate, exposing traffic to interception.",
        remediation="Remove rejectUnauthorized: false and trust a proper CA chain.",
        pattern=re.compile(r"rejectUnauthorized\s*:\s*false", re.I),
        reason="A Node TLS option disables certificate verification.",
    ),
    PatternRule(
        detector_id="D010",
        title="TLS certificate verification disabled",
        severity="High",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="An unverified SSL context skips certificate validation for every connection it is used on.",
        remediation="Use a default verified context (ssl.create_default_context) and supply trusted CAs as needed.",
        pattern=re.compile(r"ssl\._create_unverified_context\s*\("),
        reason="An unverified SSL context is created.",
    ),
)

# D011: production debug mode.
DEBUG_RULES = (
    PatternRule(
        detector_id="D011",
        title="Debug mode enabled",
        severity="High",
        confidence="high",
        owasp=("A05:2021-Security Misconfiguration",),
        impact="The Werkzeug/Flask debugger allows arbitrary code execution if the app is reachable.",
        remediation="Never run with debug=True outside local development; drive it from an environment flag that defaults to off.",
        pattern=re.compile(r"\.run\s*\([^)]*debug\s*=\s*True"),
        reason="A web server is started with debug=True.",
    ),
    PatternRule(
        detector_id="D011",
        title="Debug mode enabled",
        severity="Medium",
        confidence="medium",
        owasp=("A05:2021-Security Misconfiguration",),
        impact="DEBUG = True leaks stack traces, settings, and secrets in error responses.",
        remediation="Set DEBUG from an environment variable that defaults to False in production.",
        pattern=re.compile(r"\bDEBUG\s*=\s*True\b"),
        reason="A framework debug flag is hard-coded to True.",
    ),
)

# D009: SQL built by string interpolation and handed to a query call.
_SQL_EXEC_RE = re.compile(r"\.(?:execute|executemany|query|raw)\s*\(", re.I)
_SQL_KEYWORD_RE = re.compile(
    r"\b(?:select|insert\s+into|update|delete\s+from|drop\s+table|union\s+select|where)\b",
    re.I,
)
_SQL_BUILD_RE = re.compile(r"f['\"]|['\"]\s*\+|\+\s*['\"]|['\"]\s*%|%\s*\(|\.format\s*\(")


def _scan_pattern_rules(
    files: Iterable[SourceFile],
    rules: tuple[PatternRule, ...],
    *,
    extensions: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if extensions is not None and file.path.suffix.lower() not in extensions:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            for rule in rules:
                match = rule.pattern.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        status="suspected",
                        source="static",
                        detector_id=rule.detector_id,
                        owasp=list(rule.owasp),
                        location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": rule.reason},
                        impact=rule.impact,
                        remediation=rule.remediation,
                    )
                )
    return findings


def detect_private_keys(files: Iterable[SourceFile]) -> list[Finding]:
    return _scan_pattern_rules(files, PRIVATE_KEY_RULES)


def detect_dangerous_sinks(files: Iterable[SourceFile]) -> list[Finding]:
    return _scan_pattern_rules(files, DANGEROUS_SINK_RULES, extensions=CODE_EXTENSIONS)


def detect_disabled_tls_verification(files: Iterable[SourceFile]) -> list[Finding]:
    return _scan_pattern_rules(files, TLS_RULES, extensions=CODE_EXTENSIONS)


def detect_debug_mode(files: Iterable[SourceFile]) -> list[Finding]:
    return _scan_pattern_rules(files, DEBUG_RULES, extensions=CODE_EXTENSIONS)


def detect_sql_injection(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            exec_match = _SQL_EXEC_RE.search(line)
            if not exec_match:
                continue
            if not _SQL_KEYWORD_RE.search(line) or not _SQL_BUILD_RE.search(line):
                continue
            findings.append(
                Finding(
                    title="Possible SQL injection",
                    severity="High",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D009",
                    owasp=["A03:2021-Injection"],
                    location=Location(file=file.relative_path, line=line_no, column=exec_match.start() + 1),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "A SQL statement appears to be built with string interpolation and executed directly."},
                    impact="Building SQL with string interpolation lets attacker input alter the query and read or modify unintended data.",
                    remediation="Use parameterized queries (placeholders with bound parameters) instead of interpolating values into the SQL string.",
                )
            )
    return findings


def run_detectors(files: list[SourceFile]) -> list[Finding]:
    return [
        *detect_service_role_in_client(files),
        *detect_committed_secrets(files),
        *detect_permissive_access_policy(files),
        *detect_vulnerable_dependencies(files),
        *detect_permissive_cors(files),
        *detect_private_keys(files),
        *detect_dangerous_sinks(files),
        *detect_sql_injection(files),
        *detect_disabled_tls_verification(files),
        *detect_debug_mode(files),
    ]
