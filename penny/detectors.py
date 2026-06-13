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


SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# A high-entropy token sitting inside a URL is almost always a doc/asset id, not
# a credential (real URL-borne secrets use known prefixes, caught separately).
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")


def _is_benign_high_entropy_token(value: str) -> bool:
    if _SRI_HASH_RE.match(value):
        return True
    if _UUID_RE.match(value):
        return True
    if _HEX_RE.match(value) and len(value) in _HASH_DIGEST_LENGTHS:
        return True
    return False


def _within_url(line: str, start: int, end: int) -> bool:
    return any(match.start() <= start and end <= match.end() for match in _URL_RE.finditer(line))


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


def _max_severity(severities: Iterable[str]) -> str:
    best, best_rank = "Info", 99
    for severity in severities:
        rank = SEVERITY_RANK.get(severity, 50)
        if rank < best_rank:
            best, best_rank = severity, rank
    return best if best_rank < 99 else "High"


def _highest_version(versions: Iterable[str]) -> str:
    best, best_key = "", None
    for version in versions:
        key = _parse_version(version)
        if key and (best_key is None or key > best_key):
            best, best_key = version, key
    return best


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
                if _within_url(line, token_match.start(), token_match.end()):
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


@dataclass(frozen=True)
class ParsedDependency:
    ecosystem: str
    package: str
    version: str
    file: SourceFile
    line_no: int
    line: str


def _iter_dependencies(files: Iterable[SourceFile]) -> Iterable[ParsedDependency]:
    """Yield every (ecosystem, package, version) pin from supported manifests."""
    for file in files:
        lower_path = file.relative_path.lower()
        if lower_path.endswith("package.json"):
            try:
                package_json = json.loads(file.text)
            except json.JSONDecodeError:
                continue
            lines = file.text.splitlines()
            for block in (package_json.get("dependencies", {}), package_json.get("devDependencies", {})):
                if not isinstance(block, dict):
                    continue
                for package, raw_version in block.items():
                    version = str(raw_version).lstrip("^~>=< ")
                    line_no = next((index for index, line in enumerate(lines, start=1) if f'"{package}"' in line), 1)
                    line = lines[line_no - 1] if lines else ""
                    yield ParsedDependency("npm", package, version, file, line_no, line)
        elif lower_path.endswith("requirements.txt"):
            for line_no, line in enumerate(file.text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                match = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.!+\-]+)", stripped)
                if not match:
                    continue
                yield ParsedDependency("pypi", match.group(1), match.group(2), file, line_no, line)


@dataclass(frozen=True)
class DependencyRecord:
    package: str
    ecosystem: str
    version: str
    file: str
    line_no: int
    line: str
    advisories: tuple[dict, ...]
    source: str


def _curated_advisory(dep: ParsedDependency) -> dict | None:
    vuln = VULNERABLE_DEPENDENCIES.get((dep.ecosystem, dep.package.lower()))
    if vuln and _version_less_than(dep.version, vuln.vulnerable_below):
        return {"id": vuln.cve, "cve": vuln.cve, "severity": vuln.severity, "fixed_version": vuln.safe_version, "summary": vuln.summary}
    return None


def collect_dependency_records(files: Iterable[SourceFile], lookup=None) -> list[DependencyRecord]:
    """One record per vulnerable dependency pin.

    With ``lookup`` (e.g. OSV) each pin is checked against the live feed and
    falls back to the curated list when the feed returns nothing; without it,
    only the curated list is used.
    """
    records: list[DependencyRecord] = []
    for dep in _iter_dependencies(files):
        advisories: list[dict] = []
        source = "curated"
        if lookup is not None:
            for advisory in lookup(dep.ecosystem, dep.package, dep.version):
                advisories.append(
                    {
                        "id": getattr(advisory, "advisory_id", ""),
                        "cve": getattr(advisory, "cve", ""),
                        "severity": getattr(advisory, "severity", "High") or "High",
                        "fixed_version": getattr(advisory, "fixed_version", "") or "",
                        "summary": getattr(advisory, "summary", ""),
                    }
                )
            if advisories:
                source = "osv.dev"
        if not advisories:
            curated = _curated_advisory(dep)
            if curated:
                advisories = [curated]
        if not advisories:
            continue
        records.append(
            DependencyRecord(
                package=dep.package,
                ecosystem=dep.ecosystem,
                version=dep.version,
                file=dep.file.relative_path,
                line_no=dep.line_no,
                line=dep.line,
                advisories=tuple(advisories),
                source=source,
            )
        )
    return records


def build_dependencies_finding(records: list[DependencyRecord]) -> list[Finding]:
    """Collapse every vulnerable dependency into a single D005 finding (a list)."""
    if not records:
        return []
    all_severities = [adv["severity"] for record in records for adv in record.advisories]
    total_advisories = sum(len(record.advisories) for record in records)
    sources = {record.source for record in records}
    source = sources.pop() if len(sources) == 1 else "mixed"
    listed = []
    for record in records:
        cves = [adv["cve"] for adv in record.advisories if adv.get("cve")]
        recommended = _highest_version(adv.get("fixed_version", "") for adv in record.advisories)
        listed.append(
            {
                "package": record.package,
                "ecosystem": record.ecosystem,
                "detected_version": record.version,
                "location": f"{record.file}:{record.line_no}",
                "recommended_version": recommended or "see advisories",
                "advisory_count": len(record.advisories),
                "cves": cves or [adv["id"] for adv in record.advisories],
            }
        )
    first = records[0]
    package_count = len(records)
    return [
        Finding(
            title=f"Vulnerable dependencies: {package_count} package(s), {total_advisories} advisory(ies)",
            severity=_max_severity(all_severities),
            confidence="high",
            status="suspected",
            source="static",
            detector_id="D005",
            owasp=["A06:2021-Vulnerable and Outdated Components"],
            location=Location(file=first.file, line=first.line_no, column=_line_column(first.line, first.package)),
            snippet=redact_text(first.line.strip()),
            evidence={
                "package_count": package_count,
                "advisory_count": total_advisories,
                "source": source,
                "vulnerable_dependencies": listed,
            },
            impact="Known-vulnerable dependencies can reintroduce exploitable behavior even when application code looks safe.",
            remediation="Upgrade the listed packages to their recommended fixed versions (or later), regenerate lockfiles, and rerun dependency tests.",
        )
    ]


def detect_vulnerable_dependencies(files: Iterable[SourceFile]) -> list[Finding]:
    return build_dependencies_finding(collect_dependency_records(files))


def detect_dependencies_via_advisories(files: Iterable[SourceFile], lookup) -> list[Finding]:
    """One grouped D005 finding from a live advisory feed (e.g. OSV.dev).

    ``lookup(ecosystem, package, version) -> list[Advisory]`` is injected so this
    stays offline-testable; any provider exposing ``advisory_id``, ``cve``,
    ``severity``, ``summary``, and ``fixed_version`` works.
    """
    return build_dependencies_finding(collect_dependency_records(files, lookup))


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
        # Scoped to HTTP-client context so it doesn't collide with JWT's verify=False (D016).
        pattern=re.compile(r"(?:requests|httpx|aiohttp|urllib3|\bsession\b|\.(?:get|post|put|patch|delete|head|request))\b[^\n]*?\bverify\s*=\s*False\b", re.I),
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


# D012: state-changing data operations issued straight from browser code.
CLIENT_WRITE_PATTERNS = (
    (re.compile(r"\.from\([^)]*\)\s*\.\s*(?:insert|update|delete|upsert)\s*\("), "Supabase"),
    (re.compile(r"\b(?:setDoc|updateDoc|deleteDoc|addDoc)\s*\("), "Firestore"),
    (re.compile(r"\.collection\([^)]*\)[^;\n]{0,80}?\.\s*(?:add|set|update|delete)\s*\("), "Firestore"),
    (re.compile(r"\.doc\([^)]*\)\s*\.\s*(?:set|update|delete)\s*\("), "Firestore"),
    (re.compile(r"\b(?:set|update|remove|push)\s*\(\s*ref\s*\("), "Realtime Database"),
    (re.compile(r"\.ref\([^)]*\)\s*\.\s*(?:set|update|remove|push)\s*\("), "Realtime Database"),
)
_SERVER_PATH_MARKERS = ("/api/", "/server/", "/backend/", "/functions/", "/routes/", "/pages/api/", "/app/api/")


def _is_server_path(relative_path: str) -> bool:
    lowered = "/" + relative_path.lower()
    return any(marker in lowered for marker in _SERVER_PATH_MARKERS)


def detect_client_side_db_writes(files: Iterable[SourceFile]) -> list[Finding]:
    """Flag direct database/BaaS mutations in browser-shipped code.

    Covers Supabase and Firebase (Firestore modular + namespaced, and Realtime
    Database). When the client writes to the database directly (no server-side
    route to authorize the operation), access control can only come from backend
    rules — for AI-built apps that "lack a proper backend" this is the core
    trust-boundary risk. Server-side files (api/server/functions paths) excluded.
    """
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CLIENT_EXTENSIONS:
            continue
        if _is_server_path(file.relative_path):
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            for pattern, vendor in CLIENT_WRITE_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        title="Client-side database write without a server-side authorization layer",
                        severity="High",
                        confidence="medium",
                        status="suspected",
                        source="static",
                        detector_id="D012",
                        owasp=["A01:2021-Broken Access Control"],
                        location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={
                            "reason": f"A {vendor} data-mutation call runs in browser-shipped code; the client is fully attacker-controlled, so it cannot enforce access control.",
                            "vendor": vendor,
                        },
                        impact="When the browser writes to the database directly, there is no trusted server to authorize the operation. Unless backend rules (e.g. row-level security or Firebase security rules) are airtight, any user can forge, tamper with, or delete other users' data.",
                        remediation="Route privileged reads/writes through a server-side API or serverless/cloud function that authenticates the user and authorizes each operation; treat the client as untrusted and tighten the database security rules.",
                    )
                )
                break
    return findings


# D013: permissive Firebase security rules (the Firebase equivalent of D003).
_FIREBASE_RULES_FILES = ("firestore.rules", "storage.rules", "database.rules.json")
_RULES_OPEN_RE = re.compile(r"allow\s+[a-z,\s]+:\s*if\s+true\b", re.I)
_RULES_AUTH_ONLY_RE = re.compile(r"allow\s+[a-z,\s]+:\s*if\s+request\.auth\s*!=\s*null\s*;", re.I)
_RTDB_OPEN_RE = re.compile(r'"\.(?:read|write)"\s*:\s*(?:true|"true"|"auth\s*!=\s*null"|"now\b)', re.I)


def _is_firebase_rules_file(relative_path: str) -> bool:
    name = relative_path.rsplit("/", 1)[-1].lower()
    return name in _FIREBASE_RULES_FILES or name.endswith(".rules")


def detect_permissive_firebase_rules(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if not _is_firebase_rules_file(file.relative_path):
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            open_match = _RULES_OPEN_RE.search(line) or _RTDB_OPEN_RE.search(line)
            auth_only = _RULES_AUTH_ONLY_RE.search(line)
            if open_match:
                findings.append(
                    Finding(
                        title="Firebase security rule grants unrestricted access",
                        severity="High",
                        confidence="high",
                        status="suspected",
                        source="static",
                        detector_id="D013",
                        owasp=["A01:2021-Broken Access Control"],
                        location=Location(file=file.relative_path, line=line_no, column=open_match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "A Firebase rule allows read/write unconditionally (e.g. `if true` or `\".read\": true`)."},
                        impact="An open Firebase rule lets any client (often unauthenticated) read or write the affected data directly, bypassing the app entirely.",
                        remediation="Scope every rule to the authenticated owner (e.g. `allow read, write: if request.auth.uid == resource.data.ownerId`); never ship `if true` on real data.",
                    )
                )
            elif auth_only:
                findings.append(
                    Finding(
                        title="Firebase security rule authorizes any signed-in user",
                        severity="Medium",
                        confidence="medium",
                        status="suspected",
                        source="static",
                        detector_id="D013",
                        owasp=["A01:2021-Broken Access Control"],
                        location=Location(file=file.relative_path, line=line_no, column=auth_only.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "A Firebase rule authorizes any authenticated user without an ownership check."},
                        impact="`if request.auth != null` lets any signed-in user touch the data, so one user can read or modify another user's records.",
                        remediation="Add an ownership predicate such as `request.auth.uid == resource.data.ownerId` instead of allowing every authenticated user.",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Data-flow-ish detectors (D014/D015/D019/D023).
#
# Pure regex can't trace taint, so these stay high-precision by only firing when
# a dangerous *sink* and a visible *request-derived input* appear together on the
# same line. That misses multi-line flows (recall) but almost never fires on
# benign code (precision) — the tradeoff the project explicitly prefers.
# ---------------------------------------------------------------------------

# Untrusted-input markers. Express (`req.query/params/body/...`), Flask/Django
# (`request.args/form/json/...`), and JS template interpolation of `req`.
_REQUEST_INPUT_RE = re.compile(
    r"\breq(?:uest)?\.(?:query|params?|body|args|form|values|data|cookies|headers|url|path|files|json|GET|POST|get_json)\b"
    r"|\brequest\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|get_json)\b"
    r"|\$\{\s*req(?:uest)?[.\[]",
    re.I,
)
# A value is being *built* (interpolated/concatenated/formatted) rather than passed verbatim.
_STRING_BUILD_RE = re.compile(r"f['\"]|`[^`]*\$\{|['\"]\s*\+|\+\s*['\"]|\.format\s*\(|%\s*[\(s]")


def _has_request_input(fragment: str) -> bool:
    return bool(_REQUEST_INPUT_RE.search(fragment))


# D014: server-side request forgery — an outbound HTTP call whose URL is request-derived.
_SSRF_SINK_RE = re.compile(
    r"\b(?:requests\.(?:get|post|put|patch|delete|head|request)"
    r"|httpx\.(?:get|post|put|patch|delete|head|request|stream)"
    r"|urllib\.request\.urlopen|urlopen"
    r"|axios(?:\.(?:get|post|put|patch|delete|request|head))?"
    r"|node-fetch|fetch|got|superagent\.[a-z]+)\s*\(",
    re.I,
)


def detect_ssrf(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            match = _SSRF_SINK_RE.search(line)
            if not match or not _has_request_input(line[match.end() - 1 :]):
                continue
            findings.append(
                Finding(
                    title="Possible server-side request forgery (SSRF)",
                    severity="High",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D014",
                    owasp=["A10:2021-Server-Side Request Forgery"],
                    location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "An outbound HTTP request is built from request-controlled input."},
                    impact="An attacker who controls the target URL can make the server reach internal services, cloud metadata endpoints, or arbitrary hosts.",
                    remediation="Validate the destination against an allowlist of trusted hosts/schemes; never fetch a URL taken directly from user input.",
                )
            )
    return findings


# D015: path traversal — a filesystem read/serve sink fed request-derived input.
_PATH_SINK_RE = re.compile(
    r"\b(?:open|io\.open|codecs\.open"
    r"|fs\.readFile(?:Sync)?|fs\.writeFile(?:Sync)?|fs\.createReadStream|fs\.createWriteStream"
    r"|res\.sendFile|sendFile|res\.download|send_file|send_from_directory)\s*\(",
    re.I,
)


def detect_path_traversal(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            match = _PATH_SINK_RE.search(line)
            if not match or not _has_request_input(line[match.start() :]):
                continue
            findings.append(
                Finding(
                    title="Possible path traversal",
                    severity="High",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D015",
                    owasp=["A01:2021-Broken Access Control"],
                    location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "A filesystem path is built from request-controlled input."},
                    impact="An attacker can supply '../' sequences to read or write files outside the intended directory.",
                    remediation="Resolve the path and confirm it stays within an allowed base directory; reject absolute paths and '..' segments.",
                )
            )
    return findings


# D019: open redirect — a redirect target taken from request input.
_REDIRECT_SINK_RE = re.compile(
    r"\b(?:res\.redirect|response\.redirect|redirect"
    r"|location\.assign|location\.replace"
    r"|window\.location(?:\.href)?\s*=|location\.href\s*=)\s*\(?",
    re.I,
)


def detect_open_redirect(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            match = _REDIRECT_SINK_RE.search(line)
            if not match or not _has_request_input(line[match.start() :]):
                continue
            findings.append(
                Finding(
                    title="Possible open redirect",
                    severity="Medium",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D019",
                    owasp=["A01:2021-Broken Access Control"],
                    location=Location(file=file.relative_path, line=line_no, column=match.start() + 1),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "A redirect destination is taken directly from request input."},
                    impact="Open redirects let attackers craft trusted-looking links that bounce victims to phishing or malware sites.",
                    remediation="Redirect only to a fixed set of safe paths, or validate the target against an allowlist of trusted hosts.",
                )
            )
    return findings


# D023: prompt injection — untrusted input concatenated into an LLM prompt/system
# message (OWASP LLM01). On-brand for AI-built apps: regex catches the obvious
# string-built case; the --ai pass reasons about the rest.
_PROMPT_VAR_RE = re.compile(
    r"\b(?:system[_-]?prompt|sys_prompt|user_prompt|prompt|instruction|preamble|messages?|template)\b",
    re.I,
)


def detect_prompt_injection(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            if not _PROMPT_VAR_RE.search(line):
                continue
            if not _STRING_BUILD_RE.search(line) or not _has_request_input(line):
                continue
            is_system = bool(re.search(r"\b(?:system[_-]?prompt|sys_prompt|instruction|preamble)\b", line, re.I))
            match = _PROMPT_VAR_RE.search(line)
            findings.append(
                Finding(
                    title="Untrusted input built into an LLM prompt",
                    severity="High" if is_system else "Medium",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D023",
                    owasp=["A03:2021-Injection", "LLM01:2025-Prompt Injection"],
                    location=Location(file=file.relative_path, line=line_no, column=(match.start() + 1) if match else 1),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "Request-controlled input is concatenated/interpolated into an LLM prompt or message."},
                    impact="An attacker can inject instructions that override the system prompt, exfiltrate data, or abuse tools the model can call.",
                    remediation="Keep untrusted input in a clearly delimited user turn, never in the system prompt; validate/escape it and constrain tool/function permissions.",
                )
            )
    return findings


# D016: insecure JWT handling — disabled signature verification or the 'none' alg.
JWT_RULES = (
    PatternRule(
        detector_id="D016",
        title="JWT signature verification disabled",
        severity="Critical",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="Accepting the 'none' algorithm lets anyone forge a valid-looking token with any claims.",
        remediation="Pin an explicit signing algorithm (e.g. RS256/HS256) and reject 'none'; never include 'none' in the allowed algorithms.",
        pattern=re.compile(r"\balgorithms?['\"]?\s*[:=]\s*\[?\s*['\"]none['\"]", re.I),
        reason="A JWT library is configured to accept the 'none' (unsigned) algorithm.",
    ),
    PatternRule(
        detector_id="D016",
        title="JWT signature verification disabled",
        severity="High",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="Decoding a JWT without verifying its signature lets an attacker tamper with the claims.",
        remediation="Always verify the signature: pass a key and remove verify=False / verify_signature: False.",
        pattern=re.compile(r"jwt\.decode\s*\([^)]*verify\s*=\s*False|verify_signature['\"]?\s*:\s*False", re.I),
        reason="A JWT is decoded with signature verification turned off.",
    ),
)


def detect_insecure_jwt(files: Iterable[SourceFile]) -> list[Finding]:
    return _scan_pattern_rules(files, JWT_RULES, extensions=CODE_EXTENSIONS)


# D017: weak cryptography — broken modes/ciphers (unconditional) and weak hashing
# or randomness used in a security context (guarded to avoid flagging cache keys).
WEAK_CRYPTO_RULES = (
    PatternRule(
        detector_id="D017",
        title="Insecure cipher mode (ECB)",
        severity="Medium",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking structure of the data.",
        remediation="Use an authenticated mode such as AES-GCM with a unique nonce per message.",
        pattern=re.compile(r"\bMODE_ECB\b|['\"](?:aes-(?:128|192|256)-ecb|des-ecb)['\"]", re.I),
        reason="An ECB block-cipher mode is selected.",
    ),
    PatternRule(
        detector_id="D017",
        title="Broken cipher (DES/RC4)",
        severity="Medium",
        confidence="high",
        owasp=("A02:2021-Cryptographic Failures",),
        impact="DES and RC4 are cryptographically broken and must not protect sensitive data.",
        remediation="Replace DES/RC4 with a modern authenticated cipher such as AES-GCM or ChaCha20-Poly1305.",
        pattern=re.compile(r"\bcreateCipher(?:iv)?\s*\(\s*['\"](?:des|des-cbc|rc4)['\"]|\bDES\.new\s*\(|\bARC4\.new\s*\(", re.I),
        reason="A broken cipher (DES or RC4) is instantiated.",
    ),
)
_WEAK_HASH_RE = re.compile(r"\bhashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)", re.I)
_INSECURE_RANDOM_RE = re.compile(r"\bMath\.random\s*\(\s*\)|\brandom\.(?:random|randint|choice|randrange)\s*\(", re.I)
_SECURITY_CONTEXT_RE = re.compile(r"\b(?:password|passwd|pwd|secret|credential|token|salt|otp|nonce|session|api[_-]?key|reset)\b", re.I)


def detect_insecure_crypto(files: Iterable[SourceFile]) -> list[Finding]:
    findings = _scan_pattern_rules(files, WEAK_CRYPTO_RULES, extensions=CODE_EXTENSIONS)
    for file in files:
        if file.path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            if not _SECURITY_CONTEXT_RE.search(line):
                continue
            hash_match = _WEAK_HASH_RE.search(line)
            rand_match = _INSECURE_RANDOM_RE.search(line)
            if hash_match:
                findings.append(
                    Finding(
                        title="Weak hash in a security context",
                        severity="Medium",
                        confidence="medium",
                        status="suspected",
                        source="static",
                        detector_id="D017",
                        owasp=["A02:2021-Cryptographic Failures"],
                        location=Location(file=file.relative_path, line=line_no, column=hash_match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "MD5/SHA-1 is used near a password/secret/token."},
                        impact="MD5 and SHA-1 are fast and broken; hashing passwords or tokens with them is trivially attackable.",
                        remediation="Use a slow password hash (bcrypt/scrypt/Argon2) for passwords, or SHA-256+ for integrity.",
                    )
                )
            elif rand_match:
                findings.append(
                    Finding(
                        title="Insecure randomness for a secret",
                        severity="Medium",
                        confidence="medium",
                        status="suspected",
                        source="static",
                        detector_id="D017",
                        owasp=["A02:2021-Cryptographic Failures"],
                        location=Location(file=file.relative_path, line=line_no, column=rand_match.start() + 1),
                        snippet=redact_text(line.strip()),
                        evidence={"reason": "A non-cryptographic RNG is used to build a token/secret-like value."},
                        impact="Math.random()/random are predictable, so tokens or secrets generated from them can be guessed.",
                        remediation="Use a CSPRNG: crypto.randomBytes / secrets.token_urlsafe for any security-sensitive value.",
                    )
                )
    return findings


# D018: DOM XSS sinks in client code. Precision-first: the inherently-dangerous
# HTML APIs (dangerouslySetInnerHTML/v-html/insertAdjacentHTML) fire unconditionally,
# while innerHTML/outerHTML, jQuery .html(), and document.write only fire when the
# written value is dynamic — static markup literals are left alone.
_DANGEROUS_HTML_RE = re.compile(r"dangerouslySetInnerHTML|\bv-html\b|\binsertAdjacentHTML\s*\(")
_INNERHTML_RE = re.compile(r"\.(?:inner|outer)HTML\s*=\s*(\S.*)$")
_JQUERY_HTML_RE = re.compile(r"\$\([^)]*\)\.html\s*\(\s*([^)\s].*?)\)?\s*;?\s*$")
_DOCWRITE_RE = re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*(\S.*?)\)?\s*;?\s*$")
# .vue/.html templates carry v-html and inline document.write; keep them in scope.
XSS_EXTENSIONS = CLIENT_EXTENSIONS | {".vue", ".html"}


# A right-hand side that is exactly one quoted string literal — optionally
# terminated by `;` and a trailing line/block comment — is static markup, not a
# dynamic (attacker-influenceable) value. Matching the whole shape lets a trailing
# comment (`el.innerHTML = '<hr>';  // note`) stay recognized as static.
_STATIC_LITERAL_RE = re.compile(r"""^\s*(['"])(?:\\.|(?!\1).)*\1\s*;?\s*(?://.*|/\*.*)?$""")


def _is_dynamic_rhs(rhs: str) -> bool:
    """True when the assigned value is not a single static string literal."""
    rhs = rhs.strip()
    if "${" in rhs or "+" in rhs:
        return True
    return not _STATIC_LITERAL_RE.match(rhs)


def detect_xss_sinks(files: Iterable[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.path.suffix.lower() not in XSS_EXTENSIONS:
            continue
        for line_no, line in enumerate(file.text.splitlines(), start=1):
            match = _DANGEROUS_HTML_RE.search(line)
            column = None
            if match:
                column = match.start() + 1
            else:
                inner = _INNERHTML_RE.search(line)
                if inner and _is_dynamic_rhs(inner.group(1)):
                    column = inner.start() + 1
                else:
                    jq = _JQUERY_HTML_RE.search(line)
                    if jq and _is_dynamic_rhs(jq.group(1)):
                        column = jq.start() + 1
                    else:
                        docw = _DOCWRITE_RE.search(line)
                        if docw and docw.group(1).strip() not in {"", "''", '""'}:
                            column = docw.start() + 1
            if column is None:
                continue
            findings.append(
                Finding(
                    title="Possible DOM XSS sink",
                    severity="Medium",
                    confidence="medium",
                    status="suspected",
                    source="static",
                    detector_id="D018",
                    owasp=["A03:2021-Injection"],
                    location=Location(file=file.relative_path, line=line_no, column=column),
                    snippet=redact_text(line.strip()),
                    evidence={"reason": "A dynamic value is written into the DOM as HTML (innerHTML/dangerouslySetInnerHTML/v-html/jQuery .html()/document.write)."},
                    impact="Rendering attacker-influenced HTML without sanitization enables cross-site scripting.",
                    remediation="Set textContent instead of innerHTML, or sanitize the HTML with a vetted library (e.g. DOMPurify) before injecting it.",
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
        *detect_client_side_db_writes(files),
        *detect_permissive_firebase_rules(files),
        *detect_ssrf(files),
        *detect_path_traversal(files),
        *detect_insecure_jwt(files),
        *detect_insecure_crypto(files),
        *detect_xss_sinks(files),
        *detect_open_redirect(files),
        *detect_prompt_injection(files),
    ]
