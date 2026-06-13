"""nuclei-style templated checks for exposed tech surfaces (detector A013).

Where ``probe_exposed_paths`` (A006) and the brute-force list (D020) look for
*generic* sensitive files, this module is a small, extensible registry of
*fingerprinted* checks: each :class:`Template` names a path, the response shape
that identifies a specific technology surface (Spring Actuator, Prometheus, a
Laravel/Symfony debug profiler, Jenkins/Grafana/Kibana panels, …), and the
severity of finding it exposed.

Everything is a read-only GET through :class:`~penny.guardrails.TargetGate`, so
it inherits the method/rate/redirect guardrails. The check is baseline-aware: a
catch-all responder (SPA dev server, wildcard route) that returns the same page
for every path cannot make a template "match", which keeps the false-positive
rate down (see the SPA catch-all guard the brute-force module also uses).

Add coverage by appending a :class:`Template` to :data:`TEMPLATES`; the runner and
tests pick it up automatically.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .feed import EventFeed
from .models import Finding, Location
from .redaction import redact_text

_MISSING_PATH = "/__penny_template_missing_resource__"


@dataclass(frozen=True)
class Template:
    id: str
    path: str
    label: str
    severity: str
    body_regex: re.Pattern[str] | None = None
    status_codes: frozenset[int] = field(default_factory=lambda: frozenset({200}))
    header_regex: tuple[str, re.Pattern[str]] | None = None
    tags: tuple[str, ...] = ()
    note: str = ""


def _t(id, path, label, severity, body=None, statuses=(200,), header=None, tags=(), note=""):
    return Template(
        id=id,
        path=path,
        label=label,
        severity=severity,
        body_regex=re.compile(body, re.I) if body else None,
        status_codes=frozenset(statuses),
        header_regex=(header[0], re.compile(header[1], re.I)) if header else None,
        tags=tags,
        note=note,
    )


# Curated fingerprint templates. Each one identifies a *specific* exposed surface
# by a distinctive response signature rather than a bare 200, so a match is
# meaningful even on servers that return 200 for unknown paths.
TEMPLATES: tuple[Template, ...] = (
    _t("spring-actuator-env", "/actuator/env", "Spring Boot actuator /env", "High",
       body=r'"propertySources"|"systemEnvironment"', tags=("spring", "infoleak"),
       note="Actuator /env leaks environment variables, often including secrets."),
    _t("spring-actuator-heapdump", "/actuator/heapdump", "Spring Boot actuator heapdump", "Critical",
       header=("content-type", r"application/octet-stream|hprof"), tags=("spring", "infoleak"),
       note="A downloadable heap dump exposes in-memory secrets, tokens, and credentials."),
    _t("spring-actuator-mappings", "/actuator/mappings", "Spring Boot actuator route map", "Medium",
       body=r'"mappings"|"dispatcherServlets"', tags=("spring", "infoleak")),
    _t("prometheus-metrics", "/metrics", "Prometheus metrics endpoint", "Low",
       body=r"(?m)^# (?:HELP|TYPE) \w+|process_cpu_seconds_total", tags=("metrics", "infoleak"),
       note="Metrics endpoints can leak internal hostnames, routes, and request volumes."),
    _t("go-pprof", "/debug/pprof/", "Go net/http/pprof profiler", "High",
       body=r"/debug/pprof/|Types of profiles available", tags=("golang", "infoleak"),
       note="pprof exposes goroutine/heap profiles and enables resource-exhaustion."),
    _t("laravel-telescope", "/telescope/requests", "Laravel Telescope dashboard", "High",
       body=r"Telescope|telescope-cmp|laravel", tags=("laravel", "debug"),
       note="Telescope exposes requests, queries, and payloads in production."),
    _t("symfony-profiler", "/_profiler", "Symfony web profiler", "High",
       body=r"Symfony Profiler|sf-toolbar|_profiler", tags=("symfony", "debug")),
    _t("django-debug-toolbar", "/__debug__/", "Django debug toolbar", "Medium",
       body=r"djDebug|django-debug-toolbar", tags=("django", "debug")),
    _t("jenkins-script", "/script", "Jenkins script console", "Critical",
       body=r"Groovy script|hudson|jenkins", tags=("jenkins", "rce"),
       note="The Jenkins script console is remote code execution if reachable unauthenticated."),
    _t("jenkins-api", "/api/json", "Jenkins JSON API", "Medium",
       body=r'"_class"\s*:\s*"hudson', tags=("jenkins",)),
    _t("phpmyadmin", "/phpmyadmin/", "phpMyAdmin console", "High",
       body=r"phpMyAdmin|pma_username", tags=("db", "panel")),
    _t("adminer", "/adminer.php", "Adminer database console", "High",
       body=r"Adminer|adminer\.org", tags=("db", "panel")),
    _t("grafana-login", "/login", "Grafana login panel", "Low",
       body=r"grafana|grafanaBootData", tags=("grafana", "panel")),
    _t("kibana", "/app/kibana", "Kibana app", "Medium",
       body=r"kbn-|kibana", tags=("elastic", "panel")),
    _t("traefik-dashboard", "/dashboard/", "Traefik dashboard", "Medium",
       body=r"traefik|<title>Traefik", tags=("traefik", "panel")),
    _t("consul-ui", "/ui/", "Consul UI", "Medium",
       body=r"consul|CONSUL_", tags=("consul", "panel")),
    _t("wordpress-login", "/wp-login.php", "WordPress login", "Low",
       body=r"wordpress|wp-submit|user_login", tags=("wordpress", "panel")),
    _t("wordpress-xmlrpc", "/xmlrpc.php", "WordPress XML-RPC", "Medium",
       body=r"XML-RPC server accepts POST requests only|xmlrpc", tags=("wordpress",),
       note="xmlrpc.php enables credential brute-force amplification and pingback SSRF."),
    _t("drupal-changelog", "/CHANGELOG.txt", "Drupal CHANGELOG", "Low",
       body=r"Drupal \d|drupal\.org", tags=("drupal", "infoleak")),
    _t("env-debug-vars", "/debug/vars", "Go expvar debug endpoint", "Medium",
       body=r'"cmdline"|"memstats"', tags=("golang", "infoleak")),
)


def _normalized_body(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())[:512]


def _catch_all_body(gate) -> str | None:
    """Body of a wildcard responder, or None if the server distinguishes 404s."""
    try:
        resp = gate.request("GET", _MISSING_PATH)
    except Exception:  # noqa: BLE001
        return None
    if resp.status_code == 200 and resp.text.strip():
        return _normalized_body(resp.text)
    return None


def _headers(response) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in getattr(response, "headers", {}).items()}


def _template_matches(template: Template, response, catch_all: str | None) -> bool:
    if response.status_code not in template.status_codes:
        return False
    # A catch-all responder serving the same page for everything proves nothing.
    if catch_all is not None and _normalized_body(response.text) == catch_all:
        return False
    if template.header_regex is not None:
        name, pattern = template.header_regex
        if not pattern.search(_headers(response).get(name.lower(), "")):
            return False
    if template.body_regex is not None:
        if not template.body_regex.search(response.text):
            return False
    return True


def _severity_rank(severity: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(severity, 0)


def run_template_checks(
    gate,
    *,
    feed: EventFeed | None = None,
    templates: Iterable[Template] = TEMPLATES,
) -> list[Finding]:
    """Run each fingerprint template (read-only GET) and aggregate matches."""
    catch_all = _catch_all_body(gate)
    matches: list[dict[str, object]] = []
    for template in templates:
        try:
            response = gate.request("GET", template.path)
        except Exception:  # noqa: BLE001 - one bad path must not stop the sweep
            continue
        if _template_matches(template, response, catch_all):
            matches.append(
                {
                    "id": template.id,
                    "path": template.path,
                    "label": template.label,
                    "severity": template.severity,
                    "status": response.status_code,
                    "tags": list(template.tags),
                    "note": template.note,
                }
            )
            if feed:
                feed.emit("red", f"  template match: {template.label} at {template.path} ({template.severity})")
    if not matches:
        if feed:
            feed.emit("red", "Template checks found no fingerprinted tech surfaces exposed")
        return []
    severity = max((match["severity"] for match in matches), key=_severity_rank)  # type: ignore[arg-type]
    return [
        Finding(
            title="Fingerprinted technology surfaces exposed",
            severity=severity,
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="A013",
            owasp=[
                "A05:2021-Security Misconfiguration",
                "A02:2025-Security Misconfiguration",
                "WSTG-INFO-02",
                "WSTG-CONF-05",
            ],
            location=Location(file="dynamic:templates", line=1, column=1),
            snippet=redact_text(f"{len(matches)} fingerprinted surface(s) matched: " + ", ".join(str(m["label"]) for m in matches)[:200]),
            evidence={
                "dynamic_probe": {
                    "probe": "templates",
                    "status": "confirmed",
                    "matches": matches,
                    "stored_response": "template id, path, status, and matched label only",
                },
                "attack_path": "Each matched surface is a known administrative, debug, or info-leak endpoint reachable without authentication.",
            },
            impact="Exposed debug consoles, profilers, metrics, and admin panels leak internals and can be direct paths to code execution or credential theft.",
            remediation="Disable or authenticate these surfaces in production; bind admin/debug tooling to internal networks and remove profilers/consoles from production builds.",
        )
    ]
