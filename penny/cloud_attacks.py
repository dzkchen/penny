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


# Registry of cloud attack types -> runner. Extend with supabase-dump, cred-stuffing, etc.
CLOUD_ATTACKS = {
    "load": run_cloud_load_test,
}


def available_attacks() -> list[str]:
    return sorted(CLOUD_ATTACKS)
