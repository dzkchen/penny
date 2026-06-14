"""Sandbox-test orchestrator: ephemeral heretic/gemma-3 GPU box that actively breaches.

This is Penny's most aggressive tier. Flow:

    bake (one-time)   provision GPU box -> install heretic + vLLM -> abliterate gemma-3 ->
                      install a boot-time vLLM service -> snapshot the box -> destroy build box.
    sandbox-test      strict TXT-ownership gate -> provision a GPU box FROM the snapshot ->
                      wait for the local model to come up -> push & run the remote agent
                      (penny/sandbox_agent.py) -> parse JSONL findings -> destroy the box.

Authorization boundary: the target must pass the STRICT TXT-ownership gate
(:func:`penny.guardrails.host_authorization_error` with ``strict_txt=True``) — this path
never honors ``PENNY_DISABLE_TXT_PROOF``. Localhost/private still passes for plumbing tests.

Cost safety mirrors the cloud tier: confirm-before-spinup, 30-min auto-destroy backstop,
``reap()`` of expired boxes, ``MAX_BOXES`` ceiling, and ephemeral teardown in ``finally``.
"""

from __future__ import annotations

import json
import os
import shlex
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .feed import EventFeed
from .guardrails import host_authorization_error
from .models import Finding, Location
from .redaction import redact_text, redact_value
from . import vultr

SANDBOX_STATE = Path(".penny") / "sandbox.json"
# Default to a PRE-DECENSORED model (heretic/abliteration already applied and published).
# Serving an existing one is far more robust than running heretic unattended on the box —
# heretic is interactive (it prompts to save) and needs ~30-45 min of GPU. We use the
# heretic-org Qwen3-4B-*Instruct* build: ~8 GB bf16 (fits the 16 GB A16), and Instruct beats
# the Thinking variant here — the agent only needs short STRICT-JSON actions, so we skip the
# slow <think> blocks (30-90s/turn) and get more reliable formatting + lower latency.
# Must be a transformers/safetensors repo (NOT a *-GGUF). Override with PENNY_HERETIC_MODEL.
DEFAULT_HERETIC_MODEL = "heretic-org/Qwen3-4B-Instruct-2507-heretic"
MODEL_PORT = 8000
MODEL_ALIAS = "heretic"  # vLLM --served-model-name; must match sandbox_agent.py --model default
MODEL_DIR = "/opt/penny/model"  # flat, real-file model dir vLLM serves from (no HF symlink/blob cache)


# ---------------------------------------------------------------------------
# Config / snapshot state
# ---------------------------------------------------------------------------

def heretic_model() -> str:
    return os.environ.get("PENNY_HERETIC_MODEL", "").strip() or DEFAULT_HERETIC_MODEL


def _vllm_spec() -> str:
    """pip spec for vLLM. Pinned to a CUDA 12.4 (torch 2.6/cu124) build by default to match
    Vultr's GPU-image driver — the latest vLLM needs a CUDA 12.8+ driver the box doesn't have.
    Override with PENNY_VLLM_SPEC (e.g. a newer pin) if you upgrade the box driver."""
    return os.environ.get("PENNY_VLLM_SPEC", "").strip() or "vllm==0.8.5.post1"


def _transformers_spec() -> str:
    """pip spec for transformers, installed AFTER vLLM to override its (too-old) pin. The
    cu124-compatible vLLM ships a transformers that can't load newer model tokenizers
    (e.g. Qwen3-2507 -> 'Qwen2Tokenizer has no attribute all_special_tokens_extended').
    Override with PENNY_TRANSFORMERS_SPEC. Empty string skips the override."""
    return os.environ.get("PENNY_TRANSFORMERS_SPEC", "transformers==4.53.3").strip()


def _load_sandbox_state() -> dict[str, Any]:
    if not SANDBOX_STATE.exists():
        return {}
    try:
        return json.loads(SANDBOX_STATE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_sandbox_state(state: dict[str, Any]) -> None:
    SANDBOX_STATE.parent.mkdir(parents=True, exist_ok=True)
    SANDBOX_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def snapshot_id() -> str | None:
    env = os.environ.get("PENNY_SANDBOX_SNAPSHOT_ID", "").strip()
    if env:
        return env
    return _load_sandbox_state().get("snapshot_id")


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


# ---------------------------------------------------------------------------
# One-time bake: produce the heretic/gemma-3 snapshot
# ---------------------------------------------------------------------------

def _driver_script() -> str:
    """Phase 1 (cheap, before the reboot): install the NVIDIA driver.

    Vultr's base Ubuntu image ships no GPU driver, so we install it and reboot to load
    the kernel module. Kept separate from the serve step so a driver failure costs ~5 min
    rather than failing after the slow model download.
    """
    return "\n".join([
        "set -ex",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update -y",
        "apt-get install -y ubuntu-drivers-common",
        # Headless/compute driver; fall back to the desktop autoinstall, then a pinned server pkg.
        "ubuntu-drivers install --gpgpu || ubuntu-drivers install || apt-get install -y nvidia-driver-535-server",
    ])


def _serve_script(model: str) -> str:
    """Phase 2 (after reboot): verify the GPU, install vLLM in a venv, serve the model.

    A venv avoids clobbering Debian-managed system packages (the PyJWT/`--break-system-packages`
    error). The boot-time service serves the decensored model on 127.0.0.1 only; vLLM downloads
    the model into the root HF cache on first start, so the snapshot captures it for fast reuse.
    """
    hf = os.environ.get("HF_TOKEN", "").strip()
    return "\n".join([
        "set -ex",
        "export DEBIAN_FRONTEND=noninteractive",
        # Wait for any boot-time apt / unattended-upgrade to release the dpkg lock.
        "for i in $(seq 1 40); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done",
        "nvidia-smi",  # fail loudly here if the driver/GPU isn't visible
        "apt-get update -y",
        "apt-get install -y python3-venv git",
        "python3 -m venv /opt/penny/venv",
        "/opt/penny/venv/bin/pip install -U pip",
        # Pin vLLM to a torch+cu124 build so it matches the box's CUDA 12.4 driver. The latest
        # vLLM bundles a torch built for CUDA 12.8+, which this driver is too old to run.
        f"/opt/penny/venv/bin/pip install {_vllm_spec()} huggingface_hub",
        # Bump transformers past vLLM's old pin so newer model tokenizers load.
        (f"/opt/penny/venv/bin/pip install {_transformers_spec()}" if _transformers_spec() else "true"),
        # Download the model into a flat, real-file dir (NOT the HF symlink/blob cache, where a
        # 0-byte model.safetensors.index.json kept winning over re-fetches). Then VERIFY the
        # weights index before serving so an incomplete download can never be frozen into the
        # snapshot. `set -e` aborts the bake on any failure here.
        f"mkdir -p {MODEL_DIR}",
        f"HF_TOKEN={shlex.quote(hf)} /opt/penny/venv/bin/huggingface-cli download {shlex.quote(model)} --local-dir {MODEL_DIR}",
        # Must have either a non-empty sharded index or a single non-empty safetensors file...
        f"test -s {MODEL_DIR}/model.safetensors.index.json || test -s {MODEL_DIR}/model.safetensors",
        # ...and if there's an index, it must parse AND every shard it names must exist on disk.
        f"if [ -f {MODEL_DIR}/model.safetensors.index.json ]; then /opt/penny/venv/bin/python - <<'PY'\n"
        "import json, os, sys\n"
        f"d = {MODEL_DIR!r}\n"
        "m = json.load(open(os.path.join(d, 'model.safetensors.index.json')))['weight_map']\n"
        "missing = sorted({f for f in m.values() if not os.path.getsize(os.path.join(d, f))})\n"
        "sys.exit('incomplete shards: ' + ', '.join(missing)) if missing else print('index ok:', len(set(m.values())), 'shards')\n"
        "PY\n"
        "fi",
        "cat >/etc/systemd/system/penny-vllm.service <<EOF",
        "[Unit]",
        "Description=Penny sandbox vLLM (heretic gemma-3)",
        "After=network.target",
        # Disable the systemd start-limit: with Restart=always and the default burst (5 starts
        # / 10s), a slow-to-fail vLLM trips the limit and the unit jams in 'failed', so a later
        # `systemctl restart` is a silent no-op. We rely on our own crash-loop detection
        # (_wait_for_model bails on growing NRestarts) instead of systemd's lockout.
        "StartLimitIntervalSec=0",
        "[Service]",
        f"Environment=HF_TOKEN={hf}",
        f"ExecStart=/opt/penny/venv/bin/python -m vllm.entrypoints.openai.api_server "
        f"--model {MODEL_DIR} --host 127.0.0.1 --port {MODEL_PORT} "
        f"--served-model-name {MODEL_ALIAS} --max-model-len 8192 --gpu-memory-utilization 0.90 "
        f"--enforce-eager --trust-remote-code",
        "Restart=always",
        "[Install]",
        "WantedBy=multi-user.target",
        "EOF",
        "systemctl daemon-reload",
        "systemctl enable penny-vllm.service",
        "systemctl start penny-vllm.service",
    ])


def _ensure_gpu_driver(ip: str, feed: EventFeed) -> bool:
    """Make `nvidia-smi` work on the box, installing a driver only if one isn't already there.

    Vultr's GPU images usually ship with a matching driver already loaded, so we PROBE first
    and skip the install — layering a second driver on top is exactly what causes the
    "Driver/library version mismatch" NVML error. We only install (and reboot) when no
    working driver is present, then reboot up to twice to load a matching kernel module.
    """
    code, out, err = vultr.ssh_run(ip, "nvidia-smi", timeout=60)
    if code == 0:
        feed.emit("attack", f"[bake] GPU driver already present:\n{redact_text(out.strip()[-400:])}")
        return True

    feed.emit("attack", "[bake] no working GPU driver; installing (~5 min)...")
    code, out, err = vultr.ssh_run(ip, _driver_script(), timeout=900)
    if code != 0:
        feed.emit("attack", f"[bake] driver install failed ({code}): {redact_text((err or out)[-400:])}")
        return False

    for attempt in range(1, 3):
        feed.emit("attack", f"[bake] rebooting to load the driver (try {attempt})...")
        try:
            vultr.ssh_run(ip, "nohup sh -c 'sleep 1; reboot' >/dev/null 2>&1 &", timeout=20)
        except Exception:  # noqa: BLE001 - the connection drops as the box reboots; expected
            pass
        time.sleep(25)
        if not vultr.wait_for_ssh(ip, timeout=300):
            feed.emit("attack", "[bake] box did not come back after reboot")
            return False
        code, out, err = vultr.ssh_run(ip, "nvidia-smi", timeout=60)
        if code == 0:
            feed.emit("attack", f"[bake] GPU ready:\n{redact_text(out.strip()[-400:])}")
            return True
        feed.emit("attack", f"[bake] GPU still not ready: {redact_text((out or err).strip()[-200:])}")
    return False


def sandbox_bake(*, feed: EventFeed, auto_confirm: bool = False, model: str | None = None) -> str | None:
    """Provision a GPU box, serve a decensored gemma-3, snapshot it, destroy the build box.

    Returns the new snapshot id (also persisted to .penny/sandbox.json), or None on failure.
    """
    if not vultr.available():
        feed.emit("attack", "VULTR_API_KEY not set in .env — cannot bake the sandbox image")
        return None
    model = model or heretic_model()
    confirm = None if auto_confirm else _confirm
    feed.emit("attack", f"[bake] one-time: serve {model} on a GPU box, then snapshot it")
    try:
        box = vultr.provision(
            region=vultr.gpu_region(), plan=vultr.gpu_plan(),
            autodestroy_min=180, label="penny-sandbox-bake", confirm=confirm,
        )
    except vultr.VultrError as error:
        feed.emit("attack", f"[bake] provision failed: {error}")
        return None

    snap_id: str | None = None
    try:
        ip = vultr.wait_for_ip(box)
        feed.emit("attack", f"[bake] box up at {ip}; waiting for SSH...")
        if not vultr.wait_for_ssh(ip):
            feed.emit("attack", "[bake] SSH never came up; aborting")
            return None

        if not _ensure_gpu_driver(ip, feed):
            feed.emit("attack", "[bake] GPU driver could not be brought up; aborting")
            return None

        feed.emit("attack", "[bake] installing vLLM and starting the model server...")
        code, out, err = vultr.ssh_run(ip, _serve_script(model), timeout=1800)
        if code != 0:
            feed.emit("attack", f"[bake] serve setup failed (exit {code}) — last commands/output below")
            feed.emit("attack", f"[bake] STDOUT tail:\n{redact_text(out[-1200:])}")
            feed.emit("attack", f"[bake] STDERR tail:\n{redact_text(err[-1200:])}")
            return None

        feed.emit("attack", "[bake] waiting for the model to download and serve (first run is slow)...")
        if not _wait_for_model(ip, feed, timeout=1800):
            _dump_vllm_logs(ip, feed)
            feed.emit("attack", "[bake] model never came up (see vLLM log above). Aborting")
            return None

        # `/v1/models` returning 200 only means the API server is up — confirm the engine can
        # actually GENERATE before we freeze this into a snapshot, so a half-broken model never
        # gets baked (the failure mode behind the engine-core JSON crash on restore).
        if not _smoke_test_model(ip, feed):
            _dump_vllm_logs(ip, feed)
            feed.emit("attack", "[bake] model could not generate (see root cause above). Aborting before snapshot")
            return None

        # Quiesce before snapshotting: a snapshot taken while vLLM is writing its cache captures
        # half-written files that crash the engine on restore. Stop the service, drop the
        # volatile cache (keep the HF model cache), and flush the disk first.
        feed.emit("attack", "[bake] model serving; stopping it for a consistent snapshot...")
        vultr.ssh_run(ip, "systemctl stop penny-vllm.service; rm -rf /root/.cache/vllm /root/.cache/torch 2>/dev/null; sync", timeout=120)
        feed.emit("attack", "[bake] creating snapshot...")
        snap_id = vultr.create_snapshot(box.id, description=f"penny-sandbox-{model}")
        vultr.wait_for_snapshot(snap_id)
        state = _load_sandbox_state()
        state.update({"snapshot_id": snap_id, "model": model, "created_at": time.time()})
        _save_sandbox_state(state)
        feed.emit("attack", f"[bake] snapshot ready: {snap_id} (recorded in .penny/sandbox.json)")
    except Exception as error:  # noqa: BLE001
        feed.emit("attack", f"[bake] error: {error}")
    finally:
        feed.emit("attack", f"[bake] destroying build box {box.id}")
        vultr.destroy(box.id)
    return snap_id


# ---------------------------------------------------------------------------
# sandbox-test: ephemeral active-breach run
# ---------------------------------------------------------------------------

def _nrestarts(ip: str) -> int:
    """Read the vLLM service's systemd restart counter (0 on any error)."""
    try:
        _, restarts, _ = vultr.ssh_run(ip, "systemctl show penny-vllm -p NRestarts --value", timeout=20)
        return int((restarts or "").strip() or 0)
    except Exception:  # noqa: BLE001
        return 0


def _wait_for_model(ip: str, feed: EventFeed, *, timeout: float = 1200.0, poll: float = 10.0) -> bool:
    """Poll the box until the local vLLM endpoint answers.

    Bails out early if the vLLM systemd service is crash-looping (it has Restart=always, so a
    bad model/OOM shows up as a growing restart count) rather than waiting out the full timeout.
    The restart count is measured RELATIVE to a baseline captured up front, so a fresh restart
    after a self-heal isn't mistaken for a crash-loop from the old (pre-heal) count.
    """
    deadline = time.monotonic() + timeout
    probe = f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{MODEL_PORT}/v1/models"
    baseline = _nrestarts(ip)
    ticks = 0
    while time.monotonic() < deadline:
        try:
            code, out, _ = vultr.ssh_run(ip, probe, timeout=20)
            if out.strip() == "200":
                return True
        except Exception:  # noqa: BLE001
            pass
        ticks += 1
        if ticks % 6 == 0:  # ~once a minute: is it loading, or crash-looping?
            new_restarts = _nrestarts(ip) - baseline
            if new_restarts >= 3:
                feed.emit("attack", f"[sandbox] model service is crash-looping ({new_restarts} new restarts); giving up early")
                return False
            feed.emit("attack", "[sandbox] still waiting for the model to come up...")
        time.sleep(poll)
    return False


def _ensure_model_up(ip: str, feed: EventFeed) -> bool:
    """Make sure vLLM is serving; self-heal a bad snapshot cache only if it won't come up.

    A fresh restore is just slow to load (tens of GB), so we WAIT for it first — with the
    built-in crash-loop bail so a genuinely broken snapshot fails fast. We must NOT delete cache
    files pre-emptively: a config that is briefly 0 bytes mid-load would be destroyed and break an
    otherwise-good restore. Only after the model fails to come up do we assume a half-written
    snapshot cache and self-heal once (drop volatile caches + clear the systemd start-limit +
    restart). A healthy box serves during the wait and skips the heal entirely.
    """
    if _wait_for_model(ip, feed):
        return True
    feed.emit("attack", "[sandbox] model did not come up; repairing truncated model files and restarting once...")
    model = _load_sandbox_state().get("model") or heretic_model()
    heal = "; ".join([
        # The 'Expecting value: line 1 column 1 (char 0)' crash is vLLM json.load()-ing a
        # zero-byte/truncated file a snapshot captured mid-download (typically
        # model.safetensors.index.json). Delete the empty file(s) — weights are .safetensors,
        # so this only drops the tiny re-fetchable index/configs — then the volatile caches.
        f"find {MODEL_DIR} /root/.cache /tmp -type f -name '*.json' -size 0 -delete 2>/dev/null || true",
        "rm -rf /root/.cache/vllm /root/.cache/torch /tmp/torchinductor_* 2>/dev/null || true",
        # REPAIR the model: re-fetch missing/changed files into the SAME flat --local-dir vLLM
        # serves from (no HF symlink/blob cache to fight). Cheap when only the small index was bad.
        # Pull HF_TOKEN from the baked unit so gated repos still work. (Snapshots baked before
        # MODEL_DIR existed serve by HF-id and need a re-bake — this heal can't fix those.)
        f"mkdir -p {MODEL_DIR}",
        "export $(systemctl show penny-vllm -p Environment --value 2>/dev/null | tr ' ' '\\n' | grep -E '^HF_TOKEN=' || true)",
        f"/opt/penny/venv/bin/huggingface-cli download {shlex.quote(model)} --local-dir {MODEL_DIR} >/tmp/penny_hf_repair.log 2>&1 || true",
        # An older snapshot's unit may lack StartLimitIntervalSec=0, so it can be jammed in
        # 'failed' from a prior crash-loop. Drop an override + reset-failed so restart actually runs.
        "mkdir -p /etc/systemd/system/penny-vllm.service.d",
        "printf '[Unit]\\nStartLimitIntervalSec=0\\n' > /etc/systemd/system/penny-vllm.service.d/override.conf",
        "systemctl daemon-reload",
        "systemctl reset-failed penny-vllm.service 2>/dev/null || true",
        "systemctl restart penny-vllm.service",
    ])
    vultr.ssh_run(ip, heal, timeout=1800)  # a full shard re-fetch can take a while
    return _wait_for_model(ip, feed)


def _smoke_test_model(ip: str, feed: EventFeed) -> bool:
    """Confirm the served model can actually generate (not just that the API server is up)."""
    payload = json.dumps({"model": MODEL_ALIAS, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 4})
    cmd = (f"curl -s -m 90 -X POST http://127.0.0.1:{MODEL_PORT}/v1/chat/completions "
           f"-H 'Content-Type: application/json' -d {shlex.quote(payload)}")
    try:
        _, out, _ = vultr.ssh_run(ip, cmd, timeout=120)
    except Exception as error:  # noqa: BLE001
        feed.emit("attack", f"[bake] model smoke test errored: {error}")
        return False
    ok = '"choices"' in out
    feed.emit("attack", f"[bake] model smoke test: {'ok' if ok else 'FAILED'} — {redact_text(out.strip()[:200])}")
    return ok


def _dump_vllm_logs(ip: str, feed: EventFeed) -> None:
    """Surface the real vLLM startup error (crash-loop restarts otherwise bury the traceback)."""
    try:
        # Stop the service so its auto-restarts stop pushing the traceback out of the journal.
        vultr.ssh_run(ip, "systemctl stop penny-vllm.service >/dev/null 2>&1 || true", timeout=30)
        grep = ("journalctl -u penny-vllm.service --no-pager -n 800 2>&1 | "
                "grep -iE 'error|traceback|exception|raise|not .*support|unrecogni|no module|"
                # Keep the `File \"...\"` and JSON-decode lines too — they name the corrupt file
                # behind 'Expecting value: line 1 column 1 (char 0)', which the old filter dropped.
                "out of memory|oom|killed|assert|cuda|File \"|\\.json|jsondecode|expecting value' | tail -n 50 || true")
        _, hits, _ = vultr.ssh_run(ip, grep, timeout=60)
        if hits.strip():
            feed.emit("attack", f"[bake] vLLM errors:\n{redact_text(hits.strip()[-2200:])}")
        # The JSONDecodeError is usually a SYMPTOM: vLLM's parent reads an empty handshake from
        # an engine-core worker that already died. Capture the REAL root cause — the worker's own
        # 'EngineCore'/import/CUDA/OOM error, which prints BEFORE the JSON line.
        root = ("journalctl -u penny-vllm.service --no-pager -n 1200 2>&1 | "
                "grep -niE 'enginecore|engine core failed|worker|failed to (start|load)|safetensors|"
                "importerror|modulenotfound|no such file|permission denied|cuda error|out of memory|"
                "oom|killed|valueerror|keyerror|oserror|runtimeerror:' | grep -ivE 'engine core init"
                "ialization failed' | tail -n 30 || true")
        _, rootc, _ = vultr.ssh_run(ip, root, timeout=60)
        if rootc.strip():
            feed.emit("attack", f"[bake] vLLM root cause:\n{redact_text(rootc.strip()[-1800:])}")
        # Wider context above the JSON error to expose the caller frame that names the file/step.
        ctx = ("journalctl -u penny-vllm.service --no-pager -n 1200 2>&1 | "
               "grep -niE -B20 'jsondecodeerror|expecting value' | tail -n 40 || true")
        _, jctx, _ = vultr.ssh_run(ip, ctx, timeout=60)
        if jctx.strip():
            feed.emit("attack", f"[bake] JSON-decode context:\n{redact_text(jctx.strip()[-1800:])}")
        # Definitively list any genuinely-empty JSON files (vs. an empty-handshake red herring).
        _, empties, _ = vultr.ssh_run(
            ip, "find /root/.cache /root/.config /tmp /.cache -type f -name '*.json' -size 0 2>/dev/null | head -40 || true",
            timeout=60,
        )
        msg = empties.strip() or "(none — so the empty JSON is an empty engine-core handshake; the worker died for the root-cause reason above)"
        feed.emit("attack", f"[bake] empty JSON files in cache:\n{redact_text(msg)}")
        _, tail, terr = vultr.ssh_run(ip, "journalctl -u penny-vllm.service --no-pager -n 40 2>&1 || true", timeout=60)
        feed.emit("attack", f"[bake] vLLM log tail:\n{redact_text((tail or terr).strip()[-1600:]) or '(no logs)'}")
    except Exception as error:  # noqa: BLE001
        feed.emit("attack", f"[bake] could not fetch vLLM logs: {error}")


def _agent_source() -> str:
    return (Path(__file__).with_name("sandbox_agent.py")).read_text(encoding="utf-8")


def _finding_from_jsonl(obj: dict, target: str) -> Finding:
    """Build a redacted Finding from a remote ``{"finding": {...}}`` JSONL payload."""
    raw = redact_value(obj)
    return Finding(
        title=str(raw.get("title", "Active exploit confirmed (sandbox)")),
        severity=str(raw.get("severity", "High")),
        confidence=str(raw.get("confidence", "high")),
        status="confirmed",
        source="dynamic",
        detector_id="H001",
        owasp=list(raw.get("owasp") or ["A01:2021-Broken Access Control"]),
        location=Location(file=str(raw.get("location_file") or f"sandbox:{target}"), line=1, column=1),
        snippet=str(raw.get("snippet", ""))[:300],
        evidence={"dynamic_probe": {"probe": "heretic_sandbox", "status": "confirmed",
                                    **(raw.get("evidence") or {})}},
        impact=str(raw.get("impact", "")),
        remediation=str(raw.get("remediation", "")),
    )


def sandbox_test(
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    keep_alive: bool = False,
    auto_confirm: bool = False,
    allow_destructive: bool = False,
    max_requests: int = 60,
    max_turns: int = 24,
) -> list[Finding]:
    """Spin an ephemeral heretic/gemma-3 GPU box, actively breach `target`, then destroy it."""
    if not vultr.available():
        feed.emit("attack", "VULTR_API_KEY not set in .env — cannot use the sandbox tier")
        return []

    # Ownership gate. By default the sandbox tier requires a real DNS TXT proof (strict),
    # but for local testing it honors PENNY_DISABLE_TXT_PROOF like the rest of Penny — with
    # a loud warning, since this is the active-exploitation tier. (--i-own-this is still
    # required for public hosts even when the TXT check is bypassed.)
    host = urlparse(target).hostname
    bypass = os.environ.get("PENNY_DISABLE_TXT_PROOF", "").strip() in ("1", "true", "yes")
    error = host_authorization_error(host, i_own_this, strict_txt=not bypass)
    if error:
        feed.emit("gate", f"Sandbox-test blocked: {error}")
        return []
    if bypass:
        feed.emit("gate", "⚠️  PENNY_DISABLE_TXT_PROOF set — TXT ownership proof SKIPPED for sandbox-test "
                          "(testing only; unset it for real targets)")

    # Reuse a still-running kept box from an earlier --keep-alive run if there is one — this
    # skips the slow snapshot restore entirely (vLLM is already loaded).
    box = _reusable_box()
    reused = box is not None
    if reused:
        feed.emit("attack", f"[sandbox] reusing kept box {box.id} at {box.ip} (no provision/restore)")
        if not vultr.wait_for_ssh(box.ip, timeout=30):
            feed.emit("attack", "[sandbox] kept box unreachable; destroying it and provisioning fresh")
            vultr.destroy(box.id)
            box, reused = None, False

    if box is None:
        snap = snapshot_id()
        if not snap:
            feed.emit("attack", "No sandbox snapshot found. Run /sandbox-bake once first (or set PENNY_SANDBOX_SNAPSHOT_ID).")
            return []
        confirm = None if auto_confirm else _confirm
        try:
            box = vultr.provision(
                region=vultr.gpu_region(), plan=vultr.gpu_plan(), snapshot_id=snap,
                label="penny-sandbox", autodestroy_min=90, confirm=confirm,
            )
        except vultr.VultrError as exc:
            feed.emit("attack", f"Provision failed: {exc}")
            return []
        feed.emit("attack", f"[sandbox] box {box.id} provisioning from snapshot (auto-destroys in 90m)...")

    findings: list[Finding] = []
    box_destroyed = False
    try:
        if reused:
            ip = box.ip
        else:
            # Restoring a large snapshot (OS + driver + vLLM + baked model, tens of GB) can take
            # 15-25 min on Vultr, so allow up to 30 min and stream the boot status.
            ip = vultr.wait_for_ip(box, timeout=1800, feed=feed)
            feed.emit("attack", f"[sandbox] box up at {ip}; waiting for SSH...")
            if not vultr.wait_for_ssh(ip, timeout=300):
                feed.emit("attack", "[sandbox] SSH never came up; destroying box")
                vultr.destroy(box.id)
                box_destroyed = True
                return []
        if not _ensure_model_up(ip, feed):
            _dump_vllm_logs(ip, feed)
            # A broken model can't be salvaged here; destroy the box even under --keep-alive so the
            # next run does a clean snapshot restore instead of reusing this poisoned box forever.
            feed.emit("attack", "[sandbox] local model never became ready; destroying box (next run restores fresh)")
            vultr.destroy(box.id)
            box_destroyed = True
            return []
        feed.emit("attack", f"[sandbox] model ready; launching active breach against {target} (live)")
        cmd = (
            f"echo {_b64(_agent_source())} | base64 -d > /tmp/penny_agent.py && "
            f"python3 -u /tmp/penny_agent.py {shlex.quote(target)} "
            f"--max-requests {int(max_requests)} --max-turns {int(max_turns)}"
            + (" --allow-destructive" if allow_destructive else "")
        )
        # A thinking model on the A16 can take ~30-90s/turn; budget generously so the stream
        # isn't killed mid-attack (it's also bounded by the box's auto-destroy).
        attack_timeout = max_turns * 120 + 600

        def _on_line(line: str) -> None:
            finding = _handle_agent_line(line, target, feed)
            if finding is not None:
                findings.append(finding)

        vultr.ssh_stream(ip, cmd, timeout=attack_timeout, on_line=_on_line)
        feed.emit("attack", f"[sandbox] breach complete: {len(findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001
        feed.emit("attack", f"[sandbox] error: {exc}")
    finally:
        if box_destroyed:
            pass  # already torn down in a failure branch above
        elif keep_alive:
            feed.emit("attack", f"[sandbox] box {box.id} kept alive at {box.ip} — the next sandbox-test "
                                "reuses it (no restore). /destroy when done (auto-destroys in 90m).")
        else:
            feed.emit("attack", f"[sandbox] destroying box {box.id}")
            vultr.destroy(box.id)
    return findings


def _reusable_box():
    """Return a still-running kept sandbox box to reuse, or None.

    Lets a session avoid the slow snapshot restore on every run: a prior --keep-alive run
    leaves a 'penny-sandbox' box up (with vLLM loaded), and the next run reuses it.
    `list_boxes()` reaps anything past its auto-destroy time first, so this only returns
    boxes that are still alive.
    """
    for b in vultr.list_boxes():
        if b.label == "penny-sandbox" and b.ip and b.ip != "0.0.0.0":
            return b
    return None


def _handle_agent_line(line: str, target: str, feed: EventFeed) -> Finding | None:
    """Process one JSONL line from the remote agent: emit live progress, return a Finding if any."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "finding" in obj and isinstance(obj["finding"], dict):
        feed.emit("attack", f"[sandbox] FINDING: {redact_text(obj['finding'].get('title', ''))}")
        return _finding_from_jsonl(obj["finding"], target)
    event = obj.get("event")
    if event == "request":
        feed.emit("attack", f"[sandbox] {obj.get('method', '')} {obj.get('path', '')} — {redact_text(obj.get('reason', ''))}")
    elif event == "response":
        feed.emit("attack", f"[sandbox]   -> {obj.get('status')} ({obj.get('bytes')} bytes)")
    elif event == "blocked":
        feed.emit("gate", f"[sandbox] blocked: {obj.get('msg', '')}")
    elif event == "finish":
        feed.emit("attack", f"[sandbox] agent concluded: {redact_text(obj.get('msg', ''))}")
    elif event in ("model_error", "request_error", "no_action", "fatal"):
        feed.emit("attack", f"[sandbox] {event}: {redact_text(str(obj.get('msg', '')))}")
    return None


def _parse_agent_output(out: str, target: str, feed: EventFeed) -> list[Finding]:
    findings: list[Finding] = []
    for line in out.splitlines():
        finding = _handle_agent_line(line, target, feed)
        if finding is not None:
            findings.append(finding)
    return findings


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")
