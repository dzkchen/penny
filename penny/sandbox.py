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
# heretic is interactive (it prompts to save) and needs ~30-45 min of GPU. The default is
# the official heretic-org Qwen3-4B-Thinking build (a reasoning model, good at multi-step
# attack planning). Must be a transformers/safetensors repo (NOT a *-GGUF).
DEFAULT_HERETIC_MODEL = "heretic-org/Qwen3-4B-Thinking-2507-heretic"
MODEL_PORT = 8000
MODEL_ALIAS = "heretic"  # vLLM --served-model-name; must match sandbox_agent.py --model default


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
        "cat >/etc/systemd/system/penny-vllm.service <<EOF",
        "[Unit]",
        "Description=Penny sandbox vLLM (heretic gemma-3)",
        "After=network.target",
        "[Service]",
        f"Environment=HF_TOKEN={hf}",
        f"ExecStart=/opt/penny/venv/bin/python -m vllm.entrypoints.openai.api_server "
        f"--model {shlex.quote(model)} --host 127.0.0.1 --port {MODEL_PORT} "
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

        feed.emit("attack", "[bake] model serving; creating snapshot...")
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

def _wait_for_model(ip: str, feed: EventFeed, *, timeout: float = 1200.0, poll: float = 10.0) -> bool:
    """Poll the box until the local vLLM endpoint answers.

    Bails out early if the vLLM systemd service is crash-looping (it has Restart=always, so a
    bad model/OOM shows up as a growing restart count) rather than waiting out the full timeout.
    """
    deadline = time.monotonic() + timeout
    probe = f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{MODEL_PORT}/v1/models"
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
            try:
                _, restarts, _ = vultr.ssh_run(ip, "systemctl show penny-vllm -p NRestarts --value", timeout=20)
                n = int((restarts or "0").strip() or 0)
            except Exception:  # noqa: BLE001
                n = 0
            if n >= 3:
                feed.emit("attack", f"[sandbox] model service is crash-looping ({n} restarts); giving up early")
                return False
            feed.emit("attack", "[sandbox] still waiting for the model to come up...")
        time.sleep(poll)
    return False


def _dump_vllm_logs(ip: str, feed: EventFeed) -> None:
    """Surface the real vLLM startup error (crash-loop restarts otherwise bury the traceback)."""
    try:
        # Stop the service so its auto-restarts stop pushing the traceback out of the journal.
        vultr.ssh_run(ip, "systemctl stop penny-vllm.service >/dev/null 2>&1 || true", timeout=30)
        grep = ("journalctl -u penny-vllm.service --no-pager -n 800 2>&1 | "
                "grep -iE 'error|traceback|exception|raise|not .*support|unrecogni|no module|"
                "out of memory|oom|killed|assert|cuda' | tail -n 40 || true")
        _, hits, _ = vultr.ssh_run(ip, grep, timeout=60)
        if hits.strip():
            feed.emit("attack", f"[bake] vLLM errors:\n{redact_text(hits.strip()[-2200:])}")
        _, tail, terr = vultr.ssh_run(ip, "journalctl -u penny-vllm.service --no-pager -n 30 2>&1 || true", timeout=60)
        feed.emit("attack", f"[bake] vLLM log tail:\n{redact_text((tail or terr).strip()[-1400:]) or '(no logs)'}")
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

    snap = snapshot_id()
    if not snap:
        feed.emit("attack", "No sandbox snapshot found. Run /sandbox-bake once first (or set PENNY_SANDBOX_SNAPSHOT_ID).")
        return []

    confirm = None if auto_confirm else _confirm
    try:
        box = vultr.provision(
            region=vultr.gpu_region(), plan=vultr.gpu_plan(), snapshot_id=snap,
            label="penny-sandbox", confirm=confirm,
        )
    except vultr.VultrError as exc:
        feed.emit("attack", f"Provision failed: {exc}")
        return []

    feed.emit("attack", f"[sandbox] box {box.id} provisioning from snapshot (auto-destroys in 30m)...")
    findings: list[Finding] = []
    try:
        ip = vultr.wait_for_ip(box)
        feed.emit("attack", f"[sandbox] box up at {ip}; waiting for SSH...")
        if not vultr.wait_for_ssh(ip):
            feed.emit("attack", "[sandbox] SSH never came up; destroying box")
            return []
        if not _wait_for_model(ip, feed):
            _dump_vllm_logs(ip, feed)
            feed.emit("attack", "[sandbox] local model never became ready; destroying box")
            return []
        feed.emit("attack", f"[sandbox] model ready; launching active breach against {target}")
        cmd = (
            f"echo {_b64(_agent_source())} | base64 -d > /tmp/penny_agent.py && "
            f"python3 /tmp/penny_agent.py {shlex.quote(target)} "
            f"--max-requests {int(max_requests)} --max-turns {int(max_turns)}"
            + (" --allow-destructive" if allow_destructive else "")
        )
        timeout = max_turns * 30 + 120
        code, out, err = vultr.ssh_run(ip, cmd, timeout=timeout)
        findings = _parse_agent_output(out, target, feed)
        feed.emit("attack", f"[sandbox] breach complete: {len(findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001
        feed.emit("attack", f"[sandbox] error: {exc}")
    finally:
        if keep_alive:
            feed.emit("attack", f"[sandbox] box {box.id} kept alive (auto-destroys in 30m). /destroy to remove now.")
        else:
            feed.emit("attack", f"[sandbox] destroying box {box.id}")
            vultr.destroy(box.id)
    return findings


def _parse_agent_output(out: str, target: str, feed: EventFeed) -> list[Finding]:
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "finding" in obj and isinstance(obj["finding"], dict):
            findings.append(_finding_from_jsonl(obj["finding"], target))
            feed.emit("attack", f"[sandbox] FINDING: {redact_text(obj['finding'].get('title', ''))}")
        elif obj.get("event") == "request":
            feed.emit("red", f"[sandbox] {obj.get('method', '')} {obj.get('path', '')} ({redact_text(obj.get('reason', ''))})")
        elif obj.get("event") == "response":
            feed.emit("red", f"[sandbox]   -> status {obj.get('status')}, {obj.get('bytes')} bytes")
        elif obj.get("event") == "blocked":
            feed.emit("gate", f"[sandbox] blocked: {obj.get('msg', '')}")
        elif obj.get("event") == "finish":
            feed.emit("red", f"[sandbox] agent concluded: {redact_text(obj.get('msg', ''))}")
    return findings


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")
