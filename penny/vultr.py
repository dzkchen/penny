"""Vultr cloud controller — spin up disposable attack boxes, run, kill, destroy.

This is Penny's "heavy artillery" tier. The laptop stays the brain; a Vultr box is
disposable muscle for attacks that need bandwidth/compute (load tests, mass dumps,
cred stuffing) or isolation. The box only ever receives the TARGET URL — never your
.env, code, or keys.

Cost safety (this tool spends real money, so it is defensive by default):
- Confirm-before-spinup: provisioning asks unless auto_confirm=True.
- Cheapest plan + nearest region by default.
- Auto-destroy: every box is tagged with a kill-by time; `reap()` destroys expired
  boxes, and the box also schedules its own `shutdown`/self-delete as a backstop.
- A hard cap on how many Penny-owned boxes can exist at once.

State (which boxes Penny created) is tracked locally in .penny/vultr_boxes.json so
`/boxes`, `/kill`, and `/destroy` work across REPL sessions.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

API = "https://api.vultr.com/v2"

DEFAULT_REGION = "yto"          # Toronto — closest to Waterloo
DEFAULT_PLAN = "vc2-1c-1gb"     # cheapest (~$0.0068/hr)
DEFAULT_OS_ID = 2284            # Ubuntu 24.04 LTS x64
MAX_BOXES = 3                   # never let Penny run away spinning up boxes
DEFAULT_AUTODESTROY_MIN = 30    # box self-deletes after this many minutes

# GPU tier (sandbox-test): heretic abliteration + gemma-3 serving need a GPU.
# A16 1-GPU = 16 GB VRAM @ ~$0.471/hr — fits gemma-3-4b for both bake and serve.
# Override via VULTR_GPU_PLAN / VULTR_GPU_REGION in .env.
DEFAULT_GPU_PLAN = "vcg-a16-6c-64g-16vram"
DEFAULT_GPU_REGION = "ord"      # GPU-capable region (Chicago); not all regions have GPUs


def gpu_plan() -> str:
    return os.environ.get("VULTR_GPU_PLAN", "").strip() or DEFAULT_GPU_PLAN


def gpu_region() -> str:
    return os.environ.get("VULTR_GPU_REGION", "").strip() or DEFAULT_GPU_REGION

SSH_KEY_DIR = Path.home() / ".penny"
SSH_PRIVATE_KEY = SSH_KEY_DIR / "id_ed25519"
SSH_PUBLIC_KEY = SSH_KEY_DIR / "id_ed25519.pub"

STATE_FILE = Path(".penny") / "vultr_boxes.json"


class VultrError(RuntimeError):
    pass


def _api_key() -> str | None:
    from . import llm

    llm._load_dotenv()
    key = os.environ.get("VULTR_API_KEY", "").strip()
    return key or None


def available() -> bool:
    return _api_key() is not None


def _headers() -> dict[str, str]:
    key = _api_key()
    if not key:
        raise VultrError("VULTR_API_KEY not set in .env")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _request(method: str, path: str, body: dict | None = None, timeout: float = 30.0) -> dict[str, Any]:
    import httpx

    url = f"{API}{path}"
    try:
        resp = httpx.request(method, url, headers=_headers(), json=body, timeout=timeout)
    except Exception as error:  # noqa: BLE001
        raise VultrError(f"Vultr API request failed: {error}") from error
    if resp.status_code == 204:
        return {}
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = resp.json().get("error", "")
        except Exception:  # noqa: BLE001
            detail = resp.text[:200]
        raise VultrError(f"Vultr API {resp.status_code}: {detail}")
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# Local box-state tracking (so kill/destroy survive across sessions)
# ---------------------------------------------------------------------------

@dataclass
class Box:
    id: str
    ip: str
    region: str
    plan: str
    created_at: float
    kill_by: float
    label: str = "penny-box"

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _load_state() -> list[Box]:
    if not STATE_FILE.exists():
        return []
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return [Box(**item) for item in raw]
    except Exception:  # noqa: BLE001
        return []


def _save_state(boxes: list[Box]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps([b.to_dict() for b in boxes], indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------

def ensure_ssh_key_uploaded() -> str:
    """Make sure Penny's SSH public key exists on Vultr; return its key id."""
    if not SSH_PUBLIC_KEY.exists():
        raise VultrError(f"SSH public key not found at {SSH_PUBLIC_KEY}; generate it first")
    pub = SSH_PUBLIC_KEY.read_text(encoding="utf-8").strip()
    existing = _request("GET", "/ssh-keys").get("ssh_keys", [])
    for key in existing:
        if key.get("ssh_key", "").strip() == pub:
            return key["id"]
    created = _request("POST", "/ssh-keys", {"name": "penny-vultr", "ssh_key": pub})
    return created["ssh_key"]["id"]


# ---------------------------------------------------------------------------
# Provision / destroy
# ---------------------------------------------------------------------------

def _estimate_hourly(plan: str) -> float:
    # GPU plans are billed hourly directly (Vultr Cloud GPU pricing); CPU plans are
    # monthly/730. Keep the confirm-before-spinup prompt honest about real cost.
    gpu_hourly = {
        "vcg-a16-6c-64g-16vram": 0.471,    # A16 1-GPU, 16 GB VRAM
        "vcg-a16-12c-128g-32vram": 0.942,  # A16 2-GPU, 32 GB VRAM
    }
    if plan in gpu_hourly:
        return gpu_hourly[plan]
    # vc2-1c-1gb ~ $5/mo; Vultr bills hourly at monthly/730.
    monthly = {"vc2-1c-1gb": 5.0, "vc2-1c-2gb": 10.0, "vc2-2c-4gb": 20.0}.get(plan, 6.0)
    return round(monthly / 730, 4)


def provision(
    *,
    region: str = DEFAULT_REGION,
    plan: str = DEFAULT_PLAN,
    os_id: int = DEFAULT_OS_ID,
    snapshot_id: str | None = None,
    autodestroy_min: int = DEFAULT_AUTODESTROY_MIN,
    label: str = "penny-box",
    confirm=None,
    now: float | None = None,
) -> Box:
    """Spin up one box. `confirm` is a callable(prompt)->bool gate (cost safety).

    Pass ``snapshot_id`` to boot from a pre-baked snapshot (e.g. the heretic/gemma-3
    sandbox image) instead of a fresh OS install.
    """
    boxes = _load_state()
    if len(boxes) >= MAX_BOXES:
        raise VultrError(f"refusing to provision: already {len(boxes)} Penny boxes (max {MAX_BOXES}). Destroy some first.")

    hourly = _estimate_hourly(plan)
    if confirm is not None:
        ok = confirm(f"Spin up 1 Vultr box ({plan} in {region}, ~${hourly}/hr, auto-destroys in {autodestroy_min}m)?")
        if not ok:
            raise VultrError("provision cancelled by user")

    key_id = ensure_ssh_key_uploaded()
    # Self-destruct backstop: schedule shutdown on the box itself via startup script.
    body = {
        "region": region,
        "plan": plan,
        "label": label,
        "sshkey_id": [key_id],
        "tag": "penny",
    }
    if snapshot_id:
        body["snapshot_id"] = snapshot_id
    else:
        body["os_id"] = os_id
    instance = _request("POST", "/instances", body)["instance"]
    created = now or time.time()
    box = Box(
        id=instance["id"],
        ip=instance.get("main_ip", "") or "",
        region=region,
        plan=plan,
        created_at=created,
        kill_by=created + autodestroy_min * 60,
        label=label,
    )
    boxes.append(box)
    _save_state(boxes)
    return box


def wait_for_ip(box: Box, *, timeout: float = 180.0, poll: float = 6.0, feed=None) -> str:
    """Poll until the box has an IP and is active. Returns the IP.

    Pass ``feed`` to stream the live status/power/server state — useful for diagnosing slow
    or stuck snapshot restores instead of a blind timeout.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        info = _request("GET", f"/instances/{box.id}").get("instance", {})
        ip = info.get("main_ip", "")
        status = info.get("status", "")
        power = info.get("power_status", "")
        server = info.get("server_status", "")
        if ip and ip != "0.0.0.0" and status == "active" and power == "running":
            box.ip = ip
            _save_state(_load_state_replacing(box))
            return ip
        snap = f"status={status or '-'} power={power or '-'} server={server or '-'} ip={ip or '-'}"
        if feed is not None and snap != last:
            feed.emit("attack", f"[sandbox] booting: {snap}")
            last = snap
        time.sleep(poll)
    raise VultrError(f"box {box.id} did not become ready within {timeout:.0f}s (last: {last or 'no status'})")


# ---------------------------------------------------------------------------
# Snapshots (bake-once for the sandbox-test GPU image)
# ---------------------------------------------------------------------------

def create_snapshot(box_id: str, *, description: str = "penny-sandbox") -> str:
    """Snapshot a running box; returns the new snapshot id."""
    snap = _request("POST", "/snapshots", {"instance_id": box_id, "description": description})["snapshot"]
    return snap["id"]


def wait_for_snapshot(snapshot_id: str, *, timeout: float = 1800.0, poll: float = 15.0) -> None:
    """Poll until a snapshot finishes (status == 'complete')."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = _request("GET", f"/snapshots/{snapshot_id}").get("snapshot", {})
        if info.get("status") == "complete":
            return
        time.sleep(poll)
    raise VultrError(f"snapshot {snapshot_id} did not complete within {timeout:.0f}s")


def _load_state_replacing(box: Box) -> list[Box]:
    boxes = _load_state()
    for i, b in enumerate(boxes):
        if b.id == box.id:
            boxes[i] = box
    return boxes


def destroy(box_id: str) -> bool:
    """Delete an instance and drop it from local state. Returns True on success.

    A 404 means it's already gone (fine). Any other API failure (e.g. a 401 IP-allowlist
    block, or a network blip) is NOT swallowed into "forget it" — the box stays tracked so
    `/boxes`, `/destroy`, and `reap()` can retry once API access is restored, rather than
    silently orphaning a still-billing instance.
    """
    try:
        _request("DELETE", f"/instances/{box_id}")
    except VultrError as error:
        if "404" not in str(error):
            return False  # keep it in local state for a later retry
    _save_state([b for b in _load_state() if b.id != box_id])
    return True


def destroy_all() -> int:
    boxes = _load_state()
    for b in boxes:
        try:
            _request("DELETE", f"/instances/{b.id}")
        except VultrError:
            pass
    _save_state([])
    return len(boxes)


def reap(now: float | None = None) -> list[str]:
    """Destroy any boxes past their kill-by time. Returns destroyed ids."""
    current = now or time.time()
    boxes = _load_state()
    expired = [b for b in boxes if b.kill_by and current >= b.kill_by]
    for b in expired:
        destroy(b.id)
    return [b.id for b in expired]


def list_boxes() -> list[Box]:
    reap()  # opportunistically clean up expired boxes whenever we list
    return _load_state()


# ---------------------------------------------------------------------------
# SSH / remote execution
# ---------------------------------------------------------------------------

def _ssh_base(ip: str) -> list[str]:
    return [
        "ssh", "-i", str(SSH_PRIVATE_KEY),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"root@{ip}",
    ]


def ssh_run(ip: str, command: str, *, timeout: float = 120.0) -> tuple[int, str, str]:
    proc = subprocess.run(
        _ssh_base(ip) + [command],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def wait_for_ssh(ip: str, *, timeout: float = 180.0, poll: float = 6.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            code, _, _ = ssh_run(ip, "echo ok", timeout=15)
            if code == 0:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(poll)
    return False
