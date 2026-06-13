"""Cloud orchestrator: ties Vultr provisioning to the attack runners.

Flow: confirm -> provision -> wait for IP+SSH -> run attack from the box -> collect
findings (local) + redacted metadata (Mongo) -> optionally destroy the box.

Cost safety: confirm-before-spinup, auto-destroy timer on every box, reap() of expired
boxes, and a keep_alive flag so the user chooses ephemeral vs persistent.
"""

from __future__ import annotations

from pathlib import Path

from .cloud_attacks import CLOUD_ATTACKS, available_attacks
from .feed import EventFeed
from .guardrails import GuardrailError, TargetGate
from . import vultr


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cloud_attack(
    attack_type: str,
    target: str,
    *,
    i_own_this: bool,
    feed: EventFeed,
    keep_alive: bool = True,
    auto_confirm: bool = False,
    out_dir: Path = Path("."),
    **attack_kwargs,
) -> list:
    """Provision a box, run `attack_type` against `target`, return findings."""
    if attack_type not in CLOUD_ATTACKS:
        feed.emit("attack", f"Unknown cloud attack '{attack_type}'. Available: {', '.join(available_attacks())}")
        return []

    if not vultr.available():
        feed.emit("attack", "VULTR_API_KEY not set in .env — cannot use the cloud tier")
        return []

    # Same ownership/guardrail gate as the local tier — before spending any money.
    try:
        TargetGate(target, i_own_this=i_own_this)
    except GuardrailError as error:
        feed.emit("gate", f"Cloud attack blocked: {error}")
        return []

    confirm = None if auto_confirm else _confirm
    try:
        box = vultr.provision(confirm=confirm)
    except vultr.VultrError as error:
        feed.emit("attack", f"Provision failed: {error}")
        return []

    feed.emit("attack", f"[cloud] box {box.id} provisioning (auto-destroys in 30m)...")
    findings = []
    try:
        ip = vultr.wait_for_ip(box)
        feed.emit("attack", f"[cloud] box up at {ip}; waiting for SSH...")
        if not vultr.wait_for_ssh(ip):
            feed.emit("attack", "[cloud] SSH never came up; destroying box")
            return []
        feed.emit("attack", f"[cloud] box ready; launching '{attack_type}' against {target}")
        runner = CLOUD_ATTACKS[attack_type]
        result = runner(ip, target, feed=feed, **attack_kwargs)
        findings = result.findings
        feed.emit("attack", f"[cloud] attack complete: {len(findings)} finding(s)")
    except Exception as error:  # noqa: BLE001
        feed.emit("attack", f"[cloud] attack error: {error}")
    finally:
        if not keep_alive:
            feed.emit("attack", f"[cloud] destroying box {box.id}")
            vultr.destroy(box.id)
        else:
            feed.emit("attack", f"[cloud] box {box.id} kept alive (auto-destroys in 30m). /destroy to remove now.")
    return findings


def status(feed: EventFeed) -> None:
    boxes = vultr.list_boxes()
    if not boxes:
        feed.emit("attack", "No active Penny cloud boxes.")
        return
    import time

    now = time.time()
    for b in boxes:
        mins_left = max(0, int((b.kill_by - now) / 60))
        feed.emit("attack", f"box {b.id} @ {b.ip or 'pending'} ({b.plan}, {b.region}) — auto-destroys in ~{mins_left}m")


def kill_all(feed: EventFeed) -> None:
    """Stop running attack processes on all boxes (but keep the boxes)."""
    boxes = vultr.list_boxes()
    if not boxes:
        feed.emit("attack", "No boxes to kill attacks on.")
        return
    for b in boxes:
        if not b.ip:
            continue
        try:
            vultr.ssh_run(b.ip, "pkill -f penny_load.py; pkill -f penny_attack || true", timeout=20)
            feed.emit("attack", f"Stopped attack processes on box {b.id}")
        except Exception as error:  # noqa: BLE001
            feed.emit("attack", f"Could not reach box {b.id}: {error}")


def destroy_all(feed: EventFeed) -> None:
    count = vultr.destroy_all()
    feed.emit("attack", f"Destroyed {count} box(es).")
