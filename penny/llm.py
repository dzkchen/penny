"""Thin Anthropic Messages API client used by Penny's AI features.

Penny stays useful with zero configuration: when no ``ANTHROPIC_API_KEY`` is
available (or the request fails for any reason) the callers fall back to the
deterministic logic, so this module never raises into the CLI. It talks to the
API directly over ``httpx`` (already a dependency) to avoid pulling in the SDK.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_DEEP_MODEL = "claude-sonnet-4-6"
DEFAULT_FAST_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com"

_DOTENV_LOADED = False


def _load_dotenv(path: Path | None = None) -> None:
    """Populate ``os.environ`` from a local ``.env`` once, without overriding.

    Penny's config (``ANTHROPIC_API_KEY``, ``PENNY_DEEP_MODEL``,
    ``PENNY_FAST_MODEL``) usually lives in a local ``.env``; load it lazily so a
    bare ``penny ask`` picks the key up. Existing environment variables win.
    """
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    _DOTENV_LOADED = True
    env_path = path or Path(".env")
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def api_key() -> str | None:
    _load_dotenv()
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return key or None


def available() -> bool:
    """True when an API key is configured (in the environment or ``.env``)."""
    return api_key() is not None


def deep_model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_DEEP_MODEL", "").strip() or DEFAULT_DEEP_MODEL


def fast_model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_FAST_MODEL", "").strip() or DEFAULT_FAST_MODEL


def complete(
    prompt: str,
    *,
    system: str | None = None,
    deep: bool = True,
    max_tokens: int = 1024,
    timeout: float = 30.0,
) -> str | None:
    """Return Claude's text answer, or ``None`` if the call cannot be made.

    Any missing key, missing dependency, network error, or non-2xx response
    yields ``None`` so callers degrade to deterministic output.
    """
    key = api_key()
    if key is None:
        return None
    try:
        import httpx
    except ImportError:
        return None

    body: dict[str, object] = {
        "model": deep_model() if deep else fast_model(),
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    base_url = os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    try:
        response = httpx.post(
            f"{base_url}/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json=body,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    except Exception:
        return None

    if not isinstance(data, dict):
        return None
    blocks = data.get("content", [])
    text = "".join(
        block.get("text", "")
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()
    return text or None


def describe() -> str:
    """Short human-readable status string for the CLI feed."""
    if not available():
        return "AI disabled (no ANTHROPIC_API_KEY); using deterministic answers"
    return f"AI enabled via {deep_model()}"
