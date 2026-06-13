"""Optional live-LLM layer for Penny.

Design rules (must not break the safety model):
- The LLM only ever receives ALREADY-REDACTED findings JSON. Raw secrets never reach it.
- The LLM never performs I/O: it does not read files, run shell, or make HTTP requests.
- Every LLM call has a deterministic fallback, so the core demo runs with no API key.
- Anything the LLM returns is passed through redaction again before display, in case
  it echoes a value back.

The LLM's job is purely linguistic: explain findings, write the narrative parts of the
report, and answer questions in natural language. The deterministic Python remains the
source of truth for detection, confirmation, and structured fixes.
"""

from __future__ import annotations

import os
from pathlib import Path

from .redaction import redact_text


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _api_key() -> str | None:
    _load_dotenv()
    if os.environ.get("PENNY_DISABLE_LLM") == "1":
        return None
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    # Reject obvious placeholder values so a half-filled .env doesn't pretend to work.
    if not key or "your-key" in key or "your-real-key" in key:
        return None
    return key


# Defaults chosen for hackathon demos: fast + inexpensive so runs stay well under the
# 90s target and don't burn budget. Override with PENNY_DEEP_MODEL / PENNY_FAST_MODEL.
def _model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_DEEP_MODEL", "").strip() or "claude-sonnet-4-6"


def _fast_model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_FAST_MODEL", "").strip() or "claude-sonnet-4-6"


def llm_available() -> bool:
    """True if a usable Anthropic key is configured and the SDK is importable."""
    if _api_key() is None:
        return False
    try:
        import anthropic  # noqa: F401
    except Exception:
        return False
    return True


def _call(system: str, user: str, *, fast: bool = False, max_tokens: int = 1024) -> str | None:
    """Single Claude call. Returns redacted text, or None on any failure/no-key."""
    key = _api_key()
    if key is None:
        return None
    try:
        import anthropic
    except Exception:
        return None
    try:
        client = anthropic.Anthropic(api_key=key)
        response = client.messages.create(
            model=_fast_model() if fast else _model(),
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        text = "\n".join(parts).strip()
        if not text:
            return None
        # Defense in depth: redact anything the model echoes back.
        return redact_text(text)
    except Exception:
        return None


_ASK_SYSTEM = (
    "You are Penny, the Purple-Team agent of a consented security audit tool. "
    "You are given REDACTED findings JSON from a completed scan. Secrets are already masked as "
    "[REDACTED:...]; never try to guess or reconstruct them. "
    "Answer the user's question grounded ONLY in the provided findings. "
    "Distinguish clearly between 'suspected' (static only) and 'confirmed' (dynamically proven) findings; "
    "never describe a suspected finding as exploited. Be direct, developer-friendly, and concise. "
    "If the findings do not contain the answer, say so plainly."
)


def llm_answer(question: str, findings_json: str, *, deterministic: str) -> str:
    """Augment the deterministic ask answer with an LLM explanation when available."""
    user = (
        f"REDACTED FINDINGS JSON:\n{findings_json}\n\n"
        f"DETERMINISTIC TOOL ANSWER (ground truth, do not contradict):\n{deterministic}\n\n"
        f"USER QUESTION:\n{question}\n\n"
        "Write a clear, grounded answer for a developer. Stay consistent with the deterministic answer."
    )
    result = _call(_ASK_SYSTEM, user)
    return result if result else deterministic


_VERDICT_SYSTEM = (
    "You are Penny's Purple-Team lead. Given REDACTED findings JSON, write a single tight paragraph "
    "(3-5 sentences) that tells the developer the security story: what the red team proved, why it matters, "
    "and what to fix first. Be direct and non-alarmist. Only call something exploited if its status is 'confirmed'. "
    "Output prose only, no headings or lists."
)


def llm_verdict(findings_json: str, *, deterministic: str) -> str:
    """Replace the one-line template verdict with a richer LLM narrative when available."""
    user = (
        f"REDACTED FINDINGS JSON:\n{findings_json}\n\n"
        f"DETERMINISTIC ONE-LINE VERDICT (do not contradict):\n{deterministic}\n\n"
        "Write the purple-team verdict paragraph."
    )
    result = _call(_VERDICT_SYSTEM, user, max_tokens=512)
    return result if result else deterministic
