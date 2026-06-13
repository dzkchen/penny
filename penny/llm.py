"""Anthropic client + Penny's AI helpers (merged: feat's API client + RAG/fix layer).

Design rules (safety):
- LLM helpers that summarize findings only receive ALREADY-REDACTED findings JSON.
- The fix helper receives real local file contents (needed to patch), but only at the
  user's explicit request and its output is shown as a diff for approval.
- Every call degrades to deterministic output when no key / on any error.
- Talks to the API over httpx (already a dependency); no SDK required.
"""

from __future__ import annotations

import os
from pathlib import Path

from .redaction import redact_text

DEFAULT_DEEP_MODEL = "claude-sonnet-4-6"
DEFAULT_FAST_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com"

# Model selection mode (set via `/model` in the REPL or `penny model <mode>`):
#   auto   - Haiku for quick chat, Sonnet for the real work (default)
#   haiku  - always use the fast model
#   sonnet - always use the deep model
VALID_MODEL_MODES = ("auto", "haiku", "sonnet")


def model_mode() -> str:
    _load_dotenv()
    mode = os.environ.get("PENNY_MODEL_MODE", "").strip().lower()
    return mode if mode in VALID_MODEL_MODES else "auto"


def set_model_mode(mode: str) -> str:
    mode = mode.strip().lower()
    if mode not in VALID_MODEL_MODES:
        raise ValueError(f"model mode must be one of: {', '.join(VALID_MODEL_MODES)}")
    os.environ["PENNY_MODEL_MODE"] = mode
    return mode


def _resolve_model(deep: bool) -> str:
    """Apply the model mode: auto honors the caller's deep flag; haiku/sonnet override it."""
    mode = model_mode()
    if mode == "haiku":
        return fast_model()
    if mode == "sonnet":
        return deep_model()
    return deep_model() if deep else fast_model()  # auto


def describe_model_mode() -> str:
    mode = model_mode()
    if mode == "haiku":
        return f"model mode: haiku (always {fast_model()})"
    if mode == "sonnet":
        return f"model mode: sonnet (always {deep_model()})"
    return f"model mode: auto (chat: {fast_model()}, work: {deep_model()})"

_DOTENV_LOADED = False


def _load_dotenv(path: Path | None = None) -> None:
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
    if os.environ.get("PENNY_DISABLE_LLM") == "1":
        return None
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key or "your-key" in key or "your-real-key" in key:
        return None
    return key


# Backwards-compatible alias used by the RAG/agentic modules.
def _api_key() -> str | None:
    return api_key()


def available() -> bool:
    return api_key() is not None


def llm_available() -> bool:
    return api_key() is not None


def deep_model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_DEEP_MODEL", "").strip() or DEFAULT_DEEP_MODEL


def fast_model() -> str:
    _load_dotenv()
    return os.environ.get("PENNY_FAST_MODEL", "").strip() or DEFAULT_FAST_MODEL


def _model() -> str:
    return deep_model()


def complete(
    prompt: str,
    *,
    system: str | None = None,
    deep: bool = True,
    max_tokens: int = 1024,
    timeout: float = 30.0,
    response_schema: dict | None = None,
) -> str | None:
    """Return Claude's text answer, or None if the call cannot be made."""
    key = api_key()
    if key is None:
        return None
    try:
        import httpx
    except ImportError:
        return None

    body: dict[str, object] = {
        "model": _resolve_model(deep),
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    if response_schema is not None:
        body["output_config"] = {"format": {"type": "json_schema", "schema": response_schema}}

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
    if not available():
        return "AI disabled (no ANTHROPIC_API_KEY); using deterministic answers"
    return f"AI enabled via {deep_model()}"


def _call(system: str, user: str, *, fast: bool = False, max_tokens: int = 1024) -> str | None:
    """Single Claude call returning redacted text, or None. Used by RAG helpers."""
    result = complete(user, system=system, deep=not fast, max_tokens=max_tokens)
    return redact_text(result) if result else None


# ---------------------------------------------------------------------------
# RAG-grounded helpers (ask answer, verdict) and the code-fix helper
# ---------------------------------------------------------------------------

_ASK_SYSTEM = (
    "You are Penny, the Purple-Team agent of a consented security audit tool. "
    "You are given REDACTED findings JSON from a completed scan. Secrets are already masked as "
    "[REDACTED:...]; never try to guess or reconstruct them. "
    "Answer the user's question grounded ONLY in the provided findings. "
    "Distinguish clearly between 'suspected' (static only) and 'confirmed' (dynamically proven) findings; "
    "never describe a suspected finding as exploited. Be direct, developer-friendly, and concise. "
    "If the findings do not contain the answer, say so plainly."
)


def _rag_block(retrieved: list[dict] | None) -> str:
    if not retrieved:
        return ""
    lines = []
    for item in retrieved:
        score = item.get("score")
        score_str = f" (similarity {round(score, 3)})" if isinstance(score, (int, float)) else ""
        lines.append(f"- [{item.get('detector_id', '?')}] {item.get('title', '')}{score_str}: {item.get('remediation', '')}")
    return (
        "RETRIEVED KNOWLEDGE-BASE PATTERNS (from MongoDB vector search; use as background, "
        "do not contradict the findings):\n" + "\n".join(lines) + "\n\n"
    )


def llm_answer(question: str, findings_json: str, *, deterministic: str, retrieved: list[dict] | None = None) -> str:
    user = (
        f"{_rag_block(retrieved)}"
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


def llm_verdict(findings_json: str, *, deterministic: str, retrieved: list[dict] | None = None) -> str:
    user = (
        f"{_rag_block(retrieved)}"
        f"REDACTED FINDINGS JSON:\n{findings_json}\n\n"
        f"DETERMINISTIC ONE-LINE VERDICT (do not contradict):\n{deterministic}\n\n"
        "Write the purple-team verdict paragraph."
    )
    result = _call(_VERDICT_SYSTEM, user, max_tokens=512)
    return result if result else deterministic


_FIX_SYSTEM = (
    "You are Penny's Blue-Team remediation agent. You are given the FULL CONTENTS of one source "
    "file from a consented security audit, plus the finding(s) located in it. Produce a corrected "
    "version of the WHOLE file that fixes the security issue while preserving all unrelated code, "
    "formatting, and behavior. "
    "Rules: never invent or hardcode real secrets; move credentials to environment variables; "
    "for access-control issues add explicit ownership/auth checks; make the minimal change that fixes "
    "the issue. "
    "Output ONLY the complete corrected file contents between the markers <<<PENNY_FILE_START>>> and "
    "<<<PENNY_FILE_END>>>, with no commentary, no markdown fences, and nothing outside the markers. "
    "If you cannot safely fix it, output the two markers with the original contents unchanged between them."
)


def llm_fix_file(relative_path: str, file_contents: str, findings_for_file: str) -> str | None:
    """Ask Claude for a corrected whole-file version. Returns new contents, or None."""
    if api_key() is None:
        return None
    user = (
        f"FILE PATH: {relative_path}\n\n"
        f"FINDINGS IN THIS FILE:\n{findings_for_file}\n\n"
        f"CURRENT FILE CONTENTS:\n<<<PENNY_FILE_START>>>\n{file_contents}\n<<<PENNY_FILE_END>>>\n\n"
        "Return the corrected whole file between the markers."
    )
    text = complete(user, system=_FIX_SYSTEM, deep=True, max_tokens=8192)
    if not text:
        return None
    start = text.find("<<<PENNY_FILE_START>>>")
    end = text.find("<<<PENNY_FILE_END>>>")
    if start == -1 or end == -1 or end <= start:
        return None
    fixed = text[start + len("<<<PENNY_FILE_START>>>") : end]
    if fixed.startswith("\n"):
        fixed = fixed[1:]
    if fixed.endswith("\n"):
        fixed = fixed[:-1]
    return fixed if fixed.strip() else None
