from __future__ import annotations

import math
import re
from hashlib import sha256
from typing import Any


SERVICE_KEY_RE = re.compile(r"(?i)\bsb_service_role_[A-Za-z0-9_\-]{8,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
DB_URL_RE = re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"<>]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
KNOWN_SECRET_RE = re.compile(
    r"\b(?:sk_(?:live|test)_[A-Za-z0-9_\-]{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{20,}|"
    r"al-[A-Za-z0-9_\-]{20,})\b"
)
HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{32,}\b")


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:10]


def _mask(value: str, label: str = "secret") -> str:
    return f"[REDACTED:{label}:{_digest(value)}]"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_high_entropy(value: str) -> bool:
    if len(value) < 32:
        return False
    has_alpha = any(char.isalpha() for char in value)
    has_digit = any(char.isdigit() for char in value)
    if not (has_alpha and has_digit):
        return False
    return shannon_entropy(value) >= 4.2


def redact_text(text: str | None) -> str:
    if text is None:
        return ""
    result = str(text)
    replacements = [
        (DB_URL_RE, "db_url"),
        (SERVICE_KEY_RE, "service_key"),
        (JWT_RE, "jwt"),
        (KNOWN_SECRET_RE, "secret"),
        (EMAIL_RE, "email"),
    ]
    for pattern, label in replacements:
        result = pattern.sub(lambda match: _mask(match.group(0), label), result)

    def replace_entropy(match: re.Match[str]) -> str:
        value = match.group(0)
        if looks_high_entropy(value):
            return _mask(value, "high_entropy")
        return value

    return HIGH_ENTROPY_TOKEN_RE.sub(replace_entropy, result)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    return value
