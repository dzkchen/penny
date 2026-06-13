"""Embedding layer for the vector knowledge base.

Real semantic embeddings come from Voyage AI (Anthropic's recommended embedding
provider) when VOYAGE_API_KEY is configured. Without a key, Penny falls back to a
deterministic hash embedding so the demo still runs offline.

The whole point of the vector DB is semantic recall: "exposed API key" and "leaked
credential" should land near each other even though the words differ. Only a real
neural model does that; the hash fallback is word-overlap only and is clearly labeled.
"""

from __future__ import annotations

import os
import re
from hashlib import sha256
from pathlib import Path

# Voyage's voyage-3 family is 1024-dim; the hash fallback is 64-dim. The active
# dimension is whatever the chosen backend produces, exposed via embedding_dimensions().
VOYAGE_MODEL = "voyage-3"
VOYAGE_DIMS = 1024
HASH_DIMS = 64


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _voyage_key() -> str | None:
    _load_dotenv()
    if os.environ.get("PENNY_DISABLE_VOYAGE") == "1":
        return None
    key = os.environ.get("VOYAGE_API_KEY", "").strip()
    if not key or "your-" in key:
        return None
    return key


def backend() -> str:
    """Return the active embedding backend name: 'voyage' or 'hash'."""
    if _voyage_key() is None:
        return "hash"
    try:
        import voyageai  # noqa: F401
    except Exception:
        return "hash"
    return "voyage"


def embedding_model_name() -> str:
    return VOYAGE_MODEL if backend() == "voyage" else "penny-hash-v1"


def embedding_dimensions() -> int:
    return VOYAGE_DIMS if backend() == "voyage" else HASH_DIMS


def _hash_embedding(text: str, dimensions: int = HASH_DIMS) -> list[float]:
    vector = [0.0] * dimensions
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    if not tokens:
        return vector
    for token in tokens:
        digest = sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:2], "big") % dimensions
        sign = 1.0 if digest[2] % 2 == 0 else -1.0
        vector[index] += sign
    magnitude = sum(value * value for value in vector) ** 0.5
    if not magnitude:
        return vector
    return [round(value / magnitude, 6) for value in vector]


def _voyage_embedding(text: str, *, input_type: str) -> list[float] | None:
    key = _voyage_key()
    if key is None:
        return None
    try:
        import voyageai

        client = voyageai.Client(api_key=key)
        result = client.embed([text], model=VOYAGE_MODEL, input_type=input_type)
        return result.embeddings[0]
    except Exception:
        return None


def embed_document(text: str) -> list[float]:
    """Embed text being STORED in the knowledge base."""
    if backend() == "voyage":
        vector = _voyage_embedding(text, input_type="document")
        if vector is not None:
            return vector
    return _hash_embedding(text)


def embed_query(text: str) -> list[float]:
    """Embed a SEARCH query. Voyage uses a different input_type for queries."""
    if backend() == "voyage":
        vector = _voyage_embedding(text, input_type="query")
        if vector is not None:
            return vector
    return _hash_embedding(text)
