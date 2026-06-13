from __future__ import annotations

import json

from penny.redaction import redact_text, redact_value

from .conftest import PAYMENT_SECRET, SERVICE_KEY


def test_redactor_masks_supported_secret_shapes() -> None:
    raw_values = [
        SERVICE_KEY,
        PAYMENT_SECRET,
        "mongodb+srv://demo:password@example.mongodb.net/penny",
        "alice@example.test",
        "al-demoAtlasKey0123456789abcdef",
        "AbC123xYz987QwErTyUiOpAsDfGhJkLz0123456789",
    ]
    text = " ".join(raw_values)

    redacted = redact_text(text)

    for value in raw_values:
        assert value not in redacted
    assert "[REDACTED:service_key:" in redacted
    assert "[REDACTED:secret:" in redacted
    assert "[REDACTED:db_url:" in redacted
    assert "[REDACTED:email:" in redacted
    assert "[REDACTED:high_entropy:" in redacted


def test_redact_value_recurses_through_json_like_data() -> None:
    payload = {"items": [{"token": SERVICE_KEY}, {"nested": [PAYMENT_SECRET]}]}
    encoded = json.dumps(redact_value(payload))

    assert SERVICE_KEY not in encoded
    assert PAYMENT_SECRET not in encoded
