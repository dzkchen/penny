from __future__ import annotations

import pytest

import penny.guardrails as guardrails
from penny.guardrails import GuardrailError, TargetGate


def test_guardrails_allow_local_targets() -> None:
    gate = TargetGate("http://127.0.0.1:8787")
    assert gate.build_url("/health") == "http://127.0.0.1:8787/health"


def test_guardrails_block_public_targets_without_txt_proof(monkeypatch) -> None:
    # A public host is allowed only by a matching DNS TXT proof; with none, the gate blocks.
    # Clear the local-testing bypass so .env (PENNY_DISABLE_TXT_PROOF=1) can't mask the gate.
    monkeypatch.delenv("PENNY_DISABLE_TXT_PROOF", raising=False)
    monkeypatch.setattr(guardrails, "_lookup_txt_records", lambda hostname: [])
    with pytest.raises(GuardrailError, match="TXT proof"):
        TargetGate("https://example.com")


def test_guardrails_allow_public_targets_with_matching_txt_proof(monkeypatch) -> None:
    monkeypatch.delenv("PENNY_DISABLE_TXT_PROOF", raising=False)
    monkeypatch.setattr(
        guardrails,
        "_lookup_txt_records",
        lambda hostname: ["penny-verify=authorized"] if hostname in {"_penny.example.com", "example.com"} else [],
    )
    gate = TargetGate("https://example.com")
    assert gate.build_url("/health") == "https://example.com/health"


def test_guardrails_block_public_ip_literals() -> None:
    # Public IP literals can't carry a _penny.<host> TXT subdomain, so they are always blocked.
    with pytest.raises(GuardrailError, match="public IP literals are blocked"):
        TargetGate("https://8.8.8.8")


def test_guardrails_block_unsafe_methods_and_request_overage() -> None:
    gate = TargetGate("http://127.0.0.1:8787", max_requests=0)
    with pytest.raises(GuardrailError, match="unsafe HTTP method"):
        gate.validate_method("POST")
    with pytest.raises(GuardrailError, match="request cap"):
        gate.request("GET", "/health")


def test_guardrails_allow_read_only_preflight_methods() -> None:
    gate = TargetGate("http://127.0.0.1:8787")
    gate.validate_method("HEAD")
    gate.validate_method("OPTIONS")
