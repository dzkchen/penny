from __future__ import annotations

from penny.transport import TlsInfo, _parse_hsts, analyze_transport


def _issues(findings: list) -> set[str]:
    assert len(findings) == 1
    return {item["issue"] for item in findings[0].evidence["dynamic_probe"]["issues"]}


def test_plain_http_target_is_critical() -> None:
    findings = analyze_transport("http://shop.local", tls=None, hsts_header="", plaintext_http_served=None)
    assert findings[0].detector_id == "A011"
    assert findings[0].severity == "Critical"
    assert _issues(findings) == {"no_tls"}


def test_healthy_https_has_no_findings() -> None:
    tls = TlsInfo(negotiated_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=200)
    findings = analyze_transport(
        "https://shop.local",
        tls=tls,
        hsts_header="max-age=63072000; includeSubDomains; preload",
        plaintext_http_served=False,
    )
    assert findings == []


def test_expired_cert_and_legacy_tls_is_critical() -> None:
    tls = TlsInfo(
        negotiated_version="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        legacy_versions=["TLSv1", "TLSv1.1"],
        cert_expired=True,
    )
    findings = analyze_transport(
        "https://shop.local",
        tls=tls,
        hsts_header="max-age=63072000; includeSubDomains",
        plaintext_http_served=False,
    )
    issues = _issues(findings)
    assert {"certificate_expired", "legacy_tls_accepted"} <= issues
    assert findings[0].severity == "Critical"


def test_missing_hsts_with_cleartext_served_is_high() -> None:
    tls = TlsInfo(negotiated_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=300)
    findings = analyze_transport("https://shop.local", tls=tls, hsts_header="", plaintext_http_served=True)
    issues = _issues(findings)
    assert {"hsts_missing", "plaintext_http_accepted"} <= issues
    assert findings[0].severity == "High"


def test_missing_hsts_without_cleartext_is_medium() -> None:
    tls = TlsInfo(negotiated_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=300)
    findings = analyze_transport("https://shop.local", tls=tls, hsts_header="", plaintext_http_served=False)
    assert findings[0].severity == "Medium"
    assert _issues(findings) == {"hsts_missing"}


def test_weak_cipher_and_short_hsts_flagged() -> None:
    tls = TlsInfo(negotiated_version="TLSv1.2", cipher="ECDHE-RSA-RC4-SHA", days_to_expiry=300)
    findings = analyze_transport("https://shop.local", tls=tls, hsts_header="max-age=3600", plaintext_http_served=False)
    issues = _issues(findings)
    assert {"weak_cipher", "hsts_short_max_age", "hsts_no_subdomains"} <= issues


def test_parse_hsts() -> None:
    assert _parse_hsts("max-age=31536000; includeSubDomains; preload") == (31536000, True, True)
    assert _parse_hsts("max-age=0") == (0, False, False)
    assert _parse_hsts("") == (None, False, False)
