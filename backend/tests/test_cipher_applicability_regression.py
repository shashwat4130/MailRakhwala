"""Regression tests for evidence-gated TLS cipher findings."""

from app.services.compliance_engine import ComplianceEngine


def _smtp_context(handshake: bool):
    return {
        "protocol": "SMTP",
        "starttls_state": "CAPABILITY_ADVERTISED",
        "reconstruction_status": "COMPLETE",
        "unresolved_gaps": False,
        "tls_transition_detected": False,
        "tls_handshake_observed": handshake,
        "plaintext_observed": not handshake,
        "plaintext_observed_value": "PLAINTEXT_SMTP" if not handshake else None,
    }


def test_plaintext_smtp_does_not_generate_cipher_finding():
    report = ComplianceEngine().evaluate_session(
        stream_id="smtp-plaintext",
        tls_params={"cipher_suite": None},
        starttls_params=_smtp_context(False),
    )

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "RULE-STARTTLS-002" in rule_ids
    assert "RULE-CIPHER-001" not in rule_ids
    assert "RULE-CIPHER-UNKNOWN" not in rule_ids


def test_tls_handshake_with_missing_cipher_does_not_guess_cipher_finding():
    report = ComplianceEngine().evaluate_session(
        stream_id="tls-missing-cipher",
        tls_params={"version": "TLS 1.3", "cipher_suite": None},
        starttls_params=_smtp_context(True),
    )

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "RULE-CIPHER-001" not in rule_ids
    assert "RULE-CIPHER-UNKNOWN" not in rule_ids


def test_genuine_tls_handshake_with_null_cipher_still_generates_cipher_finding():
    report = ComplianceEngine().evaluate_session(
        stream_id="tls-null-cipher",
        tls_params={
            "version": "TLS 1.2",
            "cipher_suite": "TLS_RSA_WITH_NULL_SHA",
        },
        starttls_params={
            **_smtp_context(True),
            "tls_transition_detected": True,
        },
    )

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "RULE-CIPHER-001" in rule_ids
