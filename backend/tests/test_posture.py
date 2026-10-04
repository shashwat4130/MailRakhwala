from types import SimpleNamespace
import pytest

from app.schemas.posture import PostureSeverity
from app.services.posture import PostureEngineService, PostureRuleCatalog


def _make_finding(rule_id: str, prop: str = "security.property", val: str = "insecure_val", c_idx=None):
    return SimpleNamespace(
        finding_id=f"F-{rule_id}",
        rule_id=rule_id,
        status="NON_COMPLIANT",
        evidence=SimpleNamespace(
            observed_property=prop,
            observed_value=val,
            certificate_index=c_idx,
        ),
    )


def test_catalog_19_rules_sum_to_exactly_100():
    """Verify that all 19 posture rules exist and their penalties sum to exactly 100."""
    catalog = PostureRuleCatalog()
    assert catalog.rule_count == 19
    total_penalty = sum(r["penalty"] for r in catalog.rules.values())
    assert total_penalty == 100

    # Severity hierarchy validation
    for rule in catalog.rules.values():
        penalty = rule["penalty"]
        severity = rule["severity"]
        if severity == "CRITICAL":
            assert penalty == 15
        elif severity == "HIGH":
            assert penalty == 10
        elif severity == "MEDIUM":
            assert penalty == 5
        elif severity == "LOW":
            assert penalty in (2, 3)


def test_clean_capture_scores_100():
    """Clean capture with zero findings yields 100/100 posture score."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-clean",
        stream_id="stream-1",
        findings=[],
        is_applicable=True,
    )
    assert report.total_penalty == 0
    assert report.posture_score == 100
    assert report.severity == PostureSeverity.LOW
    assert len(report.deductions) == 0


def test_one_low_3pt_scores_97():
    """A single 3-point LOW rule (e.g. RC4 stream cipher) deducts 3 points -> 97/100."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-low-3",
        stream_id="stream-1",
        findings=[_make_finding("RULE-CIPHER-002", "tls.cipher_suite", "TLS_RSA_WITH_RC4_128_SHA")],
        is_applicable=True,
    )
    assert report.total_penalty == 3
    assert report.posture_score == 97
    assert report.severity == PostureSeverity.LOW
    assert len(report.deductions) == 1
    assert report.deductions[0].penalty == 3
    assert report.deductions[0].severity == "LOW"


def test_one_low_2pt_scores_98():
    """A single 2-point LOW rule (e.g. unapproved cipher) deducts 2 points -> 98/100."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-low-2",
        stream_id="stream-1",
        findings=[_make_finding("RULE-CIPHER-UNKNOWN", "tls.cipher_suite.approved", "FALSE")],
        is_applicable=True,
    )
    assert report.total_penalty == 2
    assert report.posture_score == 98
    assert report.severity == PostureSeverity.LOW
    assert len(report.deductions) == 1
    assert report.deductions[0].penalty == 2
    assert report.deductions[0].severity == "LOW"


def test_one_medium_scores_95():
    """A single 5-point MEDIUM rule (e.g. expired certificate) deducts 5 points -> 95/100."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-med",
        stream_id="stream-1",
        findings=[_make_finding("RULE-CERT-001", "certificate.validity.not_after", "EXPIRED")],
        is_applicable=True,
    )
    assert report.total_penalty == 5
    assert report.posture_score == 95
    # Canonical severity never understates verified findings: max(LOW, MEDIUM) = MEDIUM
    assert report.severity == PostureSeverity.MEDIUM
    assert len(report.deductions) == 1
    assert report.deductions[0].penalty == 5
    assert report.deductions[0].severity == "MEDIUM"


def test_one_high_scores_90():
    """A single 10-point HIGH rule (e.g. STARTTLS downgrade) deducts 10 points -> 90/100."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-high",
        stream_id="stream-1",
        findings=[_make_finding("RULE-STARTTLS-002", "starttls.state", "DOWNGRADE_OBSERVED")],
        is_applicable=True,
    )
    assert report.total_penalty == 10
    assert report.posture_score == 90
    # Canonical severity never understates verified findings: max(LOW, HIGH) = HIGH
    assert report.severity == PostureSeverity.HIGH
    assert len(report.deductions) == 1
    assert report.deductions[0].penalty == 10
    assert report.deductions[0].severity == "HIGH"


def test_one_critical_scores_85():
    """A single 15-point CRITICAL rule (e.g. SSL 2.0 / 3.0) deducts 15 points -> 85/100."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-crit",
        stream_id="stream-1",
        findings=[_make_finding("RULE-TLS-001", "tls.version", "SSL_3_0")],
        is_applicable=True,
    )
    assert report.total_penalty == 15
    assert report.posture_score == 85
    # Canonical severity never understates verified findings: max(LOW, CRITICAL) = CRITICAL
    assert report.severity == PostureSeverity.CRITICAL
    assert len(report.deductions) == 1
    assert report.deductions[0].penalty == 15
    assert report.deductions[0].severity == "CRITICAL"


def test_multiple_findings_combine_correctly():
    """
    Multiple findings combine additively from the 100-point budget:
      Critical (15) + High (10) + Medium (5) + Low (2) = 32
      Score = 100 - 32 = 68/100.
      Canonical severity = CRITICAL (highest verified finding).
    """
    findings = [
        _make_finding("RULE-CIPHER-001", "tls.cipher_suite", "TLS_NULL_WITH_NULL_NULL"),  # 15
        _make_finding("RULE-PLAINTEXT-001", "cleartext.transport", "SMTP_PLAINTEXT"),       # 10
        _make_finding("RULE-CERT-003", "rsa.public_key.length", "1024"),                     # 5
        _make_finding("RULE-CIPHER-004", "tls.cipher_suite.mode", "CBC"),                   # 2
    ]
    report = PostureEngineService().evaluate_posture(
        session_id="test-multi",
        stream_id="stream-1",
        findings=findings,
        is_applicable=True,
    )
    assert report.total_penalty == 32
    assert report.posture_score == 68
    assert report.severity == PostureSeverity.CRITICAL
    assert len(report.deductions) == 4


def test_all_19_rules_maximum_penalty_equals_100_and_score_is_zero():
    """
    When all 19 deterministic rules fire simultaneously:
    Sum of all penalties = 100.
    Theoretical minimum score = 0/100.
    """
    catalog = PostureRuleCatalog()
    all_findings = []
    for upstream_id, rule in catalog.upstream_index.items():
        all_findings.append(_make_finding(upstream_id, "test.property", f"test_val_{upstream_id}"))

    assert len(all_findings) == 19

    report = PostureEngineService().evaluate_posture(
        session_id="test-all-19",
        stream_id="stream-1",
        findings=all_findings,
        is_applicable=True,
    )
    assert report.total_penalty == 100
    assert report.posture_score == 0
    assert report.severity == PostureSeverity.CRITICAL
    assert len(report.deductions) == 19


def test_no_score_can_become_negative():
    """Posture score is strictly non-negative (>= 0)."""
    catalog = PostureRuleCatalog()
    all_findings = [
        _make_finding(u_id, "prop", f"val_{u_id}")
        for u_id in catalog.upstream_index
    ]
    report = PostureEngineService().evaluate_posture(
        session_id="test-neg",
        stream_id="stream-1",
        findings=all_findings,
        is_applicable=True,
    )
    assert report.posture_score == 0
    assert report.posture_score >= 0


def test_repeated_packets_do_not_multiply_rule_penalty():
    """Repeated occurrences of the same rule do not deduct multiple times."""
    findings = [
        _make_finding("RULE-STARTTLS-002", "starttls.state", "DOWNGRADE_PKT_1"),
        _make_finding("RULE-STARTTLS-002", "starttls.state", "DOWNGRADE_PKT_2"),
        _make_finding("RULE-STARTTLS-002", "starttls.state", "DOWNGRADE_PKT_3"),
    ]
    report = PostureEngineService().evaluate_posture(
        session_id="test-repeat",
        stream_id="stream-1",
        findings=findings,
        is_applicable=True,
    )
    assert report.total_penalty == 10
    assert report.posture_score == 90
    assert len(report.deductions) == 1


def test_non_applicable_posture_returns_none_score():
    """Non-email or non-applicable captures return posture_score=None."""
    report = PostureEngineService().evaluate_posture(
        session_id="test-na",
        stream_id="stream-na",
        findings=[],
        is_applicable=False,
    )
    assert report.posture_score is None
    assert report.severity is None
    assert report.total_penalty == 0
    assert report.evaluated_findings_count == 0
    assert report.applicability == "NOT_APPLICABLE"
    assert report.assessment_status == "NOT_APPLICABLE"
