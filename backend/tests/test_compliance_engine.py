"""
MailRakhwala Compliance Engine Test Suite (Step 21)
Validates deterministic cryptographic compliance evaluation against Step 4 rules.
"""

from datetime import datetime, timezone
import pytest

from app.schemas.compliance_engine import ComplianceStatus
from app.schemas.domain import TriState, FindingCategory, SeverityLevel
from app.schemas.identity_analysis import (
    IdentityAnalysisResult,
    IdentityRelationship,
    IdentityRelationshipType,
    IdentityStatus,
)
from app.schemas.revocation_trust import (
    CertificateTrustEvidence,
    CRLEvidence,
    OCSPObservedStatus,
    OCSPEvidence,
    OCSPVerificationStatus,
    OfflineTrustResult,
    TrustValidationStatus,
)
from app.services.compliance_engine import compliance_engine
from app.services.rule_loader import RuleCatalogError, rule_catalog


# ============================================================
# 1. TLS VERSION EVALUATION TESTS
# ============================================================

def test_tls_1_0_non_compliant():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 1.0"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.rule_id == "RULE-TLS-002"
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_tls_1_1_non_compliant():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 1.1"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.rule_id == "RULE-TLS-002"
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_ssl_3_0_critical_non_compliant():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "SSL 3.0"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.rule_id == "RULE-TLS-001"
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.CRITICAL


def test_tls_1_2_compliant():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 1.2"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.rule_id == "RULE-TLS-003"
    assert f.status == ComplianceStatus.COMPLIANT


def test_tls_1_3_compliant():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 1.3"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.rule_id == "RULE-TLS-004"
    assert f.status == ComplianceStatus.COMPLIANT


def test_tls_version_missing_unknown():
    rep = compliance_engine.evaluate_session("s1", tls_params={})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.status == ComplianceStatus.UNKNOWN


def test_tls_version_unrecognized_unknown():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 9.9"})
    f = next(f for f in rep.findings if f.category == FindingCategory.TLS_VERSION)
    assert f.status == ComplianceStatus.UNKNOWN


# ============================================================
# 2. CIPHER SUITE EVALUATION TESTS
# ============================================================

def test_approved_cipher_uses_approved_rule_not_cbc_rule():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    rep = compliance_engine.evaluate_session("stream-1", tls_params=tls)
    cipher_findings = [f for f in rep.findings if f.category == FindingCategory.CIPHER_SUITE]
    assert len(cipher_findings) == 1
    assert cipher_findings[0].rule_id == "RULE-CIPHER-APPROVED"
    assert cipher_findings[0].status == ComplianceStatus.COMPLIANT
    assert not any(f.rule_id == "RULE-CIPHER-004" for f in cipher_findings)


def test_cbc_cipher_uses_cbc_rule():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}
    rep = compliance_engine.evaluate_session("stream-1", tls_params=tls)
    cipher_findings = [f for f in rep.findings if f.category == FindingCategory.CIPHER_SUITE]
    assert len(cipher_findings) == 1
    assert cipher_findings[0].rule_id == "RULE-CIPHER-004"
    assert cipher_findings[0].status == ComplianceStatus.NON_COMPLIANT


def test_null_cipher_critical():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_NULL_SHA"}
    rep = compliance_engine.evaluate_session("s1", tls_params=tls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CIPHER-001")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.CRITICAL


def test_rc4_cipher_critical():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"}
    rep = compliance_engine.evaluate_session("s1", tls_params=tls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CIPHER-002")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.CRITICAL


def test_3des_cipher_high():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    rep = compliance_engine.evaluate_session("s1", tls_params=tls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CIPHER-003")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_unknown_cipher_uses_unknown_rule_and_status_unknown():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_EXOTIC_EXPERIMENTAL_CIPHER"}
    rep = compliance_engine.evaluate_session("stream-1", tls_params=tls)
    cipher_findings = [f for f in rep.findings if f.category == FindingCategory.CIPHER_SUITE]
    assert len(cipher_findings) == 1
    assert cipher_findings[0].rule_id == "RULE-CIPHER-UNKNOWN"
    assert cipher_findings[0].status == ComplianceStatus.UNKNOWN


def test_missing_cipher_suite_unknown():
    rep = compliance_engine.evaluate_session("s1", tls_params={"version": "TLS 1.2"})
    f = next(f for f in rep.findings if f.category == FindingCategory.CIPHER_SUITE)
    assert f.status == ComplianceStatus.UNKNOWN


# ============================================================
# 3. KEY EXCHANGE & PFS TESTS
# ============================================================

def test_kex_no_pfs_non_compliant():
    kex = {"has_forward_secrecy": TriState.FALSE, "exchange_type": "RSA"}
    rep = compliance_engine.evaluate_session("s1", key_exchange_params=kex)
    f = next(f for f in rep.findings if f.rule_id == "RULE-KEX-001")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_kex_pfs_compliant():
    kex = {"has_forward_secrecy": TriState.TRUE, "exchange_type": "ECDHE"}
    rep = compliance_engine.evaluate_session("s1", key_exchange_params=kex)
    f = next(f for f in rep.findings if f.rule_id == "RULE-KEX-001")
    assert f.status == ComplianceStatus.COMPLIANT


def test_kex_weak_dh_param_bits():
    kex = {"has_forward_secrecy": TriState.TRUE, "exchange_type": "DHE", "dh_param_bits": 1024}
    rep = compliance_engine.evaluate_session("s1", key_exchange_params=kex)
    f = next(f for f in rep.findings if f.rule_id == "RULE-KEX-002")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_kex_strong_dh_param_bits():
    kex = {"has_forward_secrecy": TriState.TRUE, "exchange_type": "DHE", "dh_param_bits": 2048}
    rep = compliance_engine.evaluate_session("s1", key_exchange_params=kex)
    f = next(f for f in rep.findings if f.rule_id == "RULE-KEX-002")
    assert f.status == ComplianceStatus.COMPLIANT


def test_kex_missing_evidence_unknown():
    rep = compliance_engine.evaluate_session("s1", key_exchange_params=None)
    f = next(f for f in rep.findings if f.rule_id == "RULE-KEX-001")
    assert f.status == ComplianceStatus.UNKNOWN


# ============================================================
# 4. CERTIFICATE SECURITY AUDIT TESTS
# ============================================================

def test_cert_expired():
    ref = datetime(2026, 9, 18, tzinfo=timezone.utc)
    cert = {"is_expired": TriState.TRUE, "is_not_yet_valid": TriState.FALSE}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert, reference_time=ref)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-001")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.HIGH


def test_cert_not_yet_valid():
    ref = datetime(2026, 9, 18, tzinfo=timezone.utc)
    cert = {"is_expired": TriState.FALSE, "is_not_yet_valid": TriState.TRUE}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert, reference_time=ref)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-002")
    assert f.status == ComplianceStatus.NON_COMPLIANT


def test_cert_active_window_compliant():
    ref = datetime(2026, 9, 18, tzinfo=timezone.utc)
    cert = {"is_expired": TriState.FALSE, "is_not_yet_valid": TriState.FALSE}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert, reference_time=ref)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-001")
    assert f.status == ComplianceStatus.COMPLIANT


def test_cert_validity_without_reference_time_unknown():
    cert = {"is_expired": TriState.FALSE, "is_not_yet_valid": TriState.FALSE}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert, reference_time=None)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-001")
    assert f.status == ComplianceStatus.UNKNOWN


def test_cert_weak_rsa_key_critical():
    cert = {"public_key_algorithm": "RSA", "public_key_bits": 1024}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-003")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.CRITICAL


def test_cert_strong_rsa_key_compliant():
    cert = {"public_key_algorithm": "RSA", "public_key_bits": 2048}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-003")
    assert f.status == ComplianceStatus.COMPLIANT


def test_cert_weak_signature_critical():
    cert = {"signature_algorithm": "sha1WithRSAEncryption"}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert)
    f = next(f for f in rep.findings if f.rule_id == "RULE-CERT-004")
    assert f.status == ComplianceStatus.NON_COMPLIANT
    assert f.severity == SeverityLevel.CRITICAL


def test_cert_self_signed_non_compliant():
    cert = {"is_self_signed": TriState.TRUE}
    rep = compliance_engine.evaluate_session("s1", cert_audit_params=cert)
    f = next(f for f in rep.findings if f.rule_id == "RULE-PKI-001")
    assert f.status == ComplianceStatus.NON_COMPLIANT


# ============================================================
# 5. STARTTLS EVALUATION TESTS
# ============================================================

def test_starttls_downgrade_suspected():
    stls = {"starttls_state": "DOWNGRADE_SUSPECTED"}
    rep = compliance_engine.evaluate_session("s1", starttls_params=stls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-STARTTLS-002")
    assert f.status == ComplianceStatus.NON_COMPLIANT


def test_starttls_succeeded():
    stls = {"starttls_state": "SUCCEEDED"}
    rep = compliance_engine.evaluate_session("s1", starttls_params=stls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-STARTTLS-002")
    assert f.status == ComplianceStatus.COMPLIANT


def test_starttls_implicit_not_applicable():
    stls = {"starttls_state": "NOT_APPLICABLE"}
    rep = compliance_engine.evaluate_session("s1", starttls_params=stls)
    f = next(f for f in rep.findings if f.rule_id == "RULE-STARTTLS-002")
    assert f.status == ComplianceStatus.NOT_APPLICABLE


# ============================================================
# 6. IDENTITY ALIGNMENT TESTS
# ============================================================

def test_identity_match_compliant():
    id_res = IdentityAnalysisResult(
        stream_id="s1",
        certificate_index=0,
        relationships=[
            IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                left_name="TLS ClientHello SNI",
                left_value="mail.example.com",
                right_name="Server Certificate SAN",
                right_value="mail.example.com",
                status=IdentityStatus.MATCH,
                explanation="Observed SNI matches observed SAN entry perfectly.",
            )
        ],
        overall_interpretation="Consistent session identity observed across indicators.",
    )
    rep = compliance_engine.evaluate_session("s1", identity_result=id_res)
    f = next(f for f in rep.findings if f.rule_id == "RULE-IDENTITY-001")
    assert f.status == ComplianceStatus.COMPLIANT


def test_identity_mismatch_non_compliant():
    id_res = IdentityAnalysisResult(
        stream_id="s1",
        certificate_index=0,
        relationships=[
            IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                left_name="TLS ClientHello SNI",
                left_value="mail.adversary.org",
                right_name="Server Certificate SAN",
                right_value="mail.example.com",
                status=IdentityStatus.MISMATCH,
                explanation="Observed SNI does not match any SAN entries.",
            )
        ],
        overall_interpretation="Identity mismatch observed.",
    )
    rep = compliance_engine.evaluate_session("s1", identity_result=id_res)
    f = next(f for f in rep.findings if f.rule_id == "RULE-IDENTITY-001")
    assert f.status == ComplianceStatus.NON_COMPLIANT


def test_identity_unavailable_unknown():
    id_res = IdentityAnalysisResult(
        stream_id="s1",
        certificate_index=0,
        relationships=[
            IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                left_name="TLS ClientHello SNI",
                left_value=None,
                right_name="Server Certificate SAN",
                right_value="mail.example.com",
                status=IdentityStatus.UNAVAILABLE,
                explanation="SNI extension was not observed in the ClientHello.",
            )
        ],
        overall_interpretation="SNI was unavailable.",
    )
    rep = compliance_engine.evaluate_session("s1", identity_result=id_res)
    f = next(f for f in rep.findings if f.rule_id == "RULE-IDENTITY-001")
    assert f.status == ComplianceStatus.UNKNOWN


# ============================================================
# 7. TRUST & OCSP STAPLING TESTS
# ============================================================

def test_trust_validation_statuses():
    # 1. VALIDATED_LOCALLY
    t1 = OfflineTrustResult(
        stream_id="stream-1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="stream-1",
            leaf_fingerprint_sha256="aa" * 32,
            trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="stream-1",
            explanation="No OCSP response stapled in session",
        ),
        crl_evidence=CRLEvidence(
            stream_id="stream-1",
            explanation="No CRL distribution point evaluated offline",
        ),
        overall_trust_state=TrustValidationStatus.VALIDATED_LOCALLY,
    )
    rep1 = compliance_engine.evaluate_session("stream-1", trust_result=t1)
    trust_f1 = next(f for f in rep1.findings if f.rule_id == "RULE-TRUST-001")
    assert trust_f1.status == ComplianceStatus.COMPLIANT

    # 2. NOT_VALIDATED
    t2 = OfflineTrustResult(
        stream_id="stream-1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="stream-1",
            leaf_fingerprint_sha256="bb" * 32,
            trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="stream-1",
            explanation="No OCSP response stapled in session",
        ),
        crl_evidence=CRLEvidence(
            stream_id="stream-1",
            explanation="No CRL distribution point evaluated offline",
        ),
        overall_trust_state=TrustValidationStatus.NOT_VALIDATED,
    )
    rep2 = compliance_engine.evaluate_session("stream-1", trust_result=t2)
    trust_f2 = next(f for f in rep2.findings if f.rule_id == "RULE-TRUST-001")
    assert trust_f2.status == ComplianceStatus.NON_COMPLIANT

    # 3. UNAVAILABLE_FROM_PCAP
    t3 = OfflineTrustResult(
        stream_id="stream-1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="stream-1",
            leaf_fingerprint_sha256="cc" * 32,
            trust_validation_status=TrustValidationStatus.UNAVAILABLE_FROM_PCAP,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="stream-1",
            explanation="No OCSP response stapled in session",
        ),
        crl_evidence=CRLEvidence(
            stream_id="stream-1",
            explanation="No CRL distribution point evaluated offline",
        ),
        overall_trust_state=TrustValidationStatus.UNAVAILABLE_FROM_PCAP,
    )
    rep3 = compliance_engine.evaluate_session("stream-1", trust_result=t3)
    trust_f3 = next(f for f in rep3.findings if f.rule_id == "RULE-TRUST-001")
    assert trust_f3.status == ComplianceStatus.UNKNOWN


def test_ocsp_observed_vs_verification_semantics():
    # GOOD + VERIFIED -> COMPLIANT
    t_good_ver = OfflineTrustResult(
        stream_id="s1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="s1",
            leaf_fingerprint_sha256="11" * 32,
            trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="s1",
            observed_status=OCSPObservedStatus.GOOD,
            verification_status=OCSPVerificationStatus.VERIFIED,
            explanation="OCSP response verified against issuer certificate",
        ),
        crl_evidence=CRLEvidence(
            stream_id="s1",
            explanation="No CRL evaluation needed",
        ),
        overall_trust_state=TrustValidationStatus.VALIDATED_LOCALLY,
    )
    rep1 = compliance_engine.evaluate_session("s1", trust_result=t_good_ver)
    f1 = next(f for f in rep1.findings if f.rule_id == "RULE-REVOC-001")
    assert f1.status == ComplianceStatus.COMPLIANT

    # GOOD + NOT_VERIFIED -> UNKNOWN
    t_good_unver = OfflineTrustResult(
        stream_id="s1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="s1",
            leaf_fingerprint_sha256="22" * 32,
            trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="s1",
            observed_status=OCSPObservedStatus.GOOD,
            verification_status=OCSPVerificationStatus.NOT_VERIFIED,
            explanation="OCSP status good but cryptographic verification unperformed",
        ),
        crl_evidence=CRLEvidence(
            stream_id="s1",
            explanation="No CRL evaluation needed",
        ),
        overall_trust_state=TrustValidationStatus.VALIDATED_LOCALLY,
    )
    rep2 = compliance_engine.evaluate_session("s1", trust_result=t_good_unver)
    f2 = next(f for f in rep2.findings if f.rule_id == "RULE-REVOC-001")
    assert f2.status == ComplianceStatus.UNKNOWN

    # REVOKED -> NON_COMPLIANT
    t_rev = OfflineTrustResult(
        stream_id="s1",
        certificate_trust=CertificateTrustEvidence(
            stream_id="s1",
            leaf_fingerprint_sha256="33" * 32,
            trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
        ),
        ocsp_evidence=OCSPEvidence(
            stream_id="s1",
            observed_status=OCSPObservedStatus.REVOKED,
            verification_status=OCSPVerificationStatus.VERIFIED,
            explanation="Certificate explicitly marked revoked in OCSP payload",
        ),
        crl_evidence=CRLEvidence(
            stream_id="s1",
            explanation="No CRL evaluation needed",
        ),
        overall_trust_state=TrustValidationStatus.VALIDATED_LOCALLY,
    )
    rep3 = compliance_engine.evaluate_session("s1", trust_result=t_rev)
    f3 = next(f for f in rep3.findings if f.rule_id == "RULE-REVOC-001")
    assert f3.status == ComplianceStatus.NON_COMPLIANT


# ============================================================
# 8. DETERMINISM, DEDUPLICATION, & CONTRACT TESTS
# ============================================================

def test_nonexistent_rule_lookup_raises_rule_catalog_error():
    with pytest.raises(RuleCatalogError):
        rule_catalog.require_rule("RULE-NONEXISTENT-999")


def test_deterministic_finding_id_repeated_evaluations():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    rep1 = compliance_engine.evaluate_session("stream-10", tls_params=tls)
    rep2 = compliance_engine.evaluate_session("stream-10", tls_params=tls)
    assert [f.finding_id for f in rep1.findings] == [f.finding_id for f in rep2.findings]


def test_distinct_streams_generate_distinct_finding_ids():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    rep1 = compliance_engine.evaluate_session("stream-A", tls_params=tls)
    rep2 = compliance_engine.evaluate_session("stream-B", tls_params=tls)
    assert rep1.findings[0].finding_id != rep2.findings[0].finding_id


def test_deduplication_collapses_identical_evidence():
    tls = {"version": "TLS 1.2", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    rep = compliance_engine.evaluate_session("s1", tls_params=tls)
    rule_ids = [f.rule_id for f in rep.findings]
    assert len(rule_ids) == len(set(rule_ids))


def test_overall_compliance_precedence_non_compliant_wins():
    tls_bad = {"version": "TLS 1.0", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    rep = compliance_engine.evaluate_session("s1", tls_params=tls_bad)
    assert rep.overall_compliance == ComplianceStatus.NON_COMPLIANT


def test_overall_compliance_precedence_compliant_plus_unknown_is_unknown():
    tls_good = {"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}
    # Leaving kex, cert, identity missing results in UNKNOWN findings
    rep = compliance_engine.evaluate_session("s2", tls_params=tls_good)
    assert rep.overall_compliance == ComplianceStatus.UNKNOWN


def test_overall_compliance_not_applicable_alone_is_unknown():
    stls = {"starttls_state": "NOT_APPLICABLE"}
    rep = compliance_engine.evaluate_session("s1", starttls_params=stls)
    # Check overall logic when only NOT_APPLICABLE findings are evaluated
    rep.findings = [f for f in rep.findings if f.status == ComplianceStatus.NOT_APPLICABLE]
    rep.summary.non_compliant_count = 0
    rep.summary.compliant_count = 0
    rep.summary.unknown_count = 0
    rep.summary.not_applicable_count = 1
    if rep.summary.non_compliant_count > 0:
        overall = ComplianceStatus.NON_COMPLIANT
    elif rep.summary.unknown_count > 0 or (rep.summary.compliant_count == 0):
        overall = ComplianceStatus.UNKNOWN
    else:
        overall = ComplianceStatus.COMPLIANT
    assert overall == ComplianceStatus.UNKNOWN