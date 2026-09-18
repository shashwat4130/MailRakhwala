"""
Tests verifying Step 19 Identity & Trust Analysis.
Deterministic offline tests verifying hostname matching, wildcard handling,
and identity correlation across TLS SNI, Certificate SAN, mail host, and DNS/trust context.
"""

from datetime import datetime, timezone
import pytest

from app.schemas.certificate_parsing import (
    CertificateParseStatus,
    DistinguishedName,
    ParsedCertificate,
    SubjectAlternativeNames,
)
from app.schemas.identity_analysis import (
    IdentityRelationshipType,
    IdentityStatus,
)
from app.services.identity_analyzer import identity_analyzer, match_hostname


def _build_dummy_cert(
    san_dns=None,
    common_name="mail.example.org",
    cert_index=0,
    raw_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    frame_number=10,
    timestamp=100.5,
) -> ParsedCertificate:
    sans = san_dns if san_dns is not None else []
    return ParsedCertificate(
        certificate_index=cert_index,
        stream_id="stream-test-identity",
        frame_number=frame_number,
        timestamp=timestamp,
        raw_der_sha256=raw_sha256,
        parse_status=CertificateParseStatus.PARSED,
        subject=DistinguishedName(
            common_name=common_name,
            raw_dn_string=f"CN={common_name}" if common_name else "CN=None",
        ),
        issuer=DistinguishedName(
            common_name="CA Issuer",
            raw_dn_string="CN=CA Issuer",
        ),
        san=SubjectAlternativeNames(
            dns_names=sans,
            has_san=len(sans) > 0,
        ),
        not_before=datetime.now(timezone.utc),
        not_after=datetime.now(timezone.utc),
    )


# --- Hostname Matcher Tests ---

def test_exact_sni_san_match():
    assert match_hostname("mail.example.com", "mail.example.com") is True


def test_case_insensitive_hostname_match():
    assert match_hostname("MAIL.Example.COM", "mail.example.com") is True
    assert match_hostname("mail.example.com", "MAIL.EXAMPLE.COM") is True


def test_valid_wildcard_san_match():
    assert match_hostname("mail.example.com", "*.example.com") is True
    assert match_hostname("smtp.secure.example.com", "*.secure.example.com") is True


def test_invalid_wildcard_handling():
    assert match_hostname("sub.mail.example.com", "*.example.com") is False
    assert match_hostname("mail.example.com", "mail.*.com") is False
    assert match_hostname("example.com", "*.com") is False
    assert match_hostname("mail.example.com", "m*.example.com") is False


def test_unrelated_sni_san_mismatch():
    assert match_hostname("mail.attacker.com", "mail.example.com") is False
    assert match_hostname("example.net", "example.com") is False


def test_malformed_invalid_hostname_inputs():
    assert match_hostname("", "mail.example.com") is False
    assert match_hostname(None, "mail.example.com") is False
    assert match_hostname("mail.example.com", "") is False
    assert match_hostname("...", "...") is False


# --- Fix 1: No Subject CN Fallback for SAN ---

def test_san_absent_cn_matching_sni_returns_unavailable():
    # Certificate has CN='mail.example.com', but SAN is absent
    cert = _build_dummy_cert(san_dns=[], common_name="mail.example.com")
    res = identity_analyzer.analyze(cert, sni="mail.example.com")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.status == IdentityStatus.UNAVAILABLE
    assert "no subject alternative name" in rel.explanation.lower()


# --- Identity Analyzer Core Tests ---

def test_sni_vs_san_exact_match():
    cert = _build_dummy_cert(san_dns=["mail.example.com", "smtp.example.com"])
    res = identity_analyzer.analyze(cert, sni="mail.example.com")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.status == IdentityStatus.MATCH
    assert rel.matched_entry == "mail.example.com"


def test_sni_vs_san_mismatch():
    cert = _build_dummy_cert(san_dns=["mail.example.com"])
    res = identity_analyzer.analyze(cert, sni="phishing.domain.org")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.status == IdentityStatus.MISMATCH
    assert "phishing.domain.org" in rel.explanation


def test_sni_unavailable():
    cert = _build_dummy_cert(san_dns=["mail.example.com"])
    res = identity_analyzer.analyze(cert, sni=None)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.status == IdentityStatus.UNAVAILABLE


def test_san_unavailable_when_empty():
    cert = _build_dummy_cert(san_dns=[], common_name=None)
    res = identity_analyzer.analyze(cert, sni="mail.example.com")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.status == IdentityStatus.UNAVAILABLE


def test_observed_mail_host_vs_san_match():
    cert = _build_dummy_cert(san_dns=["smtp.mailcorp.org"])
    res = identity_analyzer.analyze(cert, observed_mail_host="smtp.mailcorp.org")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_HOST_VS_SAN)
    assert rel.status == IdentityStatus.MATCH
    assert rel.matched_entry == "smtp.mailcorp.org"


def test_observed_mail_host_vs_san_needs_context():
    cert = _build_dummy_cert(san_dns=["smtp.mailcorp.org"])
    res = identity_analyzer.analyze(cert, observed_mail_host="internal-relay-01.local")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_HOST_VS_SAN)
    assert rel.status == IdentityStatus.NEEDS_CONTEXT


def test_observed_mail_host_unavailable():
    cert = _build_dummy_cert(san_dns=["mail.example.com"])
    res = identity_analyzer.analyze(cert, observed_mail_host=None)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_HOST_VS_SAN)
    assert rel.status == IdentityStatus.UNAVAILABLE


def test_sni_vs_mail_host_match():
    cert = _build_dummy_cert()
    res = identity_analyzer.analyze(cert, sni="mail.corp.org", observed_mail_host="mail.corp.org")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_MAIL_HOST)
    assert rel.status == IdentityStatus.MATCH


def test_sni_vs_mail_host_mismatch_context():
    cert = _build_dummy_cert()
    res = identity_analyzer.analyze(cert, sni="mail.corp.org", observed_mail_host="inbound-lb.corp.org")

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_MAIL_HOST)
    assert rel.status == IdentityStatus.NEEDS_CONTEXT


# --- Fix 3: DNS/MX Conservative Semantics ---

def test_dns_mx_evidence_direct_match():
    cert = _build_dummy_cert()
    dns_ctx = {"mx_records": ["mx1.example.com", "mx2.example.com"]}
    res = identity_analyzer.analyze(cert, sni="mx1.example.com", dns_mx_context=dns_ctx)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX)
    assert rel.status == IdentityStatus.MATCH
    assert rel.matched_entry == "mx1.example.com"


def test_dns_mx_unrelated_yields_needs_context_not_mismatch():
    cert = _build_dummy_cert()
    dns_ctx = {"mx_records": ["mx1.example.com", "mx2.example.com"]}
    res = identity_analyzer.analyze(cert, sni="relay01.outbound.org", dns_mx_context=dns_ctx)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX)
    # Conservative: absence of direct match in MX list is NEEDS_CONTEXT, not an outright MISMATCH
    assert rel.status == IdentityStatus.NEEDS_CONTEXT
    assert "mx records designate domain routing destinations" in rel.explanation.lower()


def test_dns_mx_explicit_contradiction_yields_mismatch():
    cert = _build_dummy_cert()
    dns_ctx = {"mx_records": ["mx1.example.com"], "explicit_contradiction": True}
    res = identity_analyzer.analyze(cert, sni="spoofed.domain.org", dns_mx_context=dns_ctx)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX)
    assert rel.status == IdentityStatus.MISMATCH


def test_dns_mx_evidence_unavailable():
    cert = _build_dummy_cert()
    res = identity_analyzer.analyze(cert, sni="mail.example.com", dns_mx_context=None)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX)
    assert rel.status == IdentityStatus.UNAVAILABLE


# --- Fix 2: Trust Path Never Claims Trust in Step 19 ---

def test_trust_path_evidence_unavailable():
    cert = _build_dummy_cert()
    res = identity_analyzer.analyze(cert, trust_path_context=None)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.CERTIFICATE_VS_TRUST_PATH)
    assert rel.status == IdentityStatus.UNAVAILABLE


def test_trust_path_evidence_supplied_yields_needs_context_not_match():
    cert = _build_dummy_cert()
    trust_ctx = {"trust_path_status": "VERIFIED"}
    res = identity_analyzer.analyze(cert, trust_path_context=trust_ctx)

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.CERTIFICATE_VS_TRUST_PATH)
    # Fix 2: Step 19 surfaces trust context as NEEDS_CONTEXT, never MATCH
    assert rel.status == IdentityStatus.NEEDS_CONTEXT
    assert "step 19 does not independently validate" in rel.explanation.lower()
    for lim in rel.limitations:
        assert "trusted" not in lim or "does not claim" in lim


# --- Fix 4: Evidence Traceability and Provenance ---

def test_evidence_traceability_survives_into_relationships():
    cert = _build_dummy_cert(
        san_dns=["mail.trace.org"],
        cert_index=3,
        raw_sha256="deadbeef12345678",
        frame_number=42,
        timestamp=123.456,
    )
    res = identity_analyzer.analyze(cert, sni="mail.trace.org")

    assert res.certificate_index == 3
    assert res.raw_der_sha256 == "deadbeef12345678"
    assert res.stream_id == "stream-test-identity"

    rel = next(r for r in res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN)
    assert rel.certificate_index == 3
    assert rel.raw_der_sha256 == "deadbeef12345678"
    assert rel.frame_number == 42
    assert rel.timestamp == 123.456
    assert rel.left_source == "TLS_CLIENT_HELLO"
    assert rel.right_source == "CERTIFICATE_SAN"


def test_no_false_attack_classification_from_mismatch():
    cert = _build_dummy_cert(san_dns=["secure.example.com"])
    res = identity_analyzer.analyze(cert, sni="unrelated.example.com")

    interp_lower = res.overall_interpretation.lower()
    for bad_word in ["attack", "mitm", "malicious", "adversary", "compromise"]:
        assert bad_word not in interp_lower


def test_multi_certificate_chain_indexing():
    cert0 = _build_dummy_cert(san_dns=["leaf.org"], cert_index=0, raw_sha256="aaaa")
    cert1 = _build_dummy_cert(san_dns=["ca.org"], cert_index=1, raw_sha256="bbbb")

    res0 = identity_analyzer.analyze(cert0, sni="leaf.org")
    res1 = identity_analyzer.analyze(cert1, sni="leaf.org")

    assert res0.certificate_index == 0
    assert res0.raw_der_sha256 == "aaaa"
    assert res1.certificate_index == 1
    assert res1.raw_der_sha256 == "bbbb"