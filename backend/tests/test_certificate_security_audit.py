"""
Tests verifying Step 18 Certificate Security Audit.
Deterministic offline tests checking validity, weak keys, deprecated digests, self-signed detection, and chain ordering.
"""

from datetime import datetime, timedelta, timezone
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from app.schemas.certificate_extraction import RawExtractedCertificate
from app.schemas.certificate_parsing import ParsedCertificateChain
from app.schemas.certificate_security_audit import CertificateFindingType
from app.schemas.domain import SeverityLevel, TriState
from app.services.certificate_parser import certificate_parser
from app.services.certificate_security_auditor import certificate_security_auditor


def _create_cert(
    private_key,
    subject_cn="mail.example.org",
    issuer_cn="mail.example.org",
    hash_algo=hashes.SHA256(),
    not_before=None,
    not_after=None,
    ca=False,
) -> bytes:
    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=1))
    na = not_after or (now + timedelta(days=90))

    sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(iss)
        .public_key(private_key.public_key())
        .serial_number(0xABCD1234)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )

    cert = builder.sign(private_key, hash_algo)
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def rsa_2048_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def rsa_1024_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _parse_der(der_bytes: bytes, index: int = 0, stream_id: str = "test-stream"):
    raw = RawExtractedCertificate(
        certificate_index=index,
        raw_der=der_bytes,
        raw_der_hex=der_bytes.hex(),
        der_length=len(der_bytes),
        stream_id=stream_id,
    )
    return certificate_parser.parse_raw_certificate(raw)


def test_valid_certificate(rsa_2048_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(rsa_2048_key, not_before=now - timedelta(days=10), not_after=now + timedelta(days=50))
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    assert audit.is_expired == TriState.FALSE
    assert audit.is_not_yet_valid == TriState.FALSE
    assert audit.has_weak_key == TriState.FALSE
    assert audit.has_weak_signature == TriState.FALSE
    finding_types = [f.finding_type for f in audit.findings]
    assert CertificateFindingType.CERTIFICATE_EXPIRED not in finding_types
    assert CertificateFindingType.WEAK_RSA_KEY not in finding_types


def test_expired_certificate(rsa_2048_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(rsa_2048_key, not_before=now - timedelta(days=40), not_after=now - timedelta(days=10))
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    assert audit.is_expired == TriState.TRUE
    finding = next((f for f in audit.findings if f.finding_type == CertificateFindingType.CERTIFICATE_EXPIRED), None)
    assert finding is not None
    assert finding.finding_id == "RULE-CERT-001"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.evidence.observed_property == "not_after"


def test_not_yet_valid_certificate(rsa_2048_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(rsa_2048_key, not_before=now + timedelta(days=5), not_after=now + timedelta(days=90))
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    assert audit.is_not_yet_valid == TriState.TRUE
    finding = next((f for f in audit.findings if f.finding_type == CertificateFindingType.CERTIFICATE_NOT_YET_VALID), None)
    assert finding is not None
    assert finding.finding_id == "RULE-CERT-002"
    assert finding.severity == SeverityLevel.MEDIUM


def test_weak_rsa_key(rsa_1024_key):
    der = _create_cert(rsa_1024_key)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.has_weak_key == TriState.TRUE
    finding = next((f for f in audit.findings if f.finding_type == CertificateFindingType.WEAK_RSA_KEY), None)
    assert finding is not None
    assert finding.finding_id == "RULE-CERT-003"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.evidence.observed_value == 1024
    assert finding.evidence.reference_value == 2048


def test_strong_rsa_key(rsa_2048_key):
    der = _create_cert(rsa_2048_key)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.has_weak_key == TriState.FALSE
    weak_findings = [f for f in audit.findings if f.finding_type == CertificateFindingType.WEAK_RSA_KEY]
    assert len(weak_findings) == 0


def test_ec_certificate(ec_key):
    der = _create_cert(ec_key)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.has_weak_key == TriState.FALSE
    ec_weak_findings = [f for f in audit.findings if f.finding_type == CertificateFindingType.WEAK_EC_CURVE]
    assert len(ec_weak_findings) == 0


def test_ed25519_certificate():
    priv = ed25519.Ed25519PrivateKey.generate()
    sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519.org")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(iss)
        .public_key(priv.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(priv, None)
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now + timedelta(days=1))

    assert audit.has_weak_key == TriState.FALSE


def test_weak_signature_algorithm(rsa_2048_key):
    der = _create_cert(rsa_2048_key, hash_algo=hashes.SHA256())
    parsed = _parse_der(der)
    # Simulate captured certificate with deprecated SHA-1 signature
    parsed.signature_hash_algorithm = "sha1"
    parsed.signature_algorithm_name = "sha1WithRSAEncryption"
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.has_weak_signature == TriState.TRUE
    finding = next((f for f in audit.findings if f.finding_type == CertificateFindingType.WEAK_SIGNATURE_ALGORITHM), None)
    assert finding is not None
    assert finding.finding_id == "RULE-CERT-004"
    assert finding.severity == SeverityLevel.CRITICAL


def test_modern_signature_algorithm(rsa_2048_key):
    der = _create_cert(rsa_2048_key, hash_algo=hashes.SHA384())
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.has_weak_signature == TriState.FALSE
    sig_findings = [f for f in audit.findings if f.finding_type == CertificateFindingType.WEAK_SIGNATURE_ALGORITHM]
    assert len(sig_findings) == 0


def test_self_signed_certificate(rsa_2048_key):
    der = _create_cert(rsa_2048_key, subject_cn="mail.self.org", issuer_cn="mail.self.org")
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.is_self_signed == TriState.TRUE
    finding = next((f for f in audit.findings if f.finding_type == CertificateFindingType.SELF_SIGNED_CERTIFICATE), None)
    assert finding is not None
    assert finding.finding_id == "RULE-PKI-001"
    assert finding.severity == SeverityLevel.MEDIUM


def test_non_self_signed_certificate(rsa_2048_key):
    der = _create_cert(rsa_2048_key, subject_cn="mail.child.org", issuer_cn="mail.ca-root.org")
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    assert audit.is_self_signed == TriState.FALSE
    ss_findings = [f for f in audit.findings if f.finding_type == CertificateFindingType.SELF_SIGNED_CERTIFICATE]
    assert len(ss_findings) == 0


def test_unknown_missing_reference_time(rsa_2048_key):
    der = _create_cert(rsa_2048_key)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=None)

    assert audit.is_expired == TriState.UNKNOWN
    assert audit.is_not_yet_valid == TriState.UNKNOWN
    assert any("reference timestamp missing" in lim.lower() for lim in audit.audit_limitations)


def test_malformed_certificate_input():
    from app.schemas.certificate_parsing import CertificateParseStatus, ParsedCertificate
    malformed_cert = ParsedCertificate(
        certificate_index=0,
        stream_id="stream-bad",
        parse_status=CertificateParseStatus.MALFORMED_DER,
        parse_error="Invalid ASN.1 length",
    )
    audit = certificate_security_auditor.audit_certificate(malformed_cert)

    assert len(audit.findings) == 1
    assert audit.findings[0].finding_type == CertificateFindingType.EMPTY_OR_CORRUPT_CERTIFICATE


def test_chain_related_audit_behavior(rsa_2048_key):
    der1 = _create_cert(rsa_2048_key, subject_cn="leaf.org", issuer_cn="intermediate.org")
    der2 = _create_cert(rsa_2048_key, subject_cn="unrelated.org", issuer_cn="root.org")

    parsed1 = _parse_der(der1, index=0)
    parsed2 = _parse_der(der2, index=1)

    chain = ParsedCertificateChain(
        stream_id="stream-mismatch",
        total_certificates=2,
        certificates=[parsed1, parsed2],
    )
    res = certificate_security_auditor.audit_chain(chain)

    assert any(f.finding_type == CertificateFindingType.CHAIN_DN_SEQUENCE_MISMATCH for f in res.chain_findings)


def test_chain_duplicate_detection(rsa_2048_key):
    der = _create_cert(rsa_2048_key, subject_cn="dup.org", issuer_cn="dup.org")
    parsed1 = _parse_der(der, index=0)
    parsed2 = _parse_der(der, index=1)

    chain = ParsedCertificateChain(
        stream_id="stream-dup",
        total_certificates=2,
        certificates=[parsed1, parsed2],
    )
    res = certificate_security_auditor.audit_chain(chain)

    assert any(f.finding_type == CertificateFindingType.DUPLICATE_CERTIFICATE_IN_CHAIN for f in res.chain_findings)


def test_finding_evidence_structure(rsa_1024_key):
    der = _create_cert(rsa_1024_key)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed)

    finding = audit.findings[0]
    assert finding.evidence.certificate_index == 0
    assert finding.evidence.rule_id == "RULE-CERT-003"
    assert finding.evidence.observed_value == 1024
    assert finding.evidence.reference_value == 2048
    assert finding.recommendation != ""


def test_multiple_findings_on_one_certificate(rsa_1024_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(
        rsa_1024_key,
        subject_cn="multi.bad.org",
        issuer_cn="multi.bad.org",
        hash_algo=hashes.SHA256(),
        not_before=now - timedelta(days=60),
        not_after=now - timedelta(days=10),
    )
    parsed = _parse_der(der)
    # Simulate weak signature algorithm without relying on OS OpenSSL to sign SHA-1
    parsed.signature_hash_algorithm = "sha1"
    parsed.signature_algorithm_name = "sha1WithRSAEncryption"

    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    f_types = {f.finding_type for f in audit.findings}
    assert CertificateFindingType.CERTIFICATE_EXPIRED in f_types
    assert CertificateFindingType.WEAK_RSA_KEY in f_types
    assert CertificateFindingType.WEAK_SIGNATURE_ALGORITHM in f_types
    assert CertificateFindingType.SELF_SIGNED_CERTIFICATE in f_types
    assert len(audit.findings) >= 4


def test_no_false_positives_modern_cert(rsa_2048_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(
        rsa_2048_key,
        subject_cn="secure.bank.org",
        issuer_cn="Secure Global CA",
        hash_algo=hashes.SHA256(),
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=90),
    )
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    assert len(audit.findings) == 0


def test_deterministic_repeated_evaluation(rsa_1024_key):
    now = datetime.now(timezone.utc)
    der = _create_cert(rsa_1024_key, hash_algo=hashes.SHA256())
    parsed = _parse_der(der)
    parsed.signature_hash_algorithm = "sha1"
    parsed.signature_algorithm_name = "sha1WithRSAEncryption"

    audit1 = certificate_security_auditor.audit_certificate(parsed, ref_time=now)
    audit2 = certificate_security_auditor.audit_certificate(parsed, ref_time=now)

    assert [f.finding_id for f in audit1.findings] == [f.finding_id for f in audit2.findings]
    assert [f.severity for f in audit1.findings] == [f.severity for f in audit2.findings]


def test_dsa_weak_key():
    params = dsa.generate_parameters(key_size=1024)
    priv = params.generate_private_key()
    sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa.org")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(iss)
        .public_key(priv.public_key())
        .serial_number(100)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(priv, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    parsed = _parse_der(der)
    audit = certificate_security_auditor.audit_certificate(parsed, ref_time=now + timedelta(days=1))

    assert audit.has_weak_key == TriState.TRUE
    assert any(f.finding_type == CertificateFindingType.WEAK_DSA_KEY for f in audit.findings)


def test_basic_constraints_ca_anomaly_on_leaf(rsa_2048_key):
    der_leaf_with_ca = _create_cert(rsa_2048_key, subject_cn="leaf.ca.org", ca=True)
    parsed_leaf_ca = _parse_der(der_leaf_with_ca, index=0)
    audit_leaf_ca = certificate_security_auditor.audit_certificate(parsed_leaf_ca)

    anomaly = next((f for f in audit_leaf_ca.findings if f.finding_type == CertificateFindingType.BASIC_CONSTRAINTS_CA_MISMATCH), None)
    assert anomaly is not None
    assert anomaly.severity == SeverityLevel.LOW
    assert anomaly.evidence.observed_property == "basicConstraints.ca"
    assert anomaly.evidence.observed_value is True

    der_normal_leaf = _create_cert(rsa_2048_key, subject_cn="leaf.normal.org", ca=False)
    parsed_normal = _parse_der(der_normal_leaf, index=0)
    audit_normal = certificate_security_auditor.audit_certificate(parsed_normal)

    normal_anomaly = next((f for f in audit_normal.findings if f.finding_type == CertificateFindingType.BASIC_CONSTRAINTS_CA_MISMATCH), None)
    assert normal_anomaly is None