"""
Tests verifying Step 17 X.509 Certificate Parsing.
Uses local deterministic cryptography fixtures without network dependencies.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from app.schemas.certificate_extraction import (
    CertificateChainExtractionResult,
    CertificateExtractionStatus,
    RawExtractedCertificate,
)
from app.schemas.certificate_parsing import CertificateParseStatus
from app.services.certificate_parser import certificate_parser


def _generate_rsa_cert_der(
    common_name="mail.example.org",
    org="Example Corp",
    key_size=2048,
    san_dns=None,
    san_ips=None,
    critical_basic_constraints=True,
) -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(0xDEADBEEF)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=critical_basic_constraints,
        )
    )

    if san_dns or san_ips:
        names = []
        if san_dns:
            names.extend([x509.DNSName(d) for d in san_dns])
        if san_ips:
            names.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips])
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        )

    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _generate_ec_cert_der(curve=ec.SECP256R1()) -> bytes:
    private_key = ec.generate_private_key(curve)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "smtp.ecc-mail.org"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(0x123456789ABC)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_valid_rsa_certificate_parsing():
    der = _generate_rsa_cert_der(key_size=2048)
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
        stream_id="stream-1",
        first_frame_number=14,
        first_timestamp=100.0,
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.parse_status == CertificateParseStatus.PARSED
    assert parsed.certificate_index == 0
    assert parsed.stream_id == "stream-1"
    assert parsed.frame_number == 14
    assert parsed.timestamp == 100.0
    assert parsed.public_key.algorithm == "RSA"
    assert parsed.public_key.key_size_bits == 2048
    assert parsed.public_key.exponent == 65537
    assert parsed.signature_hash_algorithm.lower() == "sha256"


def test_valid_ec_certificate_parsing():
    der = _generate_ec_cert_der(ec.SECP256R1())
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.parse_status == CertificateParseStatus.PARSED
    assert parsed.public_key.algorithm == "EC"
    assert parsed.public_key.curve_name == "secp256r1"
    assert parsed.public_key.key_size_bits == 256
    assert parsed.signature_hash_algorithm.lower() == "sha384"


def test_subject_and_issuer_extraction():
    der = _generate_rsa_cert_der(common_name="imap.mail.corp", org="Mail Secure Ltd")
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.subject.common_name == "imap.mail.corp"
    assert parsed.subject.organization == "Mail Secure Ltd"
    assert parsed.subject.country == "IN"
    assert parsed.issuer.common_name == "imap.mail.corp"
    assert "CN=imap.mail.corp" in parsed.subject.raw_dn_string


def test_san_extraction_dns_and_ips():
    der = _generate_rsa_cert_der(
        san_dns=["smtp.domain.org", "pop.domain.org"],
        san_ips=["192.168.1.100", "10.0.0.1"],
    )
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.san.has_san is True
    assert "smtp.domain.org" in parsed.san.dns_names
    assert "pop.domain.org" in parsed.san.dns_names
    assert "192.168.1.100" in parsed.san.ip_addresses
    assert "10.0.0.1" in parsed.san.ip_addresses


def test_certificate_with_no_san():
    der = _generate_rsa_cert_der(san_dns=None, san_ips=None)
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.san.has_san is False
    assert len(parsed.san.dns_names) == 0
    assert len(parsed.san.ip_addresses) == 0


def test_serial_number_extraction():
    der = _generate_rsa_cert_der()
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.serial_number == 0xDEADBEEF
    assert parsed.serial_number_hex == "DEADBEEF"


def test_temporal_validity_extraction():
    der = _generate_rsa_cert_der()
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.not_before is not None
    assert parsed.not_after is not None
    assert parsed.not_before.tzinfo == timezone.utc
    assert parsed.not_after.tzinfo == timezone.utc
    assert parsed.not_after > parsed.not_before


def test_critical_extension_handling():
    der = _generate_rsa_cert_der(critical_basic_constraints=True)
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    basic_ext = next((e for e in parsed.extensions if e.name == "basicConstraints"), None)
    assert basic_ext is not None
    assert basic_ext.critical is True
    assert basic_ext.details["ca"] is False


def test_malformed_der_handling():
    corrupted_der = b"\x30\x82\x01\x00" + b"\xff" * 50
    raw = RawExtractedCertificate(
        certificate_index=1,
        raw_der=corrupted_der,
        raw_der_hex=corrupted_der.hex(),
        der_length=len(corrupted_der),
        stream_id="stream-corrupted",
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.parse_status == CertificateParseStatus.MALFORMED_DER
    assert parsed.parse_error is not None
    assert "DER decoding failed" in parsed.parse_error
    assert parsed.subject is None


def test_empty_der_handling():
    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=b"",
        raw_der_hex="",
        der_length=1,
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.parse_status == CertificateParseStatus.EMPTY_DER
    assert "empty" in parsed.parse_error.lower()


def test_certificate_chain_ordering_preservation():
    leaf_der = _generate_rsa_cert_der(common_name="leaf.mail.org")
    inter_der = _generate_rsa_cert_der(common_name="intermediate.ca.org")

    chain_extraction = CertificateChainExtractionResult(
        stream_id="stream-chain-1",
        status=CertificateExtractionStatus.COMPLETE,
        certificates=[
            RawExtractedCertificate(
                certificate_index=0,
                raw_der=leaf_der,
                raw_der_hex=leaf_der.hex(),
                der_length=len(leaf_der),
                stream_id="stream-chain-1",
            ),
            RawExtractedCertificate(
                certificate_index=1,
                raw_der=inter_der,
                raw_der_hex=inter_der.hex(),
                der_length=len(inter_der),
                stream_id="stream-chain-1",
            ),
        ],
        total_certificates=2,
    )

    parsed_chain = certificate_parser.parse_chain(chain_extraction)

    assert parsed_chain.total_certificates == 2
    assert parsed_chain.has_parse_failures is False
    assert parsed_chain.certificates[0].certificate_index == 0
    assert parsed_chain.certificates[0].subject.common_name == "leaf.mail.org"
    assert parsed_chain.certificates[1].certificate_index == 1
    assert parsed_chain.certificates[1].subject.common_name == "intermediate.ca.org"


def test_ed25519_key_handling():
    priv = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519.org")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10))
        .sign(priv, None)
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    raw = RawExtractedCertificate(
        certificate_index=0,
        raw_der=der,
        raw_der_hex=der.hex(),
        der_length=len(der),
    )
    parsed = certificate_parser.parse_raw_certificate(raw)

    assert parsed.parse_status == CertificateParseStatus.PARSED
    assert parsed.public_key.algorithm == "ED25519"
    assert parsed.public_key.key_size_bits == 256