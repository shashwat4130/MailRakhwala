"""
Tests verifying Step 20 Offline Revocation & Trust Evidence.
Uses local deterministic cryptography fixtures without network dependencies.
"""

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from app.schemas.certificate_parsing import (
    CertificateParseStatus,
    DistinguishedName,
    ParsedCertificate,
    ParsedCertificateChain,
    SubjectAlternativeNames,
)
from app.schemas.revocation_trust import (
    CRLEvidenceStatus,
    OCSPObservedStatus,
    OCSPVerificationStatus,
    TrustValidationStatus,
)
from app.services.trust_revocation_service import (
    TrustRevocationService,
    TrustStoreManager,
)


def _gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(
    sub_cn,
    iss_cn,
    priv_key,
    issuer_priv_key=None,
    is_ca=False,
    not_before=None,
    not_after=None,
    serial=1,
) -> tuple[x509.Certificate, bytes]:
    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=5))
    na = not_after or (now + timedelta(days=90))
    sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sub_cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, iss_cn)])

    signing_key = issuer_priv_key if issuer_priv_key is not None else priv_key

    builder = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(iss)
        .public_key(priv_key.public_key())
        .serial_number(serial)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, cert.public_bytes(serialization.Encoding.DER)


def _build_ocsp_response(
    leaf_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    issuer_key,
    status=ocsp.OCSPCertStatus.GOOD,
) -> bytes:
    builder = ocsp.OCSPResponseBuilder()
    now = datetime.now(timezone.utc)
    builder = builder.add_response(
        cert=leaf_cert,
        issuer=issuer_cert,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=now - timedelta(hours=1),
        next_update=now + timedelta(hours=24),
        revocation_time=now if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=x509.ReasonFlags.key_compromise if status == ocsp.OCSPCertStatus.REVOKED else None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)
    response = builder.sign(issuer_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def pki_hierarchy():
    root_key = _gen_rsa()
    inter_key = _gen_rsa()
    leaf_key = _gen_rsa()

    root_cert, root_der = _build_cert("Test Root CA", "Test Root CA", root_key, is_ca=True, serial=100)
    inter_cert, inter_der = _build_cert("Test Intermediate CA", "Test Root CA", inter_key, issuer_priv_key=root_key, is_ca=True, serial=101)
    leaf_cert, leaf_der = _build_cert("mail.testcorp.com", "Test Intermediate CA", leaf_key, issuer_priv_key=inter_key, is_ca=False, serial=102)

    return {
        "root_cert": root_cert, "root_der": root_der, "root_key": root_key,
        "inter_cert": inter_cert, "inter_der": inter_der, "inter_key": inter_key,
        "leaf_cert": leaf_cert, "leaf_der": leaf_der, "leaf_key": leaf_key,
    }


def _make_parsed_chain(stream_id, der_certs):
    certs = []
    for idx, der in enumerate(der_certs):
        fp = hashlib.sha256(der).hexdigest()
        certs.append(
            ParsedCertificate(
                certificate_index=idx,
                stream_id=stream_id,
                raw_der_sha256=fp,
                parse_status=CertificateParseStatus.PARSED,
            )
        )
    return ParsedCertificateChain(
        stream_id=stream_id,
        total_certificates=len(certs),
        certificates=certs,
    )


# --- 1. Trust Store & Path Validation Tests ---

def test_valid_trusted_chain(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-1", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.VALIDATED_LOCALLY
    assert res.certificate_trust.trust_anchor is not None
    assert "Test Root CA" in res.certificate_trust.trust_anchor.subject_dn


def test_untrusted_root(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    # Empty trust store (no trusted root)
    store.is_loaded = True
    service = TrustRevocationService(trust_store=store)

    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-2", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "untrusted issuer" in res.certificate_trust.failure_reason.lower()


def test_missing_intermediate(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    # Supply only leaf; intermediate missing
    der_list = [pki_hierarchy["leaf_der"]]
    chain = _make_parsed_chain("stream-3", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "untrusted issuer" in res.certificate_trust.failure_reason.lower()


def test_wrong_issuer_break_in_chain(pki_hierarchy):
    unrelated_key = _gen_rsa()
    unrelated_cert, unrelated_der = _build_cert("Unrelated CA", "Unrelated CA", unrelated_key, is_ca=True)

    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    # Leaf expecting 'Test Intermediate CA', but provided 'Unrelated CA'
    der_list = [pki_hierarchy["leaf_der"], unrelated_der]
    chain = _make_parsed_chain("stream-4", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "signature verification failed" in res.certificate_trust.failure_reason.lower()


def test_broken_signature_fails_validation(pki_hierarchy):
    other_key = _gen_rsa()
    # Inter forged signature
    tampered_inter, tampered_der = _build_cert(
        "Test Intermediate CA", "Test Root CA", pki_hierarchy["inter_key"],
        issuer_priv_key=other_key, is_ca=True,
    )
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [pki_hierarchy["leaf_der"], tampered_der]
    chain = _make_parsed_chain("stream-5", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED


def test_expired_certificate_fails_validation(pki_hierarchy):
    now = datetime.now(timezone.utc)
    expired_leaf, exp_der = _build_cert(
        "mail.expired.org", "Test Root CA", pki_hierarchy["leaf_key"],
        issuer_priv_key=pki_hierarchy["root_key"],
        not_before=now - timedelta(days=60),
        not_after=now - timedelta(days=10),
    )
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [exp_der]
    chain = _make_parsed_chain("stream-6", der_list)
    res = service.analyze_session_trust(chain, der_list, reference_time=now)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "expired on" in res.certificate_trust.failure_reason.lower()


def test_not_yet_valid_certificate_fails_validation(pki_hierarchy):
    now = datetime.now(timezone.utc)
    future_leaf, future_der = _build_cert(
        "mail.future.org", "Test Root CA", pki_hierarchy["leaf_key"],
        issuer_priv_key=pki_hierarchy["root_key"],
        not_before=now + timedelta(days=10),
        not_after=now + timedelta(days=90),
    )
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [future_der]
    chain = _make_parsed_chain("stream-7", der_list)
    res = service.analyze_session_trust(chain, der_list, reference_time=now)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "not valid until" in res.certificate_trust.failure_reason.lower()


def test_self_signed_trusted_root_validates(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    # Validated directly when root is presented and explicitly in store
    der_list = [pki_hierarchy["root_der"]]
    chain = _make_parsed_chain("stream-8", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.VALIDATED_LOCALLY


def test_self_signed_untrusted_leaf_fails(pki_hierarchy):
    leaf_self, leaf_self_der = _build_cert("self.org", "self.org", pki_hierarchy["leaf_key"])
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [leaf_self_der]
    chain = _make_parsed_chain("stream-9", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED


def test_malformed_certificate_handled_safely():
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.is_loaded = True
    service = TrustRevocationService(trust_store=store)

    bad_der = b"\x30\x82\xff\xff" + b"\x00" * 30
    der_list = [bad_der]
    chain = _make_parsed_chain("stream-bad", der_list)
    res = service.analyze_session_trust(chain, der_list)

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED
    assert "failed decoding" in res.certificate_trust.failure_reason.lower()


def test_captured_certificate_cannot_become_trust_anchor(pki_hierarchy):
    # Root cert is in the PCAP stream, but NOT added to local TrustStoreManager
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.is_loaded = True  # Store is loaded, but empty of this root
    service = TrustRevocationService(trust_store=store)

    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"], pki_hierarchy["root_der"]]
    chain = _make_parsed_chain("stream-pcap-anchor", der_list)
    res = service.analyze_session_trust(chain, der_list)

    # Must NOT automatically trust captured root
    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED


def test_trust_store_unavailable():
    store = TrustStoreManager(ca_bundle_path=Path("nonexistent_ca.pem"))
    store.is_loaded = False
    service = TrustRevocationService(trust_store=store)

    chain = _make_parsed_chain("stream-missing-store", [b"\x30\x00"])
    res = service.analyze_session_trust(chain, [b"\x30\x00"])

    assert res.certificate_trust.trust_validation_status == TrustValidationStatus.UNAVAILABLE_FROM_PCAP


# --- 2. Chain Integrity & Traceability Tests ---

def test_chain_ordering_and_fingerprints_preserved(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-trace", der_list)
    res = service.analyze_session_trust(chain, der_list)

    leaf_fp = hashlib.sha256(pki_hierarchy["leaf_der"]).hexdigest()
    inter_fp = hashlib.sha256(pki_hierarchy["inter_der"]).hexdigest()
    assert res.certificate_trust.leaf_fingerprint_sha256 == leaf_fp
    assert res.certificate_trust.chain_fingerprints_sha256 == [leaf_fp, inter_fp]


def test_explicit_validation_reference_time(pki_hierarchy):
    store = TrustStoreManager(ca_bundle_path=Path("dummy_missing.pem"))
    store.add_trusted_anchor(pki_hierarchy["root_cert"])
    service = TrustRevocationService(trust_store=store)

    ref = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)
    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-time", der_list)
    res = service.analyze_session_trust(chain, der_list, reference_time=ref)

    assert res.certificate_trust.validation_reference_time == ref


# --- 3. Captured OCSP Stapling Tests ---

def test_no_stapled_ocsp_yields_unavailable(pki_hierarchy):
    service = TrustRevocationService()
    der_list = [pki_hierarchy["leaf_der"]]
    chain = _make_parsed_chain("stream-no-ocsp", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=None)

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.UNAVAILABLE
    assert res.ocsp_evidence.verification_status == OCSPVerificationStatus.UNAVAILABLE


def test_valid_captured_ocsp_good(pki_hierarchy):
    service = TrustRevocationService()
    ocsp_bytes = _build_ocsp_response(
        pki_hierarchy["leaf_cert"],
        pki_hierarchy["inter_cert"],
        pki_hierarchy["inter_key"],
        status=ocsp.OCSPCertStatus.GOOD,
    )
    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-ocsp-good", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=ocsp_bytes)

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.GOOD
    assert res.ocsp_evidence.serial_number_hex == f"{pki_hierarchy['leaf_cert'].serial_number:X}"
    assert res.ocsp_evidence.this_update is not None


def test_captured_ocsp_revoked(pki_hierarchy):
    service = TrustRevocationService()
    ocsp_bytes = _build_ocsp_response(
        pki_hierarchy["leaf_cert"],
        pki_hierarchy["inter_cert"],
        pki_hierarchy["inter_key"],
        status=ocsp.OCSPCertStatus.REVOKED,
    )
    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-ocsp-revoked", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=ocsp_bytes)

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.REVOKED
    assert "revoked" in res.overall_trust_state.lower()


def test_captured_ocsp_unknown(pki_hierarchy):
    service = TrustRevocationService()
    ocsp_bytes = _build_ocsp_response(
        pki_hierarchy["leaf_cert"],
        pki_hierarchy["inter_cert"],
        pki_hierarchy["inter_key"],
        status=ocsp.OCSPCertStatus.UNKNOWN,
    )
    der_list = [pki_hierarchy["leaf_der"], pki_hierarchy["inter_der"]]
    chain = _make_parsed_chain("stream-ocsp-unknown", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=ocsp_bytes)

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.UNKNOWN


def test_malformed_ocsp_payload():
    service = TrustRevocationService()
    chain = _make_parsed_chain("stream-ocsp-malformed", [b"\x30\x00"])
    res = service.analyze_session_trust(
        chain, [b"\x30\x00"], captured_ocsp_response_bytes=b"garbage_not_ocsp"
    )

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.MALFORMED


def test_ocsp_serial_association_discrepancy(pki_hierarchy):
    service = TrustRevocationService()
    other_key = _gen_rsa()
    other_cert, _ = _build_cert("other.org", "Test Root CA", other_key, serial=9999)
    # OCSP signed for serial 9999, but presented with leaf serial 102
    ocsp_bytes = _build_ocsp_response(
        other_cert,
        pki_hierarchy["inter_cert"],
        pki_hierarchy["inter_key"],
    )
    der_list = [pki_hierarchy["leaf_der"]]
    chain = _make_parsed_chain("stream-ocsp-mismatch", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=ocsp_bytes)

    assert any("does not match" in lim.lower() for lim in res.ocsp_evidence.limitations)


# --- 4. Passive CRL and Boundary Assertions ---

def test_no_captured_crl_returns_unavailable():
    service = TrustRevocationService()
    chain = _make_parsed_chain("stream-crl", [b"\x30\x00"])
    res = service.analyze_session_trust(chain, [b"\x30\x00"])

    assert res.crl_evidence.crl_evidence_status == CRLEvidenceStatus.UNAVAILABLE_FROM_PCAP
    assert "live crl retrieval is prohibited" in res.crl_evidence.limitations[0].lower()


def test_absence_of_ocsp_does_not_claim_unrevoked(pki_hierarchy):
    service = TrustRevocationService()
    der_list = [pki_hierarchy["leaf_der"]]
    chain = _make_parsed_chain("stream-no-overstatement", der_list)
    res = service.analyze_session_trust(chain, der_list, captured_ocsp_response_bytes=None)

    assert res.ocsp_evidence.observed_status == OCSPObservedStatus.UNAVAILABLE
    assert "not revoked" not in res.overall_trust_state.lower()


def test_no_risk_or_attack_verdicts_emitted(pki_hierarchy):
    service = TrustRevocationService()
    der_list = [pki_hierarchy["leaf_der"]]
    chain = _make_parsed_chain("stream-clean-verdict", der_list)
    res = service.analyze_session_trust(chain, der_list)

    # Verification state descriptions must remain neutral and non-judgmental
    for bad in ["attack", "mitm", "malicious", "phishing", "cve"]:
        assert bad not in res.overall_trust_state.lower()
        if res.certificate_trust.failure_reason:
            assert bad not in res.certificate_trust.failure_reason.lower()