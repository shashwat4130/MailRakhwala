"""
MailRakhwala Offline Revocation & Trust Evidence Service (Step 20)
Performs deterministic offline chain path verification against a local CA bundle
and parses captured TLS OCSP stapling (CertificateStatus) payloads.
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, dsa, ed25519, ed448
from cryptography.x509 import ocsp

from app.schemas.certificate_parsing import ParsedCertificate, ParsedCertificateChain
from app.schemas.revocation_trust import (
    CertificateTrustEvidence,
    CRLEvidence,
    CRLEvidenceStatus,
    OCSPEvidence,
    OCSPObservedStatus,
    OCSPVerificationStatus,
    OfflineTrustResult,
    TrustAnchorEvidence,
    TrustValidationStatus,
)

DEFAULT_TRUST_STORE_PATH = Path(__file__).resolve().parent.parent / "core" / "trust_store" / "cacert.pem"


class TrustStoreManager:
    """Manages an offline collection of trusted Root CA certificates."""

    def __init__(self, ca_bundle_path: Optional[Path] = None):
        self.ca_bundle_path = ca_bundle_path or DEFAULT_TRUST_STORE_PATH
        self.anchors_by_subject: Dict[str, List[x509.Certificate]] = {}
        self.anchors_by_fingerprint: Dict[str, x509.Certificate] = {}
        self.is_loaded = False
        self.source_id = str(self.ca_bundle_path)
        self.version = "1.0.0-offline"
        self._load_bundle()

    def _load_bundle(self):
        if not self.ca_bundle_path.exists():
            self.is_loaded = False
            return

        try:
            with open(self.ca_bundle_path, "rb") as f:
                pem_data = f.read()
            certs = x509.load_pem_x509_certificates(pem_data)
            for c in certs:
                self.add_trusted_anchor(c)
            self.is_loaded = len(self.anchors_by_fingerprint) > 0
        except Exception:
            self.is_loaded = False

    def add_trusted_anchor(self, cert: x509.Certificate):
        """Add a certificate to the trusted anchor registry."""
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        self.anchors_by_fingerprint[fp] = cert
        sub_str = cert.subject.rfc4514_string()
        self.anchors_by_subject.setdefault(sub_str, []).append(cert)
        self.is_loaded = True

    def find_anchors_for_issuer(self, issuer_dn: str) -> List[x509.Certificate]:
        return self.anchors_by_subject.get(issuer_dn, [])

    def get_anchor_by_fingerprint(self, fp: str) -> Optional[x509.Certificate]:
        return self.anchors_by_fingerprint.get(fp)


class TrustRevocationService:
    """Evaluates offline chain path validity and inspects captured OCSP stapling."""

    def __init__(self, trust_store: Optional[TrustStoreManager] = None):
        self.trust_store = trust_store or TrustStoreManager()

    def analyze_session_trust(
        self,
        chain: ParsedCertificateChain,
        raw_der_certs: List[bytes],
        captured_ocsp_response_bytes: Optional[bytes] = None,
        reference_time: Optional[datetime] = None,
        ocsp_frame_number: Optional[int] = None,
        ocsp_timestamp: Optional[float] = None,
    ) -> OfflineTrustResult:
        """Evaluates offline chain trust, parses captured OCSP responses, and returns an OfflineTrustResult."""
        ref_time = reference_time
        if ref_time is not None and ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        # 1. Offline Chain Path Validation
        trust_evidence = self._validate_chain_path(
            chain=chain,
            raw_der_certs=raw_der_certs,
            ref_time=ref_time,
        )

        # 2. Captured OCSP Stapling Inspection
        leaf_cert = None
        if raw_der_certs and len(raw_der_certs) > 0:
            try:
                leaf_cert = x509.load_der_x509_certificate(raw_der_certs[0])
            except Exception:
                leaf_cert = None

        ocsp_evidence = self._analyze_captured_ocsp(
            ocsp_bytes=captured_ocsp_response_bytes,
            leaf_cert=leaf_cert,
            ref_time=ref_time,
            frame_number=ocsp_frame_number,
            timestamp=ocsp_timestamp,
        )

        # 3. Passive CRL Evidence
        crl_evidence = self._analyze_crl_evidence(chain)

        # Derive overall factual statement
        overall_state = self._derive_overall_state(trust_evidence, ocsp_evidence)

        return OfflineTrustResult(
            stream_id=chain.stream_id,
            certificate_trust=trust_evidence,
            ocsp_evidence=ocsp_evidence,
            crl_evidence=crl_evidence,
            overall_trust_state=overall_state,
        )

    def _validate_chain_path(
        self,
        chain: ParsedCertificateChain,
        raw_der_certs: List[bytes],
        ref_time: Optional[datetime],
    ) -> CertificateTrustEvidence:
        stream_id = chain.stream_id
        leaf_fp = chain.certificates[0].raw_der_sha256 if chain.certificates else "UNKNOWN"
        chain_fps = [c.raw_der_sha256 for c in chain.certificates if c.raw_der_sha256]

        base_kwargs = {
            "stream_id": stream_id,
            "certificate_index": 0,
            "leaf_fingerprint_sha256": leaf_fp or "UNKNOWN",
            "chain_fingerprints_sha256": chain_fps,
            "validation_reference_time": ref_time,
        }

        if not self.trust_store.is_loaded:
            return CertificateTrustEvidence(
                **base_kwargs,
                trust_validation_status=TrustValidationStatus.UNAVAILABLE_FROM_PCAP,
                failure_reason="No local CA trust store was found or configured in the environment.",
                limitations=["Local trust store bundle is missing; path verification aborted."],
            )

        if not raw_der_certs or len(raw_der_certs) == 0:
            return CertificateTrustEvidence(
                **base_kwargs,
                trust_validation_status=TrustValidationStatus.UNAVAILABLE_FROM_PCAP,
                failure_reason="No raw certificate data available in capture.",
            )

        # Decode raw DER certificates
        x509_chain: List[x509.Certificate] = []
        for idx, der in enumerate(raw_der_certs):
            try:
                cert = x509.load_der_x509_certificate(der)
                x509_chain.append(cert)
            except Exception as e:
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                    failure_reason=f"Failed decoding certificate at index {idx}: {str(e)}",
                )

        leaf = x509_chain[0]

        # Check temporal validity at ref_time if provided
        if ref_time:
            if ref_time < leaf.not_valid_before_utc:
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                    failure_reason=f"Leaf certificate not valid until {leaf.not_valid_before_utc.isoformat()}.",
                )
            if ref_time > leaf.not_valid_after_utc:
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                    failure_reason=f"Leaf certificate expired on {leaf.not_valid_after_utc.isoformat()}.",
                )

        # Verify signature sequence across presentation chain
        curr = leaf
        for i in range(1, len(x509_chain)):
            parent = x509_chain[i]
            if not self._verify_signature(curr, parent):
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                    failure_reason=f"Signature verification failed between index {i-1} and index {i}.",
                )
            if not self._is_ca(parent):
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                    failure_reason=f"Intermediate certificate at index {i} does not have CA basicConstraint.",
                )
            curr = parent

        # Terminate against local CA trust store
        issuer_str = curr.issuer.rfc4514_string()
        curr_fp = hashlib.sha256(curr.public_bytes(serialization.Encoding.DER)).hexdigest()

        # Check if curr is already a known root in trust store
        if curr_fp in self.trust_store.anchors_by_fingerprint:
            anchor_cert = self.trust_store.anchors_by_fingerprint[curr_fp]
            return CertificateTrustEvidence(
                **base_kwargs,
                trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
                trust_anchor=TrustAnchorEvidence(
                    fingerprint_sha256=curr_fp,
                    subject_dn=anchor_cert.subject.rfc4514_string(),
                    trust_store_source=self.trust_store.source_id,
                    trust_store_version=self.trust_store.version,
                ),
            )

        # Search candidates in trust store matching issuer_str
        candidates = self.trust_store.find_anchors_for_issuer(issuer_str)
        if not candidates:
            return CertificateTrustEvidence(
                **base_kwargs,
                trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
                failure_reason=f"Chain terminates at untrusted issuer '{issuer_str}'; no matching trust anchor found in local bundle.",
                limitations=["Captured certificates cannot serve as trust anchors unless explicitly present in the local bundle."],
            )

        for anchor in candidates:
            if self._verify_signature(curr, anchor):
                anchor_fp = hashlib.sha256(anchor.public_bytes(serialization.Encoding.DER)).hexdigest()
                return CertificateTrustEvidence(
                    **base_kwargs,
                    trust_validation_status=TrustValidationStatus.VALIDATED_LOCALLY,
                    trust_anchor=TrustAnchorEvidence(
                        fingerprint_sha256=anchor_fp,
                        subject_dn=anchor.subject.rfc4514_string(),
                        trust_store_source=self.trust_store.source_id,
                        trust_store_version=self.trust_store.version,
                    ),
                )

        return CertificateTrustEvidence(
            **base_kwargs,
            trust_validation_status=TrustValidationStatus.NOT_VALIDATED,
            failure_reason="Issuer DN matches trust store anchor, but cryptographic signature check failed.",
        )

    def _verify_signature(self, child: x509.Certificate, parent: x509.Certificate) -> bool:
        """Cryptographically verifies child certificate signature using parent public key."""
        try:
            pub_key = parent.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
                return True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
                return True
            elif isinstance(pub_key, ed25519.Ed25519PublicKey) or isinstance(pub_key, ed448.Ed448PublicKey):
                pub_key.verify(child.signature, child.tbs_certificate_bytes)
                return True
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    child.signature_hash_algorithm,
                )
                return True
            return False
        except Exception:
            return False

    def _is_ca(self, cert: x509.Certificate) -> bool:
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            return bool(ext.value.ca)
        except x509.ExtensionNotFound:
            return False

    def _analyze_captured_ocsp(
        self,
        ocsp_bytes: Optional[bytes],
        leaf_cert: Optional[x509.Certificate],
        ref_time: Optional[datetime],
        frame_number: Optional[int],
        timestamp: Optional[float],
    ) -> OCSPEvidence:
        if not ocsp_bytes or len(ocsp_bytes) == 0:
            return OCSPEvidence(
                observed_status=OCSPObservedStatus.UNAVAILABLE,
                verification_status=OCSPVerificationStatus.UNAVAILABLE,
                explanation="No stapled OCSP response (CertificateStatus) was present in the captured TLS handshake.",
                limitations=[
                    "OCSP stapling is optional; absence does not imply certificate revocation.",
                    "Live OCSP queries are prohibited in passive network forensics."
                ],
            )

        evidence_fp = hashlib.sha256(ocsp_bytes).hexdigest()

        try:
            ocsp_resp = ocsp.load_der_ocsp_response(ocsp_bytes)
        except Exception as e:
            return OCSPEvidence(
                observed_status=OCSPObservedStatus.MALFORMED,
                verification_status=OCSPVerificationStatus.NOT_VERIFIED,
                raw_evidence_sha256=evidence_fp,
                frame_number=frame_number,
                timestamp=timestamp,
                explanation=f"Malformed OCSP response payload: {str(e)}",
            )

        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return OCSPEvidence(
                observed_status=OCSPObservedStatus.UNKNOWN,
                verification_status=OCSPVerificationStatus.NOT_VERIFIED,
                raw_evidence_sha256=evidence_fp,
                frame_number=frame_number,
                timestamp=timestamp,
                explanation=f"Captured OCSP response status code is {ocsp_resp.response_status.name}.",
            )

        observed = OCSPObservedStatus.UNKNOWN
        serial_hex = f"{ocsp_resp.serial_number:X}" if ocsp_resp.serial_number else None
        cert_status = ocsp_resp.certificate_status

        if cert_status == ocsp.OCSPCertStatus.GOOD:
            observed = OCSPObservedStatus.GOOD
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            observed = OCSPObservedStatus.REVOKED
        elif cert_status == ocsp.OCSPCertStatus.UNKNOWN:
            observed = OCSPObservedStatus.UNKNOWN

        serial_matches = False
        if leaf_cert and ocsp_resp.serial_number == leaf_cert.serial_number:
            serial_matches = True

        limitations: List[str] = []
        if leaf_cert and not serial_matches:
            limitations.append("Captured OCSP serial number does not match presented leaf certificate.")

        verification = OCSPVerificationStatus.NOT_VERIFIED
        explanation = (
            f"Observed OCSP response status: {observed.value} for serial {serial_hex}. "
            f"Response produced at {ocsp_resp.produced_at.isoformat() if ocsp_resp.produced_at else 'unknown'}."
        )

        return OCSPEvidence(
            serial_number_hex=serial_hex,
            observed_status=observed,
            verification_status=verification,
            produced_at=ocsp_resp.produced_at,
            this_update=ocsp_resp.this_update,
            next_update=ocsp_resp.next_update,
            raw_evidence_sha256=evidence_fp,
            frame_number=frame_number,
            timestamp=timestamp,
            explanation=explanation,
            limitations=limitations,
        )

    def _analyze_crl_evidence(self, chain: ParsedCertificateChain) -> CRLEvidence:
        dps: List[str] = []
        if chain.certificates and chain.certificates[0].extensions:
            for ext in chain.certificates[0].extensions:
                if "crl" in ext.name.lower():
                    dps.append(ext.value_summary)

        return CRLEvidence(
            crl_evidence_status=CRLEvidenceStatus.UNAVAILABLE_FROM_PCAP,
            distribution_points=dps,
            explanation="No offline CRL payload was captured in the stream; live CRL fetching is disabled.",
        )

    def _derive_overall_state(
        self,
        trust: CertificateTrustEvidence,
        ocsp: OCSPEvidence,
    ) -> str:
        if ocsp.observed_status == OCSPObservedStatus.REVOKED:
            return "Captured OCSP evidence indicates certificate is REVOKED."
        if trust.trust_validation_status == TrustValidationStatus.VALIDATED_LOCALLY:
            return "Certificate chain successfully validated against local trusted CA store."
        if trust.trust_validation_status == TrustValidationStatus.NOT_VALIDATED:
            return f"Certificate chain could not be validated offline: {trust.failure_reason}"
        return "Offline trust evidence unavailable from capture."


trust_revocation_service = TrustRevocationService()