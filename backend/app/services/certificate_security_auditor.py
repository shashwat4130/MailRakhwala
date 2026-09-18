"""
MailRakhwala Certificate Security Auditor Service (Step 18)
Deterministic, passive security audit evaluating parsed X.509 properties.
"""

from datetime import datetime, timezone
from typing import List, Optional, Set

from app.schemas.certificate_parsing import (
    CertificateParseStatus,
    ParsedCertificate,
    ParsedCertificateChain,
)
from app.schemas.certificate_security_audit import (
    CertificateEvidence,
    CertificateFindingType,
    CertificateSecurityAuditResult,
    CertificateSecurityFinding,
    SingleCertificateAudit,
)
from app.schemas.domain import ConfidenceLevel, FindingCategory, SeverityLevel, TriState

# Step 18 Deterministic Policy Constants (NIST SP 800-52r2 / RFC 9155 baselines)
DEPRECATED_SIGNATURE_DIGESTS = {"md5", "sha1", "md2"}
DEPRECATED_CURVES = {"secp160r1", "secp192r1", "prime192v1", "c2pnb163v1"}
MIN_RSA_KEY_BITS = 2048
MIN_DSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 256


class CertificateSecurityAuditor:
    """Performs deterministic, evidence-backed security audits on parsed X.509 certificates."""

    def audit_chain(
        self,
        chain: ParsedCertificateChain,
        reference_time: Optional[datetime] = None,
    ) -> CertificateSecurityAuditResult:
        """Audits all parsed certificates in chain presentation order and chain-level integrity."""
        ref_time = reference_time
        if ref_time is not None and ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        cert_audits: List[SingleCertificateAudit] = []
        all_findings: List[CertificateSecurityFinding] = []

        for cert in chain.certificates:
            audit = self.audit_certificate(cert, ref_time=ref_time)
            cert_audits.append(audit)
            all_findings.extend(audit.findings)

        chain_findings = self._audit_chain_properties(chain)
        all_findings.extend(chain_findings)

        has_crit_or_high = any(
            f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in all_findings
        )

        return CertificateSecurityAuditResult(
            stream_id=chain.stream_id,
            total_certificates_audited=len(cert_audits),
            reference_time=ref_time,
            certificate_audits=cert_audits,
            chain_findings=chain_findings,
            all_findings=all_findings,
            has_critical_or_high=has_crit_or_high,
        )

    def audit_certificate(
        self,
        cert: ParsedCertificate,
        ref_time: Optional[datetime] = None,
    ) -> SingleCertificateAudit:
        """Evaluates a single ParsedCertificate for security findings."""
        findings: List[CertificateSecurityFinding] = []
        limitations: List[str] = []

        if cert.parse_status != CertificateParseStatus.PARSED:
            findings.append(
                CertificateSecurityFinding(
                    finding_id="RULE-CERT-MALFORMED",
                    finding_type=CertificateFindingType.EMPTY_OR_CORRUPT_CERTIFICATE,
                    title="Malformed or Unparseable Certificate Data",
                    category=FindingCategory.CERTIFICATE_VALIDITY,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Raw DER extraction could not be parsed: {cert.parse_error or cert.parse_status.value}",
                    evidence=CertificateEvidence(
                        certificate_index=cert.certificate_index,
                        stream_id=cert.stream_id,
                        raw_der_sha256=cert.raw_der_sha256,
                        observed_property="parse_status",
                        observed_value=cert.parse_status.value,
                        rule_id="RULE-CERT-MALFORMED",
                    ),
                    recommendation="Inspect PCAP reassembly to determine if certificate data was truncated.",
                )
            )
            return SingleCertificateAudit(
                certificate_index=cert.certificate_index,
                raw_der_sha256=cert.raw_der_sha256,
                stream_id=cert.stream_id,
                findings=findings,
                audit_limitations=["Certificate could not be parsed; security checks aborted."],
            )

        is_expired, is_not_yet_valid = self._audit_validity(cert, ref_time, findings, limitations)
        has_weak_key = self._audit_public_key(cert, findings, limitations)
        has_weak_sig = self._audit_signature_algorithm(cert, findings, limitations)
        is_self_signed = self._audit_self_signed(cert, findings)
        self._audit_extensions(cert, findings)

        return SingleCertificateAudit(
            certificate_index=cert.certificate_index,
            raw_der_sha256=cert.raw_der_sha256,
            stream_id=cert.stream_id,
            is_expired=is_expired,
            is_not_yet_valid=is_not_yet_valid,
            is_self_signed=is_self_signed,
            has_weak_key=has_weak_key,
            has_weak_signature=has_weak_sig,
            findings=findings,
            audit_limitations=limitations,
        )

    def _audit_validity(
        self,
        cert: ParsedCertificate,
        ref_time: Optional[datetime],
        findings: List[CertificateSecurityFinding],
        limitations: List[str],
    ) -> tuple[TriState, TriState]:
        if ref_time is None:
            limitations.append("Reference timestamp missing; validity window could not be evaluated.")
            return TriState.UNKNOWN, TriState.UNKNOWN

        if cert.not_before is None or cert.not_after is None:
            limitations.append("Validity dates absent in parsed certificate.")
            return TriState.UNKNOWN, TriState.UNKNOWN

        is_expired = TriState.FALSE
        is_not_yet_valid = TriState.FALSE

        if ref_time > cert.not_after:
            is_expired = TriState.TRUE
            findings.append(
                CertificateSecurityFinding(
                    finding_id="RULE-CERT-001",
                    finding_type=CertificateFindingType.CERTIFICATE_EXPIRED,
                    title="Expired X.509 Server Certificate",
                    category=FindingCategory.CERTIFICATE_VALIDITY,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Certificate expired on {cert.not_after.isoformat()} (evaluated at {ref_time.isoformat()}).",
                    evidence=CertificateEvidence(
                        certificate_index=cert.certificate_index,
                        stream_id=cert.stream_id,
                        raw_der_sha256=cert.raw_der_sha256,
                        observed_property="not_after",
                        observed_value=cert.not_after.isoformat(),
                        reference_value=ref_time.isoformat(),
                        rule_id="RULE-CERT-001",
                        evaluation_time=ref_time,
                    ),
                    recommendation="Renew and deploy an active, valid TLS certificate immediately.",
                )
            )

        if ref_time < cert.not_before:
            is_not_yet_valid = TriState.TRUE
            findings.append(
                CertificateSecurityFinding(
                    finding_id="RULE-CERT-002",
                    finding_type=CertificateFindingType.CERTIFICATE_NOT_YET_VALID,
                    title="Certificate Not Yet Valid",
                    category=FindingCategory.CERTIFICATE_VALIDITY,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Certificate not valid until {cert.not_before.isoformat()} (evaluated at {ref_time.isoformat()}).",
                    evidence=CertificateEvidence(
                        certificate_index=cert.certificate_index,
                        stream_id=cert.stream_id,
                        raw_der_sha256=cert.raw_der_sha256,
                        observed_property="not_before",
                        observed_value=cert.not_before.isoformat(),
                        reference_value=ref_time.isoformat(),
                        rule_id="RULE-CERT-002",
                        evaluation_time=ref_time,
                    ),
                    recommendation="Verify server clock synchronization (NTP) and certificate activation window.",
                )
            )

        return is_expired, is_not_yet_valid

    def _audit_public_key(
        self,
        cert: ParsedCertificate,
        findings: List[CertificateSecurityFinding],
        limitations: List[str],
    ) -> TriState:
        if cert.public_key is None:
            limitations.append("Public key parameters are missing from parsed certificate.")
            return TriState.UNKNOWN

        algo = cert.public_key.algorithm.upper()
        bits = cert.public_key.key_size_bits

        if algo == "RSA":
            if bits is not None and bits < MIN_RSA_KEY_BITS:
                findings.append(
                    CertificateSecurityFinding(
                        finding_id="RULE-CERT-003",
                        finding_type=CertificateFindingType.WEAK_RSA_KEY,
                        title="Insufficient RSA Public Key Length (< 2048 bits)",
                        category=FindingCategory.CERTIFICATE_VALIDITY,
                        severity=SeverityLevel.CRITICAL,
                        confidence=ConfidenceLevel.HIGH,
                        description=f"Observed RSA public key modulus length of {bits} bits is below the {MIN_RSA_KEY_BITS}-bit security baseline.",
                        evidence=CertificateEvidence(
                            certificate_index=cert.certificate_index,
                            stream_id=cert.stream_id,
                            raw_der_sha256=cert.raw_der_sha256,
                            observed_property="public_key.key_size_bits",
                            observed_value=bits,
                            reference_value=MIN_RSA_KEY_BITS,
                            rule_id="RULE-CERT-003",
                        ),
                        recommendation="Re-issue certificate with an RSA key of at least 2048 bits or an approved modern elliptic curve.",
                    )
                )
                return TriState.TRUE
            return TriState.FALSE

        elif algo == "DSA":
            if bits is not None and bits < MIN_DSA_KEY_BITS:
                findings.append(
                    CertificateSecurityFinding(
                        finding_id="RULE-CERT-DSA-WEAK",
                        finding_type=CertificateFindingType.WEAK_DSA_KEY,
                        title="Legacy Undersized DSA Public Key (< 2048 bits)",
                        category=FindingCategory.CERTIFICATE_VALIDITY,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        description=f"Observed DSA key length of {bits} bits is below the {MIN_DSA_KEY_BITS}-bit baseline.",
                        evidence=CertificateEvidence(
                            certificate_index=cert.certificate_index,
                            stream_id=cert.stream_id,
                            raw_der_sha256=cert.raw_der_sha256,
                            observed_property="public_key.key_size_bits",
                            observed_value=bits,
                            reference_value=MIN_DSA_KEY_BITS,
                            rule_id="RULE-CERT-DSA-WEAK",
                        ),
                        recommendation="Migrate from DSA to RSA (>= 2048 bits) or ECDSA (>= 256 bits).",
                    )
                )
                return TriState.TRUE
            return TriState.FALSE

        elif algo == "EC":
            curve = (cert.public_key.curve_name or "").lower()
            if curve in DEPRECATED_CURVES or (bits is not None and bits < MIN_EC_KEY_BITS):
                findings.append(
                    CertificateSecurityFinding(
                        finding_id="RULE-CERT-EC-WEAK",
                        finding_type=CertificateFindingType.WEAK_EC_CURVE,
                        title="Weak or Deprecated Elliptic Curve",
                        category=FindingCategory.CERTIFICATE_VALIDITY,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        description=f"Observed EC curve '{curve}' ({bits} bits) does not satisfy modern cryptographic standards.",
                        evidence=CertificateEvidence(
                            certificate_index=cert.certificate_index,
                            stream_id=cert.stream_id,
                            raw_der_sha256=cert.raw_der_sha256,
                            observed_property="public_key.curve_name",
                            observed_value=curve,
                            reference_value="secp256r1/P-256 or stronger",
                            rule_id="RULE-CERT-EC-WEAK",
                        ),
                        recommendation="Re-issue the certificate using an approved modern elliptic-curve public key such as secp256r1/P-256, secp384r1/P-384, or another policy-approved certificate key algorithm.",
                    )
                )
                return TriState.TRUE
            return TriState.FALSE

        elif algo in ("ED25519", "ED448"):
            return TriState.FALSE

        limitations.append(f"Public key algorithm '{algo}' cannot be evaluated deterministically.")
        return TriState.UNKNOWN

    def _audit_signature_algorithm(
        self,
        cert: ParsedCertificate,
        findings: List[CertificateSecurityFinding],
        limitations: List[str],
    ) -> TriState:
        hash_algo = (cert.signature_hash_algorithm or "").lower()
        algo_name = (cert.signature_algorithm_name or "").lower()

        is_weak = False
        weak_cause = ""

        for deprecated in DEPRECATED_SIGNATURE_DIGESTS:
            if hash_algo == deprecated or deprecated in algo_name:
                is_weak = True
                weak_cause = deprecated.upper()
                break

        if is_weak:
            findings.append(
                CertificateSecurityFinding(
                    finding_id="RULE-CERT-004",
                    finding_type=CertificateFindingType.WEAK_SIGNATURE_ALGORITHM,
                    title=f"Weak Signature Algorithm in Certificate ({weak_cause})",
                    category=FindingCategory.CERTIFICATE_VALIDITY,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    description=f"Certificate is signed with obsolete digest algorithm {weak_cause} ({cert.signature_algorithm_name}).",
                    evidence=CertificateEvidence(
                        certificate_index=cert.certificate_index,
                        stream_id=cert.stream_id,
                        raw_der_sha256=cert.raw_der_sha256,
                        observed_property="signature_algorithm",
                        observed_value=cert.signature_algorithm_name or hash_algo,
                        reference_value="SHA-256 or stronger",
                        rule_id="RULE-CERT-004",
                    ),
                    recommendation="Replace certificate with one signed via SHA-256, SHA-384, or SHA-512.",
                )
            )
            return TriState.TRUE

        if not hash_algo and not algo_name:
            limitations.append("Signature algorithm is missing or unparsed.")
            return TriState.UNKNOWN

        return TriState.FALSE

    def _audit_self_signed(
        self,
        cert: ParsedCertificate,
        findings: List[CertificateSecurityFinding],
    ) -> TriState:
        if cert.subject is None or cert.issuer is None:
            return TriState.UNKNOWN

        sub_str = (cert.subject.raw_dn_string or "").strip()
        iss_str = (cert.issuer.raw_dn_string or "").strip()

        if sub_str and iss_str and sub_str == iss_str:
            findings.append(
                CertificateSecurityFinding(
                    finding_id="RULE-PKI-001",
                    finding_type=CertificateFindingType.SELF_SIGNED_CERTIFICATE,
                    title="Self-Signed Server Certificate",
                    category=FindingCategory.CERTIFICATE_CHAIN,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    description="Subject DN equals Issuer DN; certificate signature is self-asserted.",
                    evidence=CertificateEvidence(
                        certificate_index=cert.certificate_index,
                        stream_id=cert.stream_id,
                        raw_der_sha256=cert.raw_der_sha256,
                        observed_property="subject_equals_issuer",
                        observed_value=sub_str,
                        reference_value="External CA Issuer",
                        rule_id="RULE-PKI-001",
                    ),
                    recommendation="Deploy a certificate issued by a recognized CA or verify if self-signed cert is intended for this environment.",
                    limitations=[
                        "Subject/Issuer equality indicates self-signed status; cryptographic trust path validation occurs in Step 20."
                    ]
                )
            )
            return TriState.TRUE

        return TriState.FALSE

    def _audit_extensions(
        self,
        cert: ParsedCertificate,
        findings: List[CertificateSecurityFinding],
    ):
        for ext in cert.extensions:
            if ext.name == "basicConstraints" and cert.certificate_index == 0:
                ca_val = ext.details.get("ca", False)
                if ca_val is True:
                    findings.append(
                        CertificateSecurityFinding(
                            finding_id="RULE-CERT-BC-ANOMALY",
                            finding_type=CertificateFindingType.BASIC_CONSTRAINTS_CA_MISMATCH,
                            title="End-Entity Certificate Configured as CA",
                            category=FindingCategory.CERTIFICATE_VALIDITY,
                            severity=SeverityLevel.LOW,
                            confidence=ConfidenceLevel.HIGH,
                            description="Leaf certificate (index 0) specifies basicConstraints ca=True.",
                            evidence=CertificateEvidence(
                                certificate_index=cert.certificate_index,
                                stream_id=cert.stream_id,
                                raw_der_sha256=cert.raw_der_sha256,
                                observed_property="basicConstraints.ca",
                                observed_value=True,
                                reference_value=False,
                                rule_id="RULE-CERT-BC-ANOMALY",
                            ),
                            recommendation="Ensure end-entity TLS certificates set basicConstraints CA to False.",
                        )
                    )

    def _audit_chain_properties(
        self,
        chain: ParsedCertificateChain,
    ) -> List[CertificateSecurityFinding]:
        findings: List[CertificateSecurityFinding] = []
        observed_fingerprints: Set[str] = set()

        for idx, cert in enumerate(chain.certificates):
            fp = cert.raw_der_sha256
            if fp:
                if fp in observed_fingerprints:
                    findings.append(
                        CertificateSecurityFinding(
                            finding_id="RULE-CHAIN-DUPLICATE",
                            finding_type=CertificateFindingType.DUPLICATE_CERTIFICATE_IN_CHAIN,
                            title="Duplicate Certificate in TLS Handshake Chain",
                            category=FindingCategory.CERTIFICATE_CHAIN,
                            severity=SeverityLevel.LOW,
                            confidence=ConfidenceLevel.HIGH,
                            description=f"Certificate at index {idx} duplicates a previously supplied certificate.",
                            evidence=CertificateEvidence(
                                certificate_index=idx,
                                stream_id=chain.stream_id,
                                raw_der_sha256=fp,
                                observed_property="raw_der_sha256",
                                observed_value=fp,
                                rule_id="RULE-CHAIN-DUPLICATE",
                            ),
                            recommendation="Remove redundant duplicate certificates from the server chain bundle.",
                        )
                    )
                observed_fingerprints.add(fp)

            if idx > 0 and idx < len(chain.certificates):
                child = chain.certificates[idx - 1]
                parent = cert
                if child.issuer and parent.subject:
                    child_iss = (child.issuer.raw_dn_string or "").strip()
                    parent_sub = (parent.subject.raw_dn_string or "").strip()
                    if child_iss and parent_sub and child_iss != parent_sub:
                        findings.append(
                            CertificateSecurityFinding(
                                finding_id="RULE-CHAIN-ORDER-MISMATCH",
                                finding_type=CertificateFindingType.CHAIN_DN_SEQUENCE_MISMATCH,
                                title="Certificate Chain Issuer/Subject DN Sequence Inconsistency",
                                category=FindingCategory.CERTIFICATE_CHAIN,
                                severity=SeverityLevel.MEDIUM,
                                confidence=ConfidenceLevel.HIGH,
                                description=(
                                    f"Observed DN sequence inconsistency: child certificate (index {idx-1}) "
                                    f"Issuer DN does not match parent certificate (index {idx}) Subject DN."
                                ),
                                evidence=CertificateEvidence(
                                    certificate_index=idx,
                                    stream_id=chain.stream_id,
                                    raw_der_sha256=parent.raw_der_sha256,
                                    observed_property="child_issuer_vs_parent_subject_dn",
                                    observed_value=f"Child Issuer: {child_iss} | Parent Subject: {parent_sub}",
                                    rule_id="RULE-CHAIN-ORDER-MISMATCH",
                                ),
                                recommendation="Verify that certificates in the server chain are ordered correctly (Leaf -> Intermediate -> Root).",
                                limitations=[
                                    "DN sequence comparison checks subject-to-issuer string linkage only; cryptographic signature verification and trust store anchoring belong to later steps."
                                ]
                            )
                        )

        return findings


certificate_security_auditor = CertificateSecurityAuditor()