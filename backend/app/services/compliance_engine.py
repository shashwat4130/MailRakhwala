"""
MailRakhwala Deterministic Cryptographic Compliance Engine Service (Step 21)
Evaluates observed cryptographic parameters strictly against authoritative Step 4 rules.
Pipeline: Observed Evidence -> Authoritative Step 4 Rule -> Deterministic Evaluation -> Finding -> Severity -> Recommendation
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set

from app.schemas.compliance_engine import (
    ComplianceEvidence,
    ComplianceFinding,
    ComplianceStatus,
    RuleEvaluationSummary,
    SessionComplianceReport,
)
from app.schemas.domain import FindingCategory, SeverityLevel, TriState
from app.schemas.identity_analysis import IdentityAnalysisResult, IdentityRelationshipType, IdentityStatus
from app.schemas.revocation_trust import (
    OCSPObservedStatus,
    OCSPVerificationStatus,
    OfflineTrustResult,
    TrustValidationStatus,
)
from app.services.rule_loader import rule_catalog


class ComplianceEngine:
    """Authoritative compliance engine evaluating strictly against Step 4 rules."""

    VERSION = "21.0.0"

    def evaluate_session(
        self,
        stream_id: str,
        tls_params: Optional[Dict[str, Any]] = None,
        key_exchange_params: Optional[Dict[str, Any]] = None,
        cert_audit_params: Optional[Dict[str, Any]] = None,
        identity_result: Optional[IdentityAnalysisResult] = None,
        trust_result: Optional[OfflineTrustResult] = None,
        starttls_params: Optional[Dict[str, Any]] = None,
        reference_time: Optional[datetime] = None,
    ) -> SessionComplianceReport:
        ref_time = reference_time
        if ref_time is not None and ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        findings: List[ComplianceFinding] = []
        rules_evaluated: Set[str] = set()

        # 1. TLS Protocol Version Evaluation
        findings.extend(self._eval_tls_version(stream_id, tls_params, rules_evaluated))

        # 2. Cipher Suite Evaluation
        findings.extend(self._eval_cipher_suite(stream_id, tls_params, rules_evaluated))

        # 3. Key Exchange & Forward Secrecy Evaluation
        findings.extend(self._eval_key_exchange(stream_id, key_exchange_params, rules_evaluated))

        # 4. Certificate Validity & Cryptography Evaluation
        findings.extend(self._eval_certificate(stream_id, cert_audit_params, ref_time, rules_evaluated))

        # 5. STARTTLS Protocol Flow Evaluation
        findings.extend(self._eval_starttls(stream_id, starttls_params, rules_evaluated))

        # 6. Identity & Hostname Alignment Evaluation
        findings.extend(self._eval_identity(stream_id, identity_result, rules_evaluated))

        # 7. Trust & Revocation Evidence Evaluation
        findings.extend(self._eval_trust_and_revocation(stream_id, trust_result, rules_evaluated))

        # Evidence-aware deduplication
        deduped_findings: List[ComplianceFinding] = []
        seen_keys: Set[tuple] = set()
        for f in findings:
            ev = f.evidence
            key = (
                f.rule_id,
                ev.stream_id,
                ev.observed_property,
                str(ev.observed_value),
                ev.certificate_index,
                ev.raw_der_sha256,
            )
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_findings.append(f)

        # Summary calculation
        summary = RuleEvaluationSummary(
            total_rules_evaluated=len(rules_evaluated),
            total_findings_generated=len(deduped_findings),
            compliant_count=sum(1 for f in deduped_findings if f.status == ComplianceStatus.COMPLIANT),
            non_compliant_count=sum(1 for f in deduped_findings if f.status == ComplianceStatus.NON_COMPLIANT),
            unknown_count=sum(1 for f in deduped_findings if f.status == ComplianceStatus.UNKNOWN),
            not_applicable_count=sum(1 for f in deduped_findings if f.status == ComplianceStatus.NOT_APPLICABLE),
        )

        # Precedence: NON_COMPLIANT > UNKNOWN > COMPLIANT
        if summary.non_compliant_count > 0:
            overall = ComplianceStatus.NON_COMPLIANT
        elif summary.unknown_count > 0:
            overall = ComplianceStatus.UNKNOWN
        elif summary.compliant_count > 0:
            overall = ComplianceStatus.COMPLIANT
        else:
            overall = ComplianceStatus.UNKNOWN

        return SessionComplianceReport(
            stream_id=stream_id,
            engine_version=self.VERSION,
            reference_time=ref_time,
            overall_compliance=overall,
            summary=summary,
            findings=deduped_findings,
        )

    # --- 1. TLS Version Evaluator ---
    def _eval_tls_version(
        self, stream_id: str, tls: Optional[Dict[str, Any]], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not tls or "version" not in tls or not tls["version"]:
            evaluated.add("RULE-TLS-002")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-002",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="tls.version",
                    observed_val="UNAVAILABLE",
                    ref_val=">= TLS 1.2",
                )
            )
            return findings

        ver_str = str(tls["version"]).strip().upper()

        if ver_str in ("SSL 2.0", "SSL 3.0", "0X0200", "0X0300", "SSLV2", "SSLV3"):
            evaluated.add("RULE-TLS-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-001",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.version",
                    observed_val=ver_str,
                    ref_val=">= TLS 1.2",
                    frame=tls.get("frame_number"),
                    ts=tls.get("timestamp"),
                )
            )
        elif ver_str in ("TLS 1.0", "TLS 1.1", "0X0301", "0X0302"):
            evaluated.add("RULE-TLS-002")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-002",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.version",
                    observed_val=ver_str,
                    ref_val=">= TLS 1.2",
                    frame=tls.get("frame_number"),
                    ts=tls.get("timestamp"),
                )
            )
        elif ver_str in ("TLS 1.2", "0X0303"):
            evaluated.add("RULE-TLS-003")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-003",
                    status=ComplianceStatus.COMPLIANT,
                    observed_prop="tls.version",
                    observed_val=ver_str,
                    ref_val="TLS 1.2",
                    frame=tls.get("frame_number"),
                    ts=tls.get("timestamp"),
                )
            )
        elif ver_str in ("TLS 1.3", "0X0304"):
            evaluated.add("RULE-TLS-004")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-004",
                    status=ComplianceStatus.COMPLIANT,
                    observed_prop="tls.version",
                    observed_val=ver_str,
                    ref_val="TLS 1.3",
                    frame=tls.get("frame_number"),
                    ts=tls.get("timestamp"),
                )
            )
        else:
            evaluated.add("RULE-TLS-002")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TLS-002",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="tls.version",
                    observed_val=ver_str,
                    ref_val=">= TLS 1.2",
                )
            )
        return findings

    # --- 2. Cipher Suite Evaluator ---
    def _eval_cipher_suite(
        self, stream_id: str, tls: Optional[Dict[str, Any]], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not tls or "cipher_suite" not in tls or not tls["cipher_suite"]:
            target_rule = "RULE-CIPHER-UNKNOWN" if rule_catalog.get_rule("RULE-CIPHER-UNKNOWN") else "RULE-CIPHER-001"
            evaluated.add(target_rule)
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id=target_rule,
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="tls.cipher_suite",
                    observed_val="UNAVAILABLE",
                    ref_val="Approved AEAD Cipher Suite",
                )
            )
            return findings

        cs = str(tls["cipher_suite"]).strip().upper()

        if "NULL" in cs:
            evaluated.add("RULE-CIPHER-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CIPHER-001",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="Non-NULL Cipher",
                )
            )
        elif "RC4" in cs:
            evaluated.add("RULE-CIPHER-002")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CIPHER-002",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="Prohibited RC4",
                )
            )
        elif "3DES" in cs or "DES" in cs:
            evaluated.add("RULE-CIPHER-003")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CIPHER-003",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="128-bit or 256-bit block cipher",
                )
            )
        elif "_CBC_" in cs:
            evaluated.add("RULE-CIPHER-004")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CIPHER-004",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="AEAD cipher mode",
                )
            )
        elif cs in rule_catalog.approved_ciphers:
            target_rule = "RULE-CIPHER-APPROVED" if rule_catalog.get_rule("RULE-CIPHER-APPROVED") else "RULE-CIPHER-004"
            evaluated.add(target_rule)
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id=target_rule,
                    status=ComplianceStatus.COMPLIANT,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="Approved AEAD",
                )
            )
        else:
            target_rule = "RULE-CIPHER-UNKNOWN" if rule_catalog.get_rule("RULE-CIPHER-UNKNOWN") else "RULE-CIPHER-001"
            evaluated.add(target_rule)
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id=target_rule,
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="tls.cipher_suite",
                    observed_val=cs,
                    ref_val="Approved AEAD Suite",
                )
            )
        return findings

    # --- 3. Key Exchange Evaluator ---
    def _eval_key_exchange(
        self, stream_id: str, kex: Optional[Dict[str, Any]], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not kex:
            evaluated.add("RULE-KEX-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-KEX-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="kex.parameters",
                    observed_val="UNAVAILABLE",
                    ref_val="Ephemeral Key Exchange (PFS)",
                )
            )
            return findings

        pfs = kex.get("has_forward_secrecy")
        kex_type = str(kex.get("exchange_type", "UNKNOWN")).upper()

        if pfs == TriState.FALSE or kex_type == "RSA":
            evaluated.add("RULE-KEX-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-KEX-001",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="kex.has_forward_secrecy",
                    observed_val="FALSE",
                    ref_val="TRUE",
                )
            )
        elif pfs == TriState.TRUE:
            evaluated.add("RULE-KEX-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-KEX-001",
                    status=ComplianceStatus.COMPLIANT,
                    observed_prop="kex.has_forward_secrecy",
                    observed_val="TRUE",
                    ref_val="TRUE",
                )
            )

        dh_bits = kex.get("dh_param_bits")
        if dh_bits is not None:
            evaluated.add("RULE-KEX-002")
            if dh_bits < 2048:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-KEX-002",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="kex.dh_param_bits",
                        observed_val=dh_bits,
                        ref_val=">= 2048",
                    )
                )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-KEX-002",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="kex.dh_param_bits",
                        observed_val=dh_bits,
                        ref_val=">= 2048",
                    )
                )
        return findings

    # --- 4. Certificate Validity & Cryptography Evaluator ---
    def _eval_certificate(
        self,
        stream_id: str,
        cert: Optional[Dict[str, Any]],
        ref_time: Optional[datetime],
        evaluated: Set[str],
    ) -> List[ComplianceFinding]:
        findings = []
        if not cert:
            evaluated.add("RULE-CERT-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CERT-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="cert.presence",
                    observed_val="UNAVAILABLE",
                    ref_val="Valid Server Certificate",
                )
            )
            return findings

        cert_idx = cert.get("certificate_index", 0)
        raw_sha = cert.get("raw_der_sha256")

        evaluated.add("RULE-CERT-001")
        if ref_time is None:
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-CERT-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="cert.validity",
                    observed_val="NO_REFERENCE_TIME",
                    ref_val="Valid ISO UTC Reference Time",
                    cert_idx=cert_idx,
                    raw_sha=raw_sha,
                )
            )
        else:
            is_expired = cert.get("is_expired")
            is_not_yet_valid = cert.get("is_not_yet_valid")

            if is_expired == TriState.TRUE:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-001",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="cert.not_after",
                        observed_val=cert.get("not_after"),
                        ref_val=ref_time.isoformat(),
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )
            elif is_not_yet_valid == TriState.TRUE:
                evaluated.add("RULE-CERT-002")
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-002",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="cert.not_before",
                        observed_val=cert.get("not_before"),
                        ref_val=ref_time.isoformat(),
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )
            elif is_expired == TriState.FALSE and is_not_yet_valid == TriState.FALSE:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-001",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="cert.validity",
                        observed_val="ACTIVE",
                        ref_val="Within active window",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-001",
                        status=ComplianceStatus.UNKNOWN,
                        observed_prop="cert.validity",
                        observed_val="UNAVAILABLE",
                        ref_val="Active window",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )

        # Public Key Length
        key_bits = cert.get("public_key_bits")
        key_algo = str(cert.get("public_key_algorithm", "")).upper()
        if key_algo == "RSA":
            evaluated.add("RULE-CERT-003")
            if key_bits is not None:
                if key_bits < 2048:
                    findings.append(
                        self._build_finding(
                            stream_id=stream_id,
                            rule_id="RULE-CERT-003",
                            status=ComplianceStatus.NON_COMPLIANT,
                            observed_prop="cert.public_key_bits",
                            observed_val=key_bits,
                            ref_val=">= 2048",
                            cert_idx=cert_idx,
                            raw_sha=raw_sha,
                        )
                    )
                else:
                    findings.append(
                        self._build_finding(
                            stream_id=stream_id,
                            rule_id="RULE-CERT-003",
                            status=ComplianceStatus.COMPLIANT,
                            observed_prop="cert.public_key_bits",
                            observed_val=key_bits,
                            ref_val=">= 2048",
                            cert_idx=cert_idx,
                            raw_sha=raw_sha,
                        )
                    )

        # Signature Digest
        sig_algo = str(cert.get("signature_algorithm", "")).lower()
        if sig_algo:
            evaluated.add("RULE-CERT-004")
            if any(w in sig_algo for w in ("md5", "sha1", "md2")):
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-004",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="cert.signature_algorithm",
                        observed_val=sig_algo,
                        ref_val="SHA-256 or stronger",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-CERT-004",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="cert.signature_algorithm",
                        observed_val=sig_algo,
                        ref_val="SHA-256 or stronger",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )

        # Self-signed
        is_self_signed = cert.get("is_self_signed")
        if is_self_signed is not None:
            evaluated.add("RULE-PKI-001")
            if is_self_signed == TriState.TRUE:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-PKI-001",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="cert.is_self_signed",
                        observed_val="TRUE",
                        ref_val="CA-issued certificate",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )
            elif is_self_signed == TriState.FALSE:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-PKI-001",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="cert.is_self_signed",
                        observed_val="FALSE",
                        ref_val="CA-issued certificate",
                        cert_idx=cert_idx,
                        raw_sha=raw_sha,
                    )
                )

        return findings

    # --- 5. STARTTLS Evaluator ---
    def _eval_starttls(
        self, stream_id: str, stls: Optional[Dict[str, Any]], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not stls:
            return findings

        state = str(stls.get("starttls_state", "")).upper()
        evaluated.add("RULE-STARTTLS-002")

        if state == "DOWNGRADE_SUSPECTED":
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-STARTTLS-002",
                    status=ComplianceStatus.NON_COMPLIANT,
                    observed_prop="starttls.state",
                    observed_val=state,
                    ref_val="SUCCEEDED or NOT_APPLICABLE",
                )
            )
        elif state in ("SUCCEEDED", "TLS_TRANSITION_DETECTED"):
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-STARTTLS-002",
                    status=ComplianceStatus.COMPLIANT,
                    observed_prop="starttls.state",
                    observed_val=state,
                    ref_val="SUCCEEDED",
                )
            )
        elif state == "NOT_APPLICABLE":
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-STARTTLS-002",
                    status=ComplianceStatus.NOT_APPLICABLE,
                    observed_prop="starttls.state",
                    observed_val=state,
                    ref_val="NOT_APPLICABLE",
                )
            )
        return findings

    # --- 6. Identity Evaluator ---
    def _eval_identity(
        self, stream_id: str, id_res: Optional[IdentityAnalysisResult], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not id_res:
            evaluated.add("RULE-IDENTITY-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-IDENTITY-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="identity.sni_vs_san",
                    observed_val="UNAVAILABLE",
                    ref_val="MATCH",
                )
            )
            return findings

        sni_san_rel = next(
            (r for r in id_res.relationships if r.relationship_type == IdentityRelationshipType.SNI_VS_SAN),
            None,
        )
        if sni_san_rel:
            evaluated.add("RULE-IDENTITY-001")
            if sni_san_rel.status == IdentityStatus.MATCH:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-IDENTITY-001",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="identity.sni_vs_san",
                        observed_val="MATCH",
                        ref_val="MATCH",
                        cert_idx=id_res.certificate_index,
                        raw_sha=id_res.raw_der_sha256,
                    )
                )
            elif sni_san_rel.status == IdentityStatus.MISMATCH:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-IDENTITY-001",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="identity.sni_vs_san",
                        observed_val="MISMATCH",
                        ref_val="MATCH",
                        cert_idx=id_res.certificate_index,
                        raw_sha=id_res.raw_der_sha256,
                    )
                )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-IDENTITY-001",
                        status=ComplianceStatus.UNKNOWN,
                        observed_prop="identity.sni_vs_san",
                        observed_val=sni_san_rel.status.value,
                        ref_val="MATCH",
                        cert_idx=id_res.certificate_index,
                        raw_sha=id_res.raw_der_sha256,
                    )
                )
        return findings

    # --- 7. Trust & Revocation Evaluator ---
    def _eval_trust_and_revocation(
        self, stream_id: str, trust_res: Optional[OfflineTrustResult], evaluated: Set[str]
    ) -> List[ComplianceFinding]:
        findings = []
        if not trust_res:
            evaluated.add("RULE-TRUST-001")
            evaluated.add("RULE-REVOC-001")
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-TRUST-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="trust.validation_status",
                    observed_val="UNAVAILABLE",
                    ref_val="VALIDATED_LOCALLY",
                )
            )
            findings.append(
                self._build_finding(
                    stream_id=stream_id,
                    rule_id="RULE-REVOC-001",
                    status=ComplianceStatus.UNKNOWN,
                    observed_prop="ocsp.observed_status",
                    observed_val="UNAVAILABLE",
                    ref_val="GOOD (VERIFIED)",
                )
            )
            return findings

        # Path validation (Defensively check sub-model existence)
        cert_trust = getattr(trust_res, "certificate_trust", None)
        if cert_trust:
            t_stat = cert_trust.trust_validation_status
            evaluated.add("RULE-TRUST-001")
            if t_stat == TrustValidationStatus.VALIDATED_LOCALLY:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-TRUST-001",
                        status=ComplianceStatus.COMPLIANT,
                        observed_prop="trust.validation_status",
                        observed_val=t_stat.value,
                        ref_val="VALIDATED_LOCALLY",
                        cert_idx=cert_trust.certificate_index,
                        raw_sha=cert_trust.leaf_fingerprint_sha256,
                    )
                )
            elif t_stat == TrustValidationStatus.NOT_VALIDATED:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-TRUST-001",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="trust.validation_status",
                        observed_val=t_stat.value,
                        ref_val="VALIDATED_LOCALLY",
                        cert_idx=cert_trust.certificate_index,
                        raw_sha=cert_trust.leaf_fingerprint_sha256,
                    )
                )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-TRUST-001",
                        status=ComplianceStatus.UNKNOWN,
                        observed_prop="trust.validation_status",
                        observed_val=t_stat.value,
                        ref_val="VALIDATED_LOCALLY",
                        cert_idx=cert_trust.certificate_index,
                        raw_sha=cert_trust.leaf_fingerprint_sha256,
                    )
                )

        # OCSP Stapling (Defensively check sub-model existence & enforce Verified distinction)
        ocsp = getattr(trust_res, "ocsp_evidence", None)
        if ocsp:
            evaluated.add("RULE-REVOC-001")
            ocsp_stat = ocsp.observed_status
            ocsp_ver = ocsp.verification_status

            if ocsp_stat == OCSPObservedStatus.REVOKED:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-REVOC-001",
                        status=ComplianceStatus.NON_COMPLIANT,
                        observed_prop="ocsp.observed_status",
                        observed_val=f"{ocsp_stat.value} ({ocsp_ver.value})",
                        ref_val="GOOD (VERIFIED)",
                    )
                )
            elif ocsp_stat == OCSPObservedStatus.GOOD:
                if ocsp_ver == OCSPVerificationStatus.VERIFIED:
                    findings.append(
                        self._build_finding(
                            stream_id=stream_id,
                            rule_id="RULE-REVOC-001",
                            status=ComplianceStatus.COMPLIANT,
                            observed_prop="ocsp.observed_status",
                            observed_val="GOOD (VERIFIED)",
                            ref_val="GOOD (VERIFIED)",
                        )
                    )
                else:
                    findings.append(
                        self._build_finding(
                            stream_id=stream_id,
                            rule_id="RULE-REVOC-001",
                            status=ComplianceStatus.UNKNOWN,
                            observed_prop="ocsp.observed_status",
                            observed_val="GOOD (NOT_VERIFIED)",
                            ref_val="GOOD (VERIFIED)",
                        )
                    )
            else:
                findings.append(
                    self._build_finding(
                        stream_id=stream_id,
                        rule_id="RULE-REVOC-001",
                        status=ComplianceStatus.UNKNOWN,
                        observed_prop="ocsp.observed_status",
                        observed_val=ocsp_stat.value,
                        ref_val="GOOD (VERIFIED)",
                    )
                )

        return findings

    def _build_finding(
        self,
        stream_id: str,
        rule_id: str,
        status: ComplianceStatus,
        observed_prop: str,
        observed_val: Any,
        ref_val: Any,
        frame: Optional[int] = None,
        ts: Optional[float] = None,
        cert_idx: Optional[int] = None,
        raw_sha: Optional[str] = None,
    ) -> ComplianceFinding:
        # Load directly from authoritative Step 4 rule definition
        rule_def = rule_catalog.require_rule(rule_id)

        # Deterministic SHA-256 identifier
        evidence_digest_src = f"{stream_id}_{rule_id}_{observed_prop}_{observed_val}_{cert_idx}_{raw_sha}_{frame}_{ts}"
        ev_hash = hashlib.sha256(evidence_digest_src.encode("utf-8")).hexdigest()[:12]
        cert_part = f"-c{cert_idx}" if cert_idx is not None else ""
        finding_id = f"FINDING-{rule_id}-{stream_id}{cert_part}-{ev_hash}"

        return ComplianceFinding(
            finding_id=finding_id,
            rule_id=rule_id,
            category=rule_def.category,
            title=rule_def.title,
            description=rule_def.description,
            severity=rule_def.severity,
            status=status,
            recommendation=rule_def.remediation,
            evidence=ComplianceEvidence(
                stream_id=stream_id,
                packet_number=frame,
                timestamp=ts,
                certificate_index=cert_idx,
                raw_der_sha256=raw_sha,
                observed_property=observed_prop,
                observed_value=str(observed_val) if observed_val is not None else "UNAVAILABLE",
                reference_value=str(ref_val) if ref_val is not None else None,
                rule_id=rule_id,
            ),
        )


compliance_engine = ComplianceEngine()