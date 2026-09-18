"""
MailRakhwala Certificate Security Audit Schemas (Step 18)
Structured data contracts for evidence-backed certificate security findings.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

from app.schemas.domain import ConfidenceLevel, FindingCategory, SeverityLevel, TriState


class CertificateFindingType(str, Enum):
    # Validity
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    CERTIFICATE_NOT_YET_VALID = "CERTIFICATE_NOT_YET_VALID"
    VALIDITY_WINDOW_UNKNOWN = "VALIDITY_WINDOW_UNKNOWN"

    # Public Key
    WEAK_RSA_KEY = "WEAK_RSA_KEY"
    WEAK_DSA_KEY = "WEAK_DSA_KEY"
    WEAK_EC_CURVE = "WEAK_EC_CURVE"
    UNKNOWN_PUBLIC_KEY = "UNKNOWN_PUBLIC_KEY"

    # Signature Algorithm
    WEAK_SIGNATURE_ALGORITHM = "WEAK_SIGNATURE_ALGORITHM"
    UNKNOWN_SIGNATURE_ALGORITHM = "UNKNOWN_SIGNATURE_ALGORITHM"

    # Identity & Self-Signed
    SELF_SIGNED_CERTIFICATE = "SELF_SIGNED_CERTIFICATE"

    # Extensions & Constraints
    BASIC_CONSTRAINTS_CA_MISMATCH = "BASIC_CONSTRAINTS_CA_MISMATCH"
    CRITICAL_EXTENSION_ANOMALY = "CRITICAL_EXTENSION_ANOMALY"

    # Chain Context
    DUPLICATE_CERTIFICATE_IN_CHAIN = "DUPLICATE_CERTIFICATE_IN_CHAIN"
    CHAIN_DN_SEQUENCE_MISMATCH = "CHAIN_DN_SEQUENCE_MISMATCH"
    CHAIN_ISSUER_SUBJECT_MISMATCH = "CHAIN_DN_SEQUENCE_MISMATCH"  # Compatibility alias
    EMPTY_OR_CORRUPT_CERTIFICATE = "EMPTY_OR_CORRUPT_CERTIFICATE"


class CertificateEvidence(BaseModel):
    """Forensic evidence substantiating a certificate security finding."""
    certificate_index: int = Field(..., description="0-based chain index of the audited certificate")
    stream_id: Optional[str] = Field(default=None, description="Correlated TCP stream ID")
    raw_der_sha256: Optional[str] = Field(default=None, description="SHA-256 fingerprint of the raw certificate DER")
    observed_property: str = Field(..., description="The exact attribute or field extracted from evidence")
    observed_value: Any = Field(..., description="The observed value of the field")
    reference_value: Optional[Any] = Field(default=None, description="The baseline, threshold, or reference comparison value")
    rule_id: str = Field(..., description="Step 4 rulebook identifier or audit policy ID")
    evaluation_time: Optional[datetime] = Field(default=None, description="UTC timestamp used as temporal reference")


class CertificateSecurityFinding(BaseModel):
    """Deterministic, explainable security finding for an X.509 certificate."""
    finding_id: str = Field(..., description="Rule identifier (e.g. RULE-CERT-001)")
    finding_type: CertificateFindingType
    title: str
    category: FindingCategory = FindingCategory.CERTIFICATE_VALIDITY
    severity: SeverityLevel
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH  # or ConfidenceLevel.CONFIRMED
    description: str
    evidence: CertificateEvidence
    recommendation: str
    limitations: List[str] = Field(default_factory=list)


class SingleCertificateAudit(BaseModel):
    """Consolidated audit outcome for a single X.509 certificate."""
    certificate_index: int
    raw_der_sha256: Optional[str] = None
    stream_id: Optional[str] = None
    is_expired: TriState = TriState.UNKNOWN
    is_not_yet_valid: TriState = TriState.UNKNOWN
    is_self_signed: TriState = TriState.UNKNOWN
    has_weak_key: TriState = TriState.UNKNOWN
    has_weak_signature: TriState = TriState.UNKNOWN
    findings: List[CertificateSecurityFinding] = Field(default_factory=list)
    audit_limitations: List[str] = Field(default_factory=list)


class CertificateSecurityAuditResult(BaseModel):
    """Aggregate certificate security audit outcome for a TLS session chain."""
    stream_id: str
    total_certificates_audited: int = 0
    reference_time: Optional[datetime] = None
    certificate_audits: List[SingleCertificateAudit] = Field(default_factory=list)
    chain_findings: List[CertificateSecurityFinding] = Field(default_factory=list)
    all_findings: List[CertificateSecurityFinding] = Field(default_factory=list)
    has_critical_or_high: bool = False
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Passive certificate auditing evaluates cryptographic properties without active CRL/OCSP network queries.",
            "Host identity matching (SNI vs SAN) and trust-store root validation belong to Steps 19 and 20."
        ]
    )

    @field_validator("reference_time")
    @classmethod
    def ensure_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v