"""
MailRakhwala Offline Revocation & Trust Evidence Schemas (Step 20)
Data contracts for offline chain path validation against bundled CA roots
and passive OCSP stapling inspection.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class TrustValidationStatus(str, Enum):
    VALIDATED_LOCALLY = "VALIDATED_LOCALLY"
    NOT_VALIDATED = "NOT_VALIDATED"
    UNAVAILABLE_FROM_PCAP = "UNAVAILABLE_FROM_PCAP"


class OCSPObservedStatus(str, Enum):
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"
    MALFORMED = "MALFORMED"
    UNAVAILABLE = "UNAVAILABLE"


class OCSPVerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNAVAILABLE = "UNAVAILABLE"


class CRLEvidenceStatus(str, Enum):
    PRESENT_ANALYZED = "PRESENT_ANALYZED"
    NOT_PRESENT = "NOT_PRESENT"
    UNAVAILABLE_FROM_PCAP = "UNAVAILABLE_FROM_PCAP"


class TrustAnchorEvidence(BaseModel):
    """Forensic details of the root CA certificate anchoring a validated path."""
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint of the trust anchor")
    subject_dn: str = Field(..., description="RFC 4514 Subject DN of the trust anchor")
    trust_store_source: str = Field(..., description="Identifier or path of the trust store bundle")
    trust_store_version: str = Field(default="1.0.0-offline", description="Version of the local CA bundle")


class CertificateTrustEvidence(BaseModel):
    """Deterministic offline path validation outcome for a presented certificate chain."""
    stream_id: str
    certificate_index: int = 0
    leaf_fingerprint_sha256: str
    chain_fingerprints_sha256: List[str] = Field(default_factory=list)
    trust_validation_status: TrustValidationStatus
    trust_anchor: Optional[TrustAnchorEvidence] = None
    validation_reference_time: Optional[datetime] = None
    failure_reason: Optional[str] = None
    validation_method: str = Field(
        default="OFFLINE_LOCAL_STORE_PATH_VERIFICATION",
        description="Mechanism used to evaluate cryptographic path"
    )
    limitations: List[str] = Field(default_factory=list)

    @field_validator("validation_reference_time")
    @classmethod
    def ensure_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class OCSPEvidence(BaseModel):
    """Forensic evidence extracted from captured TLS CertificateStatus (OCSP stapling)."""
    certificate_index: int = 0
    serial_number_hex: Optional[str] = None
    observed_status: OCSPObservedStatus = OCSPObservedStatus.UNAVAILABLE
    verification_status: OCSPVerificationStatus = OCSPVerificationStatus.UNAVAILABLE
    produced_at: Optional[datetime] = None
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    responder_id: Optional[str] = None
    raw_evidence_sha256: Optional[str] = None
    frame_number: Optional[int] = None
    timestamp: Optional[float] = None
    explanation: str = Field(..., description="Factual description of observed OCSP data")
    limitations: List[str] = Field(default_factory=list)


class CRLEvidence(BaseModel):
    """Representation of passive CRL distribution points or captured CRL data."""
    crl_evidence_status: CRLEvidenceStatus = CRLEvidenceStatus.UNAVAILABLE_FROM_PCAP
    distribution_points: List[str] = Field(default_factory=list)
    explanation: str = Field(
        default="Passive PCAP inspection does not perform online CRL retrieval.",
        description="Factual evidence statement"
    )
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Live CRL retrieval is prohibited in passive offline forensics.",
            "Absence of captured CRL data does NOT indicate the certificate is unrevoked."
        ]
    )


class OfflineTrustResult(BaseModel):
    """Consolidated Step 20 result covering trust path, OCSP stapling, and CRL evidence."""
    stream_id: str
    certificate_trust: CertificateTrustEvidence
    ocsp_evidence: OCSPEvidence
    crl_evidence: CRLEvidence
    overall_trust_state: str = Field(..., description="High-level factual forensic summary")
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Validation was executed strictly offline using the local CA trust bundle.",
            "No external network queries (DNS, live CA, OCSP, CRL) were performed.",
            "Absence of revocation evidence does not prove a certificate remains unrevoked."
        ]
    )