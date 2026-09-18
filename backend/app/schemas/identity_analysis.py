"""
MailRakhwala Identity & Trust Analysis Schemas (Step 19)
Data contracts for passive correlation between observed TLS SNI, Certificate SAN,
mail-server session hostnames, and offline DNS/trust context.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IdentityStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"


class IdentityRelationshipType(str, Enum):
    SNI_VS_SAN = "SNI_VS_SAN"
    MAIL_HOST_VS_SAN = "MAIL_HOST_VS_SAN"
    SNI_VS_MAIL_HOST = "SNI_VS_MAIL_HOST"
    MAIL_IDENTITY_VS_DNS_MX = "MAIL_IDENTITY_VS_DNS_MX"
    CERTIFICATE_VS_TRUST_PATH = "CERTIFICATE_VS_TRUST_PATH"


class IdentityRelationship(BaseModel):
    """Pairwise identity correlation between two observed network indicators with full provenance."""
    relationship_type: IdentityRelationshipType
    left_name: str = Field(..., description="Description of the source/left indicator")
    left_value: Optional[str] = Field(default=None, description="Observed left indicator string")
    left_source: Optional[str] = Field(default=None, description="Source layer/protocol of left indicator")
    right_name: str = Field(..., description="Description of the target/right indicator")
    right_value: Optional[str] = Field(default=None, description="Observed right indicator string")
    right_source: Optional[str] = Field(default=None, description="Source layer/protocol of right indicator")
    status: IdentityStatus
    matched_entry: Optional[str] = Field(default=None, description="The specific entry that validated the match")
    frame_number: Optional[int] = Field(default=None, description="Frame number where observable occurred")
    timestamp: Optional[float] = Field(default=None, description="Timestamp of observable")
    raw_reference: Optional[str] = Field(default=None, description="Raw evidence reference or pointer")
    certificate_index: Optional[int] = Field(default=None, description="Target certificate index")
    raw_der_sha256: Optional[str] = Field(default=None, description="Target certificate raw DER SHA-256")
    explanation: str = Field(..., description="Deterministic, explainable rationale for the status")
    limitations: List[str] = Field(default_factory=list)


class IdentityAnalysisResult(BaseModel):
    """Consolidated identity and trust alignment output for a captured session."""
    stream_id: str
    certificate_index: int = 0
    raw_der_sha256: Optional[str] = None
    sni_observed: Optional[str] = None
    mail_host_observed: Optional[str] = None
    san_entries: List[str] = Field(default_factory=list)
    relationships: List[IdentityRelationship] = Field(default_factory=list)
    overall_interpretation: str = Field(..., description="High-level factual assessment of identity consistency")
    dns_mx_evidence_present: bool = False
    trust_path_evidence_present: bool = False
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Passive identity analysis evaluates consistency across observed session indicators.",
            "An identity mismatch or absence of evidence does NOT indicate active malicious tampering or MITM.",
            "Full offline PKI trust-path resolution and revocation checking belong to Step 20."
        ]
    )