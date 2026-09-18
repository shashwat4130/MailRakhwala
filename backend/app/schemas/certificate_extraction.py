"""
MailRakhwala Certificate Extraction Schemas (Step 16)
Structured data contracts for raw X.509 / DER certificate objects extracted from TLS handshakes.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class CertificateExtractionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"
    GAP_DISRUPTION = "GAP_DISRUPTION"
    MALFORMED_CERTIFICATE = "MALFORMED_CERTIFICATE"
    OVERSIZED_CERTIFICATE = "OVERSIZED_CERTIFICATE"
    NO_CERTIFICATE_MESSAGE = "NO_CERTIFICATE_MESSAGE"


class RawExtractedCertificate(BaseModel):
    """Normalized raw X.509 certificate extracted from a TLS handshake."""
    certificate_index: int = Field(..., description="0-based chain index (0 is end-entity/leaf)")
    raw_der: bytes = Field(..., description="Exact raw DER certificate bytes")
    raw_der_hex: str = Field(..., description="Hexadecimal representation of raw DER")
    der_length: int = Field(..., ge=1, description="Length of DER certificate in bytes")
    stream_offset: int = Field(default=0, ge=0, description="Offset in handshake payload")
    stream_id: Optional[str] = Field(default=None, description="Correlated TCP stream ID")
    first_frame_number: Optional[int] = Field(default=None, description="Packet frame number")
    first_timestamp: Optional[float] = Field(default=None, description="Packet timestamp")


class CertificateChainExtractionResult(BaseModel):
    """Extraction output containing ordered raw certificates and forensic metadata."""
    stream_id: str
    status: CertificateExtractionStatus
    certificates: List[RawExtractedCertificate] = Field(default_factory=list)
    total_certificates: int = 0
    has_gap_disruption: bool = False
    malformed_reason: Optional[str] = None
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Step 16 extracts raw DER certificate bytes only without verifying cryptographic signatures.",
            "Certificate validity, key strength, SAN, and trust chain are audited in subsequent pipeline steps."
        ]
    )