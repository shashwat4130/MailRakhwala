"""
MailRakhwala STARTTLS Downgrade & Plaintext Fallback Analysis Contracts (Step 11)
Adheres strictly to passive PCAP forensic limitations (RFC 3207, RFC 8314).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.domain import SeverityLevel
from app.schemas.protocol import ConfidenceLevel, EmailProtocol
from app.schemas.starttls import StarttlsState
from app.schemas.tcp_stream import ReconstructionStatus


class DowngradeAssessmentStatus(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BENIGN = "BENIGN"
    PLAINTEXT_FALLBACK_OBSERVED = "PLAINTEXT_FALLBACK_OBSERVED"
    NEGOTIATION_REJECTED = "NEGOTIATION_REJECTED"
    DOWNGRADE_SUSPECTED = "DOWNGRADE_SUSPECTED"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class DowngradeIndicatorType(str, Enum):
    NONE = "NONE"
    PORT_NOT_APPLICABLE = "PORT_NOT_APPLICABLE"
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    STARTTLS_ADVERTISED_NOT_REQUESTED = "STARTTLS_ADVERTISED_NOT_REQUESTED"
    STARTTLS_SERVER_REJECTED = "STARTTLS_SERVER_REJECTED"
    ACCEPTED_NO_TLS_TRANSITION = "ACCEPTED_NO_TLS_TRANSITION"
    PLAINTEXT_CONTINUATION_POST_ACCEPTANCE = "PLAINTEXT_CONTINUATION_POST_ACCEPTANCE"
    PROTOCOL_STATE_INCONSISTENCY = "PROTOCOL_STATE_INCONSISTENCY"


class DowngradeEvidence(BaseModel):
    """Forensic evidence details captured from the stream."""
    stream_id: str
    protocol: EmailProtocol
    client_endpoint: str
    server_endpoint: str
    starttls_state: StarttlsState
    reconstruction_status: ReconstructionStatus
    has_unresolved_gaps: bool
    tls_transition_detected: bool
    observed_events: List[str] = Field(default_factory=list)
    observed_commands: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Passive capture analysis cannot determine adversary intervention or intent.",
            "Rejection or fallback may be due to benign client/server configuration or network policy."
        ]
    )


class DowngradeFinding(BaseModel):
    """Individual security-relevant downgrade or plaintext fallback observation."""
    finding_id: str
    rule_id: str = "RULE-STARTTLS-002"
    indicator_type: DowngradeIndicatorType
    title: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    status: DowngradeAssessmentStatus
    description: str
    evidence: DowngradeEvidence
    recommendation: str


class DowngradeAnalysisResult(BaseModel):
    """Complete Step 11 downgrade assessment output for a single TCP stream."""
    stream_id: str
    protocol: EmailProtocol
    status: DowngradeAssessmentStatus
    confidence: ConfidenceLevel
    is_downgrade_suspected: bool
    findings: List[DowngradeFinding] = Field(default_factory=list)
    summary: str