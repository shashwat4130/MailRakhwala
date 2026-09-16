"""
MailRakhwala Email Protocol Classification Schemas (Step 09)
Data contracts for multi-signal passive classification of reconstructed TCP streams.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.tcp_stream import ReconstructionStatus


class EmailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SignalType(str, Enum):
    PORT = "PORT"
    SERVER_BANNER = "SERVER_BANNER"
    CLIENT_COMMAND = "CLIENT_COMMAND"
    SERVER_RESPONSE = "SERVER_RESPONSE"
    IMPLICIT_TLS_PORT = "IMPLICIT_TLS_PORT"


class EvidenceRecord(BaseModel):
    """Specific verifiable indicator observed in the stream."""
    signal_type: SignalType
    description: str
    matched_value: Optional[str] = None
    is_client: bool = False
    is_server: bool = False


class ProtocolClassification(BaseModel):
    """Forensic classification output for a single reconstructed TCP stream."""
    stream_id: str
    protocol: EmailProtocol = EmailProtocol.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    reconstruction_status: ReconstructionStatus
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    matched_indicators: List[str] = Field(default_factory=list)
    is_tls_port_context: bool = False
    has_unresolved_gaps: bool = False