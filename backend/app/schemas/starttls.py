"""
MailRakhwala STARTTLS State Machine Schemas (Step 10)
Domain contracts for explicit STARTTLS state transitions, evidence, and outcomes.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.protocol import ConfidenceLevel, EmailProtocol, EvidenceRecord
from app.schemas.tcp_stream import ReconstructionStatus


class StarttlsState(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    CONNECTED = "CONNECTED"
    GREETING_SEEN = "GREETING_SEEN"
    CAPABILITY_ADVERTISED = "CAPABILITY_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    SERVER_ACCEPTED = "SERVER_ACCEPTED"
    SERVER_REJECTED = "SERVER_REJECTED"
    TLS_TRANSITION_DETECTED = "TLS_TRANSITION_DETECTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class StarttlsTransition(BaseModel):
    """Represents an observed state transition in the STARTTLS exchange."""
    from_state: StarttlsState
    to_state: StarttlsState
    trigger: str
    is_client: bool = False
    is_server: bool = False
    observed_text: Optional[str] = None


class StarttlsAssessment(BaseModel):
    """Structured assessment of the STARTTLS lifecycle for a reconstructed TCP stream."""
    stream_id: str
    protocol: EmailProtocol
    starttls_state: StarttlsState
    confidence: ConfidenceLevel
    transitions: List[StarttlsTransition] = Field(default_factory=list)
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    reconstruction_status: ReconstructionStatus
    unresolved_gaps: bool = False
    tls_transition_detected: bool = False
    explanation: str