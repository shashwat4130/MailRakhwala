"""
MailRakhwala Reconstructed TCP Stream Schemas (Step 08)
Strictly bounded data contracts for bidirectional TCP streams, fragmented reassembly, and reassembly metrics.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class StreamLifecycle(str, Enum):
    UNKNOWN = "UNKNOWN"
    ESTABLISHING = "ESTABLISHING"
    ESTABLISHED = "ESTABLISHED"
    GRACEFULLY_CLOSED = "GRACEFULLY_CLOSED"
    RESET = "RESET"
    ABRUPT_END = "ABRUPT_END"


class ReconstructionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    TRUNCATED = "TRUNCATED"
    AMBIGUOUS = "AMBIGUOUS"


class TerminationReason(str, Enum):
    FIN = "FIN"
    RST = "RST"
    INACTIVITY_TIMEOUT = "INACTIVITY_TIMEOUT"
    MAX_BYTES_EXCEEDED = "MAX_BYTES_EXCEEDED"
    END_OF_CAPTURE = "END_OF_CAPTURE"
    PURGED = "PURGED"
    CONNECTION_REUSED = "CONNECTION_REUSED"


class SequenceGap(BaseModel):
    """Represents an unresolved gap between expected and received TCP sequence numbers."""
    start_seq: int = Field(..., description="Expected starting sequence number of the gap")
    end_seq: int = Field(..., description="Next observed sequence number after the gap")
    gap_bytes: int = Field(..., description="Estimated missing bytes in the stream")


class StreamFragment(BaseModel):
    """Represents a discrete contiguous block of reconstructed payload bytes."""
    start_seq: int = Field(..., description="TCP sequence number where this fragment begins")
    data: bytes = Field(..., description="Contiguous payload bytes in this block")
    is_initial_contiguous: bool = Field(False, description="True if contiguous from connection start")
    first_frame_number: Optional[int] = Field(None, description="Earliest frame number contributing to this fragment")
    first_timestamp: Optional[float] = Field(None, description="Earliest capture timestamp for this fragment")

class ReconstructedStream(BaseModel):
    """Normalized forensic bidirectional TCP stream."""
    stream_id: str = Field(..., description="Unique conversation identifier based on 4-tuple and generation")
    tshark_stream_index: Optional[int] = Field(None, description="Matching TShark tcp.stream index metadata if present")

    # 4-Tuple Endpoints
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    # Lifecycle & Forensic Evaluation
    lifecycle: StreamLifecycle = StreamLifecycle.UNKNOWN
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.INCOMPLETE
    termination_reason: TerminationReason = TerminationReason.END_OF_CAPTURE

    # Timestamps & Quantities
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    packet_count: int = 0
    client_packet_count: int = 0
    server_packet_count: int = 0

    # Contiguous Payload Volumes (up to first unresolved gap)
    client_bytes_reassembled: int = 0
    server_bytes_reassembled: int = 0
    client_payload: bytes = b""
    server_payload: bytes = b""

    # Gap-Aware Non-Contiguous Payload Fragments
    client_fragments: List[StreamFragment] = Field(default_factory=list)
    server_fragments: List[StreamFragment] = Field(default_factory=list)

    # Forensic Integrity Indicators
    client_gaps: List[SequenceGap] = Field(default_factory=list)
    server_gaps: List[SequenceGap] = Field(default_factory=list)
    has_unresolved_gaps: bool = False
    client_retransmissions: int = 0
    server_retransmissions: int = 0
    client_overlapping_segments: int = 0
    server_overlapping_segments: int = 0
    has_conflicting_overlaps: bool = False
    is_truncated: bool = False