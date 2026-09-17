"""
MailRakhwala TLS Record Layer Schemas (Step 12)
Passive inspection contracts for RFC 5246 / RFC 8446 TLS record framing.
"""

from enum import Enum, IntEnum
from typing import List, Optional
from pydantic import BaseModel, Field


class TLSRecordContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    UNKNOWN = 255

    @classmethod
    def from_int(cls, val: int) -> "TLSRecordContentType":
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


class TLSRecordVersion(IntEnum):
    SSL_3_0 = 0x0300
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304
    UNKNOWN = 0x0000

    @classmethod
    def from_int(cls, val: int) -> "TLSRecordVersion":
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


class TLSRecordParseStatus(str, Enum):
    OK = "OK"
    INCOMPLETE_HEADER = "INCOMPLETE_HEADER"
    INCOMPLETE_PAYLOAD = "INCOMPLETE_PAYLOAD"
    OVERSIZED_RECORD = "OVERSIZED_RECORD"
    UNKNOWN_CONTENT_TYPE = "UNKNOWN_CONTENT_TYPE"
    GAP_DISRUPTION = "GAP_DISRUPTION"
    CLEAN_EOF = "CLEAN_EOF"


class TLSRecord(BaseModel):
    """Normalized TLS record extracted from TCP stream."""
    record_index: int
    content_type: int
    content_type_name: str
    legacy_record_version: int
    legacy_record_version_name: str
    declared_length: int
    payload_length: int
    stream_offset: int
    payload: bytes
    is_complete: bool
    parse_status: TLSRecordParseStatus
    first_frame_number: Optional[int] = None
    first_timestamp: Optional[float] = None
    direction: Optional[str] = None
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Record-layer version does not determine final negotiated TLS version."
        ]
    )


class TLSRecordParseResult(BaseModel):
    """Aggregate result of TLS record parsing for a stream direction."""
    stream_id: str
    direction: str
    total_records: int = 0
    records: List[TLSRecord] = Field(default_factory=list)
    bytes_consumed: int = 0
    parse_status: TLSRecordParseStatus = TLSRecordParseStatus.CLEAN_EOF
    error_message: Optional[str] = None
    has_gap_disruption: bool = False
    has_unresolved_gaps: bool = False  # <-- Added missing field