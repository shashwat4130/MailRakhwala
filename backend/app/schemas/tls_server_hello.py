"""
MailRakhwala TLS ServerHello Schemas (Step 14)
Structured contracts for TLS 1.0 - 1.3 ServerHello handshakes and negotiated parameters.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.tls_client_hello import TLSExtension


class ServerHelloParseStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"
    GAP_DISRUPTION = "GAP_DISRUPTION"
    MALFORMED_HANDSHAKE = "MALFORMED_HANDSHAKE"
    OVERSIZED_HANDSHAKE = "OVERSIZED_HANDSHAKE"
    NO_SERVER_HELLO = "NO_SERVER_HELLO"
    WRONG_DIRECTION = "WRONG_DIRECTION"


class ServerHelloKeyShare(BaseModel):
    """TLS 1.3 Selected Key Share Entry (Extension 51)."""
    group: int
    key_exchange_length: int
    key_exchange_hex: str


class TLSServerHello(BaseModel):
    """Normalized, passive ServerHello handshake data."""
    msg_type: int = 2
    msg_length: int
    handshake_offset: int = 0
    legacy_version: int
    legacy_version_name: str
    negotiated_version: int
    negotiated_version_name: str
    random_hex: str
    session_id_echo_length: int
    session_id_echo_hex: str
    selected_cipher_suite_id: int
    selected_cipher_suite_name: str
    compression_method: int

    # Extensions
    supported_version: Optional[int] = None
    key_share: Optional[ServerHelloKeyShare] = None
    raw_extensions: List[TLSExtension] = Field(default_factory=list)

    # Metadata & Correlation
    stream_id: Optional[str] = None
    direction: Optional[str] = None
    first_frame_number: Optional[int] = None
    first_timestamp: Optional[float] = None
    limitations: List[str] = Field(
        default_factory=lambda: [
            "ServerHello parameters represent passive negotiated settings, not full security posture.",
            "Cipher suite and group security classifications are evaluated in subsequent pipeline stages."
        ]
    )


class ServerHelloParseResult(BaseModel):
    """Result of ServerHello extraction from a TLS Handshake record stream."""
    stream_id: str
    status: ServerHelloParseStatus
    server_hello: Optional[TLSServerHello] = None
    has_gap_disruption: bool = False
    malformed_reason: Optional[str] = None