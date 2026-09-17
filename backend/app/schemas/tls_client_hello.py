"""
MailRakhwala TLS ClientHello Schemas (Step 13)
Structured contracts for TLS 1.0 - 1.3 ClientHello handshakes and extensions.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ClientHelloParseStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"
    GAP_DISRUPTION = "GAP_DISRUPTION"
    MALFORMED_HANDSHAKE = "MALFORMED_HANDSHAKE"
    OVERSIZED_HANDSHAKE = "OVERSIZED_HANDSHAKE"
    NO_CLIENT_HELLO = "NO_CLIENT_HELLO"


class TLSExtension(BaseModel):
    """Raw or recognized TLS extension metadata."""
    extension_type: int
    extension_name: str
    length: int
    data: bytes


class KeyShareEntry(BaseModel):
    """TLS 1.3 Key Share Entry (Extension 51)."""
    group: int
    key_exchange_length: int
    key_exchange_hex: str


class TLSClientHello(BaseModel):
    """Normalized, passive ClientHello handshake data."""
    msg_type: int = 1
    msg_length: int
    handshake_offset: int = 0
    legacy_version: int
    legacy_version_name: str
    random_hex: str
    session_id_length: int
    session_id_hex: str
    cipher_suite_ids: List[int] = Field(default_factory=list)
    cipher_suite_names: List[str] = Field(default_factory=list)
    compression_methods: List[int] = Field(default_factory=list)
    
    # Recognized extensions
    server_name: Optional[str] = None
    supported_groups: List[int] = Field(default_factory=list)
    signature_algorithms: List[int] = Field(default_factory=list)
    alpn_protocols: List[str] = Field(default_factory=list)
    supported_versions: List[int] = Field(default_factory=list)
    key_shares: List[KeyShareEntry] = Field(default_factory=list)
    raw_extensions: List[TLSExtension] = Field(default_factory=list)

    # Metadata & correlation
    stream_id: Optional[str] = None
    first_frame_number: Optional[int] = None
    first_timestamp: Optional[float] = None
    limitations: List[str] = Field(
        default_factory=lambda: [
            "ClientHello proposals indicate client capabilities, not negotiated parameters.",
            "ClientHello does not confirm active tampering or adversary intervention."
        ]
    )


class ClientHelloParseResult(BaseModel):
    """Result of ClientHello extraction from a TLS Handshake record stream."""
    stream_id: str
    status: ClientHelloParseStatus
    client_hello: Optional[TLSClientHello] = None
    has_gap_disruption: bool = False
    malformed_reason: Optional[str] = None