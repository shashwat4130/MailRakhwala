"""
MailRakhwala Packet Dissection Schemas (Step 07 & Step 08)
Domain models for raw packet metadata and TCP sequence attributes extracted from captures.
"""

from typing import Optional
from pydantic import BaseModel, Field


class DissectedPacket(BaseModel):
    """Normalized metadata for a single dissected frame."""
    frame_number: int = Field(..., description="1-based frame index in capture")
    timestamp_epoch: Optional[float] = Field(None, description="Capture epoch timestamp")
    frame_len: int = Field(..., description="Frame length in bytes on wire")
    src_ip: Optional[str] = Field(None, description="IPv4 or IPv6 source address")
    dst_ip: Optional[str] = Field(None, description="IPv4 or IPv6 destination address")
    src_port: Optional[int] = Field(None, description="Transport layer source port")
    dst_port: Optional[int] = Field(None, description="Transport layer destination port")
    transport_protocol: Optional[str] = Field(None, description="Transport protocol name (e.g. TCP, UDP)")
    tcp_stream: Optional[int] = Field(None, description="TShark TCP stream index where available")
    highest_layer: Optional[str] = Field(None, description="Highest protocol layer detected by dissection")

    # Step 08 sequence and payload attributes
    tcp_seq: Optional[int] = Field(None, description="Raw TCP 32-bit sequence number")
    tcp_ack: Optional[int] = Field(None, description="Raw TCP acknowledgment number")
    tcp_flags: Optional[int] = Field(None, description="TCP control flags bitmask")
    tcp_payload_len: Optional[int] = Field(None, description="TCP payload length in bytes")
    payload: Optional[bytes] = Field(None, description="Extracted raw TCP segment payload bytes")


class DissectionSummary(BaseModel):
    """Aggregate statistics for a completed packet dissection pass."""
    total_frames: int = 0
    tcp_frames: int = 0
    udp_frames: int = 0
    other_frames: int = 0
    error_count: int = 0