"""
Unit tests for Step 12: TLS Record Layer Parser.
Verifies RFC 5246 / RFC 8446 5-byte header extraction, content types,
legacy record versions, multi-record framing, TCP fragment traversal,
bounded payload limits, and precise TCP sequence gap disruption handling.
"""

import struct
from typing import List, Optional
import pytest

from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    SequenceGap,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)
from app.schemas.tls_record import (
    TLSRecordContentType,
    TLSRecordParseStatus,
    TLSRecordVersion,
)
from app.services.tls_record_parser import TLS_RECORD_MAX_PAYLOAD, tls_record_parser


def make_stream(
    stream_id: str = "stream#tls1",
    client_payload: bytes = b"",
    server_payload: bytes = b"",
    client_fragments: Optional[List[StreamFragment]] = None,
    server_fragments: Optional[List[StreamFragment]] = None,
    client_gaps: Optional[List[SequenceGap]] = None,
    server_gaps: Optional[List[SequenceGap]] = None,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
    has_unresolved_gaps: bool = False,
) -> ReconstructedStream:
    return ReconstructedStream(
        stream_id=stream_id,
        client_ip="192.168.1.50",
        client_port=54321,
        server_ip="192.168.1.10",
        server_port=465,
        lifecycle=StreamLifecycle.ESTABLISHED,
        reconstruction_status=reconstruction_status,
        termination_reason=TerminationReason.END_OF_CAPTURE,
        client_payload=client_payload,
        server_payload=server_payload,
        client_fragments=client_fragments or [],
        server_fragments=server_fragments or [],
        client_gaps=client_gaps or [],
        server_gaps=server_gaps or [],
        has_unresolved_gaps=has_unresolved_gaps,
    )


def make_handshake_record(payload: bytes, version: int = 0x0303) -> bytes:
    """Helper to build a valid Handshake (Type 22) record."""
    header = struct.pack(">BHH", TLSRecordContentType.HANDSHAKE, version, len(payload))
    return header + payload


# ==========================================================
# 1. CORE CONTENT TYPES & VALID RECORDS
# ==========================================================

def test_valid_handshake_record():
    """1. Valid Handshake record parsed completely."""
    data = b"\x01\x00\x00\x10synthetic_client_hello"
    record_bytes = make_handshake_record(data)
    res = tls_record_parser.parse_payload(record_bytes, "stream#1", "client->server")

    assert res.total_records == 1
    assert res.parse_status == TLSRecordParseStatus.CLEAN_EOF
    rec = res.records[0]
    assert rec.content_type == 22
    assert rec.content_type_name == "HANDSHAKE"
    assert rec.legacy_record_version == 0x0303
    assert rec.legacy_record_version_name == "TLS_1_2"
    assert rec.declared_length == len(data)
    assert rec.payload_length == len(data)
    assert rec.payload == data
    assert rec.is_complete is True
    assert rec.parse_status == TLSRecordParseStatus.OK


def test_valid_application_data_record():
    """2. Valid ApplicationData (Type 23) record."""
    payload = b"encrypted_app_data_stream_payload"
    record_bytes = struct.pack(">BHH", 23, 0x0303, len(payload)) + payload
    res = tls_record_parser.parse_payload(record_bytes, "stream#1", "client->server")

    assert res.total_records == 1
    rec = res.records[0]
    assert rec.content_type == 23
    assert rec.content_type_name == "APPLICATION_DATA"
    assert rec.payload == payload
    assert rec.is_complete is True
    assert rec.parse_status == TLSRecordParseStatus.OK


def test_valid_alert_record():
    """3. Valid Alert (Type 21) record."""
    payload = b"\x02\x28"  # Fatal, Handshake Failure
    record_bytes = struct.pack(">BHH", 21, 0x0303, len(payload)) + payload
    res = tls_record_parser.parse_payload(record_bytes, "stream#1", "server->client")

    assert res.total_records == 1
    rec = res.records[0]
    assert rec.content_type == 21
    assert rec.content_type_name == "ALERT"
    assert rec.payload == payload
    assert rec.is_complete is True


def test_valid_change_cipher_spec_record():
    """4. Valid ChangeCipherSpec (Type 20) record."""
    payload = b"\x01"
    record_bytes = struct.pack(">BHH", 20, 0x0303, 1) + payload
    res = tls_record_parser.parse_payload(record_bytes, "stream#1", "client->server")

    assert res.total_records == 1
    rec = res.records[0]
    assert rec.content_type == 20
    assert rec.content_type_name == "CHANGE_CIPHER_SPEC"
    assert rec.payload == payload
    assert rec.is_complete is True


# ==========================================================
# 2. MULTI-RECORD & TCP FRAGMENT TRAVERSAL
# ==========================================================

def test_multiple_consecutive_records():
    """5. Multiple consecutive TLS records in single stream."""
    rec1 = make_handshake_record(b"HELLO_1")
    rec2 = struct.pack(">BHH", 20, 0x0303, 1) + b"\x01"
    rec3 = struct.pack(">BHH", 23, 0x0303, 5) + b"APP01"

    payload = rec1 + rec2 + rec3
    res = tls_record_parser.parse_payload(payload, "stream#1", "client->server")

    assert res.total_records == 3
    assert res.bytes_consumed == len(payload)
    assert res.records[0].content_type == 22
    assert res.records[1].content_type == 20
    assert res.records[2].content_type == 23
    assert all(r.is_complete for r in res.records)


def test_record_header_split_across_tcp_fragments():
    """6. Record header split across fragments correlates offsets and passes."""
    rec = make_handshake_record(b"FRAGMENTED_HEADER_TEST")
    frag1 = StreamFragment(start_seq=1, data=rec[:3], first_frame_number=10, first_timestamp=100.0)
    frag2 = StreamFragment(start_seq=4, data=rec[3:], first_frame_number=11, first_timestamp=100.1)

    res = tls_record_parser.parse_payload(
        payload=rec,
        stream_id="stream#frag_hdr",
        direction="client->server",
        fragments=[frag1, frag2],
    )
    assert res.total_records == 1
    assert res.records[0].is_complete is True
    assert res.records[0].first_frame_number == 10


def test_record_payload_split_across_tcp_fragments():
    """7. Record payload split across fragments."""
    rec = make_handshake_record(b"PAYLOAD_ACROSS_TWO_TCP_SEGMENTS")
    frag1 = StreamFragment(start_seq=1, data=rec[:12], first_frame_number=20, first_timestamp=200.0)
    frag2 = StreamFragment(start_seq=13, data=rec[12:], first_frame_number=21, first_timestamp=200.05)

    res = tls_record_parser.parse_payload(
        payload=rec,
        stream_id="stream#frag_payload",
        direction="client->server",
        fragments=[frag1, frag2],
    )
    assert res.total_records == 1
    assert res.records[0].is_complete is True
    assert res.records[0].first_frame_number == 20


def test_multiple_records_in_one_tcp_fragment():
    """8. Multiple records packed into single TCP fragment."""
    rec1 = make_handshake_record(b"REC_A")
    rec2 = make_handshake_record(b"REC_B")
    data = rec1 + rec2
    frag = StreamFragment(start_seq=1, data=data, first_frame_number=30, first_timestamp=300.0)

    res = tls_record_parser.parse_payload(
        payload=data,
        stream_id="stream#single_frag",
        direction="client->server",
        fragments=[frag],
    )
    assert res.total_records == 2
    assert res.records[0].first_frame_number == 30
    assert res.records[1].first_frame_number == 30


# ==========================================================
# 3. TRUNCATION & BOUNDARY CONDITIONS
# ==========================================================

def test_incomplete_1_to_4_byte_record_header():
    """9. Incomplete 1-4 byte header terminates with INCOMPLETE_HEADER."""
    for partial_len in (1, 2, 3, 4):
        partial = b"\x16\x03\x03\x00\x10"[:partial_len]
        res = tls_record_parser.parse_payload(partial, "stream#1", "client->server")
        assert res.parse_status == TLSRecordParseStatus.INCOMPLETE_HEADER
        assert len(res.records) == 1
        assert res.records[0].is_complete is False
        assert res.records[0].parse_status == TLSRecordParseStatus.INCOMPLETE_HEADER


def test_incomplete_record_payload():
    """10. Header is complete but payload is truncated."""
    header = struct.pack(">BHH", 22, 0x0303, 50)
    truncated_data = header + b"short_payload"

    res = tls_record_parser.parse_payload(truncated_data, "stream#1", "client->server")
    assert res.parse_status == TLSRecordParseStatus.INCOMPLETE_PAYLOAD
    assert len(res.records) == 1
    assert res.records[0].is_complete is False
    assert res.records[0].declared_length == 50
    assert res.records[0].payload_length == len(b"short_payload")


def test_declared_length_larger_than_available_bytes():
    """11. Declared length larger than available bytes terminates safely."""
    header = struct.pack(">BHH", 23, 0x0303, 1000)
    data = header + b"only_10_bytes"

    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.parse_status == TLSRecordParseStatus.INCOMPLETE_PAYLOAD
    assert res.records[0].is_complete is False


def test_oversized_declared_record_length():
    """12. Declared length exceeding maximum limit halts with OVERSIZED_RECORD."""
    oversized_len = TLS_RECORD_MAX_PAYLOAD + 100
    header = struct.pack(">BHH", 22, 0x0303, oversized_len)

    res = tls_record_parser.parse_payload(header, "stream#1", "client->server")
    assert res.parse_status == TLSRecordParseStatus.OVERSIZED_RECORD
    assert res.records[0].is_complete is False
    assert res.records[0].parse_status == TLSRecordParseStatus.OVERSIZED_RECORD
    assert res.records[0].payload == b""


def test_unknown_content_type():
    """13. Unsupported content type does not crash; flagged as UNKNOWN."""
    header = struct.pack(">BHH", 99, 0x0303, 4)
    data = header + b"test"

    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.total_records == 1
    assert res.records[0].content_type == 99
    assert res.records[0].content_type_name == "UNKNOWN"
    assert res.records[0].parse_status == TLSRecordParseStatus.UNKNOWN_CONTENT_TYPE


# ==========================================================
# 4. PROTOCOL VERSIONS & ZERO/EMPTY SCENARIOS
# ==========================================================

def test_tls_1_0_record_version():
    """14. TLS 1.0 legacy version recognized."""
    data = make_handshake_record(b"TLS10", version=0x0301)
    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].legacy_record_version == 0x0301
    assert res.records[0].legacy_record_version_name == "TLS_1_0"


def test_tls_1_1_record_version():
    """15. TLS 1.1 legacy version recognized."""
    data = make_handshake_record(b"TLS11", version=0x0302)
    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].legacy_record_version == 0x0302
    assert res.records[0].legacy_record_version_name == "TLS_1_1"


def test_tls_1_2_record_version():
    """16. TLS 1.2 legacy version recognized."""
    data = make_handshake_record(b"TLS12", version=0x0303)
    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].legacy_record_version == 0x0303
    assert res.records[0].legacy_record_version_name == "TLS_1_2"


def test_tls_1_3_legacy_record_version():
    """17. TLS 1.3 legacy record version 0x0303 or 0x0304 recognized."""
    data = make_handshake_record(b"TLS13", version=0x0304)
    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].legacy_record_version == 0x0304
    assert res.records[0].legacy_record_version_name == "TLS_1_3"


def test_unknown_reserved_version():
    """18. Unknown version does not crash."""
    data = make_handshake_record(b"UNKNOWN_VER", version=0x0A0A)
    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].legacy_record_version == 0x0A0A
    assert res.records[0].legacy_record_version_name == "UNKNOWN"


def test_zero_length_payload():
    """19. Zero-length payload record supported."""
    header = struct.pack(">BHH", 22, 0x0303, 0)
    res = tls_record_parser.parse_payload(header, "stream#1", "client->server")
    assert res.total_records == 1
    assert res.records[0].declared_length == 0
    assert res.records[0].payload_length == 0
    assert res.records[0].is_complete is True


def test_empty_input():
    """20. Empty input produces zero records and clean EOF."""
    res = tls_record_parser.parse_payload(b"", "stream#empty", "client->server")
    assert res.total_records == 0
    assert res.bytes_consumed == 0
    assert res.parse_status == TLSRecordParseStatus.CLEAN_EOF


def test_no_fabrication_on_incomplete_data():
    """21. No bytes fabricated when payload is short."""
    partial = make_handshake_record(b"ABCDE")[:-2]
    res = tls_record_parser.parse_payload(partial, "stream#1", "client->server")
    assert res.records[0].payload == b"ABC"
    assert res.records[0].is_complete is False


def test_unresolved_tcp_gap_handling():
    """22. Unresolved TCP gap flag exposed cleanly."""
    data = make_handshake_record(b"WITH_GAP")
    res = tls_record_parser.parse_payload(
        data,
        "stream#gap",
        "client->server",
        has_unresolved_gaps=True,
    )
    assert res.total_records == 1
    assert res.has_unresolved_gaps is True


def test_multiple_independent_reconstructed_streams():
    """23. Multiple streams maintain directional and identity isolation."""
    s1 = make_stream(stream_id="stream#1", client_payload=make_handshake_record(b"STREAM_1"))
    s2 = make_stream(stream_id="stream#2", client_payload=make_handshake_record(b"STREAM_2"))

    c1, s1_res = tls_record_parser.parse_stream(s1)
    c2, s2_res = tls_record_parser.parse_stream(s2)

    assert c1.stream_id == "stream#1"
    assert c2.stream_id == "stream#2"
    assert c1.records[0].payload == b"STREAM_1"
    assert c2.records[0].payload == b"STREAM_2"


def test_direction_frame_metadata_preservation():
    """24. Direction and frame metadata preserved."""
    rec = make_handshake_record(b"METADATA")
    frag = StreamFragment(start_seq=1, data=rec, first_frame_number=42, first_timestamp=1700000000.5)

    res = tls_record_parser.parse_payload(
        rec,
        "stream#1",
        "server->client",
        fragments=[frag],
    )
    assert res.direction == "server->client"
    assert res.records[0].direction == "server->client"
    assert res.records[0].first_frame_number == 42
    assert res.records[0].first_timestamp == 1700000000.5


def test_exact_stream_offsets():
    """25. Stream offsets accurate across consecutive records."""
    r1 = make_handshake_record(b"FIRST")
    r2 = make_handshake_record(b"SECOND_LONGER")
    data = r1 + r2

    res = tls_record_parser.parse_payload(data, "stream#1", "client->server")
    assert res.records[0].stream_offset == 0
    assert res.records[1].stream_offset == len(r1)


def test_parser_termination_status():
    """26. Status indicates clean EOF on exact consume."""
    rec = make_handshake_record(b"CLEAN")
    res = tls_record_parser.parse_payload(rec, "stream#1", "client->server")
    assert res.parse_status == TLSRecordParseStatus.CLEAN_EOF


def test_boundary_size_record_within_allowed_limit():
    """27. Boundary-size record at 16384 bytes parsed successfully."""
    payload = b"X" * TLS_RECORD_MAX_PAYLOAD
    rec = make_handshake_record(payload)

    res = tls_record_parser.parse_payload(rec, "stream#1", "client->server")
    assert res.total_records == 1
    assert res.records[0].is_complete is True
    assert res.records[0].payload_length == TLS_RECORD_MAX_PAYLOAD


def test_boundary_size_record_above_allowed_limit():
    """28. Record at 16385 bytes rejected cleanly."""
    header = struct.pack(">BHH", 22, 0x0303, TLS_RECORD_MAX_PAYLOAD + 1)
    res = tls_record_parser.parse_payload(header, "stream#1", "client->server")
    assert res.parse_status == TLSRecordParseStatus.OVERSIZED_RECORD
    assert res.records[0].is_complete is False


def test_malformed_input_must_not_crash():
    """29. Arbitrary garbage bytes do not raise exceptions."""
    garbage = b"\xff\xff\x00\x02\xaa\xbb\xcc"
    res = tls_record_parser.parse_payload(garbage, "stream#1", "client->server")
    assert res.records[0].content_type == 255
    assert res.records[0].content_type_name == "UNKNOWN"


def test_regression_steps_1_to_11_unaffected():
    """30. Step 12 parsing preserves Step 8 ReconstructedStream lifecycle and contents."""
    stream = make_stream(
        client_payload=make_handshake_record(b"REGRESSION_CHECK"),
        server_payload=make_handshake_record(b"SERVER_RESP"),
    )
    c_res, s_res = tls_record_parser.parse_stream(stream)
    assert c_res.total_records == 1
    assert s_res.total_records == 1
    assert stream.lifecycle == StreamLifecycle.ESTABLISHED


# ==========================================================
# 5. DEDICATED TCP SEQUENCE GAP REGRESSION TESTS
# ==========================================================

def test_gap_exists_after_complete_tls_record():
    """31. Gap exists AFTER a complete TLS record: record valid, gap exposed, no disruption."""
    payload = make_handshake_record(b"COMPLETE_DATA")
    res = tls_record_parser.parse_payload(
        payload=payload,
        stream_id="stream#gap_after",
        direction="client->server",
        has_unresolved_gaps=True,
        gaps=[SequenceGap(start_seq=100 + len(payload), end_seq=200, gap_bytes=50)],
    )
    assert res.total_records == 1
    assert res.records[0].is_complete is True
    assert res.records[0].parse_status == TLSRecordParseStatus.OK
    assert res.has_unresolved_gaps is True
    assert res.has_gap_disruption is False
    assert res.parse_status == TLSRecordParseStatus.CLEAN_EOF


def test_gap_occurs_inside_tls_record_payload():
    """32. Gap occurs inside TLS record payload: GAP_DISRUPTION, no fabricated bytes."""
    header = struct.pack(">BHH", 22, 0x0303, 100)  # Declared length: 100 bytes
    partial_payload = b"A" * 30                     # Only 30 contiguous bytes received
    res = tls_record_parser.parse_payload(
        payload=header + partial_payload,
        stream_id="stream#gap_in_payload",
        direction="client->server",
        has_unresolved_gaps=True,
    )
    assert res.total_records == 1
    rec = res.records[0]
    assert rec.is_complete is False
    assert rec.declared_length == 100
    assert rec.payload_length == 30
    assert rec.payload == partial_payload
    assert rec.parse_status == TLSRecordParseStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True
    assert res.parse_status == TLSRecordParseStatus.GAP_DISRUPTION


def test_gap_occurs_inside_tls_record_header():
    """33. Gap occurs inside TLS record header: GAP_DISRUPTION, no fabricated header fields."""
    partial_header = b"\x16\x03\x03"  # Only 3 bytes of header present
    res = tls_record_parser.parse_payload(
        payload=partial_header,
        stream_id="stream#gap_in_header",
        direction="client->server",
        has_unresolved_gaps=True,
    )
    assert res.total_records == 1
    rec = res.records[0]
    assert rec.is_complete is False
    assert rec.declared_length == 0
    assert rec.payload == partial_header
    assert rec.parse_status == TLSRecordParseStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True
    assert res.parse_status == TLSRecordParseStatus.GAP_DISRUPTION


def test_multiple_records_first_complete_second_crosses_gap():
    """34. Multiple records where first is complete and second crosses a gap."""
    rec1 = make_handshake_record(b"RECORD_1")
    rec2_hdr = struct.pack(">BHH", 23, 0x0303, 50)  # Declared 50 bytes
    rec2_partial = b"PARTIAL_REC2"                  # 12 contiguous bytes
    payload = rec1 + rec2_hdr + rec2_partial

    res = tls_record_parser.parse_payload(
        payload=payload,
        stream_id="stream#multi_gap",
        direction="client->server",
        has_unresolved_gaps=True,
    )
    assert res.total_records == 2
    assert res.records[0].is_complete is True
    assert res.records[0].parse_status == TLSRecordParseStatus.OK
    assert res.records[1].is_complete is False
    assert res.records[1].parse_status == TLSRecordParseStatus.GAP_DISRUPTION
    assert res.records[1].payload_length == len(rec2_partial)
    assert res.has_gap_disruption is True
    assert res.parse_status == TLSRecordParseStatus.GAP_DISRUPTION


def test_gap_before_first_record_aborts_cleanly():
    """35. Gap occurs before contiguous bytes begin: aborts without parsing non-contiguous data."""
    frag = StreamFragment(
        start_seq=500,
        data=make_handshake_record(b"POST_GAP"),
        is_initial_contiguous=False,
    )
    res = tls_record_parser.parse_payload(
        payload=b"",
        stream_id="stream#gap_before",
        direction="client->server",
        fragments=[frag],
        has_unresolved_gaps=True,
    )
    assert res.total_records == 0
    assert res.has_gap_disruption is True
    assert res.parse_status == TLSRecordParseStatus.GAP_DISRUPTION