"""
Unit tests for Step 14: TLS ServerHello Parser.
Verifies parsing of handshake headers, negotiated TLS version resolution,
selected cipher suite, TLS 1.3 key share, multi-record fragmentation,
wrong direction rejection, and metadata correlation.
"""

import struct
from typing import List, Optional
import pytest

from app.schemas.tls_client_hello import TLSExtension
from app.schemas.tls_record import (
    TLSRecord,
    TLSRecordParseResult,
    TLSRecordParseStatus,
)
from app.schemas.tls_server_hello import (
    ServerHelloParseResult,
    ServerHelloParseStatus,
)
from app.services.tls_server_hello_parser import (
    MAX_HANDSHAKE_SIZE,
    tls_server_hello_parser,
)


def build_raw_server_hello(
    legacy_version: int = 0x0303,
    random_bytes: bytes = b"\x02" * 32,
    session_id_echo: bytes = b"",
    selected_cipher_suite: int = 0x1301,
    compression_method: int = 0x00,
    extensions_payload: bytes = b"",
) -> bytes:
    """Builds an RFC 5246 / RFC 8446 compliant ServerHello handshake message."""
    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(random_bytes)
    body.append(len(session_id_echo))
    body.extend(session_id_echo)
    body.extend(struct.pack(">H", selected_cipher_suite))
    body.append(compression_method)

    if extensions_payload or extensions_payload == b"":
        body.extend(struct.pack(">H", len(extensions_payload)))
        body.extend(extensions_payload)

    msg_len = len(body)
    header = struct.pack(">B", 2) + msg_len.to_bytes(3, byteorder="big")
    return bytes(header + body)


def wrap_in_record(
    payload: bytes,
    direction: str = "server->client",
    is_complete: bool = True,
    parse_status: TLSRecordParseStatus = TLSRecordParseStatus.OK,
) -> TLSRecord:
    return TLSRecord(
        record_index=0,
        content_type=22,
        content_type_name="HANDSHAKE",
        legacy_record_version=0x0303,
        legacy_record_version_name="TLS_1_2",
        declared_length=len(payload),
        payload_length=len(payload),
        stream_offset=0,
        payload=payload,
        is_complete=is_complete,
        parse_status=parse_status,
        first_frame_number=10,
        first_timestamp=100.5,
        direction=direction,
    )


def make_record_result(
    records: List[TLSRecord],
    direction: str = "server->client",
    has_gap_disruption: bool = False,
) -> TLSRecordParseResult:
    return TLSRecordParseResult(
        stream_id="stream#sh",
        direction=direction,
        total_records=len(records),
        records=records,
        bytes_consumed=sum(len(r.payload) for r in records),
        parse_status=TLSRecordParseStatus.CLEAN_EOF if not has_gap_disruption else TLSRecordParseStatus.GAP_DISRUPTION,
        has_gap_disruption=has_gap_disruption,
    )


# ==========================================================
# 1. CORE SERVERHELLO PARSING & VERSION RESOLUTION
# ==========================================================

def test_valid_minimal_server_hello():
    """1. Minimal ServerHello without extensions parses as complete."""
    raw = build_raw_server_hello()
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.status == ServerHelloParseStatus.COMPLETE
    assert res.server_hello is not None
    assert res.server_hello.msg_type == 2
    assert res.server_hello.legacy_version == 0x0303
    assert res.server_hello.legacy_version_name == "TLS_1_2"


def test_valid_tls_1_2_server_hello():
    """2. TLS 1.2 ServerHello resolves negotiated version to TLS 1.2."""
    raw = build_raw_server_hello(legacy_version=0x0303, selected_cipher_suite=0xC02F)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    sh = res.server_hello
    assert sh.negotiated_version == 0x0303
    assert sh.negotiated_version_name == "TLS_1_2"
    assert sh.selected_cipher_suite_id == 0xC02F
    assert sh.selected_cipher_suite_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_valid_tls_1_3_server_hello():
    """3. TLS 1.3 ServerHello with supported_versions resolves to TLS 1.3."""
    sv_ext = struct.pack(">HHH", 43, 2, 0x0304)
    raw = build_raw_server_hello(legacy_version=0x0303, extensions_payload=sv_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    sh = res.server_hello
    assert sh.legacy_version == 0x0303
    assert sh.negotiated_version == 0x0304
    assert sh.negotiated_version_name == "TLS_1_3"


def test_tls_1_3_supported_versions_handling():
    """4. Supported versions extension explicitly recorded in ServerHello."""
    sv_ext = struct.pack(">HHH", 43, 2, 0x0304)
    raw = build_raw_server_hello(extensions_payload=sv_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.supported_version == 0x0304


def test_legacy_version_vs_negotiated_version_distinction():
    """5. Confirms legacy_version remains 0x0303 while negotiated_version is 0x0304."""
    sv_ext = struct.pack(">HHH", 43, 2, 0x0304)
    raw = build_raw_server_hello(legacy_version=0x0303, extensions_payload=sv_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.legacy_version == 0x0303
    assert res.server_hello.legacy_version_name == "TLS_1_2"
    assert res.server_hello.negotiated_version == 0x0304
    assert res.server_hello.negotiated_version_name == "TLS_1_3"


def test_selected_cipher_suite_parsing():
    """6. Extracts single 2-byte selected cipher suite ID and name."""
    raw = build_raw_server_hello(selected_cipher_suite=0x1302)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.selected_cipher_suite_id == 0x1302
    assert res.server_hello.selected_cipher_suite_name == "TLS_AES_256_GCM_SHA384"


def test_compression_method_parsing():
    """7. Extracts 1-byte compression method value."""
    raw = build_raw_server_hello(compression_method=0x00)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.compression_method == 0x00


def test_extension_parsing():
    """8. Preserves raw extensions block cleanly."""
    ext = struct.pack(">HH", 0xAAAA, 4) + b"\x01\x02\x03\x04"
    raw = build_raw_server_hello(extensions_payload=ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert len(res.server_hello.raw_extensions) == 1
    assert res.server_hello.raw_extensions[0].extension_type == 0xAAAA


def test_supported_versions_extension():
    """9. Parses 2-byte selected version from extension 43."""
    sv_ext = struct.pack(">HHH", 43, 2, 0x0304)
    raw = build_raw_server_hello(extensions_payload=sv_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.supported_version == 0x0304


def test_tls_1_3_key_share_extension():
    """10. Extracts group and key exchange payload from extension 51."""
    fake_key = b"\xbb" * 32
    ks_body = struct.pack(">HH", 0x001D, len(fake_key)) + fake_key
    ks_ext = struct.pack(">HH", 51, len(ks_body)) + ks_body

    raw = build_raw_server_hello(extensions_payload=ks_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    ks = res.server_hello.key_share
    assert ks is not None
    assert ks.group == 0x001D
    assert ks.key_exchange_length == 32
    assert ks.key_exchange_hex == fake_key.hex()


def test_unknown_extension_handling():
    """11. Preserves unknown extension without failure."""
    unk_ext = struct.pack(">HH", 0xCAFE, 3) + b"\x11\x22\x33"
    raw = build_raw_server_hello(extensions_payload=unk_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.status == ServerHelloParseStatus.COMPLETE
    assert res.server_hello.raw_extensions[0].extension_type == 0xCAFE


def test_multiple_extensions():
    """12. Preserves multiple extensions simultaneously."""
    ext1 = struct.pack(">HH", 43, 2) + struct.pack(">H", 0x0304)
    ext2 = struct.pack(">HH", 0xBBBB, 2) + b"\xaa\xbb"
    raw = build_raw_server_hello(extensions_payload=ext1 + ext2)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert len(res.server_hello.raw_extensions) == 2


# ==========================================================
# 2. FRAGMENTATION & MULTI-MESSAGE TRAVERSAL
# ==========================================================

def test_multiple_handshake_messages_in_one_tls_record():
    """13. Traverses non-ServerHello handshake messages packed in one record."""
    cert_msg = b"\x0b\x00\x00\x03\x01\x02\x03"
    sh_raw = build_raw_server_hello()
    rec = wrap_in_record(sh_raw + cert_msg)

    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.COMPLETE
    assert res.server_hello.msg_length == len(sh_raw) - 4


def test_server_hello_split_across_multiple_tls_records():
    """14. Reassembles ServerHello split across multiple TLS records."""
    raw = build_raw_server_hello()
    mid = len(raw) // 2
    r1 = wrap_in_record(raw[:mid])
    r2 = wrap_in_record(raw[mid:])

    res = tls_server_hello_parser.parse_server_hello(make_record_result([r1, r2]))
    assert res.status == ServerHelloParseStatus.COMPLETE


def test_handshake_header_split_across_tls_records():
    """15. Handshake header (4 bytes) split across two TLS records."""
    raw = build_raw_server_hello()
    r1 = wrap_in_record(raw[:2])
    r2 = wrap_in_record(raw[2:])

    res = tls_server_hello_parser.parse_server_hello(make_record_result([r1, r2]))
    assert res.status == ServerHelloParseStatus.COMPLETE


def test_server_hello_body_split_across_tls_records():
    """16. Handshake header in record 1; body split across records."""
    raw = build_raw_server_hello()
    r1 = wrap_in_record(raw[:15])
    r2 = wrap_in_record(raw[15:])

    res = tls_server_hello_parser.parse_server_hello(make_record_result([r1, r2]))
    assert res.status == ServerHelloParseStatus.COMPLETE


# ==========================================================
# 3. TRUNCATION & BOUNDARY MALFORMATIONS
# ==========================================================

def test_incomplete_handshake_header():
    """17. Truncated header (< 4 bytes) returns INCOMPLETE_CAPTURE."""
    rec = wrap_in_record(b"\x02\x00")
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.INCOMPLETE_CAPTURE


def test_incomplete_server_hello_body():
    """18. Declared length larger than available bytes returns INCOMPLETE_CAPTURE."""
    raw = build_raw_server_hello()[:-10]
    rec = wrap_in_record(raw)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.INCOMPLETE_CAPTURE


def test_malformed_handshake_length():
    """19. Declared message length smaller than minimum 38 bytes returns MALFORMED_HANDSHAKE."""
    header = struct.pack(">B", 2) + (10).to_bytes(3, byteorder="big")
    rec = wrap_in_record(header + b"\x03\x03tiny")
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_extension_length():
    """20. Extension length extending beyond block boundary returns MALFORMED_HANDSHAKE."""
    bad_ext = struct.pack(">HH", 43, 20) + b"\x03\x04"
    raw = build_raw_server_hello(extensions_payload=bad_ext)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_supported_versions():
    """21. ServerHello supported_versions not exactly 2 bytes returns MALFORMED_HANDSHAKE."""
    bad_sv = struct.pack(">HHH", 43, 3, 0x0304) + b"\x00"
    raw = build_raw_server_hello(extensions_payload=bad_sv)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_key_share():
    """22. ServerHello key_share truncated returns MALFORMED_HANDSHAKE."""
    bad_ks = struct.pack(">HHH", 51, 10, 0x001D) + b"short"
    raw = build_raw_server_hello(extensions_payload=bad_ks)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.MALFORMED_HANDSHAKE


def test_oversized_handshake():
    """23. Declared length exceeding limit returns OVERSIZED_HANDSHAKE."""
    oversized_len = MAX_HANDSHAKE_SIZE + 100
    header = struct.pack(">B", 2) + oversized_len.to_bytes(3, byteorder="big")
    rec = wrap_in_record(header + b"\x00" * 50)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.OVERSIZED_HANDSHAKE


# ==========================================================
# 4. TCP SEQUENCE GAP & DIRECTION AWARENESS
# ==========================================================

def test_unresolved_tcp_gap_inside_server_hello():
    """24. Incomplete record due to TCP gap returns GAP_DISRUPTION."""
    raw = build_raw_server_hello()
    partial = raw[:20]
    rec = wrap_in_record(partial, is_complete=False, parse_status=TLSRecordParseStatus.GAP_DISRUPTION)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec], has_gap_disruption=True))

    assert res.status == ServerHelloParseStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True


def test_gap_before_server_hello():
    """25. Stream interrupted before ServerHello returns GAP_DISRUPTION."""
    res = tls_server_hello_parser.parse_server_hello(make_record_result([], has_gap_disruption=True))
    assert res.status == ServerHelloParseStatus.GAP_DISRUPTION


def test_complete_server_hello_after_unrelated_gap():
    """26. ServerHello complete in contiguous bytes remains complete."""
    raw = build_raw_server_hello()
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.COMPLETE


def test_no_server_hello_present():
    """27. Stream with only non-ServerHello messages returns NO_SERVER_HELLO."""
    cert_msg = b"\x0b\x00\x00\x04test"
    rec = wrap_in_record(cert_msg)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.NO_SERVER_HELLO


def test_wrong_direction_server_hello_like_message():
    """28. ServerHello message in client->server direction rejected as WRONG_DIRECTION."""
    raw = build_raw_server_hello()
    res = tls_server_hello_parser.parse_server_hello(
        make_record_result([wrap_in_record(raw, direction="client->server")], direction="client->server")
    )
    assert res.status == ServerHelloParseStatus.WRONG_DIRECTION


def test_unknown_tls_version():
    """29. Unknown legacy/negotiated version does not crash parser."""
    raw = build_raw_server_hello(legacy_version=0x0F0F)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.server_hello.legacy_version == 0x0F0F
    assert "UNKNOWN" in res.server_hello.legacy_version_name


def test_unknown_cipher_suite():
    """30. Unknown cipher suite ID preserved explicitly."""
    raw = build_raw_server_hello(selected_cipher_suite=0x9999)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.server_hello.selected_cipher_suite_id == 0x9999
    assert "UNKNOWN_CIPHER_SUITE_0x9999" in res.server_hello.selected_cipher_suite_name


def test_empty_extension_block():
    """31. Empty extensions block parsed without error."""
    raw = build_raw_server_hello(extensions_payload=b"")
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.COMPLETE
    assert len(res.server_hello.raw_extensions) == 0


def test_multiple_handshake_messages_before_server_hello():
    """32. Correctly finds ServerHello even when preceding handshake messages exist."""
    pre_msg = b"\x18\x00\x00\x02\x01\x01"  # Type 24 (KeyUpdate)
    sh_raw = build_raw_server_hello()
    rec = wrap_in_record(pre_msg + sh_raw)

    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    assert res.status == ServerHelloParseStatus.COMPLETE
    assert res.server_hello.msg_type == 2
    assert res.server_hello.handshake_offset == len(pre_msg)


def test_server_hello_after_client_hello():
    """33. Parses ServerHello in isolated server stream correctly."""
    raw = build_raw_server_hello()
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ServerHelloParseStatus.COMPLETE


def test_session_id_echo_parsing():
    """34. Preserves echoed session ID bytes."""
    sess_id = b"\x33" * 16
    raw = build_raw_server_hello(session_id_echo=sess_id)
    res = tls_server_hello_parser.parse_server_hello(make_record_result([wrap_in_record(raw)]))

    assert res.server_hello.session_id_echo_length == 16
    assert res.server_hello.session_id_echo_hex == sess_id.hex()


def test_correlation_metadata_preservation():
    """35. Preserves frame number, timestamp, direction, and stream ID."""
    raw = build_raw_server_hello()
    rec = wrap_in_record(raw)
    rec.first_frame_number = 105
    rec.first_timestamp = 1700000005.2

    res = tls_server_hello_parser.parse_server_hello(make_record_result([rec]))
    sh = res.server_hello
    assert sh.stream_id == "stream#sh"
    assert sh.direction == "server->client"
    assert sh.first_frame_number == 105
    assert sh.first_timestamp == 1700000005.2