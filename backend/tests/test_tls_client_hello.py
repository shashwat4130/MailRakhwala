"""
Unit tests for Step 13: TLS ClientHello Parser.
Verifies parsing of handshake headers, client offerings, recognized extensions,
multi-record fragmentation, TCP gap disruptions, and strict length bounding.
"""

import struct
from typing import List, Optional
import pytest

from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)
from app.schemas.tls_client_hello import (
    ClientHelloParseResult,
    ClientHelloParseStatus,
)
from app.schemas.tls_record import (
    TLSRecord,
    TLSRecordContentType,
    TLSRecordParseResult,
    TLSRecordParseStatus,
)
from app.services.tls_client_hello_parser import (
    MAX_HANDSHAKE_SIZE,
    tls_client_hello_parser,
)


def build_raw_client_hello(
    legacy_version: int = 0x0303,
    random_bytes: bytes = b"\x01" * 32,
    session_id: bytes = b"",
    cipher_suites: Optional[List[int]] = None,
    compression_methods: Optional[List[int]] = None,
    extensions_payload: bytes = b"",
) -> bytes:
    """Builds an RFC 5246 / RFC 8446 compliant ClientHello handshake message."""
    if cipher_suites is None:
        cipher_suites = [0x1301, 0x1302, 0xC02B]  # TLS_AES_128_GCM_SHA256, etc.
    if compression_methods is None:
        compression_methods = [0x00]

    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(random_bytes)
    body.append(len(session_id))
    body.extend(session_id)

    body.extend(struct.pack(">H", len(cipher_suites) * 2))
    for cs in cipher_suites:
        body.extend(struct.pack(">H", cs))

    body.append(len(compression_methods))
    body.extend(bytes(compression_methods))

    if extensions_payload or extensions_payload == b"":
        body.extend(struct.pack(">H", len(extensions_payload)))
        body.extend(extensions_payload)

    msg_len = len(body)
    header = struct.pack(">B", 1) + msg_len.to_bytes(3, byteorder="big")
    return bytes(header + body)


def wrap_in_record(payload: bytes, is_complete: bool = True, parse_status: TLSRecordParseStatus = TLSRecordParseStatus.OK) -> TLSRecord:
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
        first_frame_number=1,
        first_timestamp=100.0,
        direction="client->server",
    )


def make_record_result(records: List[TLSRecord], has_gap_disruption: bool = False) -> TLSRecordParseResult:
    return TLSRecordParseResult(
        stream_id="stream#ch",
        direction="client->server",
        total_records=len(records),
        records=records,
        bytes_consumed=sum(len(r.payload) for r in records),
        parse_status=TLSRecordParseStatus.CLEAN_EOF if not has_gap_disruption else TLSRecordParseStatus.GAP_DISRUPTION,
        has_gap_disruption=has_gap_disruption,
    )


# ==========================================================
# 1. CORE CLIENTHELLO PARSING & EXTENSIONS
# ==========================================================

def test_valid_minimal_client_hello():
    """1. Valid minimal ClientHello without extensions."""
    raw = build_raw_client_hello()
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))

    assert res.status == ClientHelloParseStatus.COMPLETE
    assert res.client_hello is not None
    assert res.client_hello.legacy_version == 0x0303
    assert res.client_hello.legacy_version_name == "TLS_1_2"
    assert len(res.client_hello.cipher_suite_ids) == 3


def test_valid_tls_1_2_style_client_hello():
    """2. Valid TLS 1.2-style ClientHello with SNI and signature algorithms."""
    # Build SNI extension (Type 0)
    host = b"mail.example.org"
    sni_data = struct.pack(">HBH", len(host) + 3, 0, len(host)) + host
    sni_ext = struct.pack(">HH", 0, len(sni_data)) + sni_data

    # Build SigAlgs extension (Type 13)
    sig_data = struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804)
    sig_ext = struct.pack(">HH", 13, len(sig_data)) + sig_data

    raw = build_raw_client_hello(extensions_payload=sni_ext + sig_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))

    assert res.status == ClientHelloParseStatus.COMPLETE
    ch = res.client_hello
    assert ch.server_name == "mail.example.org"
    assert ch.signature_algorithms == [0x0403, 0x0804]


def test_valid_tls_1_3_client_hello_with_supported_versions():
    """3. Valid TLS 1.3 ClientHello with supported_versions (Type 43)."""
    # supported_versions (1 byte length + 2 bytes per version)
    sv_data = bytes([4]) + struct.pack(">HH", 0x0304, 0x0303)
    sv_ext = struct.pack(">HH", 43, len(sv_data)) + sv_data

    raw = build_raw_client_hello(extensions_payload=sv_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))

    assert res.status == ClientHelloParseStatus.COMPLETE
    ch = res.client_hello
    assert ch.supported_versions == [0x0304, 0x0303]


def test_legacy_version_vs_supported_versions_distinction():
    """4. Confirms legacy_version remains 0x0303 while supported_versions exposes 0x0304."""
    sv_data = bytes([2]) + struct.pack(">H", 0x0304)
    sv_ext = struct.pack(">HH", 43, len(sv_data)) + sv_data

    raw = build_raw_client_hello(legacy_version=0x0303, extensions_payload=sv_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))

    ch = res.client_hello
    assert ch.legacy_version == 0x0303
    assert ch.supported_versions == [0x0304]


def test_cipher_suite_parsing():
    """5. Preserves all 2-byte cipher suite IDs in order."""
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009E]
    raw = build_raw_client_hello(cipher_suites=ciphers)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))

    assert res.client_hello.cipher_suite_ids == ciphers


def test_sni_parsing():
    """6. Extracts DNS hostname from SNI extension."""
    host = b"imap.mailrakhwala.internal"
    sni_data = struct.pack(">HBH", len(host) + 3, 0, len(host)) + host
    sni_ext = struct.pack(">HH", 0, len(sni_data)) + sni_data

    raw = build_raw_client_hello(extensions_payload=sni_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.server_name == "imap.mailrakhwala.internal"


def test_alpn_parsing():
    """7. Extracts protocol list from ALPN extension (Type 16)."""
    alpn_body = bytes([4]) + b"smtp" + bytes([8]) + b"http/1.1"
    alpn_data = struct.pack(">H", len(alpn_body)) + alpn_body
    alpn_ext = struct.pack(">HH", 16, len(alpn_data)) + alpn_data

    raw = build_raw_client_hello(extensions_payload=alpn_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.alpn_protocols == ["smtp", "http/1.1"]


def test_supported_groups_parsing():
    """8. Extracts elliptic curve / DH group IDs from extension 10."""
    sg_body = struct.pack(">H", 4) + struct.pack(">HH", 0x001D, 0x0017)  # x25519, secp256r1
    sg_ext = struct.pack(">HH", 10, len(sg_body)) + sg_body

    raw = build_raw_client_hello(extensions_payload=sg_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.supported_groups == [0x001D, 0x0017]


def test_signature_algorithms_parsing():
    """9. Extracts offered signature algorithms from extension 13."""
    sa_body = struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804)
    sa_ext = struct.pack(">HH", 13, len(sa_body)) + sa_body

    raw = build_raw_client_hello(extensions_payload=sa_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.signature_algorithms == [0x0403, 0x0804]


def test_key_share_parsing():
    """10. Extracts KeyShareEntry parameters from extension 51."""
    fake_key = b"\xaa" * 32
    ks_entry = struct.pack(">HH", 0x001D, len(fake_key)) + fake_key
    ks_body = struct.pack(">H", len(ks_entry)) + ks_entry
    ks_ext = struct.pack(">HH", 51, len(ks_body)) + ks_body

    raw = build_raw_client_hello(extensions_payload=ks_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert len(res.client_hello.key_shares) == 1
    assert res.client_hello.key_shares[0].group == 0x001D
    assert res.client_hello.key_shares[0].key_exchange_length == 32
    assert res.client_hello.key_shares[0].key_exchange_hex == fake_key.hex()


def test_unknown_extension_handling():
    """11. Preserves unknown extension ID and data safely."""
    unk_data = b"\x12\x34\x56"
    unk_ext = struct.pack(">HH", 0xF00D, len(unk_data)) + unk_data

    raw = build_raw_client_hello(extensions_payload=unk_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.COMPLETE
    assert len(res.client_hello.raw_extensions) == 1
    assert res.client_hello.raw_extensions[0].extension_type == 0xF00D


def test_multiple_extensions():
    """12. Preserves multiple concurrent extensions."""
    ext1 = struct.pack(">HH", 0xAAAA, 2) + b"\x01\x02"
    ext2 = struct.pack(">HH", 0xBBBB, 2) + b"\x03\x04"

    raw = build_raw_client_hello(extensions_payload=ext1 + ext2)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert len(res.client_hello.raw_extensions) == 2


# ==========================================================
# 2. FRAGMENTATION & MULTI-RECORD TRAVERSAL
# ==========================================================

def test_multiple_handshake_messages_in_one_tls_record():
    """13. Multiple handshake messages packed into one TLS record payload."""
    ch_raw = build_raw_client_hello()
    other_msg = b"\x02\x00\x00\x02\x01\x01"  # Trailing message
    rec = wrap_in_record(ch_raw + other_msg)

    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec]))
    assert res.status == ClientHelloParseStatus.COMPLETE
    assert res.client_hello.msg_length == len(ch_raw) - 4


def test_client_hello_split_across_multiple_tls_records():
    """14. ClientHello split across two consecutive Handshake TLS records."""
    raw = build_raw_client_hello()
    mid = len(raw) // 2
    r1 = wrap_in_record(raw[:mid])
    r2 = wrap_in_record(raw[mid:])

    res = tls_client_hello_parser.parse_client_hello(make_record_result([r1, r2]))
    assert res.status == ClientHelloParseStatus.COMPLETE
    assert res.client_hello.msg_length == len(raw) - 4


def test_handshake_header_split_across_tls_records():
    """15. Handshake header (4 bytes) split across two TLS records."""
    raw = build_raw_client_hello()
    r1 = wrap_in_record(raw[:2])
    r2 = wrap_in_record(raw[2:])

    res = tls_client_hello_parser.parse_client_hello(make_record_result([r1, r2]))
    assert res.status == ClientHelloParseStatus.COMPLETE


def test_client_hello_body_split_across_tls_records():
    """16. Handshake header in record 1; body split across record 1 and record 2."""
    raw = build_raw_client_hello()
    r1 = wrap_in_record(raw[:10])
    r2 = wrap_in_record(raw[10:])

    res = tls_client_hello_parser.parse_client_hello(make_record_result([r1, r2]))
    assert res.status == ClientHelloParseStatus.COMPLETE


# ==========================================================
# 3. TRUNCATION & BOUNDARY MALFORMATIONS
# ==========================================================

def test_incomplete_handshake_header():
    """17. Truncated handshake header (< 4 bytes) marks INCOMPLETE_CAPTURE."""
    rec = wrap_in_record(b"\x01\x00")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec]))
    assert res.status == ClientHelloParseStatus.INCOMPLETE_CAPTURE


def test_incomplete_client_hello_body():
    """18. Declared length larger than available bytes marks INCOMPLETE_CAPTURE."""
    raw = build_raw_client_hello()[:-10]
    rec = wrap_in_record(raw)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec]))
    assert res.status == ClientHelloParseStatus.INCOMPLETE_CAPTURE


def test_malformed_handshake_length():
    """19. Truncated body (< 34 bytes) marks MALFORMED_HANDSHAKE."""
    header = struct.pack(">B", 1) + (10).to_bytes(3, byteorder="big")
    rec = wrap_in_record(header + b"\x03\x03tiny")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_extension_length():
    """20. Extension length exceeding extensions block marks MALFORMED_HANDSHAKE."""
    bad_ext = struct.pack(">HH", 0, 50) + b"too_short"
    raw = build_raw_client_hello(extensions_payload=bad_ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_sni():
    """21. Truncated SNI length marks MALFORMED_HANDSHAKE."""
    bad_sni = struct.pack(">HBH", 20, 0, 30) + b"short"
    ext = struct.pack(">HH", 0, len(bad_sni)) + bad_sni
    raw = build_raw_client_hello(extensions_payload=ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_alpn():
    """22. ALPN string length exceeding block marks MALFORMED_HANDSHAKE."""
    bad_alpn = struct.pack(">H", 5) + bytes([10]) + b"abc"
    ext = struct.pack(">HH", 16, len(bad_alpn)) + bad_alpn
    raw = build_raw_client_hello(extensions_payload=ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_supported_versions():
    """23. Odd length for 2-byte versions marks MALFORMED_HANDSHAKE."""
    bad_sv = bytes([3]) + b"\x03\x04\x03"
    ext = struct.pack(">HH", 43, len(bad_sv)) + bad_sv
    raw = build_raw_client_hello(extensions_payload=ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


def test_malformed_key_share():
    """24. Truncated key share entry marks MALFORMED_HANDSHAKE."""
    bad_ks = struct.pack(">HHH", 20, 0x001D, 32) + b"too_short"
    ext = struct.pack(">HH", 51, len(bad_ks)) + bad_ks
    raw = build_raw_client_hello(extensions_payload=ext)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.MALFORMED_HANDSHAKE


# ==========================================================
# 4. TCP SEQUENCE GAP & RESOURCE BOUNDS
# ==========================================================

def test_unresolved_tcp_gap_inside_client_hello():
    """25. Incomplete record due to TCP gap flags GAP_DISRUPTION."""
    raw = build_raw_client_hello()
    partial = raw[:30]
    rec = wrap_in_record(partial, is_complete=False, parse_status=TLSRecordParseStatus.GAP_DISRUPTION)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec], has_gap_disruption=True))

    assert res.status == ClientHelloParseStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True


def test_gap_before_client_hello():
    """26. Stream interrupted before ClientHello begins returns GAP_DISRUPTION."""
    res = tls_client_hello_parser.parse_client_hello(make_record_result([], has_gap_disruption=True))
    assert res.status == ClientHelloParseStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True


def test_capture_ending_immediately_after_complete_client_hello():
    """27. Complete ClientHello parsed normally even if capture ends immediately."""
    raw = build_raw_client_hello()
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.COMPLETE


def test_oversized_handshake_message_handling():
    """28. Declared handshake message exceeding bound returns OVERSIZED_HANDSHAKE."""
    oversized_len = MAX_HANDSHAKE_SIZE + 100
    header = struct.pack(">B", 1) + oversized_len.to_bytes(3, byteorder="big")
    rec = wrap_in_record(header + b"\x00" * 100)

    res = tls_client_hello_parser.parse_client_hello(make_record_result([rec]))
    assert res.status == ClientHelloParseStatus.OVERSIZED_HANDSHAKE


def test_unknown_tls_version_handling():
    """29. Unknown/reserved legacy version does not fail."""
    raw = build_raw_client_hello(legacy_version=0x0A0A)
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.legacy_version == 0x0A0A
    assert "UNKNOWN" in res.client_hello.legacy_version_name


def test_unknown_cipher_suite_handling():
    """30. Unknown/custom cipher suite ID preserved without crashing."""
    raw = build_raw_client_hello(cipher_suites=[0xFFFF])
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.cipher_suite_ids == [0xFFFF]


def test_empty_extension_block():
    """31. Zero-length extension block handled gracefully."""
    raw = build_raw_client_hello(extensions_payload=b"")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.status == ClientHelloParseStatus.COMPLETE
    assert len(res.client_hello.raw_extensions) == 0


def test_no_sni():
    """32. Absence of SNI leaves server_name as None."""
    raw = build_raw_client_hello(extensions_payload=b"")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.server_name is None


def test_no_alpn():
    """33. Absence of ALPN returns empty protocol list."""
    raw = build_raw_client_hello(extensions_payload=b"")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.alpn_protocols == []


def test_no_supported_versions():
    """34. Absence of extension 43 returns empty supported_versions list."""
    raw = build_raw_client_hello(extensions_payload=b"")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.supported_versions == []


def test_no_key_share():
    """35. Absence of key_share returns empty key_shares list."""
    raw = build_raw_client_hello(extensions_payload=b"")
    res = tls_client_hello_parser.parse_client_hello(make_record_result([wrap_in_record(raw)]))
    assert res.client_hello.key_shares == []