"""
Unit tests for Step 16: Certificate Extraction.
Verifies extraction of raw DER certificates and ordered certificate chains,
handling of TLS 1.2 and TLS 1.3 framing, multi-record fragmentation,
TCP sequence gap disruptions, and malformed length boundaries.
"""

from typing import List, Optional
import pytest

from app.schemas.certificate_extraction import (
    CertificateExtractionStatus,
)
from app.schemas.tls_record import (
    TLSRecord,
    TLSRecordParseResult,
    TLSRecordParseStatus,
)
from app.services.certificate_extractor import (
    MAX_CERTIFICATE_SIZE,
    MAX_HANDSHAKE_SIZE,
    certificate_extractor,
)


def build_raw_certificate_handshake(
    der_certs: List[bytes],
    is_tls_13: bool = False,
    request_context: bytes = b"",
) -> bytes:
    """Constructs a deterministic TLS Certificate (0x0B) handshake message."""
    cert_list_body = bytearray()
    for cert in der_certs:
        cert_list_body.extend(len(cert).to_bytes(3, byteorder="big"))
        cert_list_body.extend(cert)
        if is_tls_13:
            cert_list_body.extend((0).to_bytes(2, byteorder="big"))  # 0 extensions

    body = bytearray()
    if is_tls_13:
        body.append(len(request_context))
        body.extend(request_context)

    body.extend(len(cert_list_body).to_bytes(3, byteorder="big"))
    body.extend(cert_list_body)

    msg_len = len(body)
    header = bytes([11]) + msg_len.to_bytes(3, byteorder="big")
    return bytes(header + body)


def wrap_in_record(
    payload: bytes,
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
        first_frame_number=101,
        first_timestamp=1700000000.0,
        direction="server->client",
    )


def make_record_result(
    records: List[TLSRecord],
    has_gap_disruption: bool = False,
) -> TLSRecordParseResult:
    return TLSRecordParseResult(
        stream_id="stream#cert_test",
        direction="server->client",
        total_records=len(records),
        records=records,
        bytes_consumed=sum(len(r.payload) for r in records),
        parse_status=TLSRecordParseStatus.CLEAN_EOF if not has_gap_disruption else TLSRecordParseStatus.GAP_DISRUPTION,
        has_gap_disruption=has_gap_disruption,
    )


# ==========================================================
# 1. CORE DER & CERTIFICATE CHAIN EXTRACTION
# ==========================================================

def test_single_der_certificate_extraction():
    """1. Extracts a single end-entity DER certificate cleanly."""
    fake_der = b"\x30\x82\x01\x00" + (b"\xab" * 252)
    raw = build_raw_certificate_handshake([fake_der])

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(raw)]))
    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 1
    cert0 = res.certificates[0]
    assert cert0.certificate_index == 0
    assert cert0.raw_der == fake_der
    assert cert0.der_length == len(fake_der)
    assert cert0.raw_der_hex == fake_der.hex()


def test_multiple_certificates_chain_ordering():
    """2. Preserves exact chain ordering across multiple certificates."""
    leaf_der = b"\x30\x82\x01\x11" + (b"\x01" * 100)
    intermediate_der = b"\x30\x82\x02\x22" + (b"\x02" * 150)
    root_der = b"\x30\x82\x03\x33" + (b"\x03" * 200)

    raw = build_raw_certificate_handshake([leaf_der, intermediate_der, root_der])
    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(raw)]))

    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 3
    assert res.certificates[0].certificate_index == 0
    assert res.certificates[0].raw_der == leaf_der
    assert res.certificates[1].certificate_index == 1
    assert res.certificates[1].raw_der == intermediate_der
    assert res.certificates[2].certificate_index == 2
    assert res.certificates[2].raw_der == root_der


def test_tls_1_3_certificate_extraction():
    """3. Parses TLS 1.3 certificate structure with request context and extensions."""
    cert_der = b"\x30\x82\x01\x00" + (b"\xbb" * 252)
    raw = build_raw_certificate_handshake([cert_der], is_tls_13=True, request_context=b"")

    res = certificate_extractor.extract_certificates(
        make_record_result([wrap_in_record(raw)]),
        is_tls_13=True,
    )
    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 1
    assert res.certificates[0].raw_der == cert_der


def test_empty_certificate_message():
    """4. Handles valid Certificate message containing zero certificates."""
    raw = build_raw_certificate_handshake([])
    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(raw)]))

    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 0
    assert len(res.certificates) == 0


def test_no_certificate_message_present():
    """5. Stream containing only non-Certificate messages returns NO_CERTIFICATE_MESSAGE."""
    other_handshake = bytes([2]) + (40).to_bytes(3, byteorder="big") + (b"\x00" * 40)
    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(other_handshake)]))

    assert res.status == CertificateExtractionStatus.NO_CERTIFICATE_MESSAGE


# ==========================================================
# 2. FRAGMENTATION & MULTI-RECORD TRAVERSAL
# ==========================================================

def test_certificate_split_across_multiple_records():
    """6. Reassembles Certificate handshake split across two TLS records."""
    fake_der = b"\x30\x82\x02\x00" + (b"\xcc" * 508)
    raw = build_raw_certificate_handshake([fake_der])
    mid = len(raw) // 2

    r1 = wrap_in_record(raw[:mid])
    r2 = wrap_in_record(raw[mid:])

    res = certificate_extractor.extract_certificates(make_record_result([r1, r2]))
    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 1
    assert res.certificates[0].raw_der == fake_der


def test_handshake_header_split_across_records():
    """7. Handshake header (4 bytes) split across two TLS records."""
    fake_der = b"\x30\x82\x01\x00" + (b"\xdd" * 100)
    raw = build_raw_certificate_handshake([fake_der])

    r1 = wrap_in_record(raw[:2])
    r2 = wrap_in_record(raw[2:])

    res = certificate_extractor.extract_certificates(make_record_result([r1, r2]))
    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.certificates[0].raw_der == fake_der


def test_multiple_handshake_messages_before_certificate():
    """8. Traverses ServerHello message to locate Certificate message in same record."""
    sh_msg = bytes([2]) + (38).to_bytes(3, byteorder="big") + (b"\x00" * 38)
    fake_der = b"\x30\x82\x01\x00" + (b"\xee" * 120)
    cert_msg = build_raw_certificate_handshake([fake_der])

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(sh_msg + cert_msg)]))
    assert res.status == CertificateExtractionStatus.COMPLETE
    assert res.total_certificates == 1
    assert res.certificates[0].raw_der == fake_der


# ==========================================================
# 3. TRUNCATION & BOUNDARY MALFORMATIONS
# ==========================================================

def test_truncated_handshake_header():
    """9. Handshake header truncated (< 4 bytes) returns INCOMPLETE_CAPTURE."""
    rec = wrap_in_record(bytes([11, 0]))
    res = certificate_extractor.extract_certificates(make_record_result([rec]))
    assert res.status == CertificateExtractionStatus.INCOMPLETE_CAPTURE


def test_truncated_certificate_payload():
    """10. Available bytes less than declared message length returns INCOMPLETE_CAPTURE."""
    fake_der = b"\x30\x82\x01\x00" + (b"\xff" * 200)
    raw = build_raw_certificate_handshake([fake_der])[:-50]

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(raw)]))
    assert res.status == CertificateExtractionStatus.INCOMPLETE_CAPTURE


def test_malformed_list_length():
    """11. Declared list length does not match available bytes -> MALFORMED_CERTIFICATE."""
    header = bytes([11]) + (20).to_bytes(3, byteorder="big")
    bad_list_len = (100).to_bytes(3, byteorder="big")  # 100 declared, only 17 available
    payload = header + bad_list_len + (b"\x00" * 17)

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(payload)]))
    assert res.status == CertificateExtractionStatus.MALFORMED_CERTIFICATE


def test_malformed_individual_certificate_length():
    """12. Individual cert length extends beyond list boundary -> MALFORMED_CERTIFICATE."""
    header = bytes([11]) + (20).to_bytes(3, byteorder="big")
    list_len = (17).to_bytes(3, byteorder="big")
    bad_cert_len = (50).to_bytes(3, byteorder="big")
    payload = header + list_len + bad_cert_len + (b"\x00" * 14)

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(payload)]))
    assert res.status == CertificateExtractionStatus.MALFORMED_CERTIFICATE


def test_oversized_handshake_message():
    """13. Handshake length exceeding MAX_HANDSHAKE_SIZE returns OVERSIZED_CERTIFICATE."""
    oversized = MAX_HANDSHAKE_SIZE + 100
    header = bytes([11]) + oversized.to_bytes(3, byteorder="big") + (b"\x00" * 100)

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(header)]))
    assert res.status == CertificateExtractionStatus.OVERSIZED_CERTIFICATE


def test_oversized_individual_certificate():
    """14. Individual certificate exceeding MAX_CERTIFICATE_SIZE returns OVERSIZED_CERTIFICATE."""
    oversized_cert_len = MAX_CERTIFICATE_SIZE + 50
    cert_list_body = oversized_cert_len.to_bytes(3, byteorder="big") + (b"\x00" * 200)
    body = len(cert_list_body).to_bytes(3, byteorder="big") + cert_list_body
    header = bytes([11]) + len(body).to_bytes(3, byteorder="big")

    res = certificate_extractor.extract_certificates(make_record_result([wrap_in_record(header + body)]))
    assert res.status == CertificateExtractionStatus.OVERSIZED_CERTIFICATE


# ==========================================================
# 4. GAPS, METADATA & ISOLATION
# ==========================================================

def test_unresolved_tcp_gap_disruption():
    """15. TCP sequence gap interrupting Certificate message returns GAP_DISRUPTION."""
    fake_der = b"\x30\x82\x01\x00" + (b"\xaa" * 100)
    raw = build_raw_certificate_handshake([fake_der])[:30]
    rec = wrap_in_record(raw, is_complete=False, parse_status=TLSRecordParseStatus.GAP_DISRUPTION)

    res = certificate_extractor.extract_certificates(make_record_result([rec], has_gap_disruption=True))
    assert res.status == CertificateExtractionStatus.GAP_DISRUPTION
    assert res.has_gap_disruption is True


def test_gap_before_certificate_message():
    """16. Stream interrupted by gap before Certificate message begins returns GAP_DISRUPTION."""
    res = certificate_extractor.extract_certificates(make_record_result([], has_gap_disruption=True))
    assert res.status == CertificateExtractionStatus.GAP_DISRUPTION


def test_metadata_and_traceability_preservation():
    """17. Preserves stream_id, frame number, timestamp, and byte offsets."""
    fake_der = b"\x30\x82\x01\x00" + (b"\x55" * 80)
    raw = build_raw_certificate_handshake([fake_der])
    rec = wrap_in_record(raw)
    rec.first_frame_number = 405
    rec.first_timestamp = 1700000405.8

    res = certificate_extractor.extract_certificates(make_record_result([rec]))
    cert = res.certificates[0]
    assert cert.stream_id == "stream#cert_test"
    assert cert.first_frame_number == 405
    assert cert.first_timestamp == 1700000405.8
    assert cert.der_length == len(fake_der)
    assert len(res.limitations) >= 2


def test_multiple_independent_streams_isolated():
    """18. Confirms independent extractions maintain stream isolation."""
    c1 = b"\x30\x82\x01\x00" + (b"\x11" * 50)
    c2 = b"\x30\x82\x01\x00" + (b"\x22" * 50)

    res1 = certificate_extractor.extract_certificates(
        TLSRecordParseResult(
            stream_id="stream#A",
            direction="server->client",
            records=[wrap_in_record(build_raw_certificate_handshake([c1]))],
        )
    )
    res2 = certificate_extractor.extract_certificates(
        TLSRecordParseResult(
            stream_id="stream#B",
            direction="server->client",
            records=[wrap_in_record(build_raw_certificate_handshake([c2]))],
        )
    )

    assert res1.stream_id == "stream#A"
    assert res2.stream_id == "stream#B"
    assert res1.certificates[0].raw_der == c1
    assert res2.certificates[0].raw_der == c2