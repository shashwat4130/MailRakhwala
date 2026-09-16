"""
Tests for Step 09: Email Protocol Classification
Covers multi-signal classification, confidence scaling, false-positive protection,
gap awareness, directionality, and implicit TLS handling.
"""

from typing import List, Optional
import pytest

from app.schemas.protocol import ConfidenceLevel, EmailProtocol, SignalType
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    SequenceGap,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)
from app.services.protocol_classifier import protocol_classifier


def make_reconstructed_stream(
    stream_id: str = "10.0.0.1:50000<->10.0.0.2:25#gen1",
    client_ip: str = "10.0.0.1",
    client_port: int = 50000,
    server_ip: str = "10.0.0.2",
    server_port: int = 25,
    client_payload: bytes = b"",
    server_payload: bytes = b"",
    client_fragments: Optional[List[StreamFragment]] = None,
    server_fragments: Optional[List[StreamFragment]] = None,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
    has_unresolved_gaps: bool = False,
) -> ReconstructedStream:
    return ReconstructedStream(
        stream_id=stream_id,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        lifecycle=StreamLifecycle.ESTABLISHED,
        reconstruction_status=reconstruction_status,
        termination_reason=TerminationReason.END_OF_CAPTURE,
        client_payload=client_payload,
        server_payload=server_payload,
        client_fragments=client_fragments or [],
        server_fragments=server_fragments or [],
        has_unresolved_gaps=has_unresolved_gaps,
    )


def test_smtp_detected_from_banner_and_ehlo():
    stream = make_reconstructed_stream(
        server_port=25,
        server_payload=b"220 mail.example.com ESMTP Postfix\r\n",
        client_payload=b"EHLO client.example.com\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.HIGH
    assert "BANNER_SMTP_220" in result.matched_indicators
    assert "CMD_SMTP" in result.matched_indicators


def test_imap_detected_from_greeting_and_command():
    stream = make_reconstructed_stream(
        server_port=143,
        server_payload=b"* OK [CAPABILITY IMAP4rev1] Mail server ready\r\n",
        client_payload=b"A001 CAPABILITY\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.IMAP
    assert result.confidence == ConfidenceLevel.HIGH
    assert "BANNER_IMAP_OK" in result.matched_indicators
    assert "CMD_IMAP" in result.matched_indicators


def test_pop3_detected_from_banner_and_command():
    stream = make_reconstructed_stream(
        server_port=110,
        server_payload=b"+OK Dovecot ready.\r\n",
        client_payload=b"USER testuser\r\nPASS secret\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.POP3
    assert result.confidence == ConfidenceLevel.HIGH
    assert "BANNER_POP3_PLUS_OK" in result.matched_indicators
    assert "CMD_POP3" in result.matched_indicators


def test_smtp_port_only_inference_is_low_confidence():
    stream = make_reconstructed_stream(server_port=25, client_payload=b"", server_payload=b"")
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.LOW
    assert len(result.evidence) == 1
    assert result.evidence[0].signal_type == SignalType.PORT


def test_imap_port_only_inference_is_low_confidence():
    stream = make_reconstructed_stream(server_port=143, client_payload=b"", server_payload=b"")
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.IMAP
    assert result.confidence == ConfidenceLevel.LOW


def test_pop3_port_only_inference_is_low_confidence():
    stream = make_reconstructed_stream(server_port=110, client_payload=b"", server_payload=b"")
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.POP3
    assert result.confidence == ConfidenceLevel.LOW


def test_unknown_arbitrary_tcp_stream():
    stream = make_reconstructed_stream(
        server_port=8080,
        client_payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        server_payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.UNKNOWN
    assert result.confidence == ConfidenceLevel.UNKNOWN


def test_false_positive_protection_for_arbitrary_text_containing_keywords():
    stream = make_reconstructed_stream(
        server_port=8080,
        # Contains "HELO" and "LOGIN" embedded within arbitrary JSON text
        client_payload=b'{"action": "SAY_OHELO", "mode": "AUTO_LOGIN_USERID"}\n',
        server_payload=b'{"status": "OK_NOT_MAIL"}\n',
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.UNKNOWN
    assert result.confidence == ConfidenceLevel.UNKNOWN


def test_direction_aware_server_greeting():
    # Client mistakenly sending server greeting is rejected as invalid
    stream = make_reconstructed_stream(
        server_port=9999,
        client_payload=b"220 rogue banner from client\r\n",
        server_payload=b"",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.UNKNOWN


def test_direction_aware_client_command():
    # Server sending client commands is not credited as client command
    stream = make_reconstructed_stream(
        server_port=9999,
        client_payload=b"",
        server_payload=b"EHLO server.sent.this\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.UNKNOWN


def test_incomplete_stream_with_valid_indicator_before_gap():
    stream = make_reconstructed_stream(
        server_port=25,
        server_payload=b"220 mail.domain.test ESMTP\r\n",
        client_payload=b"EHLO client.test\r\n",
        reconstruction_status=ReconstructionStatus.INCOMPLETE,
        has_unresolved_gaps=True,
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    # Unresolved gaps downgrade HIGH confidence to MEDIUM
    assert result.confidence == ConfidenceLevel.MEDIUM
    assert result.has_unresolved_gaps is True


def test_classification_cannot_treat_post_gap_bytes_as_contiguous():
    # The command "EHLO" is split across an unresolved sequence gap
    stream = make_reconstructed_stream(
        server_port=25,
        client_payload=b"EH",  # Contiguous before gap
        client_fragments=[
            StreamFragment(start_seq=100, data=b"EH", is_initial_contiguous=True),
            StreamFragment(start_seq=120, data=b"LO\r\n", is_initial_contiguous=False),  # After gap
        ],
        reconstruction_status=ReconstructionStatus.INCOMPLETE,
        has_unresolved_gaps=True,
    )
    result = protocol_classifier.classify_stream(stream)

    # Must NOT stitch b"EH" and b"LO\r\n" across the gap
    assert "CMD_SMTP" not in result.matched_indicators
    # Port 25 alone provides LOW confidence
    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.LOW


def test_ambiguous_reconstruction_limits_confidence():
    stream = make_reconstructed_stream(
        server_port=25,
        server_payload=b"220 mail.example.com ESMTP\r\n",
        client_payload=b"EHLO myclient\r\n",
        reconstruction_status=ReconstructionStatus.AMBIGUOUS,
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.LOW


def test_implicit_tls_ports_handled_conservatively():
    # Encrypted/opaque traffic on port 465 (SMTPS) without parsing TLS
    stream = make_reconstructed_stream(
        server_port=465,
        client_payload=b"\x16\x03\x01\x00\xa5...",
        server_payload=b"\x16\x03\x03\x00\x50...",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.LOW
    assert result.is_tls_port_context is True
    assert "PORT_SMTP_465" in result.matched_indicators


def test_ipv6_stream_classification():
    stream = make_reconstructed_stream(
        client_ip="2001:db8::1",
        server_ip="2001:db8::2",
        server_port=587,
        server_payload=b"220 mail6.example.com ESMTP\r\n",
        client_payload=b"EHLO client6.test\r\n",
    )
    result = protocol_classifier.classify_stream(stream)

    assert result.protocol == EmailProtocol.SMTP
    assert result.confidence == ConfidenceLevel.HIGH


def test_multiple_streams_classified_independently():
    stream_smtp = make_reconstructed_stream(server_port=25, server_payload=b"220 mail.org ESMTP\r\n")
    stream_imap = make_reconstructed_stream(server_port=143, server_payload=b"* OK IMAP ready\r\n")

    res1 = protocol_classifier.classify_stream(stream_smtp)
    res2 = protocol_classifier.classify_stream(stream_imap)

    assert res1.protocol == EmailProtocol.SMTP
    assert res2.protocol == EmailProtocol.IMAP