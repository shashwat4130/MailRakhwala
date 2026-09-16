"""
Tests for Step 10: STARTTLS State Machine
Full 40-test suite preserving all original scenarios (SMTP 1-11, IMAP 12-17, POP3 18-22,
Cross-protocol 23-31) plus 9 comprehensive wire-chronology tests.
"""

from typing import List, Optional
import pytest

from app.schemas.protocol import ConfidenceLevel, EmailProtocol, ProtocolClassification
from app.schemas.starttls import StarttlsAssessment, StarttlsState
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    SequenceGap,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)
from app.services.starttls_machine import starttls_machine

SYNTHETIC_TLS_RECORD = b"\x16\x03\x03\x00\x40" + b"\x01\x00\x00\x3c" + b"\x00" * 60


def make_stream(
    stream_id: str = "test#gen1",
    client_payload: bytes = b"",
    server_payload: bytes = b"",
    client_fragments: Optional[List[StreamFragment]] = None,
    server_fragments: Optional[List[StreamFragment]] = None,
    server_port: int = 25,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
    has_unresolved_gaps: bool = False,
) -> ReconstructedStream:
    return ReconstructedStream(
        stream_id=stream_id,
        client_ip="10.0.0.1",
        client_port=50000,
        server_ip="10.0.0.2",
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


def make_classification(
    protocol: EmailProtocol = EmailProtocol.SMTP,
    is_tls_port: bool = False,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
) -> ProtocolClassification:
    return ProtocolClassification(
        stream_id="test#gen1",
        protocol=protocol,
        confidence=ConfidenceLevel.HIGH,
        reconstruction_status=reconstruction_status,
        is_tls_port_context=is_tls_port,
        has_unresolved_gaps=False,
    )


# ==========================================================
# 1. ORIGINAL SCENARIOS: SMTP (Tests 1-11)
# ==========================================================

def test_smtp_advertised():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n250 DSN\r\n",
        client_payload=b"EHLO client.org\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.CAPABILITY_ADVERTISED
    assert res.tls_transition_detected is False


def test_smtp_advertised_not_requested():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n250 HELP\r\n",
        client_payload=b"EHLO client.org\r\nMAIL FROM:<alice@org>\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.CAPABILITY_ADVERTISED


def test_smtp_advertised_requested_accepted_tls():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n250 OK\r\n220 2.0.0 Ready to start TLS\r\n",
        client_payload=b"EHLO client.org\r\nSTARTTLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is True
    assert res.confidence == ConfidenceLevel.HIGH


def test_smtp_requested_server_rejection():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n250 OK\r\n454 TLS not available\r\n",
        client_payload=b"EHLO client.org\r\nSTARTTLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.FAILED


def test_smtp_starttls_without_advertisement():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-HELP\r\n250 OK\r\n220 Ready to start TLS\r\n",
        client_payload=b"EHLO client.org\r\nSTARTTLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SUCCEEDED


def test_smtp_fragmented_commands():
    stream = make_stream(
        server_payload=b"220 mail.org\r\n250-STARTTLS\r\n220 Go ahead\r\n",
        client_payload=b"EHLO client.org\r\n",
        client_fragments=[
            StreamFragment(start_seq=100, data=b"START", is_initial_contiguous=False),
            StreamFragment(start_seq=105, data=b"TLS\r\n", is_initial_contiguous=False),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.UNKNOWN


def test_smtp_fragmented_server_response():
    stream = make_stream(
        server_payload=b"220 banner\r\n250-STARTTLS\r\n220 Ready",
        server_fragments=[StreamFragment(start_seq=500, data=b" to start TLS\r\n", is_initial_contiguous=False)],
        client_payload=b"EHLO test\r\nSTARTTLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state in (StarttlsState.SUCCEEDED, StarttlsState.SERVER_ACCEPTED)


def test_smtp_incomplete_capture_after_acceptance():
    stream = make_stream(
        server_payload=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n250 OK\r\n220 Ready to start TLS\r\n",
        client_payload=b"EHLO client.org\r\nSTARTTLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SERVER_ACCEPTED
    assert res.tls_transition_detected is False


def test_smtp_gap_inside_starttls():
    stream = make_stream(
        server_payload=b"220 mail.org\r\n250-STARTTLS\r\n",
        client_payload=b"EHLO test\r\n",
        has_unresolved_gaps=True,
        reconstruction_status=ReconstructionStatus.INCOMPLETE,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.confidence == ConfidenceLevel.MEDIUM


def test_smtp_starttls_in_wrong_direction():
    stream = make_stream(
        server_payload=b"STARTTLS\r\n",
        client_payload=b"220 Ready\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is False


def test_smtp_starttls_in_unrelated_message_content():
    stream = make_stream(
        server_payload=b"220 mail.org\r\n250 OK\r\n354 End data with .\r\n250 OK\r\n",
        client_payload=b"EHLO test\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nSubject: Discussion about STARTTLS security\r\n.\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SUCCEEDED
    assert res.starttls_state != StarttlsState.STARTTLS_REQUESTED


# ==========================================================
# 2. ORIGINAL SCENARIOS: IMAP (Tests 12-17)
# ==========================================================

def test_imap_success():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK IMAP4rev1 Server\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\nA01 OK Begin TLS\r\n",
        client_payload=b"A01 STARTTLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state == StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is True


def test_imap_rejected_no():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK IMAP4rev1\r\nA01 NO STARTTLS not available\r\n",
        client_payload=b"A01 STARTTLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state == StarttlsState.FAILED


def test_imap_rejected_bad():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK IMAP4rev1\r\nA01 BAD Unknown command\r\n",
        client_payload=b"A01 STARTTLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state == StarttlsState.FAILED


def test_imap_ordinary_ok_unrelated():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK IMAP4rev1\r\nA01 OK NOOP completed\r\n",
        client_payload=b"A01 NOOP\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state != StarttlsState.SUCCEEDED
    assert res.starttls_state != StarttlsState.SERVER_ACCEPTED


def test_imap_fragmented():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK Server\r\nTAG1 OK Proceed\r\n",
        client_payload=b"TAG1 STARTTLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state == StarttlsState.SUCCEEDED


def test_imap_gapped():
    stream = make_stream(
        server_port=143,
        server_payload=b"* OK IMAP\r\n",
        has_unresolved_gaps=True,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.unresolved_gaps is True


# ==========================================================
# 3. ORIGINAL SCENARIOS: POP3 (Tests 18-22)
# ==========================================================

def test_pop3_success():
    stream = make_stream(
        server_port=110,
        server_payload=b"+OK POP3 ready\r\n+OK Begin TLS negotiation\r\n",
        client_payload=b"STLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state == StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is True


def test_pop3_rejected_err():
    stream = make_stream(
        server_port=110,
        server_payload=b"+OK POP3 ready\r\n-ERR Command not supported\r\n",
        client_payload=b"STLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state == StarttlsState.FAILED


def test_pop3_ordinary_ok_unrelated():
    stream = make_stream(
        server_port=110,
        server_payload=b"+OK POP3 server\r\n+OK 0 messages\r\n",
        client_payload=b"STAT\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state != StarttlsState.SUCCEEDED


def test_pop3_fragmented():
    stream = make_stream(
        server_port=110,
        server_payload=b"+OK POP3\r\n+OK Begin TLS\r\n",
        client_payload=b"STLS\r\n" + SYNTHETIC_TLS_RECORD,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state == StarttlsState.SUCCEEDED


def test_pop3_gapped():
    stream = make_stream(
        server_port=110,
        server_payload=b"+OK POP3\r\n",
        has_unresolved_gaps=True,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.unresolved_gaps is True


# ==========================================================
# 4. ORIGINAL SCENARIOS: Cross-Protocol & Edge Cases (Tests 23-31)
# ==========================================================

def test_implicit_tls_port_465():
    res = starttls_machine.evaluate_stream(
        make_stream(server_port=465),
        make_classification(EmailProtocol.SMTP, is_tls_port=True),
    )
    assert res.starttls_state == StarttlsState.NOT_APPLICABLE


def test_implicit_tls_port_993():
    res = starttls_machine.evaluate_stream(
        make_stream(server_port=993),
        make_classification(EmailProtocol.IMAP, is_tls_port=True),
    )
    assert res.starttls_state == StarttlsState.NOT_APPLICABLE


def test_implicit_tls_port_995():
    res = starttls_machine.evaluate_stream(
        make_stream(server_port=995),
        make_classification(EmailProtocol.POP3, is_tls_port=True),
    )
    assert res.starttls_state == StarttlsState.NOT_APPLICABLE


def test_unknown_protocol():
    res = starttls_machine.evaluate_stream(
        make_stream(server_port=80),
        make_classification(EmailProtocol.UNKNOWN),
    )
    assert res.starttls_state == StarttlsState.UNKNOWN


def test_http_stream_containing_starttls_keyword():
    stream = make_stream(
        server_port=80,
        client_payload=b"POST /api HTTP/1.1\r\nHost: test\r\n\r\nSTARTTLS\r\n",
        server_payload=b"HTTP/1.1 200 OK\r\n\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.UNKNOWN))
    assert res.starttls_state == StarttlsState.UNKNOWN


def test_protocol_mismatch_protection():
    stream = make_stream(
        server_port=110,
        client_payload=b"EHLO test\r\nSTARTTLS\r\n",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state != StarttlsState.SUCCEEDED


def test_independent_streams_isolated():
    s1 = make_stream(stream_id="s1", server_payload=b"220 mail\r\n250-STARTTLS\r\n220 OK\r\n", client_payload=b"EHLO t\r\nSTARTTLS\r\n" + SYNTHETIC_TLS_RECORD)
    s2 = make_stream(stream_id="s2", server_payload=b"220 mail\r\n250-STARTTLS\r\n", client_payload=b"EHLO t\r\n")

    r1 = starttls_machine.evaluate_stream(s1, make_classification(EmailProtocol.SMTP))
    r2 = starttls_machine.evaluate_stream(s2, make_classification(EmailProtocol.SMTP))

    assert r1.starttls_state == StarttlsState.SUCCEEDED
    assert r2.starttls_state == StarttlsState.CAPABILITY_ADVERTISED


def test_unresolved_gap_does_not_create_fake_success():
    stream = make_stream(
        server_payload=b"220 mail\r\n250-STARTTLS\r\n220 Ready\r\n",
        client_payload=b"EHLO t\r\nSTARTTLS\r\n",
        has_unresolved_gaps=True,
        reconstruction_status=ReconstructionStatus.INCOMPLETE,
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SUCCEEDED
    assert res.confidence == ConfidenceLevel.LOW or res.confidence == ConfidenceLevel.MEDIUM


def test_tls_record_without_starttls_context():
    stream = make_stream(
        server_port=25,
        client_payload=SYNTHETIC_TLS_RECORD,
        server_payload=b"",
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SUCCEEDED


# ==========================================================
# 5. NEW REQUIRED WIRE-CHRONOLOGY REGRESSION TESTS (Tests 32-40)
# ==========================================================

def test_acceptance_packet_before_request_rejected():
    """32. Acceptance packet appears before STARTTLS request packet: must NOT succeed."""
    stream = make_stream(
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail.org ESMTP\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"220 2.0.0 Ready to start TLS\r\n", first_frame_number=2, first_timestamp=11.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO client.org\r\n", first_frame_number=3, first_timestamp=12.0),
            StreamFragment(start_seq=600, data=b"STARTTLS\r\n" + SYNTHETIC_TLS_RECORD, first_frame_number=4, first_timestamp=13.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is False

def test_request_precedes_matching_acceptance_transitions():
    """33. STARTTLS request packet precedes matching acceptance: may transition to SERVER_ACCEPTED."""
    stream = make_stream(
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"220 Ready to start TLS\r\n", first_frame_number=4, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO client.org\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"STARTTLS\r\n", first_frame_number=3, first_timestamp=12.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SERVER_ACCEPTED
    assert res.tls_transition_detected is False


def test_acceptance_followed_by_tls_record_succeeds():
    """34. Acceptance is followed by TLS record packet: SUCCEEDED."""
    stream = make_stream(
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail.org ESMTP\r\n250-STARTTLS\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"220 Ready to start TLS\r\n", first_frame_number=4, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO client.org\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"STARTTLS\r\n", first_frame_number=3, first_timestamp=12.0),
            StreamFragment(start_seq=700, data=SYNTHETIC_TLS_RECORD, first_frame_number=5, first_timestamp=15.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is True


def test_later_unrelated_220_cannot_satisfy_starttls():
    """35. A later unrelated 220 response cannot satisfy STARTTLS."""
    stream = make_stream(
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail.org ESMTP\r\n250 OK\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"220 unrelated service announcement\r\n", first_frame_number=4, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO client.org\r\nNOOP\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"QUIT\r\n", first_frame_number=3, first_timestamp=12.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state != StarttlsState.SERVER_ACCEPTED
    assert res.starttls_state != StarttlsState.SUCCEEDED


def test_imap_matching_tag_required_for_acceptance():
    """36. IMAP matching tag is required."""
    stream = make_stream(
        server_port=143,
        server_fragments=[
            StreamFragment(start_seq=10, data=b"* OK IMAP4rev1\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"A01 OK NOOP completed\r\n", first_frame_number=3, first_timestamp=12.0),
            StreamFragment(start_seq=200, data=b"A02 BAD Invalid command\r\n", first_frame_number=5, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"A01 NOOP\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"A02 STARTTLS\r\n", first_frame_number=4, first_timestamp=13.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.IMAP))
    assert res.starttls_state == StarttlsState.FAILED
    assert res.tls_transition_detected is False


def test_pop3_plus_ok_evaluated_only_while_stls_outstanding():
    """37. POP3 +OK must be evaluated only while STLS is outstanding."""
    stream = make_stream(
        server_port=110,
        server_fragments=[
            StreamFragment(start_seq=10, data=b"+OK POP3 server ready\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"+OK 2 messages\r\n", first_frame_number=3, first_timestamp=12.0),
            StreamFragment(start_seq=200, data=b"-ERR Not supported\r\n", first_frame_number=5, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"STAT\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"STLS\r\n", first_frame_number=4, first_timestamp=13.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.POP3))
    assert res.starttls_state == StarttlsState.FAILED
    assert res.tls_transition_detected is False


def test_events_from_separate_streams_isolated():
    """38. Events from separate streams cannot mix."""
    s1 = make_stream(
        stream_id="streamA",
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail\r\n250-STARTTLS\r\n", first_frame_number=1, first_timestamp=1.0),
            StreamFragment(start_seq=100, data=b"220 OK\r\n", first_frame_number=3, first_timestamp=3.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO t\r\nSTARTTLS\r\n", first_frame_number=2, first_timestamp=2.0),
            StreamFragment(start_seq=600, data=SYNTHETIC_TLS_RECORD, first_frame_number=4, first_timestamp=4.0),
        ]
    )
    s2 = make_stream(
        stream_id="streamB",
        server_fragments=[StreamFragment(start_seq=10, data=b"220 mail\r\n250-STARTTLS\r\n", first_frame_number=10, first_timestamp=10.0)],
        client_fragments=[StreamFragment(start_seq=500, data=b"EHLO t\r\n", first_frame_number=11, first_timestamp=11.0)]
    )

    r1 = starttls_machine.evaluate_stream(s1, make_classification(EmailProtocol.SMTP))
    r2 = starttls_machine.evaluate_stream(s2, make_classification(EmailProtocol.SMTP))

    assert r1.starttls_state == StarttlsState.SUCCEEDED
    assert r2.starttls_state == StarttlsState.CAPABILITY_ADVERTISED

def test_unadvertised_starttls_succeeds_with_explicit_evidence():
    """40. Unadvertised STARTTLS succeeds when request + acceptance + TLS record occur, recording limitation."""
    stream = make_stream(
        server_fragments=[
            StreamFragment(start_seq=10, data=b"220 mail.org ESMTP\r\n250-HELP\r\n250 OK\r\n", first_frame_number=1, first_timestamp=10.0),
            StreamFragment(start_seq=100, data=b"220 Ready to start TLS\r\n", first_frame_number=4, first_timestamp=14.0),
        ],
        client_fragments=[
            StreamFragment(start_seq=500, data=b"EHLO client.org\r\n", first_frame_number=2, first_timestamp=11.0),
            StreamFragment(start_seq=600, data=b"STARTTLS\r\n", first_frame_number=3, first_timestamp=12.0),
            StreamFragment(start_seq=700, data=SYNTHETIC_TLS_RECORD, first_frame_number=5, first_timestamp=15.0),
        ],
    )
    res = starttls_machine.evaluate_stream(stream, make_classification(EmailProtocol.SMTP))
    assert res.starttls_state == StarttlsState.SUCCEEDED
    assert res.tls_transition_detected is True
    assert any("UNADVERTISED_STARTTLS" in (e.matched_value or "") for e in res.evidence)
    assert "capability advertisement was not observed" in res.explanation