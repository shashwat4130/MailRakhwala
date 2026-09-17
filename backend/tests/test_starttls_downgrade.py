"""
Unit tests for Step 11: STARTTLS Downgrade & Plaintext Fallback Analysis.
Validates passive PCAP forensic limitations, non-attribution boundaries,
and protocol-state downgrade conditions.
"""

from typing import List, Optional
import pytest

from app.schemas.domain import SeverityLevel
from app.schemas.protocol import (
    ConfidenceLevel,
    EmailProtocol,
    ProtocolClassification,
)
from app.schemas.starttls import (
    StarttlsAssessment,
    StarttlsState,
    StarttlsTransition,
)
from app.schemas.starttls_downgrade import (
    DowngradeAssessmentStatus,
    DowngradeIndicatorType,
)
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)
from app.services.starttls_downgrade import starttls_downgrade_service


def make_stream(
    stream_id: str = "stream#1",
    client_ip: str = "192.168.1.50",
    client_port: int = 54321,
    server_ip: str = "192.168.1.10",
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


def make_classification(
    stream_id: str = "stream#1",
    protocol: EmailProtocol = EmailProtocol.SMTP,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    is_tls_port_context: bool = False,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
) -> ProtocolClassification:
    return ProtocolClassification(
        stream_id=stream_id,
        protocol=protocol,
        confidence=confidence,
        is_tls_port_context=is_tls_port_context,
        reconstruction_status=reconstruction_status,
    )


def make_assessment(
    stream_id: str = "stream#1",
    protocol: EmailProtocol = EmailProtocol.SMTP,
    state: StarttlsState = StarttlsState.SUCCEEDED,
    tls_transition_detected: bool = True,
    transitions: Optional[List[StarttlsTransition]] = None,
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
) -> StarttlsAssessment:
    return StarttlsAssessment(
        stream_id=stream_id,
        protocol=protocol,
        starttls_state=state,
        confidence=ConfidenceLevel.HIGH,
        transitions=transitions or [],
        reconstruction_status=reconstruction_status,
        unresolved_gaps=False,
        tls_transition_detected=tls_transition_detected,
        explanation="State machine evaluation.",
    )


# ==========================================================
# 1. CORE DOWNGRADE & FALLBACK SCENARIOS
# ==========================================================

def test_smtp_advertised_not_requested():
    """1. STARTTLS advertised but not requested -> Plaintext fallback (not attack)."""
    stream = make_stream(server_port=25, client_payload=b"EHLO test\r\nMAIL FROM:<a@b>\r\n")
    assessment = make_assessment(
        state=StarttlsState.CAPABILITY_ADVERTISED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.CONNECTED,
                to_state=StarttlsState.CAPABILITY_ADVERTISED,
                trigger="250-STARTTLS",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED
    assert res.is_downgrade_suspected is False
    assert len(res.findings) == 1
    assert res.findings[0].indicator_type == DowngradeIndicatorType.STARTTLS_ADVERTISED_NOT_REQUESTED
    assert res.findings[0].severity == SeverityLevel.MEDIUM


def test_smtp_requested_and_accepted_normal():
    """2. Normal successful negotiation -> Benign, no finding."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(state=StarttlsState.SUCCEEDED, tls_transition_detected=True)
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.BENIGN
    assert res.is_downgrade_suspected is False
    assert len(res.findings) == 0


def test_smtp_requested_and_rejected():
    """3. STARTTLS requested but server rejected -> Negotiation rejected (not attack)."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(
        state=StarttlsState.SERVER_REJECTED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.STARTTLS_REQUESTED,
                to_state=StarttlsState.SERVER_REJECTED,
                trigger="454 TLS not available",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.NEGOTIATION_REJECTED
    assert res.is_downgrade_suspected is False
    assert res.findings[0].indicator_type == DowngradeIndicatorType.STARTTLS_SERVER_REJECTED
    assert res.findings[0].severity == SeverityLevel.MEDIUM


def test_accepted_starttls_with_tls_transition_observed():
    """4. Accepted STARTTLS with TLS transition observed -> No downgrade."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(state=StarttlsState.SUCCEEDED, tls_transition_detected=True)
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.BENIGN
    assert res.is_downgrade_suspected is False


def test_accepted_starttls_with_no_tls_transition():
    """5. Accepted STARTTLS with no TLS transition (premature close) -> Incomplete."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(
        state=StarttlsState.SERVER_ACCEPTED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.STARTTLS_REQUESTED,
                to_state=StarttlsState.SERVER_ACCEPTED,
                trigger="220 Ready",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.INCOMPLETE
    assert res.is_downgrade_suspected is False
    assert res.findings[0].indicator_type == DowngradeIndicatorType.ACCEPTED_NO_TLS_TRANSITION


def test_plaintext_continuation_after_accepted_starttls():
    """6. Accepted STARTTLS followed by cleartext commands -> Downgrade suspected."""
    stream = make_stream(
        server_port=25,
        client_payload=b"STARTTLS\r\nMAIL FROM:<victim@example.com>\r\nRCPT TO:<target@example.com>\r\n"
    )
    assessment = make_assessment(
        state=StarttlsState.SERVER_ACCEPTED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.STARTTLS_REQUESTED,
                to_state=StarttlsState.SERVER_ACCEPTED,
                trigger="220 Ready",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.DOWNGRADE_SUSPECTED
    assert res.is_downgrade_suspected is True
    assert res.findings[0].indicator_type == DowngradeIndicatorType.PLAINTEXT_CONTINUATION_POST_ACCEPTANCE
    assert res.findings[0].severity == SeverityLevel.HIGH


# ==========================================================
# 2. EVIDENCE UNCERTAINTY & BOUNDARY CONDITIONS
# ==========================================================

def test_incomplete_capture_before_negotiation_finishes():
    """7. Incomplete capture before negotiation finishes -> INCOMPLETE."""
    stream = make_stream(
        server_port=25,
        reconstruction_status=ReconstructionStatus.INCOMPLETE
    )
    assessment = make_assessment(
        state=StarttlsState.CONNECTED,
        tls_transition_detected=False,
        reconstruction_status=ReconstructionStatus.INCOMPLETE
    )
    classification = make_classification(
        protocol=EmailProtocol.SMTP,
        confidence=ConfidenceLevel.LOW,
        reconstruction_status=ReconstructionStatus.INCOMPLETE
    )

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.INCOMPLETE
    assert res.confidence == ConfidenceLevel.LOW
    assert res.is_downgrade_suspected is False


def test_gaps_preventing_reliable_downgrade_conclusion():
    """8. Unresolved sequence gaps -> INCOMPLETE / LOW confidence."""
    stream = make_stream(
        server_port=25,
        has_unresolved_gaps=True,
        reconstruction_status=ReconstructionStatus.INCOMPLETE,
    )
    assessment = make_assessment(
        state=StarttlsState.CONNECTED,
        tls_transition_detected=False,
        reconstruction_status=ReconstructionStatus.INCOMPLETE
    )
    classification = make_classification(
        protocol=EmailProtocol.SMTP,
        confidence=ConfidenceLevel.LOW,
        reconstruction_status=ReconstructionStatus.INCOMPLETE
    )

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.INCOMPLETE
    assert res.confidence == ConfidenceLevel.LOW
    assert res.is_downgrade_suspected is False


def test_smtp_downgrade_indicators():
    """9. SMTP downgrade evaluation retains rule ID and protocol."""
    stream = make_stream(server_port=25, client_payload=b"MAIL FROM:<a@b>\r\n")
    assessment = make_assessment(state=StarttlsState.CAPABILITY_ADVERTISED, tls_transition_detected=False)
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.protocol == EmailProtocol.SMTP
    assert res.findings[0].rule_id == "RULE-STARTTLS-002"


def test_imap_downgrade_indicators():
    """10. IMAP plaintext fallback evaluation."""
    stream = make_stream(server_port=143, client_payload=b"A01 LOGIN user pass\r\n")
    assessment = make_assessment(
        protocol=EmailProtocol.IMAP,
        state=StarttlsState.CAPABILITY_ADVERTISED,
        tls_transition_detected=False,
    )
    classification = make_classification(protocol=EmailProtocol.IMAP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED
    assert res.protocol == EmailProtocol.IMAP


def test_pop3_downgrade_indicators():
    """11. POP3 plaintext fallback evaluation."""
    stream = make_stream(server_port=110, client_payload=b"USER test\r\nPASS secret\r\n")
    assessment = make_assessment(
        protocol=EmailProtocol.POP3,
        state=StarttlsState.CAPABILITY_ADVERTISED,
        tls_transition_detected=False,
    )
    classification = make_classification(protocol=EmailProtocol.POP3)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED
    assert res.protocol == EmailProtocol.POP3


def test_implicit_tls_ports_not_applicable():
    """12. Implicit TLS ports (465, 993, 995) are NOT_APPLICABLE."""
    for port in (465, 993, 995):
        stream = make_stream(server_port=port)
        assessment = make_assessment(state=StarttlsState.NOT_APPLICABLE, tls_transition_detected=True)
        proto = (
            EmailProtocol.SMTP
            if port == 465
            else (EmailProtocol.IMAP if port == 993 else EmailProtocol.POP3)
        )
        classification = make_classification(
            protocol=proto,
            is_tls_port_context=True,
            confidence=ConfidenceLevel.HIGH,
        )

        res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
        assert res.status == DowngradeAssessmentStatus.NOT_APPLICABLE
        assert res.is_downgrade_suspected is False
        assert len(res.findings) == 0


def test_normal_successful_starttls_no_finding():
    """13. Normal successful STARTTLS produces zero findings."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(state=StarttlsState.SUCCEEDED, tls_transition_detected=True)
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert len(res.findings) == 0


def test_insufficient_evidence_unknown():
    """14. Arbitrary incomplete state resolves to UNKNOWN."""
    stream = make_stream(server_port=25)
    assessment = make_assessment(state=StarttlsState.UNKNOWN, tls_transition_detected=False)
    classification = make_classification(protocol=EmailProtocol.SMTP, confidence=ConfidenceLevel.LOW)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.UNKNOWN
    assert res.is_downgrade_suspected is False


def test_no_false_mitm_attack_claims():
    """15. PASSIVE FORENSIC SAFETY: Verify findings never claim MITM or attack proven."""
    stream = make_stream(
        server_port=25,
        client_payload=b"STARTTLS\r\nMAIL FROM:<a@b>\r\n"
    )
    assessment = make_assessment(
        state=StarttlsState.SERVER_ACCEPTED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.STARTTLS_REQUESTED,
                to_state=StarttlsState.SERVER_ACCEPTED,
                trigger="220 Ready",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    combined_text = f"{res.summary} {res.findings[0].description} {res.findings[0].title}".lower()

    assert "mitm attack detected" not in combined_text
    assert "attacker confirmed" not in combined_text
    assert "downgrade attack proven" not in combined_text


def test_evidence_is_preserved_in_result():
    """16. Endpoints, transitions, and limitations are preserved in finding evidence."""
    stream = make_stream(server_port=25, client_payload=b"EHLO test\r\n")
    assessment = make_assessment(
        state=StarttlsState.CAPABILITY_ADVERTISED,
        tls_transition_detected=False,
        transitions=[
            StarttlsTransition(
                from_state=StarttlsState.CONNECTED,
                to_state=StarttlsState.CAPABILITY_ADVERTISED,
                trigger="250-STARTTLS",
                is_server=True,
            )
        ],
    )
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    ev = res.findings[0].evidence
    assert ev.client_endpoint == "192.168.1.50:54321"
    assert ev.server_endpoint == "192.168.1.10:25"
    assert len(ev.observed_events) > 0
    assert len(ev.limitations) > 0


def test_directionality_is_respected():
    """17. Endpoint addresses map correctly to client vs. server."""
    stream = make_stream(
        client_ip="10.10.10.5",
        client_port=40001,
        server_ip="10.10.10.1",
        server_port=25,
        client_payload=b"EHLO test\r\n",
    )
    assessment = make_assessment(state=StarttlsState.CAPABILITY_ADVERTISED, tls_transition_detected=False)
    classification = make_classification(protocol=EmailProtocol.SMTP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    ev = res.findings[0].evidence
    assert ev.client_endpoint == "10.10.10.5:40001"
    assert ev.server_endpoint == "10.10.10.1:25"


def test_multiple_independent_streams():
    """18. Multi-stream evaluation maintains isolation."""
    s1 = make_stream(stream_id="stream1", client_payload=b"MAIL FROM:<a@b>\r\n")
    a1 = make_assessment(stream_id="stream1", state=StarttlsState.CAPABILITY_ADVERTISED, tls_transition_detected=False)

    s2 = make_stream(stream_id="stream2")
    a2 = make_assessment(stream_id="stream2", state=StarttlsState.SUCCEEDED, tls_transition_detected=True)

    c = make_classification(stream_id="dummy", protocol=EmailProtocol.SMTP)

    r1 = starttls_downgrade_service.evaluate_downgrade(s1, c, a1)
    r2 = starttls_downgrade_service.evaluate_downgrade(s2, c, a2)

    assert r1.status == DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED
    assert r2.status == DowngradeAssessmentStatus.BENIGN


def test_unsupported_protocol_handling():
    """19. Protocol UNKNOWN returns NOT_APPLICABLE."""
    stream = make_stream(server_port=80)
    assessment = make_assessment(protocol=EmailProtocol.UNKNOWN, state=StarttlsState.UNKNOWN, tls_transition_detected=False)
    classification = make_classification(protocol=EmailProtocol.UNKNOWN, confidence=ConfidenceLevel.UNKNOWN)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.NOT_APPLICABLE


def test_imap_rejection_marks_suspicious():
    """20. IMAP NO rejection evaluated as NEGOTIATION_REJECTED."""
    stream = make_stream(server_port=143)
    assessment = make_assessment(
        protocol=EmailProtocol.IMAP,
        state=StarttlsState.SERVER_REJECTED,
        tls_transition_detected=False,
    )
    classification = make_classification(protocol=EmailProtocol.IMAP)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.NEGOTIATION_REJECTED


def test_pop3_rejection_marks_suspicious():
    """21. POP3 -ERR rejection evaluated as NEGOTIATION_REJECTED."""
    stream = make_stream(server_port=110)
    assessment = make_assessment(
        protocol=EmailProtocol.POP3,
        state=StarttlsState.SERVER_REJECTED,
        tls_transition_detected=False,
    )
    classification = make_classification(protocol=EmailProtocol.POP3)

    res = starttls_downgrade_service.evaluate_downgrade(stream, classification, assessment)
    assert res.status == DowngradeAssessmentStatus.NEGOTIATION_REJECTED