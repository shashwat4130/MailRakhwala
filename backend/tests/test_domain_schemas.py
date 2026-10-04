"""Unit tests verifying Domain Data Contracts."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.schemas.domain import (
    TriState,
    MailProtocol,
    TransportSecurityMode,
    StarttlsState,
    KeyExchangeType,
    SeverityLevel,
    FindingCategory,
    RiskLevel,
    EvidenceRecord,
    ConnectionMetadata,
    KeyExchangeAnalysis,
    TLSAnalysis,
    CertificateAudit,
    Finding,
    RiskAssessment,
    PostureReport,
)


def test_valid_connection_metadata():
    conn = ConnectionMetadata(
        session_id="session-tcp-101",
        stream_index=0,
        source_ip="192.168.1.50",
        destination_ip="10.0.0.25",
        source_port=49812,
        destination_port=587,
        protocol=MailProtocol.SMTP,
        transport_security=TransportSecurityMode.EXPLICIT_STARTTLS,
        starttls_state=StarttlsState.SUCCEEDED,
        start_time=datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc),
    )
    assert str(conn.source_ip) == "192.168.1.50"
    assert conn.destination_port == 587
    assert conn.starttls_state == StarttlsState.SUCCEEDED


def test_invalid_ip_handling():
    with pytest.raises(ValidationError):
        ConnectionMetadata(
            session_id="bad-ip-stream",
            source_ip="999.999.999.999",
            destination_ip="10.0.0.1",
            source_port=50000,
            destination_port=25,
            start_time=datetime.now(timezone.utc),
        )


def test_tristate_semantics():
    assert TriState.from_bool(True) == TriState.TRUE
    assert TriState.from_bool(False) == TriState.FALSE
    assert TriState.from_bool(None) == TriState.UNKNOWN

    kex = KeyExchangeAnalysis(
        exchange_type=KeyExchangeType.ECDHE,
        has_forward_secrecy=TriState.UNKNOWN,
        named_group="x25519",
    )
    assert kex.has_forward_secrecy == TriState.UNKNOWN
    assert kex.has_forward_secrecy != TriState.FALSE


def test_datetime_timezone_normalization():
    naive_time = datetime(2026, 9, 14, 12, 30, 0)
    evidence = EvidenceRecord(
        field_name="tls.handshake.ciphersuite",
        observed_value="TLS_AES_256_GCM_SHA384",
        timestamp=naive_time,
    )
    assert evidence.timestamp.tzinfo is not None
    assert evidence.timestamp.tzinfo == timezone.utc


def test_finding_and_nested_evidence():
    evidence = EvidenceRecord(
        field_name="tls.handshake.version",
        observed_value="0x0301",
        expected_value=">= 0x0303",
        packet_number=14,
        stream_index=1,
    )
    finding = Finding(
        finding_id="RULE-TLS-10-DEPRECATED",
        category=FindingCategory.TLS_VERSION,
        title="Deprecated TLS Protocol (TLS 1.0)",
        severity=SeverityLevel.HIGH,
        description="TLS 1.0 violates modern RFC 8996 guidance.",
        evidence=[evidence],
        recommendation="Upgrade to TLS 1.2 or TLS 1.3.",
    )
    assert finding.severity == SeverityLevel.HIGH
    assert len(finding.evidence) == 1
    assert finding.evidence[0].packet_number == 14


def test_score_validation_bounds():
    with pytest.raises(ValidationError):
        RiskAssessment(
            numeric_score=105,
            risk_level=RiskLevel.LOW,
        )


def test_posture_report_serialization():
    report = PostureReport(
        analysis_id="job-uuid-1234",
        capture_filename="test_mail_capture.pcap",
        sessions=[],
        findings=[],
        risk_assessment=RiskAssessment(
            numeric_score=78,
            risk_level=RiskLevel.MEDIUM,
            contributing_finding_ids=["RULE-TLS-10-DEPRECATED"],
        ),
    )

    data = report.model_dump(mode="json")
    assert data["analysis_id"] == "job-uuid-1234"
    assert data["risk_assessment"]["numeric_score"] == 78
    assert data["risk_assessment"]["risk_level"] == "MEDIUM"