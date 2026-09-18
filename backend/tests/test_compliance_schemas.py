"""Tests for Step 21 Compliance Engine Data Contracts."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.schemas.compliance_engine import (
    ComplianceStatus,
    ComplianceEvidence,
    ComplianceFinding,
    RuleEvaluationSummary,
    SessionComplianceReport,
)
from app.schemas.revocation_trust import (
    CertificateTrustEvidence,
    CRLEvidence,
    OCSPObservedStatus,
    OCSPEvidence,
    OCSPVerificationStatus,
    OfflineTrustResult,
    TrustValidationStatus,
)
from app.schemas.domain import FindingCategory, SeverityLevel


def test_compliance_status_enum_values():
    assert set(ComplianceStatus) == {
        ComplianceStatus.COMPLIANT,
        ComplianceStatus.NON_COMPLIANT,
        ComplianceStatus.UNKNOWN,
        ComplianceStatus.NOT_APPLICABLE,
    }


def test_compliance_evidence_creation():
    ev = ComplianceEvidence(
        stream_id="stream-1",
        observed_property="tls.version",
        observed_value="TLS 1.2",
        reference_value=">= TLS 1.2",
        rule_id="RULE-TLS-003",
    )
    assert ev.stream_id == "stream-1"
    assert ev.packet_number is None
    assert ev.raw_der_sha256 is None


def test_compliance_evidence_optional_fields():
    ev = ComplianceEvidence(
        stream_id="stream-1",
        packet_number=42,
        timestamp=1700000000.0,
        certificate_index=1,
        raw_der_sha256="abc123hash",
        observed_property="cert.public_key_bits",
        observed_value=2048,
        reference_value=">= 2048",
        rule_id="RULE-CERT-003",
        source_component="CERT_AUDITOR",
    )
    assert ev.packet_number == 42
    assert ev.raw_der_sha256 == "abc123hash"
    assert ev.source_component == "CERT_AUDITOR"


def test_compliance_finding_deterministic():
    ev = ComplianceEvidence(
        stream_id="stream-1",
        observed_property="tls.version",
        observed_value="TLS 1.3",
        rule_id="RULE-TLS-004",
    )
    finding = ComplianceFinding(
        finding_id="FINDING-RULE-TLS-004-stream-1-1234",
        rule_id="RULE-TLS-004",
        category=FindingCategory.TLS_VERSION,
        title="Modern TLS 1.3 Protocol Negotiated",
        description="Negotiated TLS 1.3",
        severity=SeverityLevel.INFO,
        status=ComplianceStatus.COMPLIANT,
        recommendation="Maintain modern cipher suites.",
        evidence=ev,
    )
    assert finding.deterministic is True
    assert finding.engine_version == "21.0.0"


def test_rule_evaluation_summary_fields():
    summary = RuleEvaluationSummary(
        total_rules_evaluated=8,
        total_findings_generated=5,
        compliant_count=2,
        non_compliant_count=1,
        unknown_count=1,
        not_applicable_count=1,
    )
    assert summary.total_rules_evaluated == 8
    assert summary.total_findings_generated == 5
    assert summary.total_rules_evaluated != summary.total_findings_generated


def test_session_compliance_report_timezone_normalization():
    summary = RuleEvaluationSummary()
    naive = datetime(2026, 9, 18, 12, 0, 0)
    report = SessionComplianceReport(
        stream_id="stream-1",
        reference_time=naive,
        overall_compliance=ComplianceStatus.COMPLIANT,
        summary=summary,
        findings=[],
    )
    assert report.reference_time.tzinfo == timezone.utc


def test_session_compliance_report_utc_preservation():
    summary = RuleEvaluationSummary()
    aware = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)
    report = SessionComplianceReport(
        stream_id="stream-1",
        reference_time=aware,
        overall_compliance=ComplianceStatus.UNKNOWN,
        summary=summary,
        findings=[],
    )
    assert report.reference_time == aware


def test_session_compliance_report_serialization():
    ev = ComplianceEvidence(
        stream_id="s1",
        observed_property="tls.version",
        observed_value="TLS 1.2",
        rule_id="RULE-TLS-003",
    )
    finding = ComplianceFinding(
        finding_id="F1",
        rule_id="RULE-TLS-003",
        category=FindingCategory.TLS_VERSION,
        title="TLS 1.2",
        description="Desc",
        severity=SeverityLevel.INFO,
        status=ComplianceStatus.COMPLIANT,
        recommendation="Rec",
        evidence=ev,
    )
    report = SessionComplianceReport(
        stream_id="s1",
        reference_time=datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc),
        overall_compliance=ComplianceStatus.COMPLIANT,
        summary=RuleEvaluationSummary(total_rules_evaluated=1, total_findings_generated=1, compliant_count=1),
        findings=[finding],
    )
    dump = report.model_dump()
    assert dump["stream_id"] == "s1"
    assert dump["overall_compliance"] == "COMPLIANT"
    assert len(dump["findings"]) == 1


def test_session_compliance_report_json_roundtrip():
    report = SessionComplianceReport(
        stream_id="s1",
        reference_time=datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc),
        overall_compliance=ComplianceStatus.NON_COMPLIANT,
        summary=RuleEvaluationSummary(total_rules_evaluated=1, total_findings_generated=0),
        findings=[],
    )
    json_str = report.model_dump_json()
    reloaded = SessionComplianceReport.model_validate_json(json_str)
    assert reloaded.stream_id == report.stream_id
    assert reloaded.overall_compliance == report.overall_compliance


def test_evidence_requires_stream_id():
    with pytest.raises(ValidationError):
        ComplianceEvidence(observed_property="test", observed_value="val", rule_id="RULE-1")


def test_evidence_requires_rule_id():
    with pytest.raises(ValidationError):
        ComplianceEvidence(stream_id="s1", observed_property="test", observed_value="val")


def test_finding_requires_finding_id():
    ev = ComplianceEvidence(stream_id="s1", observed_property="prop", observed_value="val", rule_id="RULE-1")
    with pytest.raises(ValidationError):
        ComplianceFinding(
            rule_id="RULE-1",
            category=FindingCategory.TLS_VERSION,
            title="Title",
            description="Desc",
            severity=SeverityLevel.INFO,
            status=ComplianceStatus.COMPLIANT,
            recommendation="Rec",
            evidence=ev,
        )


def test_report_default_limitations_present():
    report = SessionComplianceReport(
        stream_id="s1",
        overall_compliance=ComplianceStatus.UNKNOWN,
        summary=RuleEvaluationSummary(),
        findings=[],
    )
    assert len(report.limitations) >= 3


def test_deterministic_evidence_serialization():
    ev1 = ComplianceEvidence(stream_id="s1", observed_property="p", observed_value=123, rule_id="R1")
    ev2 = ComplianceEvidence(stream_id="s1", observed_property="p", observed_value=123, rule_id="R1")
    assert ev1.model_dump_json() == ev2.model_dump_json()