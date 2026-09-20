"""
Tests for Step 29 Enterprise Report Export (JSON and PDF generation).
Verifies that outputs maintain precise, neutral terminology and non-calibrated models.
"""

import io
import pytest
from app.schemas.posture import CryptographicPostureReport, PostureSeverity
from app.schemas.report_export import (
    ComprehensiveAnalysisReport,
    PracticalRecommendation,
    ProtocolSecuritySummary,
    SessionMetadata,
)
from app.schemas.risk_classification import RiskClassificationResult
from app.schemas.shap_explainability import (
    ContributionDirection,
    SHAPExplanationResult,
    SHAPFeatureContribution,
    SHAPMetadata,
)
from app.services.pdf_report_generator import PDFReportGenerator


@pytest.fixture
def sample_report() -> ComprehensiveAnalysisReport:
    """Fixture providing a synthetic, non-production test report."""
    posture = CryptographicPostureReport(
        session_id="session-synth-01",
        stream_id="stream-test-01",
        posture_score=60,
        severity=PostureSeverity.MEDIUM,
        total_penalty=40,
        rule_deductions=[],
    )
    risk = RiskClassificationResult(
        stream_id="stream-test",
        predicted_class="MEDIUM",
        class_id=1,
        class_probabilities={"LOW": 0.10, "MEDIUM": 0.70, "HIGH": 0.15, "CRITICAL": 0.05},
        status_text="Risk classification evaluated by XGBoost model.",
    )
    shap_meta = SHAPMetadata(
        model_name="XGBoost",
        explainer_name="TreeExplainer",
        feature_count=19,
        base_value=0.2,
    )
    top_contrib = SHAPFeatureContribution(
        feature_name="cipher_security_score",
        feature_index=1,
        original_value=2.0,
        model_input_value=2.0,
        shap_value=0.35,
        absolute_shap_value=0.35,
        direction=ContributionDirection.INCREASES_PREDICTED_CLASS,
    )
    shap_res = SHAPExplanationResult(
        stream_id="stream-test",
        predicted_class="MEDIUM",
        predicted_class_id=1,
        class_probabilities=risk.class_probabilities,
        feature_contributions=[top_contrib],
        top_contributions=[top_contrib],
        feature_count=19,
        model_metadata=shap_meta,
        status_text="Feature attributions computed.",
    )

    return ComprehensiveAnalysisReport(
        session=SessionMetadata(
            session_id="session-synth-01",
            filename="synthetic_capture.pcap",
            filesize_bytes=1024,
            status="COMPLETED",
        ),
        protocol_summary=ProtocolSecuritySummary(
            tls_version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            perfect_forward_secrecy=True,
        ),
        posture_report=posture,
        risk_classification=risk,
        shap_explanation=shap_res,
        recommendations=[
            PracticalRecommendation(
                rule_id="RULE-TLS-01",
                title="Legacy Protocol",
                recommendation="Upgrade to TLS 1.3.",
                severity="MEDIUM",
            )
        ],
    )


def test_report_json_serialization(sample_report: ComprehensiveAnalysisReport):
    data = sample_report.model_dump(mode="json")
    assert data["session"]["session_id"] == "session-synth-01"
    assert data["posture_report"]["posture_score"] == 60
    assert data["risk_classification"]["predicted_class"] == "MEDIUM"
    assert "calibrated" not in str(data).lower()


def test_pdf_generation_bytes(sample_report: ComprehensiveAnalysisReport):
    gen = PDFReportGenerator(sample_report)
    pdf_bytes = gen.generate()
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_neutral_terminology(sample_report: ComprehensiveAnalysisReport):
    assert "calibrated" not in sample_report.methodology_disclaimer.lower()
    assert "active security failure" not in sample_report.methodology_disclaimer.lower()