"""
MailRakhwala Comprehensive Analysis Report Schema.
Step 29 Enterprise Reporting: Integrates Steps 21–28 deterministic findings,
ML feature vectors, anomaly detection, risk classification, and SHAP explainability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.anomaly_detection import AnomalyDetectionResult
from app.schemas.compliance_engine import ComplianceFinding, SessionComplianceReport
from app.schemas.ml_features import MLFeatureVector
from app.schemas.posture import CryptographicPostureReport
from app.schemas.risk_classification import RiskClassificationResult
from app.schemas.shap_explainability import SHAPExplanationResult
from app.schemas.threat_mapping import ThreatContextMapping
from app.schemas.vulnerability_mapping import VulnerabilityMappingReport, WeaknessMapping


class SessionMetadata(BaseModel):
    """Metadata detailing the analysis capture session."""
    session_id: str = Field(..., description="Unique analysis identifier")
    filename: str = Field(..., description="Name of the evaluated PCAP file")
    filesize_bytes: int = Field(default=0, description="Size of uploaded capture in bytes")
    status: str = Field(default="COMPLETED", description="Analysis execution status")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC execution timestamp",
    )
    total_streams: int = Field(default=1, description="Total email TCP streams evaluated")


class ProtocolSecuritySummary(BaseModel):
    """Concise technical summary of observed TLS/PKI protocol parameters."""
    tls_version: str = Field(default="Unavailable from captured evidence")
    cipher_suite: str = Field(default="Unavailable from captured evidence")
    key_exchange: str = Field(default="Unavailable from captured evidence")
    perfect_forward_secrecy: bool = Field(default=False)
    certificate_validity: str = Field(default="Unavailable from captured evidence")
    certificate_key_size: Optional[int] = Field(default=None)
    signature_algorithm: str = Field(default="Unavailable from captured evidence")
    san_match_status: str = Field(default="Unavailable from captured evidence")
    trust_validation: str = Field(default="Unavailable from captured evidence")
    revocation_status: str = Field(default="Unavailable from captured evidence")
    starttls_status: str = Field(default="Unavailable from captured evidence")


class PracticalRecommendation(BaseModel):
    """Actionable remediation item derived directly from deterministic findings."""
    rule_id: str = Field(..., description="Rule triggering this recommendation")
    title: str = Field(..., description="Short advisory title")
    recommendation: str = Field(..., description="Deterministic guidance text")
    severity: str = Field(..., description="Associated finding severity")


class ComprehensiveAnalysisReport(BaseModel):
    """
    Consolidated enterprise audit report uniting Steps 21 through 28.
    
    IMPORTANT METHODOLOGY NOTE:
    ML outputs (Risk Classification, Anomaly Detection, and SHAP Attributions)
    represent statistical model properties. They are raw XGBoost model probabilities
    and statistical deviations; they do NOT constitute causal proof of an attack,
    intrusion, or active security failure.
    """
    session: SessionMetadata
    protocol_summary: ProtocolSecuritySummary
    posture_report: CryptographicPostureReport
    compliance_findings: List[ComplianceFinding] = Field(default_factory=list)
    vulnerability_mappings: List[WeaknessMapping] = Field(default_factory=list)
    threat_mappings: List[ThreatContextMapping] = Field(default_factory=list)
    recommendations: List[PracticalRecommendation] = Field(default_factory=list)
    
    # ML Pipeline Results (Steps 25-28)
    feature_vector: Optional[MLFeatureVector] = None
    anomaly_detection: Optional[AnomalyDetectionResult] = None
    risk_classification: Optional[RiskClassificationResult] = None
    shap_explanation: Optional[SHAPExplanationResult] = None

    methodology_disclaimer: str = Field(
        default=(
            "Cryptographic Security Scores and Compliance Findings are derived deterministically "
            "from RFC compliance policies and PKI specifications. ML Risk Classifications reflect "
            "Step 27 XGBoost model probabilities and do not represent empirical attack frequencies. "
            "Anomaly Detection flags statistical outliers relative to reference distributions. "
            "SHAP attributions indicate mathematical feature contributions toward model prediction."
        )
    )