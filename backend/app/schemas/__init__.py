"""Domain and API schemas package exports."""

from .api import (
    AnalysisJobResponse,
    AnalysisUploadResponse,
    HealthResponse,
    JobStatus,
)
from .domain import *  # noqa: F403
from .starttls_downgrade import (
    DowngradeAnalysisResult,
    DowngradeAssessmentStatus,
    DowngradeEvidence,
    DowngradeFinding,
    DowngradeIndicatorType,
)
from .tls_record import (
    TLSRecord,
    TLSRecordContentType,
    TLSRecordParseResult,
    TLSRecordParseStatus,
    TLSRecordVersion,
)
from .tls_client_hello import (
    ClientHelloParseResult,
    ClientHelloParseStatus,
    KeyShareEntry,
    TLSClientHello,
    TLSExtension,
)
from .tls_server_hello import (
    ServerHelloKeyShare,
    ServerHelloParseResult,
    ServerHelloParseStatus,
    TLSServerHello,
)
from .certificate_extraction import (
    CertificateChainExtractionResult,
    CertificateExtractionStatus,
    RawExtractedCertificate,
)
from .certificate_parsing import (
    CertificateParseStatus,
    DistinguishedName,
    ParsedCertificate,
    ParsedCertificateChain,
    ParsedExtension,
    ParsedKeyParameters,
    SubjectAlternativeNames,
)
from .certificate_security_audit import (
    CertificateEvidence,
    CertificateFindingType,
    CertificateSecurityAuditResult,
    CertificateSecurityFinding,
    SingleCertificateAudit,
)
from .identity_analysis import (
    IdentityAnalysisResult,
    IdentityRelationship,
    IdentityRelationshipType,
    IdentityStatus,
)
from .revocation_trust import (
    CRLEvidence,
    CRLEvidenceStatus,
    CertificateTrustEvidence,
    OCSPEvidence,
    OCSPObservedStatus,
    OCSPVerificationStatus,
    OfflineTrustResult,
    TrustAnchorEvidence,
    TrustValidationStatus,
)
from .compliance_engine import (
    ComplianceEvidence,
    ComplianceFinding,
    ComplianceStatus,
    RuleEvaluationSummary,
    SessionComplianceReport,
)
from .vulnerability_mapping import (
    EvidenceConfidence,
    MappingType,
    VulnerabilityMappingReport,
    WeaknessMapping,
)
from .threat_mapping import (
    MitreAttackReference,
    SessionThreatReport,
    ThreatCategory,
    ThreatContextMapping,
    ThreatEvidence,
    ThreatMappingStatus,
)
from .posture import (
    CryptographicPostureReport,
    PostureDeduction,
    PostureSeverity,
)
from .ml_features import MLFeatureVector
from .anomaly_detection import (
    AnomalyDetectionMetadata,
    AnomalyDetectionResult,
    BatchAnomalyDetectionResult,
)
from .risk_classification import (
    BatchRiskClassificationResult,
    RiskClassificationMetadata,
    RiskClassificationResult,
)
from .shap_explainability import (
    BatchSHAPExplanationResult,
    ContributionDirection,
    GlobalFeatureImportance,
    SHAPExplanationResult,
    SHAPFeatureContribution,
    SHAPMetadata,
)
from .report_export import (
    ComprehensiveAnalysisReport,
    PracticalRecommendation,
    ProtocolSecuritySummary,
    SessionMetadata,
)

__all__ = [
    # Domain & Session
    "SessionMetadata",
    "ProtocolSecuritySummary",
    "PracticalRecommendation",
    "ComprehensiveAnalysisReport",
    # API
    "JobStatus",
    "HealthResponse",
    "AnalysisUploadResponse",
    "AnalysisJobResponse",
    # STARTTLS Downgrade
    "DowngradeAssessmentStatus",
    "DowngradeIndicatorType",
    "DowngradeEvidence",
    "DowngradeFinding",
    "DowngradeAnalysisResult",
    # TLS Handshake & Records
    "TLSRecordContentType",
    "TLSRecordVersion",
    "TLSRecordParseStatus",
    "TLSRecord",
    "TLSRecordParseResult",
    "ClientHelloParseStatus",
    "TLSExtension",
    "KeyShareEntry",
    "TLSClientHello",
    "ClientHelloParseResult",
    "ServerHelloParseStatus",
    "ServerHelloKeyShare",
    "TLSServerHello",
    "ServerHelloParseResult",
    # Certificate Analysis & Trust
    "CertificateExtractionStatus",
    "RawExtractedCertificate",
    "CertificateChainExtractionResult",
    "CertificateParseStatus",
    "DistinguishedName",
    "SubjectAlternativeNames",
    "ParsedKeyParameters",
    "ParsedExtension",
    "ParsedCertificate",
    "ParsedCertificateChain",
    "CertificateFindingType",
    "CertificateEvidence",
    "CertificateSecurityFinding",
    "SingleCertificateAudit",
    "CertificateSecurityAuditResult",
    "IdentityStatus",
    "IdentityRelationshipType",
    "IdentityRelationship",
    "IdentityAnalysisResult",
    "TrustValidationStatus",
    "OCSPObservedStatus",
    "OCSPVerificationStatus",
    "CRLEvidenceStatus",
    "TrustAnchorEvidence",
    "CertificateTrustEvidence",
    "OCSPEvidence",
    "CRLEvidence",
    "OfflineTrustResult",
    # Compliance & Vulnerabilities
    "ComplianceStatus",
    "ComplianceEvidence",
    "ComplianceFinding",
    "RuleEvaluationSummary",
    "SessionComplianceReport",
    "MappingType",
    "EvidenceConfidence",
    "WeaknessMapping",
    "VulnerabilityMappingReport",
    # Threat & Posture
    "ThreatCategory",
    "ThreatMappingStatus",
    "MitreAttackReference",
    "ThreatEvidence",
    "ThreatContextMapping",
    "SessionThreatReport",
    "PostureSeverity",
    "PostureDeduction",
    "CryptographicPostureReport",
    # Machine Learning & Explainability
    "MLFeatureVector",
    "AnomalyDetectionMetadata",
    "AnomalyDetectionResult",
    "BatchAnomalyDetectionResult",
    "RiskClassificationMetadata",
    "RiskClassificationResult",
    "BatchRiskClassificationResult",
    "ContributionDirection",
    "SHAPFeatureContribution",
    "GlobalFeatureImportance",
    "SHAPMetadata",
    "SHAPExplanationResult",
    "BatchSHAPExplanationResult",
]