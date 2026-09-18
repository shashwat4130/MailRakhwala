"""
MailRakhwala Deterministic Cryptographic Compliance Engine Schemas (Step 21)
Data contracts for evaluating observed forensic telemetry against deterministic security rules.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

from app.schemas.domain import FindingCategory, SeverityLevel


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"          # PASS
    NON_COMPLIANT = "NON_COMPLIANT"  # FAIL
    UNKNOWN = "UNKNOWN"              # Insufficient evidence
    NOT_APPLICABLE = "NOT_APPLICABLE"# Rule does not apply to protocol/context


class ComplianceEvidence(BaseModel):
    """Traceable forensic evidence backing an authoritative compliance finding."""
    stream_id: str
    packet_number: Optional[int] = None
    timestamp: Optional[float] = None
    certificate_index: Optional[int] = None
    raw_der_sha256: Optional[str] = None
    observed_property: str = Field(..., description="The observed attribute or parameter name")
    observed_value: Any = Field(..., description="The raw or normalized value observed")
    reference_value: Optional[Any] = Field(default=None, description="The expected standard baseline or threshold")
    rule_id: str = Field(..., description="Authoritative rule identifier from Step 4 rulebook")
    source_component: str = Field(default="PCAP_OBSERVATION", description="Pipeline stage producing the evidence")


class ComplianceFinding(BaseModel):
    """Authoritative, deterministic finding resulting from an authoritative rule evaluation."""
    finding_id: str = Field(..., description="Deterministic unique finding ID incorporating rule, stream, and evidence")
    rule_id: str = Field(..., description="Authoritative rulebook rule identifier (e.g. RULE-TLS-002)")
    category: FindingCategory
    title: str
    description: str
    severity: SeverityLevel
    status: ComplianceStatus
    recommendation: str
    evidence: ComplianceEvidence
    deterministic: bool = Field(default=True, description="Always true; rule output is 100% reproducible")
    engine_version: str = Field(default="21.0.0", description="Compliance engine rulebook version")
    limitations: List[str] = Field(default_factory=list)


class RuleEvaluationSummary(BaseModel):
    """Aggregate statistics for an authoritative compliance evaluation run."""
    total_rules_evaluated: int = 0
    total_findings_generated: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    unknown_count: int = 0
    not_applicable_count: int = 0


class SessionComplianceReport(BaseModel):
    """Consolidated compliance report for a captured email/TLS session."""
    stream_id: str
    engine_version: str = "21.0.0"
    reference_time: Optional[datetime] = None
    overall_compliance: ComplianceStatus
    summary: RuleEvaluationSummary
    findings: List[ComplianceFinding] = Field(default_factory=list)
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Deterministic compliance rules evaluate observed network evidence only.",
            "Missing parameters are reported as UNKNOWN or NOT_APPLICABLE rather than failure.",
            "Findings describe observed non-compliance and do not infer active attacker presence."
        ]
    )

    @field_validator("reference_time")
    @classmethod
    def ensure_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v