"""
Pydantic schemas for Step 23 - Threat Mapping & Evidence Correlation.

Maintains strict semantic separation between:
WEAKNESS != VULNERABILITY != THREAT RELEVANCE != ATT&CK TECHNIQUE EXECUTION != CONFIRMED ATTACK
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Authoritative threat context categories for passive cryptographic forensics."""
    DOWNGRADE_RELEVANCE = "DOWNGRADE_RELEVANCE"
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    INTERCEPTION_RELEVANCE = "INTERCEPTION_RELEVANCE"
    CREDENTIAL_CONFIDENTIALITY_RELEVANCE = "CREDENTIAL_CONFIDENTIALITY_RELEVANCE"
    CERTIFICATE_TRUST_ABUSE_RELEVANCE = "CERTIFICATE_TRUST_ABUSE_RELEVANCE"
    CRYPTOGRAPHIC_CONFIGURATION_ABUSE = "CRYPTOGRAPHIC_CONFIGURATION_ABUSE"
    LEGACY_PROTOCOL_EXPOSURE = "LEGACY_PROTOCOL_EXPOSURE"
    REVOCATION_INVALIDITY_RELEVANCE = "REVOCATION_INVALIDITY_RELEVANCE"


class ThreatMappingStatus(str, Enum):
    """Status indicating the degree of evidential support."""
    CONFIRMED_FROM_EVIDENCE = "CONFIRMED_FROM_EVIDENCE"
    POTENTIAL_RELEVANCE = "POTENTIAL_RELEVANCE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MitreAttackReference(BaseModel):
    """Local, deterministic MITRE ATT&CK reference."""
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID, e.g., T1040")
    technique_name: str = Field(..., description="Technique name")
    tactic: Optional[str] = Field(None, description="Primary tactic")
    url: Optional[str] = Field(None, description="Static reference URL")


class ThreatEvidence(BaseModel):
    """Preserved upstream forensic evidence linkage."""
    stream_id: str
    packet_number: Optional[int] = None
    timestamp: Optional[float] = None
    certificate_index: Optional[int] = None
    raw_der_sha256: Optional[str] = None
    upstream_finding_id: str
    upstream_rule_id: str
    upstream_mapping_id: str
    upstream_identifier: str
    observed_property: str
    observed_value: Any
    reference_value: Optional[Any] = None
    source_component: str = "Step22_WeaknessMapping"
    threat_rule_id: str


class ThreatContextMapping(BaseModel):
    """Evidence-backed threat context finding."""
    threat_mapping_id: str = Field(..., description="Deterministic SHA-256 identifier")
    rule_id: str = Field(..., description="Threat catalog rule ID applied")
    category: ThreatCategory
    title: str
    description: str
    status: ThreatMappingStatus
    evidence: ThreatEvidence
    upstream_finding_id: str
    upstream_mapping_id: str
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    mitre_attack: Optional[MitreAttackReference] = None
    limitations: str
    references: List[str] = Field(default_factory=list)
    deterministic: bool = True
    engine_version: str = "1.0.0"


class SessionThreatReport(BaseModel):
    """Structured threat report for a network session."""
    session_id: str
    stream_id: str
    engine_version: str = "1.0.0"
    threat_mappings: List[ThreatContextMapping] = Field(default_factory=list)
    total_threat_mappings: int = 0
    category_counts: Dict[str, int] = Field(default_factory=dict)
    status_counts: Dict[str, int] = Field(default_factory=dict)
    mitre_technique_counts: Dict[str, int] = Field(default_factory=dict)
    deterministic: bool = True