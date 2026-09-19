"""
Pydantic schemas for Step 24 - Cryptographic Posture & Risk Engine.

Provides simple, transparent 0-100 posture scoring with deterministic deduction breakdowns.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PostureSeverity(str, Enum):
    """Overall posture severity derived directly from the 0-100 score."""
    LOW = "LOW"            # 80 - 100
    MEDIUM = "MEDIUM"      # 60 - 79
    HIGH = "HIGH"          # 30 - 59
    CRITICAL = "CRITICAL"  # 0 - 29


class PostureDeduction(BaseModel):
    """Transparent record of a single penalty deduction applied to the score."""
    rule_id: str = Field(..., description="Deduction rule ID from posture catalog")
    title: str = Field(..., description="Human-readable title of the penalty reason")
    penalty: int = Field(..., ge=0, description="Deduction points subtracted from base score")
    upstream_rule_id: str = Field(..., description="Step 21 Compliance rule ID")
    finding_id: str = Field(..., description="Step 21 Compliance finding ID")
    weakness_id: Optional[str] = Field(None, description="Step 22 Weakness mapping ID if available")
    threat_mapping_id: Optional[str] = Field(None, description="Step 23 Threat context ID if available")
    observed_property: str = Field(..., description="Observed cryptographic property")
    observed_value: Any = Field(..., description="Observed property value")
    certificate_index: Optional[int] = None
    stream_id: str
    description: str


class CryptographicPostureReport(BaseModel):
    """Complete, transparent session cryptographic posture assessment."""
    session_id: str
    stream_id: str
    posture_score: int = Field(..., ge=0, le=100, description="Final posture score between 0 and 100")
    severity: PostureSeverity = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL posture risk")
    base_score: int = Field(default=100, description="Baseline score prior to deductions")
    total_penalty: int = Field(..., ge=0, description="Sum of all deduplicated penalties")
    deductions: List[PostureDeduction] = Field(default_factory=list, description="Breakdown of deductions applied")
    evaluated_findings_count: int = 0
    compliant_findings_count: int = 0
    non_compliant_findings_count: int = 0
    unknown_findings_count: int = 0
    deterministic: bool = True
    engine_version: str = "1.0.0"
    limitations: str = "Deterministic evaluation of observed passive network traffic. Not an attack likelihood model."