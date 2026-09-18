"""
MailRakhwala Core Domain Data Contracts (Step 3 & Step 15 extensions)
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class TriState(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_bool(cls, value: Optional[bool]) -> "TriState":
        if value is True:
            return cls.TRUE
        if value is False:
            return cls.FALSE
        return cls.UNKNOWN


class MailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class TransportSecurityMode(str, Enum):
    CLEARTEXT = "CLEARTEXT"
    EXPLICIT_STARTTLS = "EXPLICIT_STARTTLS"
    IMPLICIT_TLS = "IMPLICIT_TLS"
    UNKNOWN = "UNKNOWN"


class StarttlsState(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    ADVERTISED = "advertised"
    REQUESTED = "requested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DOWNGRADE_SUSPECTED = "downgrade_suspected"
    UNKNOWN = "unknown"


class KeyExchangeType(str, Enum):
    ECDHE = "ECDHE"
    DHE = "DHE"
    RSA = "RSA"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    PROTOCOL_FLOW = "PROTOCOL_FLOW"
    STARTTLS_SECURITY = "STARTTLS_SECURITY"
    TLS_VERSION = "TLS_VERSION"
    CIPHER_SUITE = "CIPHER_SUITE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE_VALIDITY = "CERTIFICATE_VALIDITY"
    CERTIFICATE_CHAIN = "CERTIFICATE_CHAIN"
    IDENTITY_ALIGNMENT = "IDENTITY_ALIGNMENT"
    GENERAL = "GENERAL"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
    CONFIRMED = "HIGH"
    CONFIRMED_OBSERVED = "HIGH"


class EvidenceRecord(BaseModel):
    field_name: str = Field(..., description="Observed parameter name")
    observed_value: Any = Field(..., description="Observed raw or parsed value")
    expected_value: Optional[Any] = Field(default=None, description="Expected standard baseline")
    packet_number: Optional[int] = Field(default=None, ge=1, description="1-based frame number")
    stream_index: Optional[int] = Field(default=None, ge=0, description="TCP stream index")
    protocol_context: Optional[str] = Field(default=None, description="Protocol layer")
    timestamp: Optional[datetime] = Field(default=None, description="Packet capture timestamp (UTC)")

    @field_validator("timestamp")
    @classmethod
    def ensure_utc_evidence_time(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class ConnectionMetadata(BaseModel):
    session_id: str = Field(..., description="Unique TCP stream ID")
    stream_index: Optional[int] = Field(default=None, ge=0, description="Conversation index")
    source_ip: IPvAnyAddress = Field(..., description="Client IP address")
    destination_ip: IPvAnyAddress = Field(..., description="Server IP address")
    source_port: int = Field(..., ge=1, le=65535, description="Client port (1-65535)")
    destination_port: int = Field(..., ge=1, le=65535, description="Server port (1-65535)")
    protocol: MailProtocol = Field(default=MailProtocol.UNKNOWN, description="Application protocol")
    transport_security: TransportSecurityMode = Field(default=TransportSecurityMode.UNKNOWN)
    starttls_state: StarttlsState = Field(default=StarttlsState.UNKNOWN)
    start_time: datetime = Field(..., description="UTC start timestamp")
    end_time: Optional[datetime] = Field(default=None, description="UTC end timestamp")

    @field_validator("start_time", "end_time")
    @classmethod
    def ensure_utc_connection_time(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class KeyExchangeAnalysis(BaseModel):
    exchange_type: KeyExchangeType = Field(default=KeyExchangeType.UNKNOWN)
    has_forward_secrecy: TriState = Field(default=TriState.UNKNOWN)
    named_group: Optional[str] = Field(default=None)
    named_group_id: Optional[int] = Field(default=None)
    dh_param_bits: Optional[int] = Field(default=None, ge=0)
    stream_id: Optional[str] = Field(default=None)
    negotiated_version: Optional[int] = Field(default=None)
    selected_cipher_suite_id: Optional[int] = Field(default=None)
    selected_cipher_suite_name: Optional[str] = Field(default=None)
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(
        default_factory=lambda: [
            "PFS classification is evaluated strictly from observed passive TLS handshake parameters.",
            "Passive network analysis cannot verify endpoint private key security or operational memory sanitization."
        ]
    )


class TLSAnalysis(BaseModel):
    tls_version: Optional[str] = Field(default=None)
    cipher_suite: Optional[str] = Field(default=None)
    offered_cipher_suites: List[str] = Field(default_factory=list)
    server_name_indication: Optional[str] = Field(default=None)
    alpn_negotiated: Optional[str] = Field(default=None)
    signature_algorithm: Optional[str] = Field(default=None)
    key_exchange: KeyExchangeAnalysis = Field(default_factory=KeyExchangeAnalysis)
    handshake_complete: TriState = Field(default=TriState.UNKNOWN)


class CertificateAudit(BaseModel):
    subject_dn: Optional[str] = Field(default=None)
    issuer_dn: Optional[str] = Field(default=None)
    subject_alternative_names: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = Field(default=None)
    not_before: Optional[datetime] = Field(default=None)
    not_after: Optional[datetime] = Field(default=None)
    public_key_algorithm: Optional[str] = Field(default=None)
    public_key_bits: Optional[int] = Field(default=None, ge=0)
    signature_algorithm: Optional[str] = Field(default=None)
    is_self_signed: TriState = Field(default=TriState.UNKNOWN)
    is_expired: TriState = Field(default=TriState.UNKNOWN)
    chain_valid: TriState = Field(default=TriState.UNKNOWN)
    sni_matches_san: TriState = Field(default=TriState.UNKNOWN)

    @field_validator("not_before", "not_after")
    @classmethod
    def ensure_utc_cert_time(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class Finding(BaseModel):
    finding_id: str = Field(...)
    category: FindingCategory = Field(...)
    title: str = Field(...)
    severity: SeverityLevel = Field(...)
    description: str = Field(...)
    session_id: Optional[str] = Field(default=None)
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    recommendation: str = Field(...)


class RiskAssessment(BaseModel):
    numeric_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel = Field(...)
    scoring_version: str = Field(default="1.0.0")
    contributing_finding_ids: List[str] = Field(default_factory=list)


class PostureReport(BaseModel):
    analysis_id: str = Field(...)
    capture_filename: str = Field(...)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sessions: List[ConnectionMetadata] = Field(default_factory=list)
    tls_observations: List[TLSAnalysis] = Field(default_factory=list)
    certificate_observations: List[CertificateAudit] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = Field(default=None)

    @field_validator("created_at")
    @classmethod
    def ensure_utc_created_time(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v