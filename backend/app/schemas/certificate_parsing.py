"""
MailRakhwala X.509 Certificate Parsing Schemas (Step 17)
Structured data contracts for parsed X.509 certificates derived from raw DER objects.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class CertificateParseStatus(str, Enum):
    PARSED = "PARSED"
    MALFORMED_DER = "MALFORMED_DER"
    UNSUPPORTED_STRUCTURE = "UNSUPPORTED_STRUCTURE"
    EMPTY_DER = "EMPTY_DER"
    PARTIAL_PARSE = "PARTIAL_PARSE"


class DistinguishedName(BaseModel):
    """Structured representation of X.509 Subject or Issuer DN."""
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state_or_province: Optional[str] = None
    locality: Optional[str] = None
    email_address: Optional[str] = None
    raw_dn_string: str = Field(..., description="RFC 4514 distinguished name string")
    attributes: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="All parsed DN attribute pairs preserved for forensic inspection"
    )


class SubjectAlternativeNames(BaseModel):
    """Parsed Subject Alternative Name (SAN) extension values."""
    dns_names: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    uris: List[str] = Field(default_factory=list)
    other_names: List[str] = Field(default_factory=list)
    has_san: bool = False


class ParsedKeyParameters(BaseModel):
    """Public key cryptographic parameters observed in the certificate."""
    algorithm: str = Field(..., description="Cryptographic key algorithm (e.g., RSA, EC, DSA, ED25519)")
    key_size_bits: Optional[int] = Field(default=None, ge=0, description="Modulus or field size in bits")
    curve_name: Optional[str] = Field(default=None, description="Curve identifier for EC keys (e.g., secp256r1)")
    exponent: Optional[int] = Field(default=None, description="Public exponent for RSA keys (e.g., 65537)")


class ParsedExtension(BaseModel):
    """Forensic metadata for individual X.509 extensions."""
    oid: str = Field(..., description="Dotted OID string")
    name: str = Field(..., description="Human-readable extension name")
    critical: bool = Field(default=False, description="Whether extension is marked critical")
    value_summary: str = Field(..., description="Deterministic string representation of value")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured extension properties")


class ParsedCertificate(BaseModel):
    """
    Structured X.509 certificate parsed strictly from raw DER bytes.
    Preserves chain ordering, stream context, and forensic traceability from Step 16.
    """
    # Step 16 Forensic Traceability
    certificate_index: int = Field(..., ge=0, description="0-based chain index (0 is end-entity/leaf)")
    stream_id: Optional[str] = Field(default=None, description="Correlated TCP stream ID")
    stream_offset: int = Field(default=0, ge=0, description="Byte offset in handshake payload")
    frame_number: Optional[int] = Field(default=None, description="Captured packet frame number")
    timestamp: Optional[float] = Field(default=None, description="Captured frame timestamp")
    raw_der_sha256: Optional[str] = Field(default=None, description="SHA-256 fingerprint of raw DER")

    # Step 17 Parse Status
    parse_status: CertificateParseStatus = CertificateParseStatus.PARSED
    parse_error: Optional[str] = None

    # Identity
    subject: Optional[DistinguishedName] = None
    issuer: Optional[DistinguishedName] = None
    san: SubjectAlternativeNames = Field(default_factory=SubjectAlternativeNames)

    # Serial Number
    serial_number: Optional[int] = None
    serial_number_hex: Optional[str] = None

    # Temporal Validity
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

    # Cryptographic Parameters
    public_key: Optional[ParsedKeyParameters] = None
    signature_algorithm_oid: Optional[str] = None
    signature_algorithm_name: Optional[str] = None
    signature_hash_algorithm: Optional[str] = None

    # Extensions
    extensions: List[ParsedExtension] = Field(default_factory=list)

    # Forensic Boundaries
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Passive parsing extracts observable certificate metadata without active trust validation.",
            "Certificate expiration, trust paths, and cryptographic strength are audited in subsequent steps."
        ]
    )

    @field_validator("not_before", "not_after")
    @classmethod
    def ensure_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class ParsedCertificateChain(BaseModel):
    """Ordered collection of parsed certificates for a given TLS session."""
    stream_id: str
    total_certificates: int = 0
    certificates: List[ParsedCertificate] = Field(default_factory=list)
    has_parse_failures: bool = False
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Chain ordering reflects the presentation order received in the TLS handshake.",
            "Cryptographic signature verification across parent/child nodes is reserved for Step 18+."
        ]
    )