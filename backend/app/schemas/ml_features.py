from __future__ import annotations

from typing import Any, Dict, List
from pydantic import BaseModel, Field


class MLFeatureVector(BaseModel):
    """
    Step 25: 19-Dimensional Deterministic Feature Vector for Machine Learning ingestion.
    Encodes protocol properties, certificate status, Step 21 compliance,
    Step 22 weaknesses, Step 23 threats, and Step 24 cryptographic posture score.
    """
    stream_id: str = Field(..., description="Unique identifier for the session/stream")

    # 1. Protocol & Handshake (Features 1 - 4)
    tls_version_numeric: float = Field(
        ...,
        description="Encoded TLS version (TLS 1.3 -> 4.0, TLS 1.2 -> 3.0, TLS 1.1 -> 2.0, TLS 1.0 -> 1.0, SSL 3.0/2.0 -> 0.0, Unknown -> -1.0)",
    )
    cipher_security_score: float = Field(
        ...,
        description="Cipher security rating (Modern -> 3.0, Legacy/Weak -> 1.0, Broken/Insecure -> 0.0, Unknown/Missing -> -1.0)",
    )
    key_exchange_strength: float = Field(
        ...,
        description="Key exchange strength (ECDHE/DHE/X25519 -> 2.0, Static RSA -> 0.0, Unknown -> -1.0)",
    )
    pfs_enabled: float = Field(
        ...,
        description="Perfect Forward Secrecy flag (1.0 -> Enabled, 0.0 -> Disabled, -1.0 -> Unknown)",
    )

    # 2. Certificate & Identity Validation (Features 5 - 11)
    certificate_key_size: float = Field(
        ...,
        description="Key size in bits (e.g. 2048.0, 4096.0, 256.0; missing/unknown -> -1.0)",
    )
    certificate_signature_strength: float = Field(
        ...,
        description="Signature security (SHA256/384/512/ED25519 -> 2.0, SHA1/MD5 -> 0.0, Unknown -> -1.0)",
    )
    certificate_validity_status: float = Field(
        ...,
        description="Validity status (1.0 -> Valid, 0.0 -> Expired/NotYetValid, -1.0 -> Unknown)",
    )
    san_present: float = Field(
        ...,
        description="Subject Alternative Name present (1.0 -> Yes, 0.0 -> No, -1.0 -> Unknown)",
    )
    hostname_match_status: float = Field(
        ...,
        description="Hostname matches certificate (1.0 -> Match, 0.0 -> Mismatch, -1.0 -> Unknown)",
    )
    trust_validation_status: float = Field(
        ...,
        description="Trust chain status (1.0 -> Trusted, 0.0 -> Self-signed/Untrusted, -1.0 -> Unknown)",
    )
    revocation_status: float = Field(
        ...,
        description="Revocation check (1.0 -> Good/Not Revoked, 0.0 -> Revoked, -1.0 -> Unknown/Unchecked)",
    )

    # 3. Protocol Downgrade / Exploits (Feature 12)
    starttls_downgrade: float = Field(
        ...,
        description="STARTTLS downgrade anomaly (1.0 -> Downgrade detected, 0.0 -> Normal/Clean, -1.0 -> Unknown)",
    )

    # 4. Pipeline Aggregations from Steps 21-24 (Features 13 - 18)
    compliance_violation_count: float = Field(
        ...,
        description="Total confirmed NON_COMPLIANT findings from Step 21",
    )
    unknown_finding_count: float = Field(
        ...,
        description="Total findings flagged with UNKNOWN status from Step 21",
    )
    high_critical_finding_count: float = Field(
        ...,
        description="Count of NON_COMPLIANT findings with HIGH or CRITICAL severity",
    )
    vulnerability_count: float = Field(
        ...,
        description="Count of mapped CWEs/CVEs from Step 22",
    )
    threat_mapping_count: float = Field(
        ...,
        description="Count of mapped ATT&CK threats/mitigations from Step 23",
    )
    cryptographic_security_score: float = Field(
        ...,
        description="Propagated Step 24 Posture Score (0.0 to 100.0, -1.0 if unavailable)",
    )

    # 5. Client Metadata (Feature 19)
    ja4_available: float = Field(
        ...,
        description="JA4 / TLS client fingerprint presence (1.0 -> Present, 0.0 -> Absent)",
    )

    def to_feature_list(self) -> List[float]:
        """
        Returns an ordered, 19-dimensional numerical list of features.
        Deterministic and immutable ordering for ML model ingestion.
        """
        return [
            self.tls_version_numeric,
            self.cipher_security_score,
            self.key_exchange_strength,
            self.pfs_enabled,
            self.certificate_key_size,
            self.certificate_signature_strength,
            self.certificate_validity_status,
            self.san_present,
            self.hostname_match_status,
            self.trust_validation_status,
            self.revocation_status,
            self.starttls_downgrade,
            self.compliance_violation_count,
            self.unknown_finding_count,
            self.high_critical_finding_count,
            self.vulnerability_count,
            self.threat_mapping_count,
            self.cryptographic_security_score,
            self.ja4_available,
        ]

    def to_feature_dict(self) -> Dict[str, float]:
        """
        Returns a dictionary mapping feature names to their numerical values.
        """
        return {
            "tls_version_numeric": self.tls_version_numeric,
            "cipher_security_score": self.cipher_security_score,
            "key_exchange_strength": self.key_exchange_strength,
            "pfs_enabled": self.pfs_enabled,
            "certificate_key_size": self.certificate_key_size,
            "certificate_signature_strength": self.certificate_signature_strength,
            "certificate_validity_status": self.certificate_validity_status,
            "san_present": self.san_present,
            "hostname_match_status": self.hostname_match_status,
            "trust_validation_status": self.trust_validation_status,
            "revocation_status": self.revocation_status,
            "starttls_downgrade": self.starttls_downgrade,
            "compliance_violation_count": self.compliance_violation_count,
            "unknown_finding_count": self.unknown_finding_count,
            "high_critical_finding_count": self.high_critical_finding_count,
            "vulnerability_count": self.vulnerability_count,
            "threat_mapping_count": self.threat_mapping_count,
            "cryptographic_security_score": self.cryptographic_security_score,
            "ja4_available": self.ja4_available,
        }