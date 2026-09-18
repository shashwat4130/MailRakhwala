"""
MailRakhwala Identity & Trust Analyzer Service (Step 19)
Deterministic, passive correlation of TLS SNI, Certificate SAN,
observed mail-server hostnames, and offline context.
"""

from typing import Any, Dict, List, Optional

from app.schemas.certificate_parsing import ParsedCertificate
from app.schemas.identity_analysis import (
    IdentityAnalysisResult,
    IdentityRelationship,
    IdentityRelationshipType,
    IdentityStatus,
)


def match_hostname(candidate: Optional[str], pattern: Optional[str]) -> bool:
    """
    Deterministically compare a candidate hostname against an observed SAN pattern.

    RFC 6125 Section 6.4.3 rules:
    - Case-insensitive comparison
    - Strips optional trailing dots
    - Exact matches on valid fully qualified DNS names
    - Single-label wildcard matching (*.domain.com matches mail.domain.com)
    - Wildcard MUST be the entire leftmost label (*.example.com, NOT mail*.example.com)
    - Wildcard cannot match across multiple labels (*.example.com != a.b.example.com)
    - Wildcard cannot match single-label TLDs (*.com is rejected)
    - Rejects empty strings, IP addresses, and malformed inputs
    """
    if not candidate or not pattern:
        return False

    c_norm = candidate.strip().rstrip(".").lower()
    p_norm = pattern.strip().rstrip(".").lower()

    if not c_norm or not p_norm:
        return False

    if c_norm == p_norm:
        return True

    if "*" not in p_norm:
        return False

    p_labels = p_norm.split(".")
    c_labels = c_norm.split(".")

    if len(p_labels) != len(c_labels):
        return False

    if p_labels[0] != "*":
        return False

    if len(p_labels) < 3:
        return False

    if not c_labels[0]:
        return False

    return p_labels[1:] == c_labels[1:]


class IdentityAnalyzer:
    """Passive identity alignment and contextual trust analyzer."""

    def analyze(
        self,
        cert: ParsedCertificate,
        sni: Optional[str] = None,
        observed_mail_host: Optional[str] = None,
        dns_mx_context: Optional[Dict[str, Any]] = None,
        trust_path_context: Optional[Dict[str, Any]] = None,
    ) -> IdentityAnalysisResult:
        # Strict Fix 1: Only actual DNS SAN entries are used for SAN comparisons.
        # Subject CN is NEVER used as a fallback substitute for SAN.
        san_dns_list: List[str] = []
        if cert.san and cert.san.has_san and cert.san.dns_names:
            san_dns_list = list(cert.san.dns_names)

        relationships: List[IdentityRelationship] = [
            self._evaluate_sni_vs_san(sni, san_dns_list, cert),
            self._evaluate_mail_host_vs_san(observed_mail_host, san_dns_list, cert),
            self._evaluate_sni_vs_mail_host(sni, observed_mail_host, cert),
            self._evaluate_dns_mx(observed_mail_host or sni, dns_mx_context, cert),
            self._evaluate_trust_path(cert, trust_path_context),
        ]

        return IdentityAnalysisResult(
            stream_id=cert.stream_id or "unknown-stream",
            certificate_index=cert.certificate_index,
            raw_der_sha256=cert.raw_der_sha256,
            sni_observed=sni,
            mail_host_observed=observed_mail_host,
            san_entries=san_dns_list,
            relationships=relationships,
            overall_interpretation=self._derive_overall_interpretation(relationships),
            dns_mx_evidence_present=dns_mx_context is not None,
            trust_path_evidence_present=trust_path_context is not None,
        )

    def _evaluate_sni_vs_san(
        self,
        sni: Optional[str],
        san_list: List[str],
        cert: ParsedCertificate,
    ) -> IdentityRelationship:
        common_meta = {
            "certificate_index": cert.certificate_index,
            "raw_der_sha256": cert.raw_der_sha256,
            "frame_number": cert.frame_number,
            "timestamp": cert.timestamp,
        }

        if not sni:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                left_name="TLS ClientHello SNI",
                left_value=None,
                left_source="TLS_CLIENT_HELLO",
                right_name="Certificate SAN DNS",
                right_value=", ".join(san_list) if san_list else None,
                right_source="CERTIFICATE_SAN",
                status=IdentityStatus.UNAVAILABLE,
                explanation="TLS Server Name Indication (SNI) was not present in the captured ClientHello.",
                limitations=["SNI is optional in TLS; absence does not imply a protocol failure."],
                **common_meta,
            )

        if not san_list:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                left_name="TLS ClientHello SNI",
                left_value=sni,
                left_source="TLS_CLIENT_HELLO",
                right_name="Certificate SAN DNS",
                right_value=None,
                right_source="CERTIFICATE_SAN",
                status=IdentityStatus.UNAVAILABLE,
                explanation="No Subject Alternative Name (SAN) DNS entries present in certificate.",
                limitations=["Subject Common Name is not treated as a DNS SAN substitute."],
                **common_meta,
            )

        for san_entry in san_list:
            if match_hostname(sni, san_entry):
                return IdentityRelationship(
                    relationship_type=IdentityRelationshipType.SNI_VS_SAN,
                    left_name="TLS ClientHello SNI",
                    left_value=sni,
                    left_source="TLS_CLIENT_HELLO",
                    right_name="Certificate SAN DNS",
                    right_value=", ".join(san_list),
                    right_source="CERTIFICATE_SAN",
                    status=IdentityStatus.MATCH,
                    matched_entry=san_entry,
                    explanation=f"Observed TLS SNI '{sni}' matches certificate SAN entry '{san_entry}'.",
                    **common_meta,
                )

        return IdentityRelationship(
            relationship_type=IdentityRelationshipType.SNI_VS_SAN,
            left_name="TLS ClientHello SNI",
            left_value=sni,
            left_source="TLS_CLIENT_HELLO",
            right_name="Certificate SAN DNS",
            right_value=", ".join(san_list),
            right_source="CERTIFICATE_SAN",
            status=IdentityStatus.MISMATCH,
            explanation=f"Observed TLS SNI '{sni}' does not match any certificate SAN entries: {san_list}.",
            limitations=["Identity mismatch observed; does not prove an active adversary without further context."],
            **common_meta,
        )

    def _evaluate_mail_host_vs_san(
        self,
        mail_host: Optional[str],
        san_list: List[str],
        cert: ParsedCertificate,
    ) -> IdentityRelationship:
        common_meta = {
            "certificate_index": cert.certificate_index,
            "raw_der_sha256": cert.raw_der_sha256,
            "frame_number": cert.frame_number,
            "timestamp": cert.timestamp,
        }

        if not mail_host:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_HOST_VS_SAN,
                left_name="Observed Mail Hostname",
                left_value=None,
                left_source="SESSION_MAIL_HOST",
                right_name="Certificate SAN DNS",
                right_value=", ".join(san_list) if san_list else None,
                right_source="CERTIFICATE_SAN",
                status=IdentityStatus.UNAVAILABLE,
                explanation="No mail-server hostname was observed in the session or protocol greeting.",
                limitations=["Email protocol banner/greeting was absent or encrypted."],
                **common_meta,
            )

        if not san_list:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_HOST_VS_SAN,
                left_name="Observed Mail Hostname",
                left_value=mail_host,
                left_source="SESSION_MAIL_HOST",
                right_name="Certificate SAN DNS",
                right_value=None,
                right_source="CERTIFICATE_SAN",
                status=IdentityStatus.UNAVAILABLE,
                explanation="No certificate SAN DNS entries available for comparison.",
                limitations=["Subject Common Name is not treated as a DNS SAN substitute."],
                **common_meta,
            )

        for san_entry in san_list:
            if match_hostname(mail_host, san_entry):
                return IdentityRelationship(
                    relationship_type=IdentityRelationshipType.MAIL_HOST_VS_SAN,
                    left_name="Observed Mail Hostname",
                    left_value=mail_host,
                    left_source="SESSION_MAIL_HOST",
                    right_name="Certificate SAN DNS",
                    right_value=", ".join(san_list),
                    right_source="CERTIFICATE_SAN",
                    status=IdentityStatus.MATCH,
                    matched_entry=san_entry,
                    explanation=f"Observed mail-server hostname '{mail_host}' matches certificate SAN entry '{san_entry}'.",
                    **common_meta,
                )

        return IdentityRelationship(
            relationship_type=IdentityRelationshipType.MAIL_HOST_VS_SAN,
            left_name="Observed Mail Hostname",
            left_value=mail_host,
            left_source="SESSION_MAIL_HOST",
            right_name="Certificate SAN DNS",
            right_value=", ".join(san_list),
            right_source="CERTIFICATE_SAN",
            status=IdentityStatus.NEEDS_CONTEXT,
            explanation=(
                f"Observed mail hostname '{mail_host}' differs from certificate SAN entries. "
                "In email routing, server banners frequently reflect relay or internal hostnames rather than public identities."
            ),
            limitations=["Discrepancy between banner host and certificate SAN is common in multi-tenant mail relays."],
            **common_meta,
        )

    def _evaluate_sni_vs_mail_host(
        self,
        sni: Optional[str],
        mail_host: Optional[str],
        cert: ParsedCertificate,
    ) -> IdentityRelationship:
        common_meta = {
            "certificate_index": cert.certificate_index,
            "raw_der_sha256": cert.raw_der_sha256,
            "frame_number": cert.frame_number,
            "timestamp": cert.timestamp,
        }

        if not sni or not mail_host:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_MAIL_HOST,
                left_name="TLS ClientHello SNI",
                left_value=sni,
                left_source="TLS_CLIENT_HELLO",
                right_name="Observed Mail Hostname",
                right_value=mail_host,
                right_source="SESSION_MAIL_HOST",
                status=IdentityStatus.UNAVAILABLE,
                explanation="Both TLS SNI and observed mail hostname are required for correlation.",
                **common_meta,
            )

        if match_hostname(sni, mail_host):
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.SNI_VS_MAIL_HOST,
                left_name="TLS ClientHello SNI",
                left_value=sni,
                left_source="TLS_CLIENT_HELLO",
                right_name="Observed Mail Hostname",
                right_value=mail_host,
                right_source="SESSION_MAIL_HOST",
                status=IdentityStatus.MATCH,
                matched_entry=mail_host,
                explanation=f"TLS SNI '{sni}' exactly aligns with observed mail hostname '{mail_host}'.",
                **common_meta,
            )

        return IdentityRelationship(
            relationship_type=IdentityRelationshipType.SNI_VS_MAIL_HOST,
            left_name="TLS ClientHello SNI",
            left_value=sni,
            left_source="TLS_CLIENT_HELLO",
            right_name="Observed Mail Hostname",
            right_value=mail_host,
            right_source="SESSION_MAIL_HOST",
            status=IdentityStatus.NEEDS_CONTEXT,
            explanation=(
                f"TLS SNI '{sni}' differs from session mail hostname '{mail_host}'. "
                "This frequently occurs in load-balanced clusters, CDN fronting, or relay proxies."
            ),
            limitations=["Difference may be legitimate infrastructure aliasing; context is required."],
            **common_meta,
        )

    def _evaluate_dns_mx(
        self,
        host: Optional[str],
        dns_context: Optional[Dict[str, Any]],
        cert: ParsedCertificate,
    ) -> IdentityRelationship:
        common_meta = {
            "certificate_index": cert.certificate_index,
            "raw_der_sha256": cert.raw_der_sha256,
            "frame_number": cert.frame_number,
            "timestamp": cert.timestamp,
        }

        if not dns_context or "mx_records" not in dns_context:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX,
                left_name="Observed Host/Domain",
                left_value=host,
                left_source="SESSION_METADATA",
                right_name="Captured Offline DNS/MX Records",
                right_value=None,
                right_source="CAPTURED_DNS",
                status=IdentityStatus.UNAVAILABLE,
                explanation="No offline captured DNS/MX evidence is available for this session.",
                limitations=["CrypticMail operates passively and does not issue live DNS queries."],
                **common_meta,
            )

        mx_records: List[str] = dns_context.get("mx_records", [])
        explicit_contradiction = dns_context.get("explicit_contradiction", False)

        if not mx_records:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX,
                left_name="Observed Host/Domain",
                left_value=host,
                left_source="SESSION_METADATA",
                right_name="Captured Offline DNS/MX Records",
                right_value=None,
                right_source="CAPTURED_DNS",
                status=IdentityStatus.UNAVAILABLE,
                explanation="Captured DNS record set contains no MX entries.",
                limitations=["Absence of MX records in captured packet stream does not imply a routing failure."],
                **common_meta,
            )

        # Direct supported match
        if host and any(match_hostname(host, mx) for mx in mx_records):
            matched_mx = next(mx for mx in mx_records if match_hostname(host, mx))
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX,
                left_name="Observed Host/Domain",
                left_value=host,
                left_source="SESSION_METADATA",
                right_name="Captured Offline DNS/MX Records",
                right_value=", ".join(mx_records),
                right_source="CAPTURED_DNS",
                status=IdentityStatus.MATCH,
                matched_entry=matched_mx,
                raw_reference=f"mx_records={mx_records}",
                explanation=f"Observed host '{host}' directly matches captured MX record '{matched_mx}'.",
                **common_meta,
            )

        # Only return MISMATCH if the offline evidence explicitly establishes a direct contradiction
        if explicit_contradiction:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX,
                left_name="Observed Host/Domain",
                left_value=host,
                left_source="SESSION_METADATA",
                right_name="Captured Offline DNS/MX Records",
                right_value=", ".join(mx_records),
                right_source="CAPTURED_DNS",
                status=IdentityStatus.MISMATCH,
                raw_reference=f"mx_records={mx_records}",
                explanation=f"Supplied DNS evidence explicitly contradicts observed host '{host}'.",
                limitations=["Direct contradiction explicitly asserted by offline DNS evidence."],
                **common_meta,
            )

        # Conservative semantics (Fix 3): absence of direct match in MX list is NEEDS_CONTEXT, NOT MISMATCH
        return IdentityRelationship(
            relationship_type=IdentityRelationshipType.MAIL_IDENTITY_VS_DNS_MX,
            left_name="Observed Host/Domain",
            left_value=host,
            left_source="SESSION_METADATA",
            right_name="Captured Offline DNS/MX Records",
            right_value=", ".join(mx_records),
            right_source="CAPTURED_DNS",
            status=IdentityStatus.NEEDS_CONTEXT,
            raw_reference=f"mx_records={mx_records}",
            explanation=(
                f"Observed host '{host}' was not found in captured MX record set ({mx_records}). "
                "In email architectures, MX records designate domain routing destinations, which often differ "
                "from outbound relays, load balancers, or server banner hostnames."
            ),
            limitations=[
                "Discrepancy between host and MX target does not represent an identity mismatch.",
                "Requires additional domain topology or routing context."
            ],
            **common_meta,
        )

    def _evaluate_trust_path(
        self,
        cert: ParsedCertificate,
        trust_context: Optional[Dict[str, Any]],
    ) -> IdentityRelationship:
        common_meta = {
            "certificate_index": cert.certificate_index,
            "raw_der_sha256": cert.raw_der_sha256,
            "frame_number": cert.frame_number,
            "timestamp": cert.timestamp,
        }

        if not trust_context or "trust_path_status" not in trust_context:
            return IdentityRelationship(
                relationship_type=IdentityRelationshipType.CERTIFICATE_VS_TRUST_PATH,
                left_name="Presented Certificate",
                left_value=cert.raw_der_sha256[:16] if cert.raw_der_sha256 else "Unknown Fingerprint",
                left_source="X509_CERTIFICATE",
                right_name="Local Trust-Path Context",
                right_value=None,
                right_source="LOCAL_TRUST_STORE",
                status=IdentityStatus.UNAVAILABLE,
                explanation="No local trust-path or CA root-store context was supplied for this session.",
                limitations=["Offline CA root store validation and chain building are performed in Step 20."],
                **common_meta,
            )

        tp_status = str(trust_context.get("trust_path_status", "UNKNOWN"))
        # Fix 2: Step 19 surfaces trust-path context as NEEDS_CONTEXT (never MATCH) and disclaims independent validation
        return IdentityRelationship(
            relationship_type=IdentityRelationshipType.CERTIFICATE_VS_TRUST_PATH,
            left_name="Presented Certificate",
            left_value=cert.raw_der_sha256[:16] if cert.raw_der_sha256 else "Unknown Fingerprint",
            left_source="X509_CERTIFICATE",
            right_name="Local Trust-Path Context",
            right_value=tp_status,
            right_source="LOCAL_TRUST_STORE",
            status=IdentityStatus.NEEDS_CONTEXT,
            raw_reference=str(trust_context),
            explanation=f"Surfacing supplied trust-path context ('{tp_status}'). Step 19 does not independently validate certificate trust or chain anchors.",
            limitations=[
                "Trust context is informational and externally supplied.",
                "Step 19 does not claim the certificate is cryptographically trusted; formal trust validation is reserved for Step 20."
            ],
            **common_meta,
        )

    def _derive_overall_interpretation(self, relationships: List[IdentityRelationship]) -> str:
        statuses = [r.status for r in relationships]
        if IdentityStatus.MISMATCH in statuses:
            return "One or more direct identity discrepancies observed across session parameters. Review context."
        if IdentityStatus.NEEDS_CONTEXT in statuses:
            return "Identity parameters require infrastructure context (e.g. multi-tenant relay or load balancer)."
        if IdentityStatus.MATCH in statuses and all(s in (IdentityStatus.MATCH, IdentityStatus.UNAVAILABLE) for s in statuses):
            return "Observed identity indicators consistently align across available parameters."
        return "Identity correlation is inconclusive due to unavailable indicators."


identity_analyzer = IdentityAnalyzer()