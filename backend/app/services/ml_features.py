from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.schemas.ml_features import MLFeatureVector


class MLFeatureEngineeringService:
    """
    Step 25: Converts Step 21-24 results and session context into a deterministic
    19-dimensional numerical feature vector for downstream ML scoring.
    """

    @staticmethod
    def encode_tls_version(version: Optional[str]) -> float:
        """
        Original Step 25 Feature Contract:
          TLS 1.3       -> 4.0
          TLS 1.2       -> 3.0
          TLS 1.1       -> 2.0
          TLS 1.0       -> 1.0
          SSL 3.0 / 2.0 -> 0.0
          Unknown       -> -1.0
        """
        if not version or not str(version).strip():
            return -1.0
        v = str(version).strip().upper()
        if "1.3" in v or "TLSV1.3" in v:
            return 4.0
        if "1.2" in v or "TLSV1.2" in v:
            return 3.0
        if "1.1" in v or "TLSV1.1" in v:
            return 2.0
        if "1.0" in v or "TLSV1.0" in v:
            return 1.0
        if "SSL 3.0" in v or "SSLV3" in v or "SSL 2.0" in v or "SSLV2" in v:
            return 0.0
        return -1.0

    @staticmethod
    def encode_cipher_suite(cipher: Optional[str]) -> float:
        """
        Scores cipher suites:
          Modern AEAD (GCM, CHACHA20, POLY1305, CCM) -> 3.0
          Legacy/CBC/3DES                              -> 1.0
          Broken/Insecure (NULL, RC4, EXPORT, DES40)   -> 0.0
          Unknown / Missing                            -> -1.0
        """
        if not cipher or not cipher.strip():
            return -1.0
        c = cipher.upper()
        if any(weak in c for weak in ("NULL", "RC4", "EXPORT", "DES40")):
            return 0.0
        if any(legacy in c for legacy in ("3DES", "CBC", "DES")):
            return 1.0
        if any(modern in c for modern in ("GCM", "CHACHA20", "POLY1305", "CCM")):
            return 3.0
        return -1.0

    @staticmethod
    def encode_key_exchange(kex: Optional[str]) -> Tuple[float, float]:
        """
        Determines key exchange strength and forward secrecy:
          (strength, pfs_enabled)
          ECDHE, DHE, X25519 -> (2.0, 1.0)
          Static RSA          -> (0.0, 0.0)
          Unknown / ED25519   -> (-1.0, -1.0)
        """
        if not kex or not kex.strip():
            return -1.0, -1.0
        k = kex.upper()
        # ED25519 is a signature scheme and must not imply key exchange or PFS
        if "ECDHE" in k or "DHE" in k or "X25519" in k:
            return 2.0, 1.0
        if "RSA" in k and "ECDHE" not in k and "DHE" not in k:
            return 0.0, 0.0
        return -1.0, -1.0

    @staticmethod
    def encode_signature_strength(sig_algo: Optional[str]) -> float:
        if not sig_algo or not sig_algo.strip():
            return -1.0
        s = sig_algo.upper()
        if any(bad in s for bad in ("MD5", "MD2", "SHA1", "SHA-1")):
            return 0.0
        if any(good in s for good in ("SHA256", "SHA384", "SHA512", "ED25519", "ECDSA")):
            return 2.0
        return -1.0

    def extract_features(
        self,
        stream_id: str,
        session_context: Optional[Dict[str, Any]] = None,
        compliance_findings: Optional[List[Any]] = None,
        weakness_mappings: Optional[List[Any]] = None,
        threat_mappings: Optional[List[Any]] = None,
        posture_report: Optional[Any] = None,
    ) -> MLFeatureVector:
        ctx = session_context or {}

        # 1. Handshake & Cryptographic Suite
        tls_version_numeric = self.encode_tls_version(ctx.get("tls_version"))
        cipher_security_score = self.encode_cipher_suite(ctx.get("cipher_suite"))

        explicit_kex = ctx.get("key_exchange")
        if not explicit_kex and ctx.get("cipher_suite"):
            c_suite = str(ctx.get("cipher_suite")).upper()
            if "ECDHE" in c_suite:
                explicit_kex = "ECDHE"
            elif "DHE" in c_suite:
                explicit_kex = "DHE"
            elif "RSA" in c_suite:
                explicit_kex = "RSA"

        key_exchange_strength, pfs_enabled = self.encode_key_exchange(explicit_kex)

        # 2. Certificate Details
        cert_info = ctx.get("certificate_info") or {}
        raw_key_size = cert_info.get("key_size") or ctx.get("certificate_key_size")
        try:
            certificate_key_size = float(raw_key_size) if raw_key_size is not None else -1.0
        except (ValueError, TypeError):
            certificate_key_size = -1.0

        sig_algo = cert_info.get("signature_algorithm") or ctx.get("signature_algorithm")
        certificate_signature_strength = self.encode_signature_strength(sig_algo)

        def bool_to_float(val: Optional[bool]) -> float:
            if val is True:
                return 1.0
            if val is False:
                return 0.0
            return -1.0

        certificate_validity_status = bool_to_float(
            cert_info.get("is_valid") if "is_valid" in cert_info else ctx.get("cert_valid")
        )
        san_present = bool_to_float(
            cert_info.get("san_present") if "san_present" in cert_info else ctx.get("san_present")
        )
        hostname_match_status = bool_to_float(
            cert_info.get("hostname_match") if "hostname_match" in cert_info else ctx.get("hostname_match")
        )
        trust_validation_status = bool_to_float(
            cert_info.get("is_trusted") if "is_trusted" in cert_info else ctx.get("is_trusted")
        )
        revocation_raw = cert_info.get("is_revoked") if "is_revoked" in cert_info else ctx.get("is_revoked")
        revocation_status = bool_to_float(revocation_raw)
        # Invert: 0.0 means revoked, 1.0 means verified clean, -1.0 remains unknown
        if revocation_status == 1.0:
            revocation_status = 0.0
        elif revocation_status == 0.0:
            revocation_status = 1.0

        # 3. Protocol Downgrade
        starttls_downgrade = bool_to_float(ctx.get("starttls_downgrade"))

        # 4. Aggregations (Steps 21 - 24)
        c_findings = compliance_findings or []
        violation_count = 0
        unknown_count = 0
        high_critical_count = 0

        for f in c_findings:
            raw_status = getattr(f, "status", None) or (f.get("status") if isinstance(f, dict) else None)
            status_val = getattr(raw_status, "value", raw_status)
            status_str = str(status_val).upper() if status_val is not None else ""

            raw_severity = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)
            sev_val = getattr(raw_severity, "value", raw_severity)
            sev_str = str(sev_val).upper() if sev_val is not None else ""

            if status_str == "NON_COMPLIANT":
                violation_count += 1
                if sev_str in ("HIGH", "CRITICAL"):
                    high_critical_count += 1
            elif status_str == "UNKNOWN":
                unknown_count += 1

        compliance_violation_count = float(violation_count)
        unknown_finding_count = float(unknown_count)
        high_critical_finding_count = float(high_critical_count)

        w_mappings = weakness_mappings or []
        vulnerability_count = float(len(w_mappings))

        t_mappings = threat_mappings or []
        threat_mapping_count = float(len(t_mappings))

        # Cryptographic Security Score propagation from Step 24
        if posture_report is not None:
            score = getattr(posture_report, "posture_score", None)
            if score is None and isinstance(posture_report, dict):
                score = posture_report.get("posture_score")
            cryptographic_security_score = float(score) if score is not None else -1.0
        else:
            cryptographic_security_score = -1.0

        # 5. Client Metadata
        ja4_str = ctx.get("ja4") or ctx.get("ja4_fingerprint")
        ja4_available = 1.0 if (ja4_str and str(ja4_str).strip()) else 0.0

        return MLFeatureVector(
            stream_id=stream_id,
            tls_version_numeric=tls_version_numeric,
            cipher_security_score=cipher_security_score,
            key_exchange_strength=key_exchange_strength,
            pfs_enabled=pfs_enabled,
            certificate_key_size=certificate_key_size,
            certificate_signature_strength=certificate_signature_strength,
            certificate_validity_status=certificate_validity_status,
            san_present=san_present,
            hostname_match_status=hostname_match_status,
            trust_validation_status=trust_validation_status,
            revocation_status=revocation_status,
            starttls_downgrade=starttls_downgrade,
            compliance_violation_count=compliance_violation_count,
            unknown_finding_count=unknown_finding_count,
            high_critical_finding_count=high_critical_finding_count,
            vulnerability_count=vulnerability_count,
            threat_mapping_count=threat_mapping_count,
            cryptographic_security_score=cryptographic_security_score,
            ja4_available=ja4_available,
        )