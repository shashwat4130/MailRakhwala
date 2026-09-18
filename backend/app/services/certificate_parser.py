"""
MailRakhwala X.509 Certificate Parser Service (Step 17)
Parses raw DER certificate objects into structured, typed metadata models.
"""

import hashlib
from datetime import timezone
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.schemas.certificate_extraction import (
    CertificateChainExtractionResult,
    RawExtractedCertificate,
)
from app.schemas.certificate_parsing import (
    CertificateParseStatus,
    DistinguishedName,
    ParsedCertificate,
    ParsedCertificateChain,
    ParsedExtension,
    ParsedKeyParameters,
    SubjectAlternativeNames,
)

OID_NAME_MAP: Dict[x509.ObjectIdentifier, str] = {
    NameOID.COMMON_NAME: "common_name",
    NameOID.ORGANIZATION_NAME: "organization",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizational_unit",
    NameOID.COUNTRY_NAME: "country",
    NameOID.STATE_OR_PROVINCE_NAME: "state_or_province",
    NameOID.LOCALITY_NAME: "locality",
    NameOID.EMAIL_ADDRESS: "email_address",
}


class CertificateParser:
    """Passive, deterministic parser translating DER X.509 certificates to structured models."""

    def parse_chain(self, extraction_result: CertificateChainExtractionResult) -> ParsedCertificateChain:
        """Parse all raw certificates preserved in chain order."""
        parsed_certs: List[ParsedCertificate] = []
        has_failures = False

        for raw_cert in extraction_result.certificates:
            parsed = self.parse_raw_certificate(raw_cert)
            if parsed.parse_status != CertificateParseStatus.PARSED:
                has_failures = True
            parsed_certs.append(parsed)

        return ParsedCertificateChain(
            stream_id=extraction_result.stream_id,
            total_certificates=len(parsed_certs),
            certificates=parsed_certs,
            has_parse_failures=has_failures,
        )

    def parse_raw_certificate(self, raw_cert: RawExtractedCertificate) -> ParsedCertificate:
        """Parse a single RawExtractedCertificate into a ParsedCertificate model."""
        base_kwargs = {
            "certificate_index": raw_cert.certificate_index,
            "stream_id": raw_cert.stream_id,
            "stream_offset": raw_cert.stream_offset,
            "frame_number": raw_cert.first_frame_number,
            "timestamp": raw_cert.first_timestamp,
        }

        if not raw_cert.raw_der or len(raw_cert.raw_der) == 0:
            return ParsedCertificate(
                **base_kwargs,
                parse_status=CertificateParseStatus.EMPTY_DER,
                parse_error="Certificate payload is empty (0 bytes).",
            )

        sha256_fp = hashlib.sha256(raw_cert.raw_der).hexdigest()
        base_kwargs["raw_der_sha256"] = sha256_fp

        try:
            cert = x509.load_der_x509_certificate(raw_cert.raw_der)
        except Exception as exc:
            return ParsedCertificate(
                **base_kwargs,
                parse_status=CertificateParseStatus.MALFORMED_DER,
                parse_error=f"DER decoding failed: {str(exc)}",
            )

        try:
            # 1. Distinguished Names
            subject_dn = self._parse_dn(cert.subject)
            issuer_dn = self._parse_dn(cert.issuer)

            # 2. Serial Number
            serial_int = cert.serial_number
            serial_hex = f"{serial_int:X}"

            # 3. Validity (Timezone-aware UTC)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            # 4. Public Key
            public_key_params = self._extract_public_key(cert)

            # 5. Signature Algorithm
            sig_algo_name = getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid.dotted_string))
            sig_hash_name = None
            if cert.signature_hash_algorithm:
                sig_hash_name = cert.signature_hash_algorithm.name

            # 6. Extensions & SAN
            parsed_extensions, san_model = self._parse_extensions(cert)

            return ParsedCertificate(
                **base_kwargs,
                parse_status=CertificateParseStatus.PARSED,
                subject=subject_dn,
                issuer=issuer_dn,
                san=san_model,
                serial_number=serial_int,
                serial_number_hex=serial_hex,
                not_before=not_before,
                not_after=not_after,
                public_key=public_key_params,
                signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
                signature_algorithm_name=sig_algo_name,
                signature_hash_algorithm=sig_hash_name,
                extensions=parsed_extensions,
            )
        except Exception as exc:
            return ParsedCertificate(
                **base_kwargs,
                parse_status=CertificateParseStatus.PARTIAL_PARSE,
                parse_error=f"Encountered error while extracting fields: {str(exc)}",
            )

    def _parse_dn(self, name: x509.Name) -> DistinguishedName:
        attrs: Dict[str, List[str]] = {}
        fields: Dict[str, Optional[str]] = {
            "common_name": None,
            "organization": None,
            "organizational_unit": None,
            "country": None,
            "state_or_province": None,
            "locality": None,
            "email_address": None,
        }

        for rdn in name.rdns:
            for attr in rdn:
                val_str = str(attr.value)
                oid_key = attr.oid._name if hasattr(attr.oid, "_name") else attr.oid.dotted_string
                attrs.setdefault(oid_key, []).append(val_str)

                field_name = OID_NAME_MAP.get(attr.oid)
                if field_name and fields[field_name] is None:
                    fields[field_name] = val_str

        return DistinguishedName(
            common_name=fields["common_name"],
            organization=fields["organization"],
            organizational_unit=fields["organizational_unit"],
            country=fields["country"],
            state_or_province=fields["state_or_province"],
            locality=fields["locality"],
            email_address=fields["email_address"],
            raw_dn_string=name.rfc4514_string(),
            attributes=attrs,
        )

    def _extract_public_key(self, cert: x509.Certificate) -> ParsedKeyParameters:
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return ParsedKeyParameters(
                algorithm="RSA",
                key_size_bits=public_key.key_size,
                exponent=public_key.public_numbers().e,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return ParsedKeyParameters(
                algorithm="EC",
                key_size_bits=public_key.key_size,
                curve_name=public_key.curve.name,
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            return ParsedKeyParameters(
                algorithm="DSA",
                key_size_bits=public_key.key_size,
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return ParsedKeyParameters(
                algorithm="ED25519",
                key_size_bits=256,
            )
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return ParsedKeyParameters(
                algorithm="ED448",
                key_size_bits=448,
            )
        else:
            return ParsedKeyParameters(
                algorithm="UNKNOWN",
                key_size_bits=getattr(public_key, "key_size", None),
            )

    def _parse_extensions(self, cert: x509.Certificate) -> tuple[List[ParsedExtension], SubjectAlternativeNames]:
        parsed_exts: List[ParsedExtension] = []
        san_model = SubjectAlternativeNames()

        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string
            name_str = ext.oid._name if hasattr(ext.oid, "_name") else oid_str
            critical = ext.critical
            val = ext.value

            details: Dict[str, Any] = {}
            val_summary = str(val)

            try:
                if isinstance(val, x509.SubjectAlternativeName):
                    san_dns = val.get_values_for_type(x509.DNSName)
                    san_ip = [str(ip) for ip in val.get_values_for_type(x509.IPAddress)]
                    san_email = val.get_values_for_type(x509.RFC822Name)
                    san_uri = val.get_values_for_type(x509.UniformResourceIdentifier)

                    san_model = SubjectAlternativeNames(
                        dns_names=san_dns,
                        ip_addresses=san_ip,
                        email_addresses=san_email,
                        uris=san_uri,
                        has_san=True,
                    )
                    details = {
                        "dns_names": san_dns,
                        "ip_addresses": san_ip,
                        "email_addresses": san_email,
                        "uris": san_uri,
                    }
                    val_summary = f"DNS:{len(san_dns)}, IP:{len(san_ip)}, Email:{len(san_email)}, URI:{len(san_uri)}"

                elif isinstance(val, x509.BasicConstraints):
                    details = {"ca": val.ca, "path_length": val.path_length}
                    val_summary = f"CA={val.ca}, path_length={val.path_length}"

                elif isinstance(val, x509.KeyUsage):
                    ku_flags = [
                        k for k in [
                            "digital_signature", "content_commitment", "key_encipherment",
                            "data_encipherment", "key_agreement", "key_cert_sign",
                            "crl_sign", "encipher_only", "decipher_only",
                        ] if getattr(val, k, False)
                    ]
                    details = {"usages": ku_flags}
                    val_summary = ", ".join(ku_flags)

                elif isinstance(val, x509.ExtendedKeyUsage):
                    eku_oids = [getattr(eku, "_name", eku.dotted_string) for eku in val]
                    details = {"extended_key_usages": eku_oids}
                    val_summary = ", ".join(eku_oids)

                elif isinstance(val, x509.SubjectKeyIdentifier):
                    digest_hex = val.digest.hex()
                    details = {"key_identifier": digest_hex}
                    val_summary = digest_hex

                elif isinstance(val, x509.AuthorityKeyIdentifier):
                    key_id_hex = val.key_identifier.hex() if val.key_identifier else None
                    details = {"key_identifier": key_id_hex}
                    val_summary = key_id_hex or "No Key Identifier"

            except Exception as ext_err:
                val_summary = f"Failed extracting structured details: {str(ext_err)}"

            parsed_exts.append(
                ParsedExtension(
                    oid=oid_str,
                    name=name_str,
                    critical=critical,
                    value_summary=val_summary,
                    details=details,
                )
            )

        return parsed_exts, san_model


certificate_parser = CertificateParser()