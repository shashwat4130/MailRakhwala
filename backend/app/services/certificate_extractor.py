"""
MailRakhwala Certificate Extraction Service (Step 16)
Extracts raw DER X.509 certificates and certificate chains from reassembled TLS handshake records.
"""

from typing import List, Optional

from app.schemas.certificate_extraction import (
    CertificateChainExtractionResult,
    CertificateExtractionStatus,
    RawExtractedCertificate,
)
from app.schemas.tls_record import TLSRecordContentType, TLSRecordParseResult

MAX_HANDSHAKE_SIZE = 65536
MAX_CERTIFICATE_SIZE = 32768
MAX_CHAIN_CERTIFICATES = 16


class CertificateExtractor:
    """Bounded, passive extractor for TLS Certificate (0x0B) handshake messages."""

    def extract_certificates(
        self,
        server_record_result: TLSRecordParseResult,
        is_tls_13: bool = False,
    ) -> CertificateChainExtractionResult:
        stream_id = server_record_result.stream_id

        # 1. Check for initial gap disruption
        if server_record_result.has_gap_disruption and not server_record_result.records:
            return CertificateChainExtractionResult(
                stream_id=stream_id,
                status=CertificateExtractionStatus.GAP_DISRUPTION,
                has_gap_disruption=True,
                malformed_reason="Stream interrupted by unresolved TCP gap before Certificate message.",
            )

        # 2. Reassemble contiguous Handshake record payloads
        handshake_payload = bytearray()
        first_frame = None
        first_ts = None
        encountered_gap = False

        for rec in server_record_result.records:
            if rec.content_type == TLSRecordContentType.HANDSHAKE:
                if first_frame is None:
                    first_frame = rec.first_frame_number
                    first_ts = rec.first_timestamp
                handshake_payload.extend(rec.payload)
                if not rec.is_complete:
                    encountered_gap = True
                    break

        if not handshake_payload:
            return CertificateChainExtractionResult(
                stream_id=stream_id,
                status=CertificateExtractionStatus.NO_CERTIFICATE_MESSAGE,
                malformed_reason="No Handshake records present in server stream.",
            )

        # 3. Traverse handshake messages to find Certificate (HandshakeType = 0x0B / 11)
        offset = 0
        total_len = len(handshake_payload)

        while offset < total_len:
            if total_len - offset < 4:
                if encountered_gap:
                    return CertificateChainExtractionResult(
                        stream_id=stream_id,
                        status=CertificateExtractionStatus.GAP_DISRUPTION,
                        has_gap_disruption=True,
                        malformed_reason="Handshake header cut short by TCP sequence gap.",
                    )
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.INCOMPLETE_CAPTURE,
                    malformed_reason="Incomplete handshake header (< 4 bytes remaining).",
                )

            msg_type = handshake_payload[offset]
            msg_len = int.from_bytes(handshake_payload[offset + 1 : offset + 4], byteorder="big")

            if msg_type != 11:  # 0x0B = Certificate
                if msg_len > MAX_HANDSHAKE_SIZE:
                    return CertificateChainExtractionResult(
                        stream_id=stream_id,
                        status=CertificateExtractionStatus.OVERSIZED_CERTIFICATE,
                        malformed_reason=f"Declared handshake length {msg_len} exceeds maximum limit.",
                    )
                offset += 4 + msg_len
                continue

            # Certificate Handshake Message found
            if msg_len > MAX_HANDSHAKE_SIZE:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.OVERSIZED_CERTIFICATE,
                    malformed_reason=f"Certificate message size {msg_len} exceeds limit of {MAX_HANDSHAKE_SIZE} bytes.",
                )

            available_body = total_len - (offset + 4)
            if available_body < msg_len:
                if encountered_gap:
                    return CertificateChainExtractionResult(
                        stream_id=stream_id,
                        status=CertificateExtractionStatus.GAP_DISRUPTION,
                        has_gap_disruption=True,
                        malformed_reason="Certificate message payload interrupted by TCP sequence gap.",
                    )
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.INCOMPLETE_CAPTURE,
                    malformed_reason=f"Incomplete Certificate message: received {available_body} bytes, expected {msg_len}.",
                )

            body = bytes(handshake_payload[offset + 4 : offset + 4 + msg_len])
            return self._parse_certificates(
                body=body,
                stream_id=stream_id,
                first_frame=first_frame,
                first_ts=first_ts,
                is_tls_13=is_tls_13,
            )

        return CertificateChainExtractionResult(
            stream_id=stream_id,
            status=CertificateExtractionStatus.NO_CERTIFICATE_MESSAGE,
            malformed_reason="No Certificate (type 11) message found in stream.",
        )

    def _parse_certificates(
        self,
        body: bytes,
        stream_id: str,
        first_frame: Optional[int],
        first_ts: Optional[float],
        is_tls_13: bool,
    ) -> CertificateChainExtractionResult:
        body_len = len(body)
        idx = 0

        # TLS 1.3: Skip certificate_request_context (1-byte length + context)
        if is_tls_13:
            if body_len < 1:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                    malformed_reason="Truncated TLS 1.3 certificate request context length.",
                )
            context_len = body[idx]
            idx += 1 + context_len
            if idx > body_len:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                    malformed_reason="TLS 1.3 certificate request context exceeds body boundary.",
                )

        # 3-byte total certificate list length
        if idx + 3 > body_len:
            return CertificateChainExtractionResult(
                stream_id=stream_id,
                status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                malformed_reason="Truncated certificate list length field.",
            )

        cert_list_len = int.from_bytes(body[idx : idx + 3], byteorder="big")
        idx += 3

        if idx + cert_list_len != body_len:
            return CertificateChainExtractionResult(
                stream_id=stream_id,
                status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                malformed_reason=f"Declared certificate list length {cert_list_len} does not match available bytes ({body_len - idx}).",
            )

        extracted_certs: List[RawExtractedCertificate] = []
        list_end = idx + cert_list_len
        cert_index = 0

        while idx < list_end:
            if len(extracted_certs) >= MAX_CHAIN_CERTIFICATES:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.OVERSIZED_CERTIFICATE,
                    certificates=extracted_certs,
                    total_certificates=len(extracted_certs),
                    malformed_reason=f"Certificate chain exceeds maximum allowed length ({MAX_CHAIN_CERTIFICATES}).",
                )

            # 3-byte certificate length
            if idx + 3 > list_end:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                    certificates=extracted_certs,
                    total_certificates=len(extracted_certs),
                    malformed_reason=f"Certificate {cert_index} header truncated.",
                )

            cert_len = int.from_bytes(body[idx : idx + 3], byteorder="big")
            idx += 3

            if cert_len > MAX_CERTIFICATE_SIZE:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.OVERSIZED_CERTIFICATE,
                    certificates=extracted_certs,
                    total_certificates=len(extracted_certs),
                    malformed_reason=f"Certificate {cert_index} length {cert_len} exceeds maximum size {MAX_CERTIFICATE_SIZE}.",
                )

            if idx + cert_len > list_end:
                return CertificateChainExtractionResult(
                    stream_id=stream_id,
                    status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                    certificates=extracted_certs,
                    total_certificates=len(extracted_certs),
                    malformed_reason=f"Certificate {cert_index} payload extends beyond certificate list boundary.",
                )

            raw_der = body[idx : idx + cert_len]
            idx += cert_len

            extracted_certs.append(
                RawExtractedCertificate(
                    certificate_index=cert_index,
                    raw_der=raw_der,
                    raw_der_hex=raw_der.hex(),
                    der_length=cert_len,
                    stream_offset=idx - cert_len,
                    stream_id=stream_id,
                    first_frame_number=first_frame,
                    first_timestamp=first_ts,
                )
            )
            cert_index += 1

            # TLS 1.3: Skip per-certificate extension block (2-byte length + data)
            if is_tls_13:
                if idx + 2 > list_end:
                    return CertificateChainExtractionResult(
                        stream_id=stream_id,
                        status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                        certificates=extracted_certs,
                        total_certificates=len(extracted_certs),
                        malformed_reason=f"Certificate {cert_index - 1} extensions length field truncated.",
                    )
                exts_len = int.from_bytes(body[idx : idx + 2], byteorder="big")
                idx += 2 + exts_len
                if idx > list_end:
                    return CertificateChainExtractionResult(
                        stream_id=stream_id,
                        status=CertificateExtractionStatus.MALFORMED_CERTIFICATE,
                        certificates=extracted_certs,
                        total_certificates=len(extracted_certs),
                        malformed_reason=f"Certificate {cert_index - 1} extensions extend beyond boundary.",
                    )

        return CertificateChainExtractionResult(
            stream_id=stream_id,
            status=CertificateExtractionStatus.COMPLETE,
            certificates=extracted_certs,
            total_certificates=len(extracted_certs),
            has_gap_disruption=False,
        )


certificate_extractor = CertificateExtractor()