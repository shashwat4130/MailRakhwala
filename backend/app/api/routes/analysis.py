import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile, status
from fastapi.responses import Response

from app.core.config import settings
from app.schemas.anomaly_detection import AnomalyDetectionResult
from app.schemas.api import AnalysisJobResponse, AnalysisUploadResponse, JobStatus
from app.schemas.posture import CryptographicPostureReport, PostureSeverity
from app.schemas.report_export import (
    ComprehensiveAnalysisReport,
    ProtocolSecuritySummary,
    SessionMetadata,
)
from app.schemas.risk_classification import RiskClassificationResult
from app.schemas.shap_explainability import SHAPExplanationResult
from app.services.anomaly_detector import IsolationForestDetector
from app.services.job_store import job_store
from app.services.ml_features import MLFeatureEngineeringService
from app.services.ml_model_loader import ml_model_manager
from app.services.protocol_classifier import protocol_classifier
from app.services.tls_record_parser import tls_record_parser
from app.services.tls_client_hello_parser import tls_client_hello_parser
from app.services.tls_server_hello_parser import tls_server_hello_parser
from app.services.certificate_extractor import certificate_extractor
from app.services.certificate_parser import certificate_parser
from app.services.certificate_security_auditor import certificate_security_auditor
from app.services.key_exchange_analyzer import key_exchange_analyzer
from app.services.identity_analyzer import identity_analyzer
from app.services.trust_revocation_service import trust_revocation_service
from app.services.starttls_machine import starttls_machine
from app.services.starttls_downgrade import starttls_downgrade_service
from app.services.compliance_engine import compliance_engine
from app.services.vulnerability_mapping import vulnerability_mapping_engine
from app.services.threat_mapping import ThreatMappingService
from app.services.pcap_validator import (
    MAGIC_PCAPNG_SHB,
    MAX_PCAPNG_SHB_LEN,
    MIN_PCAP_GLOBAL_HEADER_LEN,
    MIN_PCAPNG_SHB_LEN,
    PCAPNG_BOM_BE,
    PCAPNG_BOM_LE,
    PCAPValidationError,
    inspect_capture_header,
    validate_file_extension,
)
from app.services.pdf_report_generator import PDFReportGenerator
from app.services.posture import PostureEngineService
from app.services.risk_classifier import XGBoostRiskClassifier
from app.services.tcp_reassembly_service import TCPReassemblyService
from app.services.tshark_service import TSharkService

logger = logging.getLogger("mailrakhwala.analysis")
router = APIRouter(prefix="/analysis", tags=["Analysis"])


def sanitize_filename(filename: Optional[str]) -> str:
    """Strips directory traversal sequences, Windows drive letters, and isolates base name."""
    if not filename:
        return "unnamed_capture.pcap"
    clean = filename.replace("\x00", "").replace("\\", "/")
    base_name = Path(clean).name
    return base_name if base_name else "unnamed_capture.pcap"


def run_pipeline_task(analysis_id: str, pcap_path: str, filename: str):
    """
    Background worker orchestrating the forensic pipeline.

    Flow:
        TShark -> TCP reassembly -> protocol classification
        -> STARTTLS/TLS analysis -> X.509/trust/identity
        -> deterministic compliance -> weakness/threat mapping
        -> posture -> ML -> consolidated report
    """
    try:
        job = job_store.get_job(analysis_id)
        if not job:
            logger.warning("Analysis job %s no longer exists.", analysis_id)
            return

        # TShark packet dissection

        try:
            tshark = TSharkService()
            packets = list(
                tshark.dissect_packets_stream(Path(pcap_path))
            )
        except Exception as dissect_err:
            logger.exception(
                "PCAP dissection failed for %s: %s",
                analysis_id,
                dissect_err,
            )
            job_store.update_status(
                analysis_id,
                JobStatus.FAILED,
                f"PCAP dissection failed: {dissect_err}",
            )
            return

        if not packets:
            logger.warning(
                "No packet frames dissected from %s.",
                analysis_id,
            )
            job_store.update_status(
                analysis_id,
                JobStatus.FAILED,
                "No packets could be dissected from the capture.",
            )
            return

        job_store.update_status(
            analysis_id,
            JobStatus.PROCESSING,
            "Analyzing PCAP capture...",
        )

        # TCP stream reassembly

        try:
            reassembler = TCPReassemblyService()
            streams = list(
                reassembler.reassemble_packet_stream(iter(packets))
            )
        except Exception as reasm_err:
            logger.exception(
                "TCP reassembly failed for %s: %s",
                analysis_id,
                reasm_err,
            )
            job_store.update_status(
                analysis_id,
                JobStatus.FAILED,
                f"TCP stream reconstruction failed: {reasm_err}",
            )
            return

        logger.info(
            "Analysis %s reconstructed %d TCP streams.",
            analysis_id,
            len(streams),
        )

        # Protocol classification

        classifications = []

        for stream in streams:
            try:
                classification = protocol_classifier.classify_stream(stream)
                classifications.append((stream, classification))

                logger.info(
                    "Analysis %s stream %s classified as %s "
                    "(TLS-port-context=%s).",
                    analysis_id,
                    stream.stream_id,
                    classification.protocol.value,
                    classification.is_tls_port_context,
                )
            except Exception as classify_err:
                logger.exception(
                    "Protocol classification failed for %s/%s: %s",
                    analysis_id,
                    stream.stream_id,
                    classify_err,
                )

        email_protocols = {"SMTP", "IMAP", "POP3"}

        email_streams = [
            (stream, classification)
            for stream, classification in classifications
            if classification.protocol.value.upper() in email_protocols
        ]

        def _contains_tls_record(payload: bytes) -> bool:
            if not payload:
                return False

            tls_content_types = {20, 21, 22, 23, 24}
            scan_limit = min(len(payload) - 5, 64 * 1024)

            for offset in range(max(0, scan_limit)):
                content_type = payload[offset]
                version_major = payload[offset + 1]
                version_minor = payload[offset + 2]

                if (
                    content_type in tls_content_types
                    and version_major == 0x03
                    and version_minor in {0x00, 0x01, 0x02, 0x03, 0x04}
                ):
                    record_length = int.from_bytes(
                        payload[offset + 3:offset + 5],
                        byteorder="big",
                    )
                    if 0 <= record_length <= 18432:
                        return True

            return False

        is_email_applicable = bool(email_streams)
        posture_service = PostureEngineService()
        threat_mapping_service = ThreatMappingService()

        if is_email_applicable:
            all_findings = []
            all_weaknesses = []
            all_threats = []
            any_plaintext_auth_observed = False
            has_tls = False

            # Primary stream references for protocol_summary & ML
            primary_stream = email_streams[0][0]
            primary_classification = email_streams[0][1]
            primary_tls_params = None
            primary_kex_result = None
            primary_cert_chain = None
            primary_cert_audit = None
            primary_cert_params = None
            primary_identity_result = None
            primary_trust_result = None
            primary_starttls_assessment = None
            primary_downgrade_result = None
            primary_server_hello_result = None

            for stream, classification in email_streams:
                c_payload = bytes(getattr(stream, "client_payload", b"") or b"")
                s_payload = bytes(getattr(stream, "server_payload", b"") or b"")
                stream_has_tls = (
                    _contains_tls_record(c_payload)
                    or _contains_tls_record(s_payload)
                )
                if stream_has_tls:
                    has_tls = True

                stream_starttls_assessment = None
                stream_downgrade_result = None
                try:
                    stream_starttls_assessment = starttls_machine.evaluate_stream(
                        stream,
                        classification,
                    )
                    stream_downgrade_result = starttls_downgrade_service.evaluate_downgrade(
                        stream,
                        classification,
                        stream_starttls_assessment,
                    )
                except Exception as starttls_err:
                    logger.exception(
                        "STARTTLS analysis failed for %s/%s: %s",
                        analysis_id,
                        stream.stream_id,
                        starttls_err,
                    )

                stream_client_record_result = None
                stream_server_record_result = None
                stream_client_hello_result = None
                stream_server_hello_result = None
                stream_tls_handshake_observed = False

                if stream_has_tls:
                    try:
                        (
                            stream_client_record_result,
                            stream_server_record_result,
                        ) = tls_record_parser.parse_stream(stream)

                        stream_client_hello_result = (
                            tls_client_hello_parser.parse_client_hello(
                                stream_client_record_result
                            )
                        )
                        stream_server_hello_result = (
                            tls_server_hello_parser.parse_server_hello(
                                stream_server_record_result
                            )
                        )

                        stream_tls_handshake_observed = bool(
                            stream_client_hello_result is not None
                            and stream_server_hello_result is not None
                            and getattr(stream_client_hello_result.status, "value", stream_client_hello_result.status) == "COMPLETE"
                            and getattr(stream_server_hello_result.status, "value", stream_server_hello_result.status) == "COMPLETE"
                            and stream_client_hello_result.client_hello is not None
                            and stream_server_hello_result.server_hello is not None
                        )
                    except Exception as tls_err:
                        logger.exception(
                            "TLS record/hello analysis failed for %s/%s: %s",
                            analysis_id,
                            stream.stream_id,
                            tls_err,
                        )

                stream_key_exchange_result = None
                if stream_server_hello_result is not None:
                    try:
                        stream_key_exchange_result = key_exchange_analyzer.analyze(
                            stream_client_hello_result,
                            stream_server_hello_result,
                        )
                    except Exception as kex_err:
                        logger.exception(
                            "Key exchange analysis failed for %s/%s: %s",
                            analysis_id,
                            stream.stream_id,
                            kex_err,
                        )

                stream_cert_extraction = None
                stream_cert_chain = None
                stream_cert_audit = None

                if stream_server_record_result is not None and stream_tls_handshake_observed:
                    try:
                        negotiated_version = None
                        if (
                            stream_server_hello_result is not None
                            and stream_server_hello_result.server_hello is not None
                        ):
                            negotiated_version = (
                                stream_server_hello_result.server_hello.negotiated_version
                            )

                        stream_cert_extraction = (
                            certificate_extractor.extract_certificates(
                                stream_server_record_result,
                                is_tls_13=(negotiated_version == 0x0304),
                            )
                        )
                        stream_cert_chain = certificate_parser.parse_chain(
                            stream_cert_extraction
                        )

                        ref_time = None
                        if stream.first_timestamp is not None:
                            ref_time = datetime.fromtimestamp(
                                stream.first_timestamp,
                                tz=timezone.utc,
                            )

                        stream_cert_audit = certificate_security_auditor.audit_chain(
                            stream_cert_chain,
                            reference_time=ref_time,
                        )
                    except Exception as cert_err:
                        logger.exception(
                            "Certificate analysis failed for %s/%s: %s",
                            analysis_id,
                            stream.stream_id,
                            cert_err,
                        )

                stream_identity_result = None
                stream_trust_result = None
                ref_time = None
                if stream.first_timestamp is not None:
                    ref_time = datetime.fromtimestamp(
                        stream.first_timestamp,
                        tz=timezone.utc,
                    )

                if stream_cert_chain is not None and stream_cert_extraction is not None:
                    try:
                        raw_der_certs = [
                            raw.raw_der
                            for raw in stream_cert_extraction.certificates
                        ]
                        stream_trust_result = trust_revocation_service.analyze_session_trust(
                            chain=stream_cert_chain,
                            raw_der_certs=raw_der_certs,
                            captured_ocsp_response_bytes=None,
                            reference_time=ref_time,
                        )
                    except Exception as trust_err:
                        logger.exception(
                            "Offline trust analysis failed for %s/%s: %s",
                            analysis_id,
                            stream.stream_id,
                            trust_err,
                        )

                    try:
                        leaf = stream_cert_chain.certificates[0]
                        sni = None
                        if (
                            stream_client_hello_result is not None
                            and stream_client_hello_result.client_hello is not None
                        ):
                            sni = stream_client_hello_result.client_hello.server_name

                        trust_path_context = None
                        if stream_trust_result is not None:
                            trust_path_context = {
                                "trust_path_status": (
                                    stream_trust_result
                                    .certificate_trust
                                    .trust_validation_status
                                    .value
                                )
                            }

                        stream_identity_result = identity_analyzer.analyze(
                            cert=leaf,
                            sni=sni,
                            observed_mail_host=sni,
                            dns_mx_context=None,
                            trust_path_context=trust_path_context,
                        )
                    except Exception as identity_err:
                        logger.exception(
                            "Identity analysis failed for %s/%s: %s",
                            analysis_id,
                            stream.stream_id,
                            identity_err,
                        )

                stream_tls_params = None
                if stream_tls_handshake_observed and stream_server_hello_result is not None:
                    sh = stream_server_hello_result.server_hello
                    if sh is not None:
                        stream_tls_params = {
                            "version": sh.negotiated_version_name,
                            "cipher_suite": sh.selected_cipher_suite_name,
                            "frame_number": sh.first_frame_number,
                            "timestamp": sh.first_timestamp,
                        }

                stream_kex_params = None
                if stream_key_exchange_result is not None:
                    stream_kex_params = stream_key_exchange_result.model_dump(mode="json")

                stream_cert_params = None
                if stream_cert_chain is not None and stream_cert_chain.certificates:
                    leaf = stream_cert_chain.certificates[0]
                    audit_entry = None
                    if stream_cert_audit is not None and stream_cert_audit.certificate_audits:
                        audit_entry = stream_cert_audit.certificate_audits[0]
                    stream_cert_params = {
                        "certificate_index": leaf.certificate_index,
                        "raw_der_sha256": leaf.raw_der_sha256,
                        "public_key_algorithm": leaf.public_key.algorithm if leaf.public_key is not None else None,
                        "public_key_bits": leaf.public_key.key_size_bits if leaf.public_key is not None else None,
                        "signature_algorithm": leaf.signature_algorithm_name,
                        "not_before": leaf.not_before.isoformat() if leaf.not_before is not None else None,
                        "not_after": leaf.not_after.isoformat() if leaf.not_after is not None else None,
                        "is_expired": audit_entry.is_expired if audit_entry is not None else None,
                        "is_not_yet_valid": audit_entry.is_not_yet_valid if audit_entry is not None else None,
                        "is_self_signed": audit_entry.is_self_signed if audit_entry is not None else None,
                    }

                protocol_value = str(getattr(classification.protocol, "value", classification.protocol)).upper()
                if stream_starttls_assessment is not None:
                    starttls_state = getattr(stream_starttls_assessment.starttls_state, "value", stream_starttls_assessment.starttls_state)
                    reconstruction_status = getattr(stream_starttls_assessment.reconstruction_status, "value", stream_starttls_assessment.reconstruction_status)
                    unresolved_gaps = bool(stream_starttls_assessment.unresolved_gaps)
                    tls_transition_detected = bool(stream_starttls_assessment.tls_transition_detected)
                else:
                    starttls_state = "UNKNOWN"
                    reconstruction_status = "UNKNOWN"
                    unresolved_gaps = False
                    tls_transition_detected = False

                stream_starttls_params = {
                    "protocol": protocol_value,
                    "starttls_state": str(starttls_state).upper(),
                    "reconstruction_status": str(reconstruction_status).upper(),
                    "unresolved_gaps": unresolved_gaps,
                    "tls_transition_detected": tls_transition_detected,
                    "tls_handshake_observed": bool(stream_tls_handshake_observed),
                }

                client_payload = bytes(stream.client_payload or b"")
                server_payload = bytes(stream.server_payload or b"")
                plaintext_blocks = (client_payload + b"\r\n" + server_payload).upper()
                plaintext_markers = {
                    "SMTP": (b"220 ", b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:", b"AUTH ", b"DATA\r\n", b"QUIT\r\n"),
                    "IMAP": (b"* OK ", b"* PREAUTH ", b" CAPABILITY", b" LOGIN", b" SELECT", b" AUTHENTICATE"),
                    "POP3": (b"+OK ", b" USER ", b" PASS ", b" RETR ", b" STAT"),
                }
                markers = plaintext_markers.get(protocol_value, ())
                plaintext_observed = any(m in plaintext_blocks for m in markers)
                plaintext_auth_observed = (protocol_value == "SMTP" and b"AUTH " in plaintext_blocks)

                if plaintext_observed and not stream_tls_handshake_observed:
                    stream_starttls_params["plaintext_observed"] = True
                    stream_starttls_params["plaintext_observed_value"] = f"PLAINTEXT_{protocol_value}"
                if plaintext_auth_observed and not stream_tls_handshake_observed:
                    stream_starttls_params["plaintext_auth_observed"] = True
                    any_plaintext_auth_observed = True
                if stream_downgrade_result is not None and stream_downgrade_result.is_downgrade_suspected:
                    stream_starttls_params["starttls_state"] = "DOWNGRADE_SUSPECTED"

                compliance_report = compliance_engine.evaluate_session(
                    stream_id=stream.stream_id,
                    tls_params=stream_tls_params,
                    key_exchange_params=stream_kex_params,
                    cert_audit_params=stream_cert_params,
                    identity_result=stream_identity_result,
                    trust_result=stream_trust_result,
                    starttls_params=stream_starttls_params,
                    reference_time=ref_time,
                )
                vulnerability_report = vulnerability_mapping_engine.map_session(compliance_report)
                threat_report = threat_mapping_service.build_session_threat_report(
                    session_id=analysis_id,
                    stream_id=stream.stream_id,
                    weaknesses=vulnerability_report.mappings,
                )

                all_findings.extend(compliance_report.findings)
                all_weaknesses.extend(vulnerability_report.mappings)
                all_threats.extend(threat_report.threat_mappings)

                # Keep primary references: prefer stream with observed TLS handshake
                if primary_tls_params is None and stream_tls_params is not None:
                    primary_stream = stream
                    primary_classification = classification
                    primary_tls_params = stream_tls_params
                    primary_kex_result = stream_key_exchange_result
                    primary_cert_chain = stream_cert_chain
                    primary_cert_audit = stream_cert_audit
                    primary_cert_params = stream_cert_params
                    primary_identity_result = stream_identity_result
                    primary_trust_result = stream_trust_result
                    primary_starttls_assessment = stream_starttls_assessment
                    primary_downgrade_result = stream_downgrade_result
                    primary_server_hello_result = stream_server_hello_result
                elif primary_starttls_assessment is None and stream_starttls_assessment is not None:
                    primary_starttls_assessment = stream_starttls_assessment
                    primary_downgrade_result = stream_downgrade_result

            # Deduplicate findings across streams while preserving distinct rules and streams
            deduped_findings = []
            seen_finding_keys = set()
            for f in all_findings:
                ev = f.evidence
                k = (
                    f.rule_id,
                    getattr(ev, "stream_id", ""),
                    getattr(ev, "observed_property", ""),
                    str(getattr(ev, "observed_value", "")),
                    getattr(ev, "certificate_index", None),
                    getattr(ev, "raw_der_sha256", None),
                )
                if k not in seen_finding_keys:
                    seen_finding_keys.add(k)
                    deduped_findings.append(f)

            findings = deduped_findings
            weakness_mappings = all_weaknesses
            threat_mappings = all_threats

            target_stream = primary_stream
            target_classification = primary_classification
            stream_id = target_stream.stream_id if len(email_streams) == 1 else "multi-stream"

            tls_params = primary_tls_params
            key_exchange_result = primary_kex_result
            parsed_certificate_chain = primary_cert_chain
            certificate_audit = primary_cert_audit
            cert_params = primary_cert_params
            identity_result = primary_identity_result
            trust_result = primary_trust_result
            starttls_assessment = primary_starttls_assessment
            downgrade_result = primary_downgrade_result
            server_hello_result = primary_server_hello_result
            tls_handshake_observed = bool(tls_params is not None)

            posture_report = posture_service.evaluate_posture(
                session_id=analysis_id,
                stream_id=stream_id,
                findings=findings,
                weaknesses=weakness_mappings,
                threats=threat_mappings,
                scoring_context={
                    "plaintext_auth_observed": any_plaintext_auth_observed,
                },
                is_applicable=True,
            )
        else:
            target_stream = classifications[0][0] if classifications else None
            target_classification = classifications[0][1] if classifications else None
            stream_id = target_stream.stream_id if target_stream is not None else "non-email-stream"
            has_tls = False
            tls_handshake_observed = False
            tls_params = None
            key_exchange_result = None
            parsed_certificate_chain = None
            certificate_audit = None
            cert_params = None
            identity_result = None
            trust_result = None
            starttls_assessment = None
            downgrade_result = None
            server_hello_result = None
            findings = []
            weakness_mappings = []
            threat_mappings = []
            posture_report = posture_service.evaluate_posture(
                session_id=analysis_id,
                stream_id=stream_id,
                findings=[],
                weaknesses=[],
                threats=[],
                is_applicable=False,
            )

        # ML feature engineering
        features = None

        if is_email_applicable and target_stream is not None:
            try:
                feature_extractor = MLFeatureEngineeringService()

                # Build deterministic session context from extracted evidence.
                certificate_info = {}

                if cert_params is not None:
                    certificate_info = {
                        "key_size": cert_params.get("public_key_bits"),
                        "signature_algorithm": cert_params.get(
                            "signature_algorithm"
                        ),
                    }

                    expired = cert_params.get("is_expired")
                    not_yet_valid = cert_params.get("is_not_yet_valid")

                    expired_value = getattr(
                        expired,
                        "value",
                        expired,
                    )
                    not_yet_valid_value = getattr(
                        not_yet_valid,
                        "value",
                        not_yet_valid,
                    )

                    if (
                        expired_value in (True, "TRUE")
                        or not_yet_valid_value in (True, "TRUE")
                    ):
                        certificate_info["is_valid"] = False
                    elif (
                        expired_value in (False, "FALSE")
                        and not_yet_valid_value in (False, "FALSE")
                    ):
                        certificate_info["is_valid"] = True

                # Identity and trust schemas can evolve, so extract only
                # fields that are explicitly available without inventing
                # values when the upstream service did not provide them.
                if identity_result is not None:
                    identity_dict = (
                        identity_result.model_dump(mode="json")
                        if hasattr(identity_result, "model_dump")
                        else {}
                    )

                    for key in (
                        "san_present",
                        "hostname_match",
                    ):
                        if key in identity_dict:
                            certificate_info[key] = identity_dict[key]

                    if "hostname_match_status" in identity_dict:
                        certificate_info["hostname_match"] = (
                            identity_dict["hostname_match_status"]
                        )

                    if "san_match" in identity_dict:
                        certificate_info["hostname_match"] = (
                            identity_dict["san_match"]
                        )

                if trust_result is not None:
                    trust_dict = (
                        trust_result.model_dump(mode="json")
                        if hasattr(trust_result, "model_dump")
                        else {}
                    )

                    trust_status = trust_dict.get(
                        "certificate_trust",
                        {},
                    )

                    if isinstance(trust_status, dict):
                        validation_status = (
                            trust_status.get(
                                "trust_validation_status"
                            )
                        )

                        if validation_status is not None:
                            validation_value = getattr(
                                validation_status,
                                "value",
                                validation_status,
                            )
                            certificate_info["is_trusted"] = (
                                str(validation_value).upper()
                                in {
                                    "VERIFIED",
                                    "TRUSTED",
                                    "TRUE",
                                }
                            )

                    ocsp_evidence = trust_dict.get(
                        "ocsp_evidence",
                        {},
                    )

                    if isinstance(ocsp_evidence, dict):
                        observed_status = ocsp_evidence.get(
                            "observed_status"
                        )

                        if observed_status is not None:
                            observed_value = getattr(
                                observed_status,
                                "value",
                                observed_status,
                            )

                            observed_upper = str(
                                observed_value
                            ).upper()

                            if observed_upper == "REVOKED":
                                certificate_info["is_revoked"] = True
                            elif observed_upper in {
                                "GOOD",
                                "VERIFIED",
                                "NOT_REVOKED",
                                "NOT_REVOKED_OR_NO_EVIDENCE",
                            }:
                                certificate_info["is_revoked"] = False

                # Build ML-facing TLS/certificate values from the
                # authoritative values already computed above.
                tls_version = (
                    tls_params.get("version")
                    if tls_params is not None
                    else "Unavailable from captured evidence"
                )

                cipher_suite = (
                    tls_params.get("cipher_suite")
                    if tls_params is not None
                    else "Unavailable from captured evidence"
                )

                key_exchange = (
                    str(
                        getattr(
                            key_exchange_result,
                            "exchange_type",
                            "UNKNOWN",
                        ).value
                    )
                    if (
                        key_exchange_result is not None
                        and getattr(key_exchange_result, "exchange_type", None) is not None
                    )
                    else "Unavailable from captured evidence"
                )

                certificate_key_size = (
                    cert_params.get("public_key_bits")
                    if cert_params is not None
                    else None
                )

                signature_algorithm = (
                    cert_params.get("signature_algorithm")
                    if cert_params is not None
                    else "Unavailable from captured evidence"
                )

                is_downgrade = False
                if downgrade_result is not None:
                    if (
                        downgrade_result.is_downgrade_suspected
                        or getattr(downgrade_result.status, "value", str(downgrade_result.status)) in (
                            "DOWNGRADE_SUSPECTED",
                            "PLAINTEXT_FALLBACK_OBSERVED",
                        )
                    ):
                        is_downgrade = True

                if not is_downgrade and findings:
                    for f in findings:
                        f_rule = getattr(f, "rule_id", None) or (f.get("rule_id") if isinstance(f, dict) else "")
                        f_status = getattr(f, "status", None) or (f.get("status") if isinstance(f, dict) else "")
                        f_status_val = getattr(f_status, "value", f_status)
                        if f_rule == "RULE-STARTTLS-002" and str(f_status_val).upper() == "NON_COMPLIANT":
                            is_downgrade = True
                            break

                ml_context = {
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "key_exchange": key_exchange,
                    "certificate_info": certificate_info,
                    "certificate_key_size": certificate_key_size,
                    "signature_algorithm": signature_algorithm,
                    "starttls_downgrade": is_downgrade if target_stream is not None else None,
                }

                features = feature_extractor.extract_features(
                    stream_id=stream_id,
                    session_context=ml_context,
                    compliance_findings=findings,
                    weakness_mappings=weakness_mappings,
                    threat_mappings=threat_mappings,
                    posture_report=posture_report,
                )

            except Exception as feature_err:
                logger.exception(
                    "ML feature extraction failed for %s: %s",
                    analysis_id,
                    feature_err,
                )

        # ML risk classification, Anomaly detection, and SHAP explainability
        if is_email_applicable and features is not None:
            anomaly_res = ml_model_manager.run_anomaly_detection(features, stream_id=analysis_id)
            risk_res = ml_model_manager.run_risk_classification(features, stream_id=analysis_id)
            shap_res = ml_model_manager.run_shap_explanation(features, stream_id=analysis_id)
        else:
            ml_reason = "not_applicable" if not is_email_applicable else "feature_vector_unavailable"
            ml_status = (
                "Not applicable: capture is not a supported email security target."
                if not is_email_applicable
                else "Unavailable: no feature vector extracted from capture."
            )
            anomaly_res = AnomalyDetectionResult(
                available=False,
                stream_id=analysis_id,
                is_anomalous=None,
                prediction=None,
                anomaly_score=None,
                status_text=f"Anomaly detection {ml_status.lower()}",
                feature_count=19,
                model_metadata=None,
                feature_vector=None,
                reason=ml_reason,
            )
            risk_res = RiskClassificationResult(
                available=False,
                stream_id=analysis_id,
                predicted_class=None,
                class_id=None,
                class_probabilities=None,
                probabilities=None,
                feature_count=19,
                status_text=f"Risk classification {ml_status.lower()}",
                model_metadata=None,
                feature_vector=None,
                reason=ml_reason,
            )
            shap_res = SHAPExplanationResult(
                available=False,
                reason=ml_reason,
                stream_id=analysis_id,
                base_value=None,
                prediction=None,
                predicted_class=None,
                predicted_class_id=None,
                class_probabilities={},
                features=[],
                feature_contributions=[],
                top_contributions=[],
                feature_count=19,
                model_metadata=None,
                status_text=f"SHAP explanation {ml_status.lower()}",
            )

        # Protocol summary

        detected_protocol = "Non-Email"

        if target_classification is not None:
            protocol_name = (
                target_classification.protocol.value.upper()
            )

            if (
                target_classification.is_tls_port_context
                and protocol_name in email_protocols
            ):
                detected_protocol = f"{protocol_name}S"
            else:
                detected_protocol = protocol_name

        elif has_tls:
            detected_protocol = "TLS"

        tls_version = "Unavailable from captured evidence"
        cipher_suite = "Unavailable from captured evidence"
        key_exchange = "Unavailable from captured evidence"
        perfect_forward_secrecy = False

        if server_hello_result is not None:
            sh = server_hello_result.server_hello

            if sh is not None:
                tls_version = sh.negotiated_version_name
                cipher_suite = sh.selected_cipher_suite_name

        if key_exchange_result is not None:
            key_exchange = str(
                getattr(
                    key_exchange_result,
                    "exchange_type",
                    "UNKNOWN",
                ).value
                if getattr(
                    key_exchange_result,
                    "exchange_type",
                    None,
                ) is not None
                else "UNKNOWN"
            )

            pfs_value = getattr(
                key_exchange_result,
                "has_forward_secrecy",
                None,
            )

            perfect_forward_secrecy = (
                getattr(pfs_value, "value", pfs_value)
                == "TRUE"
            )

        certificate_validity = (
            "Unavailable from captured evidence"
        )
        certificate_key_size = None
        signature_algorithm = (
            "Unavailable from captured evidence"
        )

        if (
            parsed_certificate_chain is not None
            and parsed_certificate_chain.certificates
        ):
            leaf = parsed_certificate_chain.certificates[0]

            if leaf.public_key is not None:
                certificate_key_size = (
                    leaf.public_key.key_size_bits
                )

            if leaf.signature_algorithm_name:
                signature_algorithm = (
                    leaf.signature_algorithm_name
                )

            if (
                certificate_audit is not None
                and certificate_audit.certificate_audits
            ):
                audit = (
                    certificate_audit
                    .certificate_audits[0]
                )

                expired = getattr(
                    audit.is_expired,
                    "value",
                    audit.is_expired,
                )
                not_yet_valid = getattr(
                    audit.is_not_yet_valid,
                    "value",
                    audit.is_not_yet_valid,
                )

                if (
                    expired == "FALSE"
                    and not_yet_valid == "FALSE"
                ):
                    certificate_validity = "ACTIVE"
                elif expired == "TRUE":
                    certificate_validity = "EXPIRED"
                elif not_yet_valid == "TRUE":
                    certificate_validity = "NOT_YET_VALID"

        san_match_status = (
            identity_result.overall_interpretation
            if identity_result is not None
            else "Unavailable from captured evidence"
        )

        trust_validation = (
            trust_result.overall_trust_state
            if trust_result is not None
            else "Unavailable from captured evidence"
        )

        revocation_status = (
            trust_result.ocsp_evidence.observed_status.value
            if trust_result is not None
            else "Unavailable from captured evidence"
        )

        starttls_status = (
            starttls_assessment.starttls_state.value
            if starttls_assessment is not None
            else "Unavailable from captured evidence"
        )

        # Consolidated report generation
        applicability_status = "APPLICABLE" if is_email_applicable else "NOT_APPLICABLE"
        assessment_exec_status = "EVALUATED" if is_email_applicable else "NOT_APPLICABLE"
        applicability_reason_str = (
            None
            if is_email_applicable
            else "No supported email protocol/security assessment target was observed in this capture."
        )

        report = ComprehensiveAnalysisReport(
            session=SessionMetadata(
                session_id=analysis_id,
                filename=filename,
                filesize_bytes=(
                    os.path.getsize(pcap_path)
                    if os.path.exists(pcap_path)
                    else 0
                ),
                status="COMPLETED",
                total_streams=len(streams),
                applicability=applicability_status,
                assessment_status=assessment_exec_status,
            ),
            applicability=applicability_status,
            assessment_status=assessment_exec_status,
            applicability_reason=applicability_reason_str,
            protocol_summary=ProtocolSecuritySummary(
                detected_protocol=detected_protocol,
                has_tls=has_tls,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                key_exchange=key_exchange,
                perfect_forward_secrecy=perfect_forward_secrecy,
                certificate_validity=certificate_validity,
                certificate_key_size=certificate_key_size,
                signature_algorithm=signature_algorithm,
                san_match_status=san_match_status,
                trust_validation=trust_validation,
                revocation_status=revocation_status,
                starttls_status=starttls_status,
            ),
            posture_report=posture_report,
            compliance_findings=findings,
            vulnerability_mappings=weakness_mappings,
            threat_mappings=threat_mappings,
            recommendations=[],
            feature_vector=features,
            anomaly_detection=anomaly_res,
            risk_classification=risk_res,
            shap_explanation=shap_res,
        )

        job_store.set_report(
            analysis_id,
            report.model_dump(mode="json"),
        )

        job_store.update_status(
            analysis_id,
            JobStatus.COMPLETED,
            "Analysis complete.",
        )

        logger.info(
            "Analysis %s completed: streams=%d protocol=%s tls=%s findings=%d",
            analysis_id,
            len(streams),
            detected_protocol,
            has_tls,
            len(findings),
        )

    except Exception as exc:
        logger.exception(
            "Analysis pipeline failed for analysis_id=%s: %s",
            analysis_id,
            exc,
        )
        job_store.update_status(
            analysis_id,
            JobStatus.FAILED,
            f"Pipeline error: {str(exc)}",
        )


@router.post(
    "/upload",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload PCAP/PCAPNG capture for forensic assessment",
)
async def upload_capture(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    original_name = file.filename or ""
    clean_name = sanitize_filename(original_name)

    try:
        suffix = validate_file_extension(clean_name)
    except PCAPValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err.message,
        )

    analysis_id = str(uuid.uuid4())
    safe_disk_filename = f"{analysis_id}{suffix}"

    upload_root = settings.UPLOAD_DIR.resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    destination = (upload_root / safe_disk_filename).resolve()

    if upload_root not in destination.parents and destination.parent != upload_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal storage destination path.",
        )

    total_bytes = 0
    chunk_size = 1024 * 1024  # 1MB stream buffer
    header_buffer = bytearray()
    header_inspected = False

    try:
        with open(destination, "wb") as buffer:
            while chunk := await file.read(chunk_size):
                total_bytes += len(chunk)

                if total_bytes > settings.max_upload_bytes:
                    buffer.close()
                    destination.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Capture exceeds maximum allowed size of {settings.MAX_PCAP_SIZE_MB}MB",
                    )

                if not header_inspected:
                    can_take = MAX_PCAPNG_SHB_LEN - len(header_buffer)
                    if can_take > 0:
                        header_buffer.extend(chunk[:can_take])

                    if suffix == ".pcap" and len(header_buffer) >= MIN_PCAP_GLOBAL_HEADER_LEN:
                        inspect_capture_header(bytes(header_buffer[:MIN_PCAP_GLOBAL_HEADER_LEN]), suffix)
                        header_inspected = True
                        header_buffer.clear()
                    elif suffix == ".pcapng" and len(header_buffer) >= MIN_PCAPNG_SHB_LEN:
                        if header_buffer[:4] == MAGIC_PCAPNG_SHB:
                            bom = header_buffer[8:12]
                            order = "little" if bom == PCAPNG_BOM_LE else ("big" if bom == PCAPNG_BOM_BE else None)
                            if order:
                                declared_len = int.from_bytes(header_buffer[4:8], byteorder=order)
                                if len(header_buffer) >= declared_len:
                                    inspect_capture_header(bytes(header_buffer[:declared_len]), suffix)
                                    header_inspected = True
                                    header_buffer.clear()

                buffer.write(chunk)

            if not header_inspected:
                inspect_capture_header(bytes(header_buffer), suffix)
                header_buffer.clear()

    except PCAPValidationError as val_err:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=val_err.message,
        )
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist uploaded capture safely.",
        ) from exc

    if total_bytes == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded capture file is empty.",
        )

    job_store.create_job(
        analysis_id=analysis_id,
        filename=clean_name,
        storage_path=str(destination),
        file_size_bytes=total_bytes,
    )

    background_tasks.add_task(
        run_pipeline_task,
        analysis_id=analysis_id,
        pcap_path=str(destination),
        filename=clean_name,
    )

    return AnalysisUploadResponse(
        analysis_id=analysis_id,
        status=JobStatus.QUEUED,
        filename=clean_name,
        message="Capture validated and queued for analysis.",
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisJobResponse,
    summary="Query status of an analysis job",
)
async def get_analysis_job(analysis_id: str):
    job = job_store.get_job(analysis_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found.",
        )
    return job.to_response()


@router.get(
    "/{analysis_id}/report",
    summary="Get completed comprehensive analysis report",
)
async def get_analysis_report(analysis_id: str):
    job = job_store.get_job(analysis_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found.",
        )
    if job.status != JobStatus.COMPLETED or not job.report_data:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Analysis is currently {job.status.value}. Report not ready.",
        )
    return job.report_data


@router.get(
    "/{analysis_id}/report/pdf",
    summary="Export completed analysis report to PDF",
)
async def export_report_pdf(analysis_id: str):
    job = job_store.get_job(analysis_id)
    if not job or not job.report_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Completed analysis report not found.",
        )
    report_model = ComprehensiveAnalysisReport.model_validate(job.report_data)
    generator = PDFReportGenerator(report_model)
    pdf_bytes = generator.generate()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="mailrakhwala_{analysis_id}.pdf"'},
    )