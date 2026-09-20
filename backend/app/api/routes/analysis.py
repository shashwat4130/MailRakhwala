import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile, status
from fastapi.responses import Response

from app.core.config import settings
from app.schemas.api import AnalysisJobResponse, AnalysisUploadResponse, JobStatus
from app.schemas.posture import CryptographicPostureReport, PostureSeverity
from app.schemas.report_export import (
    ComprehensiveAnalysisReport,
    ProtocolSecuritySummary,
    SessionMetadata,
)
from app.services.anomaly_detector import IsolationForestDetector
from app.services.job_store import job_store
from app.services.ml_features import MLFeatureEngineeringService
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

        # ==============================================================
        # 1. TSHARK DISSECTION
        # ==============================================================

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

        # ==============================================================
        # 2. TCP STREAM REASSEMBLY
        # ==============================================================

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

        # ==============================================================
        # 3. PROTOCOL CLASSIFICATION
        # ==============================================================

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

        target_stream = None
        target_classification = None

        # Prefer an email stream; do not mistake arbitrary TLS for email.
        for stream, classification in classifications:
            if classification.protocol.value.upper() in email_protocols:
                target_stream = stream
                target_classification = classification
                break

        # ==============================================================
        # 4. TLS PRESENCE
        # ==============================================================

        has_tls = any(
            str(getattr(packet, "highest_layer", "") or "").upper() == "TLS"
            for packet in packets
        )

        if not has_tls:
            # frame.protocols is not part of the normalized packet contract,
            # so only use highest_layer here.
            has_tls = any(
                "TLS" in str(getattr(packet, "highest_layer", "") or "").upper()
                for packet in packets
            )

        # For implicit TLS email ports, a TLS session is expected even when
        # there is no plaintext email banner.
        if target_classification is not None:
            if target_classification.is_tls_port_context:
                has_tls = True

        # ==============================================================
        # 5. STARTTLS STATE ANALYSIS
        # ==============================================================

        starttls_assessment = None
        downgrade_result = None

        if target_stream is not None and target_classification is not None:
            try:
                starttls_assessment = starttls_machine.evaluate_stream(
                    target_stream,
                    target_classification,
                )
                downgrade_result = starttls_downgrade_service.evaluate_downgrade(
                    target_stream,
                    target_classification,
                    starttls_assessment,
                )
            except Exception as starttls_err:
                logger.exception(
                    "STARTTLS analysis failed for %s: %s",
                    analysis_id,
                    starttls_err,
                )

        # ==============================================================
        # 6. TLS RECORD / HELLO ANALYSIS
        # ==============================================================

        client_record_result = None
        server_record_result = None
        client_hello_result = None
        server_hello_result = None

        if target_stream is not None and has_tls:
            try:
                (
                    client_record_result,
                    server_record_result,
                ) = tls_record_parser.parse_stream(target_stream)

                client_hello_result = (
                    tls_client_hello_parser.parse_client_hello(
                        client_record_result
                    )
                )

                server_hello_result = (
                    tls_server_hello_parser.parse_server_hello(
                        server_record_result
                    )
                )

                logger.info(
                    "TLS handshake results for %s: ClientHello=%s, ServerHello=%s",
                    analysis_id,
                    client_hello_result.status.value,
                    server_hello_result.status.value,
                )

            except Exception as tls_err:
                logger.exception(
                    "TLS record/hello analysis failed for %s: %s",
                    analysis_id,
                    tls_err,
                )

        # ==============================================================
        # 7. KEY EXCHANGE / PFS
        # ==============================================================

        key_exchange_result = None

        if server_hello_result is not None:
            try:
                key_exchange_result = key_exchange_analyzer.analyze(
                    client_hello_result,
                    server_hello_result,
                )
            except Exception as kex_err:
                logger.exception(
                    "Key exchange analysis failed for %s: %s",
                    analysis_id,
                    kex_err,
                )

        # ==============================================================
        # 8. CERTIFICATE EXTRACTION + PARSING + AUDIT
        # ==============================================================

        certificate_extraction = None
        parsed_certificate_chain = None
        certificate_audit = None

        if server_record_result is not None:
            try:
                negotiated_version = None

                if (
                    server_hello_result is not None
                    and server_hello_result.server_hello is not None
                ):
                    negotiated_version = (
                        server_hello_result.server_hello.negotiated_version
                    )

                certificate_extraction = (
                    certificate_extractor.extract_certificates(
                        server_record_result,
                        is_tls_13=(negotiated_version == 0x0304),
                    )
                )

                parsed_certificate_chain = (
                    certificate_parser.parse_chain(
                        certificate_extraction
                    )
                )

                reference_time = None

                if target_stream.first_timestamp is not None:
                    reference_time = datetime.fromtimestamp(
                        target_stream.first_timestamp,
                        tz=timezone.utc,
                    )

                certificate_audit = (
                    certificate_security_auditor.audit_chain(
                        parsed_certificate_chain,
                        reference_time=reference_time,
                    )
                )

            except Exception as cert_err:
                logger.exception(
                    "Certificate analysis failed for %s: %s",
                    analysis_id,
                    cert_err,
                )

        # ==============================================================
        # 9. IDENTITY + TRUST
        # ==============================================================

        identity_result = None
        trust_result = None
        reference_time = None

        if target_stream is not None and target_stream.first_timestamp is not None:
            reference_time = datetime.fromtimestamp(
                target_stream.first_timestamp,
                tz=timezone.utc,
            )

        if parsed_certificate_chain is not None:
            try:
                raw_der_certs = [
                    raw.raw_der
                    for raw in certificate_extraction.certificates
                ]

                trust_result = trust_revocation_service.analyze_session_trust(
                    chain=parsed_certificate_chain,
                    raw_der_certs=raw_der_certs,
                    captured_ocsp_response_bytes=None,
                    reference_time=reference_time,
                )
            except Exception as trust_err:
                logger.exception(
                    "Offline trust analysis failed for %s: %s",
                    analysis_id,
                    trust_err,
                )

            try:
                leaf = parsed_certificate_chain.certificates[0]

                sni = None
                if (
                    client_hello_result is not None
                    and client_hello_result.client_hello is not None
                ):
                    sni = client_hello_result.client_hello.server_name

                trust_path_context = None
                if trust_result is not None:
                    trust_path_context = {
                        "trust_path_status": (
                            trust_result
                            .certificate_trust
                            .trust_validation_status
                            .value
                        )
                    }

                identity_result = identity_analyzer.analyze(
                    cert=leaf,
                    sni=sni,
                    observed_mail_host=sni,
                    dns_mx_context=None,
                    trust_path_context=trust_path_context,
                )

            except Exception as identity_err:
                logger.exception(
                    "Identity analysis failed for %s: %s",
                    analysis_id,
                    identity_err,
                )

        # ==============================================================
        # 10. BUILD AUTHORITATIVE TLS PARAMETERS
        # ==============================================================

        tls_params = None

        if server_hello_result is not None:
            sh = server_hello_result.server_hello

            if sh is not None:
                tls_params = {
                    "version": sh.negotiated_version_name,
                    "cipher_suite": sh.selected_cipher_suite_name,
                    "frame_number": sh.first_frame_number,
                    "timestamp": sh.first_timestamp,
                }

        kex_params = None
        if key_exchange_result is not None:
            kex_params = key_exchange_result.model_dump(mode="json")

        cert_params = None

        if (
            parsed_certificate_chain is not None
            and parsed_certificate_chain.certificates
        ):
            leaf = parsed_certificate_chain.certificates[0]

            audit_entry = None
            if (
                certificate_audit is not None
                and certificate_audit.certificate_audits
            ):
                audit_entry = certificate_audit.certificate_audits[0]

            cert_params = {
                "certificate_index": leaf.certificate_index,
                "raw_der_sha256": leaf.raw_der_sha256,
                "public_key_algorithm": (
                    leaf.public_key.algorithm
                    if leaf.public_key is not None
                    else None
                ),
                "public_key_bits": (
                    leaf.public_key.key_size_bits
                    if leaf.public_key is not None
                    else None
                ),
                "signature_algorithm": (
                    leaf.signature_algorithm_name
                ),
                "not_before": (
                    leaf.not_before.isoformat()
                    if leaf.not_before is not None
                    else None
                ),
                "not_after": (
                    leaf.not_after.isoformat()
                    if leaf.not_after is not None
                    else None
                ),
                "is_expired": (
                    audit_entry.is_expired
                    if audit_entry is not None
                    else None
                ),
                "is_not_yet_valid": (
                    audit_entry.is_not_yet_valid
                    if audit_entry is not None
                    else None
                ),
                "is_self_signed": (
                    audit_entry.is_self_signed
                    if audit_entry is not None
                    else None
                ),
            }

        starttls_params = None

        if starttls_assessment is not None:
            starttls_params = {
                "starttls_state": (
                    starttls_assessment.starttls_state.value
                )
            }

            if (
                downgrade_result is not None
                and downgrade_result.is_downgrade_suspected
            ):
                starttls_params["starttls_state"] = "DOWNGRADE_SUSPECTED"

        # ==============================================================
        # 11. STEP 21 — DETERMINISTIC COMPLIANCE
        # ==============================================================

        stream_id = (
            target_stream.stream_id
            if target_stream is not None
            else "unknown-stream"
        )

        compliance_report = compliance_engine.evaluate_session(
            stream_id=stream_id,
            tls_params=tls_params,
            key_exchange_params=kex_params,
            cert_audit_params=cert_params,
            identity_result=identity_result,
            trust_result=trust_result,
            starttls_params=starttls_params,
            reference_time=reference_time,
        )

        findings = compliance_report.findings

        # ==============================================================
        # 12. STEP 22 — VULNERABILITY / WEAKNESS MAPPING
        # ==============================================================

        vulnerability_report = vulnerability_mapping_engine.map_session(
            compliance_report
        )

        weakness_mappings = vulnerability_report.mappings

        # ==============================================================
        # 13. STEP 23 — THREAT MAPPING
        # ==============================================================

        threat_mapping_service = ThreatMappingService()

        threat_report = threat_mapping_service.build_session_threat_report(
            session_id=analysis_id,
            stream_id=stream_id,
            weaknesses=weakness_mappings,
        )

        threat_mappings = threat_report.threat_mappings

        # ==============================================================
        # 14. STEP 24 — POSTURE
        # ==============================================================

        posture_service = PostureEngineService()

        posture_report = posture_service.evaluate_posture(
            session_id=analysis_id,
            stream_id=stream_id,
            findings=findings,
            weaknesses=weakness_mappings,
            threats=threat_mappings,
        )

        # ==============================================================
        # 15. STEP 25 — ML FEATURES
        # ==============================================================

        features = None

        if target_stream is not None:
            try:
                feature_extractor = MLFeatureEngineeringService()

                # Step 25 expects explicit domain inputs rather than a stream
                # object. Build the deterministic session context from the
                # evidence already produced by Steps 12–24.
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

                ml_context = {
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "key_exchange": key_exchange,
                    "certificate_info": certificate_info,
                    "certificate_key_size": certificate_key_size,
                    "signature_algorithm": signature_algorithm,
                    "starttls_downgrade": (
                        downgrade_result.is_downgrade_suspected
                        if downgrade_result is not None
                        else None
                    ),
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

        # ==============================================================
        # 16. STEPS 26–28 — ML / SHAP
        # ==============================================================

        anomaly_res = None
        risk_res = None
        shap_res = None

        if features is not None:
            try:
                detector = IsolationForestDetector()
                if hasattr(detector, "detect"):
                    anomaly_res = detector.detect(features)
            except Exception as anomaly_err:
                logger.exception(
                    "Anomaly detection failed for %s: %s",
                    analysis_id,
                    anomaly_err,
                )

            try:
                classifier = XGBoostRiskClassifier()
                if hasattr(classifier, "classify"):
                    risk_res = classifier.classify(features)
            except Exception as risk_err:
                logger.exception(
                    "Risk classification failed for %s: %s",
                    analysis_id,
                    risk_err,
                )

            try:
                from app.services import shap_explainer

                shap_cls = getattr(
                    shap_explainer,
                    "SHAPExplainerService",
                    getattr(
                        shap_explainer,
                        "SHAPExplainer",
                        None,
                    ),
                )

                if shap_cls is not None:
                    explainer = shap_cls()
                    if hasattr(explainer, "explain"):
                        shap_res = explainer.explain(features)

            except Exception as shap_err:
                logger.exception(
                    "SHAP explanation failed for %s: %s",
                    analysis_id,
                    shap_err,
                )

        # ==============================================================
        # 17. PROTOCOL SUMMARY
        # ==============================================================

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

        # ==============================================================
        # 18. CONSOLIDATED REPORT
        # ==============================================================

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
            ),
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