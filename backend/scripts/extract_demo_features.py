#!/usr/bin/env python3
"""
Mail Rakhwala — Synthetic Demo PCAP Feature Extraction Pipeline

Runs generated PCAPs through Mail Rakhwala's actual analysis pipeline:
  TShark -> TCP Reassembly -> Protocol Classification
  -> STARTTLS State Machine -> Downgrade Assessment
  -> TLS Record Parsing -> Handshake Parsing (ClientHello / ServerHello)
  -> Key Exchange & PFS Analysis -> Certificate Extraction & Security Audit
  -> Compliance Engine -> Vulnerability Mapping -> Threat Mapping
  -> Security Posture Engine -> Canonical 19D Feature Extraction.

Outputs:
  data/demo_dataset/extracted_features.csv
  data/demo_dataset/extracted_features.json
"""

import csv
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure backend package is on sys.path
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.services.tshark_service import TSharkService
from app.services.tcp_reassembly_service import TCPReassemblyService
from app.services.protocol_classifier import protocol_classifier
from app.services.starttls_machine import starttls_machine
from app.services.starttls_downgrade import starttls_downgrade_service
from app.services.tls_record_parser import tls_record_parser
from app.services.tls_client_hello_parser import tls_client_hello_parser
from app.services.tls_server_hello_parser import tls_server_hello_parser
from app.services.key_exchange_analyzer import key_exchange_analyzer
from app.services.certificate_extractor import certificate_extractor
from app.services.certificate_parser import certificate_parser
from app.services.certificate_security_auditor import certificate_security_auditor
from app.services.trust_revocation_service import trust_revocation_service
from app.services.identity_analyzer import identity_analyzer
from app.services.compliance_engine import compliance_engine
from app.services.vulnerability_mapping import vulnerability_mapping_engine
from app.services.threat_mapping import ThreatMappingService
from app.services.posture import PostureEngineService
from app.services.ml_features import MLFeatureEngineeringService

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("extract_demo_features")


def process_single_pcap(pcap_path: Path, scenario: str, demo_risk_label: str) -> Dict[str, Any]:
    """Runs a single PCAP capture through Mail Rakhwala's actual analysis pipeline."""
    pcap_name = pcap_path.name
    analysis_id = f"demo-{pcap_name}"

    # 1. TShark Dissection
    tshark = TSharkService()
    packets = list(tshark.dissect_packets_stream(pcap_path))
    if not packets:
        raise ValueError(f"No packets dissected from {pcap_name}")

    # 2. TCP Reassembly
    reassembler = TCPReassemblyService()
    streams = list(reassembler.reassemble_packet_stream(iter(packets)))
    if not streams:
        raise ValueError(f"No TCP streams reconstructed from {pcap_name}")

    # 3. Protocol Classification
    classifications = []
    for stream in streams:
        c = protocol_classifier.classify_stream(stream)
        classifications.append((stream, c))

    email_protocols = {"SMTP", "IMAP", "POP3"}
    target_stream = None
    target_classification = None
    for stream, c in classifications:
        if c.protocol.value.upper() in email_protocols:
            target_stream = stream
            target_classification = c
            break

    if target_stream is None:
        target_stream, target_classification = classifications[0]

    # 4. Check TLS Presence
    client_payload = bytes(target_stream.client_payload or b"")
    server_payload = bytes(target_stream.server_payload or b"")

    def _contains_tls_record(payload: bytes) -> bool:
        if not payload or len(payload) < 5:
            return False
        tls_content_types = {20, 21, 22, 23, 24}
        scan_limit = min(len(payload) - 5, 64 * 1024)
        for offset in range(max(0, scan_limit)):
            ct = payload[offset]
            v_maj = payload[offset + 1]
            v_min = payload[offset + 2]
            if ct in tls_content_types and v_maj == 0x03 and v_min in {0x00, 0x01, 0x02, 0x03, 0x04}:
                rec_len = int.from_bytes(payload[offset + 3:offset + 5], byteorder="big")
                if 0 <= rec_len <= 18432:
                    return True
        return False

    tls_stream = None
    for s_cand in streams:
        cp = bytes(s_cand.client_payload or b"")
        sp = bytes(s_cand.server_payload or b"")
        if _contains_tls_record(cp) or _contains_tls_record(sp):
            tls_stream = s_cand
            break

    has_tls = tls_stream is not None

    # 5. STARTTLS & Downgrade Evaluation
    starttls_assessment = None
    downgrade_result = None
    if target_stream is not None and target_classification is not None:
        starttls_assessment = starttls_machine.evaluate_stream(target_stream, target_classification)
        downgrade_result = starttls_downgrade_service.evaluate_downgrade(target_stream, target_classification, starttls_assessment)

    # 6. TLS Handshake Analysis
    client_record_result = None
    server_record_result = None
    client_hello_result = None
    server_hello_result = None
    tls_handshake_observed = False

    if tls_stream is not None:
        client_record_result, server_record_result = tls_record_parser.parse_stream(tls_stream)
        client_hello_result = tls_client_hello_parser.parse_client_hello(client_record_result)
        server_hello_result = tls_server_hello_parser.parse_server_hello(server_record_result)

        tls_handshake_observed = bool(
            client_hello_result is not None
            and server_hello_result is not None
            and getattr(client_hello_result.status, "value", client_hello_result.status) == "COMPLETE"
            and getattr(server_hello_result.status, "value", server_hello_result.status) == "COMPLETE"
            and client_hello_result.client_hello is not None
            and server_hello_result.server_hello is not None
        )

    # 7. Key Exchange & PFS
    key_exchange_result = None
    if server_hello_result is not None:
        key_exchange_result = key_exchange_analyzer.analyze(client_hello_result, server_hello_result)

    # 8. Certificate Extraction, Audit, Identity, Trust
    parsed_certificate_chain = None
    certificate_audit = None
    raw_der_certs = []
    trust_result = None
    identity_result = None

    if server_record_result is not None:
        cert_extract_result = certificate_extractor.extract_certificates(
            server_record_result=server_record_result,
            is_tls_13=False,
        )
        if cert_extract_result and cert_extract_result.certificates:
            parsed_certificate_chain = certificate_parser.parse_chain(cert_extract_result)
            certificate_audit = certificate_security_auditor.audit_chain(parsed_certificate_chain)
            raw_der_certs = [c.raw_der for c in cert_extract_result.certificates]

            trust_result = trust_revocation_service.analyze_session_trust(
                chain=parsed_certificate_chain,
                raw_der_certs=raw_der_certs,
                captured_ocsp_response_bytes=None,
                reference_time=None,
            )

            leaf = parsed_certificate_chain.certificates[0]
            sni = None
            if client_hello_result is not None and client_hello_result.client_hello is not None:
                sni = client_hello_result.client_hello.server_name

            trust_path_context = None
            if trust_result is not None:
                trust_path_context = {
                    "trust_path_status": trust_result.certificate_trust.trust_validation_status.value
                }

            identity_result = identity_analyzer.analyze(
                cert=leaf,
                sni=sni,
                observed_mail_host=sni or "mail.demo.local",
                dns_mx_context=None,
                trust_path_context=trust_path_context,
            )

    # Authoritative TLS params
    tls_params = None
    if tls_handshake_observed and server_hello_result is not None:
        sh = server_hello_result.server_hello
        if sh is not None:
            tls_params = {
                "version": sh.negotiated_version_name,
                "cipher_suite": sh.selected_cipher_suite_name,
                "frame_number": sh.first_frame_number,
                "timestamp": sh.first_timestamp,
            }

    kex_params = key_exchange_result.model_dump(mode="json") if key_exchange_result else None

    cert_params = None
    if parsed_certificate_chain is not None and parsed_certificate_chain.certificates:
        leaf = parsed_certificate_chain.certificates[0]
        audit_entry = certificate_audit.certificate_audits[0] if certificate_audit and certificate_audit.certificate_audits else None
        cert_params = {
            "certificate_index": leaf.certificate_index,
            "raw_der_sha256": leaf.raw_der_sha256,
            "public_key_algorithm": leaf.public_key.algorithm if leaf.public_key else None,
            "public_key_bits": leaf.public_key.key_size_bits if leaf.public_key else None,
            "signature_algorithm": leaf.signature_algorithm_name,
            "is_expired": audit_entry.is_expired if audit_entry else None,
            "is_not_yet_valid": audit_entry.is_not_yet_valid if audit_entry else None,
            "is_self_signed": audit_entry.is_self_signed if audit_entry else None,
        }

    starttls_params = None
    if target_stream is not None and target_classification is not None:
        protocol_value = str(getattr(target_classification.protocol, "value", target_classification.protocol)).upper()
        starttls_params = {
            "protocol": protocol_value,
            "starttls_state": str(getattr(starttls_assessment, "starttls_state", "UNKNOWN").value).upper() if starttls_assessment else "UNKNOWN",
            "reconstruction_status": "COMPLETE",
            "unresolved_gaps": False,
            "tls_transition_detected": bool(getattr(starttls_assessment, "tls_transition_detected", False)),
            "tls_handshake_observed": bool(tls_handshake_observed),
        }
        plaintext_blocks = (client_payload + b"\r\n" + server_payload).upper()
        if b"AUTH " in plaintext_blocks and not tls_handshake_observed:
            starttls_params["plaintext_auth_observed"] = True
            starttls_params["plaintext_observed"] = True

    # 9. Deterministic Compliance Evaluation
    stream_id = target_stream.stream_id if target_stream else "stream#1"
    compliance_report = compliance_engine.evaluate_session(
        stream_id=stream_id,
        tls_params=tls_params,
        key_exchange_params=kex_params,
        cert_audit_params=cert_params,
        identity_result=identity_result,
        trust_result=trust_result,
        starttls_params=starttls_params,
    )
    findings = compliance_report.findings

    # 10. Vulnerability & Threat Mapping
    vulnerability_report = vulnerability_mapping_engine.map_session(compliance_report)
    weakness_mappings = vulnerability_report.mappings

    threat_mapping_service = ThreatMappingService()
    threat_report = threat_mapping_service.build_session_threat_report(
        session_id=analysis_id,
        stream_id=stream_id,
        weaknesses=weakness_mappings,
    )
    threat_mappings = threat_report.threat_mappings

    # 11. Security Posture Evaluation
    posture_service = PostureEngineService()
    posture_report = posture_service.evaluate_posture(
        session_id=analysis_id,
        stream_id=stream_id,
        findings=findings,
        weaknesses=weakness_mappings,
        threats=threat_mappings,
        scoring_context={"plaintext_auth_observed": bool(starttls_params and starttls_params.get("plaintext_auth_observed"))},
    )

    # 12. ML Feature Engineering (Canonical 19D Vector)
    feature_extractor = MLFeatureEngineeringService()

    certificate_info = {}
    if cert_params is not None:
        certificate_info = {
            "key_size": cert_params.get("public_key_bits"),
            "signature_algorithm": cert_params.get("signature_algorithm"),
        }
        expired = cert_params.get("is_expired")
        not_yet_valid = cert_params.get("is_not_yet_valid")
        if expired is True or not_yet_valid is True:
            certificate_info["is_valid"] = False
        elif expired is False and not_yet_valid is False:
            certificate_info["is_valid"] = True

    if identity_result is not None:
        id_dict = identity_result.model_dump(mode="json") if hasattr(identity_result, "model_dump") else {}
        for k in ("san_present", "hostname_match"):
            if k in id_dict:
                certificate_info[k] = id_dict[k]
        if "hostname_match_status" in id_dict:
            certificate_info["hostname_match"] = id_dict["hostname_match_status"]

    if trust_result is not None:
        t_dict = trust_result.model_dump(mode="json") if hasattr(trust_result, "model_dump") else {}
        v_status = t_dict.get("certificate_trust", {}).get("trust_validation_status")
        if v_status:
            certificate_info["is_trusted"] = str(v_status).upper() in {"VERIFIED", "TRUSTED", "TRUE"}

    tls_version = tls_params.get("version") if tls_params else None
    cipher_suite = tls_params.get("cipher_suite") if tls_params else None
    key_exchange = str(getattr(key_exchange_result, "exchange_type", "UNKNOWN").value) if (key_exchange_result and getattr(key_exchange_result, "exchange_type", None)) else None

    is_downgrade = False
    if downgrade_result is not None:
        if downgrade_result.is_downgrade_suspected or getattr(downgrade_result.status, "value", str(downgrade_result.status)) in ("DOWNGRADE_SUSPECTED", "PLAINTEXT_FALLBACK_OBSERVED"):
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
        "certificate_key_size": cert_params.get("public_key_bits") if cert_params else None,
        "signature_algorithm": cert_params.get("signature_algorithm") if cert_params else None,
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

    fv_dict = features.to_feature_dict()

    return {
        "pcap": pcap_name,
        "scenario": scenario,
        "demo_risk_label": demo_risk_label,
        "posture_score": posture_report.posture_score,
        "features": fv_dict,
        "findings_count": len(findings),
        "vulnerabilities_count": len(weakness_mappings),
        "threats_count": len(threat_mappings),
    }


def main():
    dataset_dir = Path("data/demo_dataset")
    manifest_file = dataset_dir / "manifest.csv"
    if not manifest_file.exists():
        print(f"Error: Manifest not found at {manifest_file}")
        sys.exit(1)

    with manifest_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        manifest_rows = list(reader)

    print(f"Loaded {len(manifest_rows)} entries from {manifest_file}")

    results = []
    errors = []

    # Process in parallel using 6 threads
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_pcap = {}
        for row in manifest_rows:
            pcap_path = dataset_dir / row["pcap"]
            scenario = row["scenario"]
            label = row["risk_label"]
            future = executor.submit(process_single_pcap, pcap_path, scenario, label)
            future_to_pcap[future] = (row["pcap"], scenario)

        completed = 0
        total = len(manifest_rows)
        for future in as_completed(future_to_pcap):
            pcap_name, scenario = future_to_pcap[future]
            completed += 1
            try:
                res = future.result()
                results.append(res)
                if completed % 20 == 0 or completed == total:
                    print(f"Processed {completed}/{total} PCAPs ({completed/total*100:.1f}%)")
            except Exception as e:
                errors.append((pcap_name, scenario, str(e)))
                print(f"Error processing {pcap_name} ({scenario}): {e}")

    print(f"\nCompleted feature extraction: {len(results)} succeeded, {len(errors)} failed.")
    if errors:
        print(f"Sample errors: {errors[:5]}")
        sys.exit(1)

    # Sort results by pcap name for determinism
    results.sort(key=lambda r: r["pcap"])

    # Canonical 19D Feature Names in strict order
    feature_names = [
        "tls_version_numeric",
        "cipher_security_score",
        "key_exchange_strength",
        "pfs_enabled",
        "certificate_key_size",
        "certificate_signature_strength",
        "certificate_validity_status",
        "san_present",
        "hostname_match_status",
        "trust_validation_status",
        "revocation_status",
        "starttls_downgrade",
        "compliance_violation_count",
        "unknown_finding_count",
        "high_critical_finding_count",
        "vulnerability_count",
        "threat_mapping_count",
        "cryptographic_security_score",
        "ja4_available",
    ]

    # Write CSV
    csv_path = dataset_dir / "extracted_features.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        header = ["pcap", "scenario", "demo_risk_label", "posture_score"] + feature_names
        writer.writerow(header)
        for r in results:
            fv = r["features"]
            row = [r["pcap"], r["scenario"], r["demo_risk_label"], r["posture_score"]] + [fv.get(fn, -1.0) for fn in feature_names]
            writer.writerow(row)

    # Write JSON
    json_path = dataset_dir / "extracted_features.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Features saved to: {csv_path} and {json_path}")

    # Summary table per scenario
    from collections import defaultdict
    scenario_stats = defaultdict(lambda: {"count": 0, "posture": [], "features": defaultdict(list)})
    for r in results:
        sc = r["scenario"]
        scenario_stats[sc]["count"] += 1
        scenario_stats[sc]["posture"].append(r["posture_score"])
        for fn in feature_names:
            scenario_stats[sc]["features"][fn].append(r["features"].get(fn, -1.0))

    print("\n" + "=" * 90)
    print("SCENARIO FEATURE VERIFICATION TABLE")
    print("=" * 90)
    print(f"{'Scenario':<22} | {'Count':<5} | {'Label':<8} | {'Posture':<7} | {'TLS_Ver':<7} | {'Cipher':<6} | {'KEX':<5} | {'PFS':<5} | {'Downgrade':<9}")
    print("-" * 90)
    for sc, data in sorted(scenario_stats.items()):
        lbl = [r["demo_risk_label"] for r in results if r["scenario"] == sc][0]
        avg_posture = sum(data["posture"]) / len(data["posture"])
        tls_ver = data["features"]["tls_version_numeric"][0]
        cipher = data["features"]["cipher_security_score"][0]
        kex = data["features"]["key_exchange_strength"][0]
        pfs = data["features"]["pfs_enabled"][0]
        dwn = data["features"]["starttls_downgrade"][0]
        print(f"{sc:<22} | {data['count']:<5} | {lbl:<8} | {avg_posture:<7.1f} | {tls_ver:<7.1f} | {cipher:<6.1f} | {kex:<5.1f} | {pfs:<5.1f} | {dwn:<9.1f}")
    print("=" * 90)


if __name__ == "__main__":
    main()
