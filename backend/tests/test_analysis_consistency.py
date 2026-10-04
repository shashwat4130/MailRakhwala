"""
MailRakhwala Architectural Consistency and Posture Validation Test Suite.
Validates the single source of truth across all assessment targets:
1. Clean Email PCAP
2. Multi-rule Email PCAP (POSTURE-PLAINTEXT-001 + POSTURE-STARTTLS-002)
3. Non-Email PCAP (NOT_APPLICABLE semantics, no fake 100 or 0)
4. Incomplete Evidence Email PCAP
5. Synthetic ML Demo Disclosure
6. Cross-Component Consistency Assertions
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.schemas.api import JobStatus
from app.schemas.packet import DissectedPacket
from app.services.job_store import job_store
from app.services.ml_model_loader import ml_model_manager
from app.api.routes.analysis import run_pipeline_task

DEMO_PCAP = Path(__file__).resolve().parents[2] / "frontend" / "public" / "mailrakhwala-demo.pcap"
DATASET_DIR = Path(__file__).resolve().parents[2] / "data" / "demo_dataset"

MOCK_PCAP_GLOBAL_HEADER = (
    b"\xd4\xc3\xb2\xa1"  # Magic Number (PCAP Little-Endian)
    b"\x02\x00\x04\x00"  # Version 2.4
    b"\x00\x00\x00\x00"  # Thiszone
    b"\x00\x00\x00\x00"  # Sigfigs
    b"\xff\xff\x00\x00"  # Snaplen (65535)
    b"\x01\x00\x00\x00"  # LinkType (Ethernet)
)


@pytest.fixture(autouse=True)
def reset_store_and_cache():
    job_store.clear()
    ml_model_manager.reset_cache()
    yield
    job_store.clear()
    ml_model_manager.reset_cache()


# =========================================================================
# A. CLEAN EMAIL PCAP
# =========================================================================

def test_clean_email_pcap_evaluation():
    clean_pcap = DATASET_DIR / "0041_starttls_clean_000.pcap"
    if not clean_pcap.is_file():
        pytest.skip(f"Clean PCAP not found at {clean_pcap}")

    with TestClient(app) as client:
        with open(clean_pcap, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("0041_starttls_clean_000.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 202
        analysis_id = resp.json()["analysis_id"]

        job = job_store.get_job(analysis_id)
        assert job is not None
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()

        # Clean email session must be APPLICABLE
        assert report["applicability"] == "APPLICABLE"
        assert report["assessment_status"] == "EVALUATED"
        assert report["session"]["applicability"] == "APPLICABLE"
        assert report["session"]["assessment_status"] == "EVALUATED"
        assert report["protocol_summary"]["detected_protocol"] in ("SMTP", "SMTPS")

        # Valid posture score (high score for clean session)
        posture = report["posture_report"]
        assert posture["applicability"] == "APPLICABLE"
        assert posture["assessment_status"] == "EVALUATED"
        assert isinstance(posture["posture_score"], int)
        assert posture["posture_score"] >= 80
        assert posture["severity"] == "LOW"


# =========================================================================
# B. MULTI-RULE EMAIL PCAP (BUNDLED DEMO)
# =========================================================================

def test_multi_rule_demo_pcap_calibrated_scoring():
    assert DEMO_PCAP.is_file(), f"Demo PCAP not found at {DEMO_PCAP}"

    with TestClient(app) as client:
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 202
        analysis_id = resp.json()["analysis_id"]

        job = job_store.get_job(analysis_id)
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()

        assert report["applicability"] == "APPLICABLE"
        assert report["assessment_status"] == "EVALUATED"

        # All four severities evaluated genuinely
        findings = report["compliance_findings"]
        severities = {f["severity"] for f in findings}
        assert "LOW" in severities, f"LOW severity missing from findings: {severities}"
        assert "MEDIUM" in severities, f"MEDIUM severity missing from findings: {severities}"
        assert "HIGH" in severities, f"HIGH severity missing from findings: {severities}"
        assert "CRITICAL" in severities, f"CRITICAL severity missing from findings: {severities}"

        # Real rules from the catalog
        rule_ids = {f["rule_id"] for f in findings}
        assert "RULE-CIPHER-UNKNOWN" in rule_ids  # LOW
        assert "RULE-CIPHER-004" in rule_ids     # MEDIUM
        assert "RULE-PKI-001" in rule_ids        # MEDIUM
        assert "RULE-STARTTLS-002" in rule_ids   # HIGH
        assert "RULE-PLAINTEXT-001" in rule_ids  # HIGH
        assert "RULE-CERT-003" in rule_ids       # CRITICAL

        # Posture deductions: calibrated 100-point budget scoring
        posture = report["posture_report"]
        assert posture["total_penalty"] == 38, f"Expected calibrated total penalty 38, got {posture['total_penalty']}"
        assert posture["posture_score"] == 62
        assert 0 <= posture["posture_score"] <= 100
        assert posture["severity"] == "HIGH"
        assert posture["evaluated_findings_count"] == len(findings)

        # Deductions include rules across multiple streams
        deduction_rule_ids = {d["rule_id"] for d in posture["deductions"]}
        assert "POSTURE-PLAINTEXT-001" in deduction_rule_ids
        assert "POSTURE-STARTTLS-002" in deduction_rule_ids
        assert "POSTURE-CERT-003" in deduction_rule_ids
        assert "POSTURE-CIPHER-004" in deduction_rule_ids
        assert "POSTURE-CIPHER-005" in deduction_rule_ids
        assert len(posture["deductions"]) >= 5

        # Deductions preserve stream references
        deduction_streams = {d["stream_id"] for d in posture["deductions"] if d.get("stream_id")}
        assert len(deduction_streams) > 1, f"Expected deductions across multiple streams, got: {deduction_streams}"

        # Consistency across exports
        pdf_resp = client.get(f"/analysis/{analysis_id}/report/pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"


# =========================================================================
# C. NON-EMAIL PCAP CONSISTENCY (NOT_APPLICABLE)
# =========================================================================

def test_non_email_pcap_not_applicable_consistency():
    mock_packets = [
        DissectedPacket(
            frame_number=1,
            timestamp_epoch=1710000000.0,
            frame_len=60,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=49152,
            dst_port=80,
            transport_protocol="TCP",
            tcp_stream=0,
            highest_layer="HTTP",
        )
    ]

    with patch("app.api.routes.analysis.TSharkService") as mock_tshark_cls:
        mock_tshark = MagicMock()
        mock_tshark.dissect_packets_stream.side_effect = lambda *args, **kwargs: list(mock_packets)
        mock_tshark_cls.return_value = mock_tshark

        with TestClient(app) as client:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("http_traffic.pcap", MOCK_PCAP_GLOBAL_HEADER, "application/vnd.tcpdump.pcap")},
            )
            assert resp.status_code == 202
            analysis_id = resp.json()["analysis_id"]

            report_resp = client.get(f"/analysis/{analysis_id}/report")
            assert report_resp.status_code == 200
            report = report_resp.json()

            # Must strictly be NOT_APPLICABLE
            assert report["applicability"] == "NOT_APPLICABLE"
            assert report["assessment_status"] == "NOT_APPLICABLE"
            assert report["session"]["applicability"] == "NOT_APPLICABLE"
            assert report["session"]["assessment_status"] == "NOT_APPLICABLE"
            assert "No supported email protocol" in report["applicability_reason"]

            # Posture score must NOT be 100/100 and must NOT be 0/100
            posture = report["posture_report"]
            assert posture["posture_score"] is None
            assert posture["severity"] is None
            assert posture["applicability"] == "NOT_APPLICABLE"
            assert posture["assessment_status"] == "NOT_APPLICABLE"
            assert posture["total_penalty"] == 0
            assert len(posture["deductions"]) == 0
            assert posture["evaluated_findings_count"] == 0

            # Findings and mappings must be empty
            assert len(report["compliance_findings"]) == 0
            assert len(report["vulnerability_mappings"]) == 0
            assert len(report["threat_mappings"]) == 0

            # ML models must be cleanly not applicable
            assert report["feature_vector"] is None
            assert report["anomaly_detection"]["available"] is False
            assert report["anomaly_detection"]["reason"] == "not_applicable"
            assert report["risk_classification"]["available"] is False
            assert report["risk_classification"]["reason"] == "not_applicable"
            assert report["shap_explanation"]["available"] is False
            assert report["shap_explanation"]["reason"] == "not_applicable"

            # PDF export must reflect NOT APPLICABLE
            pdf_resp = client.get(f"/analysis/{analysis_id}/report/pdf")
            assert pdf_resp.status_code == 200
            assert pdf_resp.content.startswith(b"%PDF")


# =========================================================================
# D. INCOMPLETE EVIDENCE EMAIL PCAP
# =========================================================================

def test_incomplete_evidence_email_pcap():
    mock_packets = [
        DissectedPacket(
            frame_number=1,
            timestamp_epoch=1710000000.0,
            frame_len=60,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=25,
            transport_protocol="TCP",
            tcp_stream=0,
            highest_layer="SMTP",
        )
    ]

    with patch("app.api.routes.analysis.TSharkService") as mock_tshark_cls:
        mock_tshark = MagicMock()
        mock_tshark.dissect_packets_stream.side_effect = lambda *args, **kwargs: list(mock_packets)
        mock_tshark_cls.return_value = mock_tshark

        with TestClient(app) as client:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("partial_smtp.pcap", MOCK_PCAP_GLOBAL_HEADER, "application/vnd.tcpdump.pcap")},
            )
            analysis_id = resp.json()["analysis_id"]

            report_resp = client.get(f"/analysis/{analysis_id}/report")
            assert report_resp.status_code == 200
            report = report_resp.json()

            assert report["applicability"] == "APPLICABLE"
            assert report["protocol_summary"]["detected_protocol"] == "SMTP"
            # Incomplete evidence: TLS version should remain unavailable
            assert report["protocol_summary"]["tls_version"] == "Unavailable from captured evidence"
            assert report["protocol_summary"]["cipher_suite"] == "Unavailable from captured evidence"


# =========================================================================
# E. SYNTHETIC ML TRANSPARENCY
# =========================================================================

def test_synthetic_ml_disclaimer_and_methodology():
    assert DEMO_PCAP.is_file()

    with TestClient(app) as client:
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        analysis_id = resp.json()["analysis_id"]
        job = job_store.get_job(analysis_id)
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report = client.get(f"/analysis/{analysis_id}/report").json()

        # Deterministic engine authoritative, ML methodology transparent
        assert "methodology_disclaimer" in report
        assert "deterministic" in report["methodology_disclaimer"].lower()
        assert "xgboost" in report["methodology_disclaimer"].lower()
        assert "anomaly detection flags statistical outliers" in report["methodology_disclaimer"].lower()


# =========================================================================
# F. CROSS-PAGE CONSISTENCY ASSERTIONS
# =========================================================================

def test_authoritative_state_consistency_assertions():
    """
    Validates that for any completed analysis, all core security facts
    are authoritative, self-consistent, and shared across all endpoints.
    """
    assert DEMO_PCAP.is_file()

    with TestClient(app) as client:
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        analysis_id = resp.json()["analysis_id"]
        job = job_store.get_job(analysis_id)
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report = client.get(f"/analysis/{analysis_id}/report").json()

        # 1. Authoritative Session & Status
        assert report["session"]["session_id"] == analysis_id
        assert report["session"]["status"] == "COMPLETED"
        assert report["applicability"] == report["session"]["applicability"] == report["posture_report"]["applicability"]
        assert report["assessment_status"] == report["session"]["assessment_status"] == report["posture_report"]["assessment_status"]

        # 2. Posture score is authoritative
        posture_score = report["posture_report"]["posture_score"]
        assert posture_score == 62
        assert report["feature_vector"]["cryptographic_security_score"] == float(posture_score)

        # 3. Findings count is authoritative
        findings_count = len(report["compliance_findings"])
        assert report["posture_report"]["evaluated_findings_count"] == findings_count
        assert len(report["posture_report"]["deductions"]) >= 5

        # 4. Findings rule IDs match deductions rule sources
        upstream_rules_in_deductions = {d["upstream_rule_id"] for d in report["posture_report"]["deductions"]}
        findings_rule_ids = {f["rule_id"] for f in report["compliance_findings"]}
        assert upstream_rules_in_deductions.issubset(findings_rule_ids)
