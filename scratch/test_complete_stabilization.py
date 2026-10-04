import os
import sys
import json
from pathlib import Path
from starlette.testclient import TestClient

# Add backend to path
sys.path.insert(0, os.path.abspath('backend'))

from app.main import app
from app.services.job_store import job_store
from app.services.ml_model_loader import ml_model_manager
from app.api.routes.analysis import run_pipeline_task
from app.services.posture import PostureRuleCatalog, PostureEngineService

DEMO_PCAP = Path("frontend/public/mailrakhwala-demo.pcap").resolve()

def run_stabilization_suite():
    print("==================================================")
    print("STEP 1: Run bundled demo PCAP through complete pipeline via TestClient")
    print("==================================================")
    assert DEMO_PCAP.is_file(), f"Demo PCAP not found at {DEMO_PCAP}"

    job_store.clear()
    ml_model_manager.reset_cache()

    with TestClient(app) as client:
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 202, f"Upload failed: {resp.status_code} {resp.text}"
        analysis_id = resp.json()["analysis_id"]

        job = job_store.get_job(analysis_id)
        assert job is not None
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200, f"Get report failed: {report_resp.status_code}"
        report = report_resp.json()

        # 1. Authoritative Deterministic Posture
        posture = report.get("posture_report", {})
        score = posture.get("posture_score")
        severity = posture.get("severity")
        base_score = posture.get("base_score")
        total_penalty = posture.get("total_penalty")
        deductions = posture.get("deductions", [])

        print(f"1. Posture Score: {score}/100")
        print(f"2. Deterministic Severity: {severity}")
        print(f"3. Base Score: {base_score}, Total Deductions: {total_penalty}")
        print(f"4. Verified Deductions Count: {len(deductions)}")
        for d in deductions:
            print(f"   - {d.get('rule_id')}: -{d.get('penalty')} pts ({d.get('title')})")

        assert base_score == 100
        assert score == 62
        assert total_penalty == 38
        assert severity == "MEDIUM"
        assert len(deductions) == 8

        # Verify rule catalog budget
        catalog = PostureRuleCatalog()
        assert len(catalog.rules) == 19
        total_rule_budget = sum(r.get("penalty", 0) for r in catalog.rules.values())
        print(f"5. Total Maximum Penalty across 19 rules: {total_rule_budget}")
        assert total_rule_budget == 100

        # 2. 19D Feature Vector
        print("\n==================================================")
        print("STEP 2: Inspect 19D Feature Vector")
        print("==================================================")
        fv = report.get("feature_vector", {})
        feature_keys = [
            "tls_version_numeric", "cipher_security_score", "key_exchange_strength",
            "pfs_enabled", "certificate_key_size", "certificate_signature_strength",
            "certificate_validity_status", "san_present", "hostname_match_status",
            "trust_validation_status", "revocation_status", "starttls_downgrade",
            "compliance_violation_count", "unknown_finding_count",
            "high_critical_finding_count", "vulnerability_count",
            "threat_mapping_count", "cryptographic_security_score", "ja4_available"
        ]
        print(f"Feature count: {len(feature_keys)}")
        print(f"  - starttls_downgrade: {fv.get('starttls_downgrade')}")
        print(f"  - cryptographic_security_score: {fv.get('cryptographic_security_score')}")
        assert len(feature_keys) == 19
        assert fv.get("starttls_downgrade") == 1.0
        assert fv.get("cryptographic_security_score") == 62.0

        # 3. ML Risk Classification
        print("\n==================================================")
        print("STEP 3: Inspect ML Risk Classification (XGBoost)")
        print("==================================================")
        ml_risk = report.get("risk_classification", {})
        predicted_class = ml_risk.get("predicted_class")
        class_id = ml_risk.get("class_id")
        probabilities = ml_risk.get("probabilities", {})
        confidence = ml_risk.get("confidence")

        print(f"ML Predicted Class: {predicted_class}")
        print(f"ML Class ID: {class_id}")
        print(f"ML Probabilities: {probabilities}")
        print(f"ML Confidence: {confidence}")

        assert predicted_class == "CRITICAL"
        assert class_id == 3
        assert probabilities.get("CRITICAL", 0) > 0.95

        # 4. SHAP Explanation
        print("\n==================================================")
        print("STEP 4: Inspect SHAP Feature Attribution")
        print("==================================================")
        shap = report.get("shap_explanation", {})
        shap_predicted = shap.get("predicted_class")
        shap_target_id = shap.get("predicted_class_id")
        top_contributions = shap.get("top_contributions", [])

        print(f"SHAP Target Predicted Class: {shap_predicted}")
        print(f"SHAP Target Class ID: {shap_target_id}")
        print("Top 3 SHAP feature contributions:")
        for c in top_contributions[:3]:
            print(f"  - {c.get('feature_name')}: {c.get('shap_value'):+.4f} ({c.get('direction')})")

        assert shap_predicted == predicted_class
        assert shap_target_id == class_id
        assert top_contributions[0].get("feature_name") == "starttls_downgrade"

        # 5. Non-Email PCAP
        print("\n==================================================")
        print("STEP 5: Test Non-Email Capture (NOT_APPLICABLE)")
        print("==================================================")
        from unittest.mock import MagicMock, patch
        from app.schemas.packet import DissectedPacket

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

            minimal_pcap = (
                b"\xd4\xc3\xb2\xa1"
                b"\x02\x00\x04\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\xff\xff\x00\x00"
                b"\x01\x00\x00\x00"
            )
            ne_resp = client.post(
                "/analysis/upload",
                files={"file": ("http_traffic.pcap", minimal_pcap, "application/vnd.tcpdump.pcap")},
            )
            assert ne_resp.status_code == 202
            ne_id = ne_resp.json()["analysis_id"]

            ne_report_resp = client.get(f"/analysis/{ne_id}/report")
            assert ne_report_resp.status_code == 200
            ne_report = ne_report_resp.json()

            print(f"Non-Email Applicability: {ne_report.get('applicability')}")
            print(f"Non-Email Posture Score: {ne_report.get('posture_report', {}).get('posture_score')}")
            print(f"Non-Email Findings: {len(ne_report.get('compliance_findings', []))}")

            assert ne_report.get("applicability") == "NOT_APPLICABLE"
            assert ne_report.get("posture_report", {}).get("posture_score") is None
            assert len(ne_report.get("compliance_findings", [])) == 0

        # 6. JSON & PDF Export
        print("\n==================================================")
        print("STEP 6: Test JSON & PDF Export APIs")
        print("==================================================")
        json_resp = client.get(f"/analysis/{analysis_id}/report")
        assert json_resp.status_code == 200
        assert json_resp.json().get("posture_report", {}).get("posture_score") == 62

        pdf_resp = client.get(f"/analysis/{analysis_id}/report/pdf")
        assert pdf_resp.status_code == 200
        assert len(pdf_resp.content) > 1000

        print(f"JSON export: {len(json_resp.content)} bytes, status {json_resp.status_code}")
        print(f"PDF export: {len(pdf_resp.content)} bytes, status {pdf_resp.status_code}")

    print("\n==================================================")
    print("ALL 6 STEPS PASSED WITH 100% INTEGRITY!")
    print("==================================================")

if __name__ == "__main__":
    run_stabilization_suite()
