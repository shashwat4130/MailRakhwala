import pytest
from pathlib import Path
from starlette.testclient import TestClient

from app.main import app
from app.services.job_store import job_store, JobStatus
from app.api.routes.analysis import run_pipeline_task
from app.services.ml_model_loader import ml_model_manager

DEMO_PCAP = Path(__file__).resolve().parents[2] / "frontend" / "public" / "mailrakhwala-demo.pcap"


def test_e2e_demo_pcap_analysis_with_trained_models():
    assert DEMO_PCAP.is_file(), f"Demo PCAP not found at {DEMO_PCAP}"
    ml_model_manager.reset_cache()
    
    with TestClient(app) as client:
        # 1. Upload
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert resp.status_code == 202, f"Upload failed: {resp.text}"
        data = resp.json()
        analysis_id = data["analysis_id"]

        # Run pipeline task synchronously
        job = job_store.get_job(analysis_id)
        assert job is not None
        run_pipeline_task(
            analysis_id=analysis_id,
            pcap_path=job.storage_path,
            filename=job.filename
        )

        # 2. Check Job Status
        status_resp = client.get(f"/analysis/{analysis_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] in ("COMPLETED", "completed")

        # 3. Check JSON Report
        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()

        # Check deterministic fields
        assert "posture_report" in report
        assert "compliance_findings" in report
        assert "vulnerability_mappings" in report
        assert "threat_mappings" in report
        assert "protocol_summary" in report

        # Check ML fields
        assert "feature_vector" in report
        fv = report["feature_vector"]
        assert fv is not None
        assert "tls_version_numeric" in fv
        assert "cipher_security_score" in fv
        assert fv["starttls_downgrade"] == 1.0

        # Anomaly Detection (live trained model)
        assert "anomaly_detection" in report
        ad = report["anomaly_detection"]
        assert ad is not None
        assert ad["available"] is True
        assert ad["is_anomalous"] in (True, False)
        assert ad["anomaly_score"] is not None

        # Risk Classification (live trained model)
        assert "risk_classification" in report
        rc = report["risk_classification"]
        assert rc is not None
        assert rc["available"] is True
        assert rc["predicted_class"] == "HIGH"
        assert rc["class_id"] == 2
        assert rc["probabilities"] is not None
        assert rc["probabilities"]["HIGH"] > 0.8

        # SHAP Explainability (live TreeExplainer)
        assert "shap_explanation" in report
        shap = report["shap_explanation"]
        assert shap is not None
        assert shap["available"] is True
        assert shap["prediction"] == "HIGH"
        assert shap["predicted_class_id"] == 2
        assert len(shap["features"]) == 19
        assert shap["features"][0]["feature"] == "starttls_downgrade"

        # 4. Check PDF Export
        pdf_resp = client.get(f"/analysis/{analysis_id}/report/pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert len(pdf_resp.content) > 1000
        assert pdf_resp.content.startswith(b"%PDF")


def test_e2e_demo_pcap_graceful_fallback_when_models_missing(monkeypatch, tmp_path):
    """Verifies that missing model artifacts do not crash deterministic analysis and report unavailable."""
    # Point models_dir to an empty directory
    ml_model_manager.reset_cache()
    monkeypatch.setattr(ml_model_manager, "models_dir", tmp_path)

    with TestClient(app) as client:
        with open(DEMO_PCAP, "rb") as f:
            resp = client.post(
                "/analysis/upload",
                files={"file": ("mailrakhwala-demo.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert resp.status_code == 202
        analysis_id = resp.json()["analysis_id"]

        job = job_store.get_job(analysis_id)
        run_pipeline_task(analysis_id, job.storage_path, job.filename)

        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()

        # Deterministic analysis is 100% functional
        assert report["posture_report"]["posture_score"] == 62
        assert len(report["compliance_findings"]) >= 4
        assert len(report["posture_report"]["deductions"]) >= 4

        # ML sections cleanly report unavailable
        assert report["anomaly_detection"]["available"] is False
        assert report["anomaly_detection"]["reason"] == "trained_model_artifact_unavailable"
        assert report["risk_classification"]["available"] is False
        assert report["risk_classification"]["reason"] == "trained_model_artifact_unavailable"
        assert report["shap_explanation"]["available"] is False
        assert report["shap_explanation"]["reason"] == "risk_model_unavailable"

    ml_model_manager.reset_cache()
