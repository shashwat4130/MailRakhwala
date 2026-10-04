import sys
from pathlib import Path
import pytest

from app.services.job_store import job_store, JobStatus
from app.api.routes.analysis import run_pipeline_task
from app.services.ml_model_loader import ml_model_manager

DATASET_DIR = Path(__file__).resolve().parents[2] / "data" / "demo_dataset"


@pytest.fixture(autouse=True)
def reset_ml_cache():
    ml_model_manager.reset_cache()
    yield
    ml_model_manager.reset_cache()


def run_capture(pcap_filename: str):
    pcap_path = DATASET_DIR / pcap_filename
    assert pcap_path.is_file(), f"PCAP {pcap_filename} not found in {DATASET_DIR}"
    job_id = f"test-{pcap_filename}"
    job_store.create_job(job_id, pcap_filename, str(pcap_path), pcap_path.stat().st_size)
    run_pipeline_task(job_id, str(pcap_path), pcap_filename)
    job = job_store.get_job(job_id)
    assert job is not None
    assert job.status == JobStatus.COMPLETED
    assert job.report_data is not None
    return job.report_data


def test_scenario_starttls_downgrade():
    """Scenario A: STARTTLS Downgrade detection and ML risk."""
    rep = run_capture("0121_starttls_downgrade_000.pcap")

    # 1. Deterministic findings
    findings = rep.get("compliance_findings", [])
    rule_ids = {f.get("rule_id") for f in findings if f.get("status") in ("NON_COMPLIANT", "non_compliant")}
    assert "RULE-STARTTLS-002" in rule_ids, "RULE-STARTTLS-002 must be triggered as NON_COMPLIANT"

    # 2. 19D Feature vector
    fv = rep.get("feature_vector", {})
    assert fv.get("starttls_downgrade") == 1.0

    # 3. Weakness / CWE mapping
    vulnerabilities = rep.get("vulnerability_mappings", [])
    cwe_ids = {v.get("cwe_id") for v in vulnerabilities}
    assert "CWE-319" in cwe_ids or len(vulnerabilities) > 0

    # 4. ML Inferences
    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "HIGH"
    assert rc.get("class_id") == 2
    assert rc.get("probabilities", {}).get("HIGH", 0) > 0.5

    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "HIGH"
    assert shap.get("predicted_class_id") == 2
    assert len(shap.get("features", [])) == 19
    top_features = [f["feature"] for f in shap["features"][:3]]
    assert "starttls_downgrade" in top_features


def test_scenario_tls_modern():
    """Scenario B: Modern TLS / clean STARTTLS."""
    rep = run_capture("0001_tls_modern_000.pcap")

    fv = rep.get("feature_vector", {})
    assert fv.get("tls_version_numeric") in (3.0, 4.0)
    assert fv.get("cipher_security_score") == 3.0
    assert fv.get("key_exchange_strength") == 2.0
    assert fv.get("pfs_enabled") == 1.0
    assert fv.get("starttls_downgrade") == 0.0

    posture = rep.get("posture_report", {})
    assert posture.get("posture_score", 0) >= 80

    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "LOW"
    assert rc.get("class_id") == 0

    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "LOW"


def test_scenario_weak_tls():
    """Scenario C: Weak TLS 1.0/1.1 with static RSA & CBC."""
    rep = run_capture("0081_weak_tls_000.pcap")

    fv = rep.get("feature_vector", {})
    assert fv.get("tls_version_numeric") in (1.0, 2.0)
    assert fv.get("key_exchange_strength") == 0.0
    assert fv.get("pfs_enabled") == 0.0
    assert fv.get("starttls_downgrade") == 0.0

    findings = rep.get("compliance_findings", [])
    rule_ids = {f.get("rule_id") for f in findings if f.get("status") in ("NON_COMPLIANT", "non_compliant")}
    assert "RULE-CIPHER-004" in rule_ids or "RULE-KEX-001" in rule_ids

    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "MEDIUM"
    assert rc.get("class_id") == 1

    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "MEDIUM"


def test_scenario_plaintext():
    """Scenario D: Plaintext SMTP with plaintext authentication."""
    rep = run_capture("0161_plaintext_000.pcap")

    fv = rep.get("feature_vector", {})
    assert fv.get("starttls_downgrade") == 0.0

    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "HIGH"
    assert rc.get("class_id") == 2

    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "HIGH"


def test_scenario_cert_bad():
    """Scenario E: Defective certificate (expired, 1024-bit key, self-signed)."""
    rep = run_capture("0201_cert_bad_000.pcap")

    fv = rep.get("feature_vector", {})
    assert fv.get("certificate_key_size") == 1024.0
    assert fv.get("certificate_validity_status") == 0.0

    findings = rep.get("compliance_findings", [])
    rule_ids = {f.get("rule_id") for f in findings if f.get("status") in ("NON_COMPLIANT", "non_compliant")}
    assert any("CERT" in r for r in rule_ids)

    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "CRITICAL"
    assert rc.get("class_id") == 3

    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "CRITICAL"
    assert shap.get("predicted_class_id") == 3


def test_bundled_demo_pcap():
    """Verify bundled demo PCAP (mailrakhwala-demo.pcap) produces canonical 62/100, HIGH deterministic severity, HIGH ML, and HIGH SHAP."""
    demo_path = Path(__file__).resolve().parents[2] / "frontend" / "public" / "mailrakhwala-demo.pcap"
    assert demo_path.is_file(), f"Demo PCAP not found at {demo_path}"

    job_id = "test-bundled-demo-pcap"
    job_store.create_job(job_id, "mailrakhwala-demo.pcap", str(demo_path), demo_path.stat().st_size)
    run_pipeline_task(job_id, str(demo_path), "mailrakhwala-demo.pcap")
    job = job_store.get_job(job_id)
    assert job is not None
    assert job.status == JobStatus.COMPLETED
    rep = job.report_data
    assert rep is not None

    # Deterministic posture
    posture = rep.get("posture_report", {})
    assert posture.get("posture_score") == 62
    deductions = posture.get("deductions", [])
    assert sum(d.get("penalty", 0) for d in deductions) == 38
    assert posture.get("severity") == "HIGH"

    # ML Risk Classification
    rc = rep.get("risk_classification", {})
    assert rc.get("available") is True
    assert rc.get("predicted_class") == "HIGH"
    assert rc.get("class_id") == 2
    assert rc.get("probabilities", {}).get("HIGH", 0) > 0.8

    # SHAP Explainability
    shap = rep.get("shap_explanation", {})
    assert shap.get("available") is True
    assert shap.get("prediction") == "HIGH"
    assert shap.get("predicted_class_id") == 2
    top_feature = shap["features"][0]
    assert top_feature["feature"] == "starttls_downgrade"
