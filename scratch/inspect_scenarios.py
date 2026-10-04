import sys
from pathlib import Path
import json

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.job_store import job_store
from app.api.routes.analysis import run_pipeline_task
from app.services.ml_model_loader import ml_model_manager

ml_model_manager.reset_cache()
DATASET_DIR = Path("data/demo_dataset")

scenarios = [
    ("Modern TLS", "0001_tls_modern_000.pcap"),
    ("Clean STARTTLS", "0041_starttls_clean_000.pcap"),
    ("Weak TLS", "0081_weak_tls_000.pcap"),
    ("STARTTLS Downgrade", "0121_starttls_downgrade_000.pcap"),
    ("Plaintext", "0161_plaintext_000.pcap"),
    ("Certificate Failure", "0201_cert_bad_000.pcap"),
]

print("=" * 80)
print("AUDITING CURRENT SIX DEMO SCENARIOS")
print("=" * 80)

for name, pcap in scenarios:
    p = DATASET_DIR / pcap
    job_id = f"inspect-{pcap}"
    job_store.create_job(job_id, pcap, str(p), p.stat().st_size)
    run_pipeline_task(job_id, str(p), pcap)
    job = job_store.get_job(job_id)
    rep = job.report_data
    
    posture = rep.get("posture_report", {})
    rc = rep.get("risk_classification", {})
    shap = rep.get("shap_explanation", {})
    fv = rep.get("feature_vector", {})
    findings = rep.get("compliance_findings", [])
    non_comp = [f for f in findings if f.get("status") == "NON_COMPLIANT"]
    severities = [f.get("severity") for f in non_comp]
    
    top_shap = []
    if shap and shap.get("features"):
        top_shap = [(f["feature"], f["impact"], f["shap_value"]) for f in shap["features"][:3]]
    
    print(f"\n--- Scenario: {name} ({pcap}) ---")
    print(f"  Analysis ID:             {job_id}")
    print(f"  Posture Score:           {posture.get('posture_score')}/100")
    print(f"  Score Severity:          {posture.get('severity')}")
    print(f"  Verified Findings:       {len(non_comp)}")
    print(f"  Finding Severities:      {severities}")
    max_sev = "LOW"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in severities:
            max_sev = s
            break
    print(f"  Highest Finding Sev:     {max_sev}")
    print(f"  ML Predicted Class:      {rc.get('predicted_class')}")
    print(f"  ML Class ID:             {rc.get('class_id')}")
    print(f"  ML Probabilities:        {rc.get('probabilities')}")
    print(f"  SHAP Target Class:       {shap.get('prediction')}")
    print(f"  Top 3 SHAP Features:     {top_shap}")
    print(f"  19D Feature Vector:      {json.dumps(fv)}")
