import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.job_store import job_store
from app.api.routes.analysis import run_pipeline_task

p = Path("frontend/public/mailrakhwala-demo.pcap")
job_id = "test-demo-details"
job_store.create_job(job_id, p.name, str(p), p.stat().st_size)
run_pipeline_task(job_id, str(p), p.name)
rep = job_store.get_job(job_id).report_data

posture = rep["posture_report"]
print("Posture Score:", posture["posture_score"])
print("Canonical Severity:", posture["severity"])
print("Total Penalty:", posture.get("total_penalty"))

print("\nDeductions (Total = %d):" % len(posture.get("deductions", [])))
for d in posture.get("deductions", []):
    print(" ", d.get("rule_id"), "penalty:", d.get("penalty"), "sev:", d.get("severity"), "title:", d.get("title"))

findings = rep.get("compliance_findings", [])
non_comp = [f for f in findings if f.get("status") == "NON_COMPLIANT"]
print("\nNon-compliant Findings (Total = %d):" % len(non_comp))
for f in non_comp:
    print(" ", f.get("rule_id"), "sev:", f.get("severity"), "title:", f.get("title"))

print("\n19D Feature Vector:")
fv = rep.get("feature_vector", {})
for k, v in fv.items():
    print(f"  {k}: {v}")
