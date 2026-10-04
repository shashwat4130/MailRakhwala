import sys
from pathlib import Path
import csv
import json

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.risk_classifier import XGBoostRiskClassifier
from app.services.shap_explainer import SHAPExplainerService
from app.services.job_store import job_store
from app.api.routes.analysis import run_pipeline_task
from app.services.ml_model_loader import ml_model_manager

# 1. First, let's extract the CURRENT features from all 240 PCAPs with our fixed compliance_engine and posture_engine!
from scripts.extract_demo_features import process_single_pcap

dataset_dir = Path("data/demo_dataset")
manifest_path = dataset_dir / "manifest.csv"

# Scenario to label mapping based on current canonical security assessment:
SCENARIO_LABELS = {
    "tls_modern": "LOW",
    "starttls_clean": "LOW",
    "weak_tls": "MEDIUM",
    "plaintext": "HIGH",
    "starttls_downgrade": "HIGH",
    "cert_bad": "CRITICAL",
}

print("Running feature extraction on all demo PCAPs with updated pipeline...")
rows = []
with manifest_path.open("r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    manifest_rows = list(reader)

for r in manifest_rows:
    pcap_name = r["pcap"]
    scenario = r["scenario"]
    pcap_path = dataset_dir / pcap_name
    canonical_label = SCENARIO_LABELS[scenario]
    
    res = process_single_pcap(pcap_path, scenario, canonical_label)
    rows.append(res)

print(f"Extracted features for {len(rows)} PCAPs.")
from collections import Counter
print("Label counts:", Counter(r["demo_risk_label"] for r in rows))

# Save updated extracted_features.csv
from scripts.train_demo_models import FEATURE_NAMES

csv_path = dataset_dir / "extracted_features.csv"
fieldnames = ["pcap", "scenario", "demo_risk_label", "posture_score"] + FEATURE_NAMES
with csv_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for item in rows:
        row = {
            "pcap": item["pcap"],
            "scenario": item["scenario"],
            "demo_risk_label": item["demo_risk_label"],
            "posture_score": item["posture_score"],
        }
        for fn in FEATURE_NAMES:
            row[fn] = item["features"].get(fn, -1.0)
        writer.writerow(row)

print("Saved updated extracted_features.csv")

# Now let's train XGBoost and evaluate!
from scripts.train_demo_models import stratified_split, load_dataset

loaded_rows = load_dataset(csv_path)
train_rows, val_rows, test_rows = stratified_split(loaded_rows, seed=20261002)

X_train = [r["vector"] for r in train_rows]
y_train = [r["demo_risk_label"] for r in train_rows]

X_val = [r["vector"] for r in val_rows]
y_val = [r["demo_risk_label"] for r in val_rows]

X_test = [r["vector"] for r in test_rows]
y_test = [r["demo_risk_label"] for r in test_rows]

from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

clf = XGBoostRiskClassifier(
    n_estimators=100,
    max_depth=3,
    learning_rate=0.1,
    random_state=20261002,
)
clf.fit(X_train, y_train)

val_preds = [clf.predict(x).predicted_class for x in X_val]
val_acc = accuracy_score(y_val, val_preds)
val_f1 = f1_score(y_val, val_preds, average="macro")

test_results = [clf.predict(x) for x in X_test]
test_preds = [r.predicted_class for r in test_results]
test_acc = accuracy_score(y_test, test_preds)
test_f1 = f1_score(y_test, test_preds, average="macro")
cm = confusion_matrix(y_test, test_preds, labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"])

print(f"\n--- METRICS ---")
print(f"Val Accuracy:  {val_acc:.4f}, Val Macro F1:  {val_f1:.4f}")
print(f"Test Accuracy: {test_acc:.4f}, Test Macro F1: {test_f1:.4f}")
print(f"Confusion Matrix (LOW, MEDIUM, HIGH, CRITICAL):\n{cm}")

# Save models to both dirs
for md in (Path("data/models"), Path("backend/data/models")):
    md.mkdir(parents=True, exist_ok=True)
    clf.save(md / "xgboost_risk.joblib")

# Now let's test inference on the 6 scenarios and on bundled demo PCAP!
ml_model_manager.reset_cache()

scenarios = [
    ("Modern TLS", "0001_tls_modern_000.pcap"),
    ("Clean STARTTLS", "0041_starttls_clean_000.pcap"),
    ("Weak TLS", "0081_weak_tls_000.pcap"),
    ("STARTTLS Downgrade", "0121_starttls_downgrade_000.pcap"),
    ("Plaintext", "0161_plaintext_000.pcap"),
    ("Certificate Failure", "0201_cert_bad_000.pcap"),
]

print("\n" + "=" * 80)
print("TESTING INFERENCE ON SIX DEMO SCENARIOS")
print("=" * 80)

for name, pcap in scenarios:
    p = dataset_dir / pcap
    job_id = f"test-{pcap}"
    job_store.create_job(job_id, pcap, str(p), p.stat().st_size)
    run_pipeline_task(job_id, str(p), pcap)
    rep = job_store.get_job(job_id).report_data
    posture = rep.get("posture_report", {})
    rc = rep.get("risk_classification", {})
    shap = rep.get("shap_explanation", {})
    print(f"\nScenario: {name}")
    print(f"  Score: {posture.get('posture_score')}/100")
    print(f"  Deterministic Severity: {posture.get('severity')}")
    print(f"  ML Predicted Class: {rc.get('predicted_class')} (Class ID: {rc.get('class_id')})")
    print(f"  ML Probabilities: {rc.get('probabilities')}")
    print(f"  SHAP Prediction: {shap.get('prediction')}")
    if shap.get("features"):
        print(f"  SHAP Top Driver: {shap['features'][0]['feature']} ({shap['features'][0]['impact']}: {shap['features'][0]['shap_value']:.4f})")

# Test bundled demo PCAP
demo_p = Path("frontend/public/mailrakhwala-demo.pcap")
job_id = "test-bundled-demo"
job_store.create_job(job_id, "mailrakhwala-demo.pcap", str(demo_p), demo_p.stat().st_size)
run_pipeline_task(job_id, str(demo_p), "mailrakhwala-demo.pcap")
demo_rep = job_store.get_job(job_id).report_data
d_posture = demo_rep.get("posture_report", {})
d_rc = demo_rep.get("risk_classification", {})
d_shap = demo_rep.get("shap_explanation", {})
print("\n" + "=" * 80)
print("BUNDLED DEMO PCAP (mailrakhwala-demo.pcap):")
print("=" * 80)
print(f"  Score:                  {d_posture.get('posture_score')}/100")
print(f"  Total Penalty:          {d_posture.get('total_penalty')} pts")
print(f"  Deterministic Severity: {d_posture.get('severity')}")
print(f"  ML Predicted Class:     {d_rc.get('predicted_class')} (Class ID: {d_rc.get('class_id')})")
print(f"  ML Probabilities:       {d_rc.get('probabilities')}")
print(f"  SHAP Prediction:        {d_shap.get('prediction')}")
if d_shap.get("features"):
    print(f"  SHAP Top Driver:        {d_shap['features'][0]['feature']} ({d_shap['features'][0]['impact']}: {d_shap['features'][0]['shap_value']:.4f})")
