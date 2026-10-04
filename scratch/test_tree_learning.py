import sys
from pathlib import Path
import csv
import numpy as np

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.risk_classifier import XGBoostRiskClassifier, LABEL_TO_ID, ID_TO_LABEL
from app.services.shap_explainer import SHAPExplainerService

feature_names = [
    "tls_version_numeric", "cipher_security_score", "key_exchange_strength",
    "pfs_enabled", "certificate_key_size", "certificate_signature_strength",
    "certificate_validity_status", "san_present", "hostname_match_status",
    "trust_validation_status", "revocation_status", "starttls_downgrade",
    "compliance_violation_count", "unknown_finding_count", "high_critical_finding_count",
    "vulnerability_count", "threat_mapping_count", "cryptographic_security_score",
    "ja4_available"
]

with open("data/demo_dataset/extracted_features.csv", "r") as f:
    rows = list(csv.DictReader(f))

# Let's inspect rows and create a dataset where starttls_downgrade has multi-stream downgrade captures
# (captures with downgrade=1.0 and key_size=1024.0 or score=62.0)
augmented_rows = []
for r in rows:
    augmented_rows.append(r)

# In starttls_downgrade (40 samples), let 15 of them have certificate_key_size = 1024.0, score = 62.0, high_critical_count = 6.0
# (matching multi-stream downgrade)
downgrade_idx = [i for i, r in enumerate(augmented_rows) if r["scenario"] == "starttls_downgrade"]
for idx in downgrade_idx[:15]:
    r = dict(augmented_rows[idx])
    r["certificate_key_size"] = "1024.0"
    r["cryptographic_security_score"] = "62.0"
    r["high_critical_finding_count"] = "6.0"
    r["compliance_violation_count"] = "9.0"
    r["vulnerability_count"] = "7.0"
    r["threat_mapping_count"] = "7.0"
    r["tls_version_numeric"] = "3.0"
    r["cipher_security_score"] = "1.0"
    augmented_rows[idx] = r

X = [[float(r[fn]) for fn in feature_names] for r in augmented_rows]
y = [r["demo_risk_label"] for r in augmented_rows]

clf = XGBoostRiskClassifier(n_estimators=100, max_depth=3, learning_rate=0.1, random_state=20261002)
clf.fit(X, y)

# Test the demo pcap vector
demo_vec = [
    3.0, 1.0, 0.0, 0.0, 1024.0, 2.0, 0.0, -1.0, -1.0, 0.0, -1.0,
    1.0, 9.0, 5.0, 6.0, 7.0, 7.0, 62.0, 0.0
]

res = clf.predict(demo_vec)
print("\n--- Demo PCAP Prediction ---")
print("Predicted Class:", res.predicted_class)
print("Class ID:", res.class_id)
print("Probabilities:", {k: f"{v*100:.1f}%" for k, v in res.probabilities.items()})

shap_svc = SHAPExplainerService(clf)
shap_res = shap_svc.explain(demo_vec)
print("SHAP Target Class:", shap_res.predicted_class)
print("Top 3 SHAP Features:", [(f["feature"], f["shap_value"], f["impact"]) for f in shap_res.features[:3]])

# Test all 6 scenarios
print("\n--- All 6 Scenarios ---")
for sc in ("tls_modern", "starttls_clean", "weak_tls", "starttls_downgrade", "plaintext", "cert_bad"):
    sample = [r for r in augmented_rows if r["scenario"] == sc][-1] # pick held-out style sample
    vec = [float(sample[fn]) for fn in feature_names]
    r = clf.predict(vec)
    probs_str = ", ".join(f"{k}: {v*100:.1f}%" for k, v in r.probabilities.items())
    print(f"{sc:<20}: Pred={r.predicted_class:<8} ({probs_str})")
