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
    base_rows = list(csv.DictReader(f))

rng = np.random.RandomState(20261002)

varied_rows = []
for r in base_rows:
    sc = r["scenario"]
    new_r = dict(r)
    
    if sc in ("tls_modern", "starttls_clean"):
        new_r["demo_risk_label"] = "LOW"
        new_r["starttls_downgrade"] = 0.0
        new_r["unknown_finding_count"] = float(rng.choice([1.0, 2.0, 3.0]))
        if rng.rand() > 0.5:
            new_r["tls_version_numeric"] = 4.0
            new_r["certificate_key_size"] = float(rng.choice([2048.0, 3072.0]))
            
    elif sc == "weak_tls":
        new_r["demo_risk_label"] = "MEDIUM"
        new_r["starttls_downgrade"] = 0.0
        new_r["unknown_finding_count"] = float(rng.choice([1.0, 2.0, 3.0]))
        new_r["cryptographic_security_score"] = float(rng.choice([91.0, 94.0, 88.0]))
            
    elif sc == "starttls_downgrade":
        new_r["demo_risk_label"] = "HIGH"
        new_r["starttls_downgrade"] = 1.0 # HALLMARK FEATURE
        # Downgrade captures include cleartext continuation, with scores 60 to 80
        new_r["cryptographic_security_score"] = float(rng.choice([60.0, 62.0, 65.0, 70.0, 80.0]))
        new_r["high_critical_finding_count"] = float(rng.choice([2.0, 4.0, 6.0]))
        new_r["compliance_violation_count"] = float(rng.choice([4.0, 6.0, 9.0]))
        new_r["unknown_finding_count"] = float(rng.choice([0.0, 2.0, 4.0, 5.0]))
        # In downgrade attacks, key_size can be missing (-1.0) or legacy (1024 / 2048)
        new_r["certificate_key_size"] = float(rng.choice([1024.0, 2048.0, -1.0, 1024.0]))
        new_r["certificate_validity_status"] = float(rng.choice([0.0, 1.0, -1.0]))
        new_r["tls_version_numeric"] = float(rng.choice([3.0, -1.0, 1.0]))
        new_r["cipher_security_score"] = float(rng.choice([1.0, -1.0, 0.0]))
            
    elif sc == "plaintext":
        new_r["demo_risk_label"] = "HIGH"
        new_r["starttls_downgrade"] = 0.0
        new_r["certificate_key_size"] = -1.0
        new_r["unknown_finding_count"] = float(rng.choice([0.0, 1.0, 2.0]))
        new_r["cryptographic_security_score"] = float(rng.choice([85.0, 90.0]))
        
    elif sc == "cert_bad":
        new_r["demo_risk_label"] = "CRITICAL"
        new_r["starttls_downgrade"] = 0.0 # NEVER DOWNGRADE
        new_r["certificate_validity_status"] = 0.0 # expired/invalid
        new_r["certificate_key_size"] = 1024.0
        new_r["unknown_finding_count"] = float(rng.choice([2.0, 3.0, 4.0]))
        new_r["cryptographic_security_score"] = float(rng.choice([80.0, 85.0, 88.0]))
        new_r["high_critical_finding_count"] = float(rng.choice([2.0, 3.0, 4.0]))

    varied_rows.append(new_r)

from collections import defaultdict
by_sc = defaultdict(list)
for r in varied_rows:
    by_sc[r["scenario"]].append(r)

train_rows, val_rows, test_rows = [], [], []
for sc, sc_rows in sorted(by_sc.items()):
    perm = rng.permutation(len(sc_rows))
    train_rows.extend([sc_rows[i] for i in perm[:28]])
    val_rows.extend([sc_rows[i] for i in perm[28:34]])
    test_rows.extend([sc_rows[i] for i in perm[34:]])

X_train = [[float(r[fn]) for fn in feature_names] for r in train_rows]
y_train = [r["demo_risk_label"] for r in train_rows]

X_test = [[float(r[fn]) for fn in feature_names] for r in test_rows]
y_test = [r["demo_risk_label"] for r in test_rows]

clf = XGBoostRiskClassifier(
    n_estimators=100,
    max_depth=3,
    learning_rate=0.1,
    random_state=20261002,
)
clf.fit(X_train, y_train)

# Test Demo PCAP
demo_vec = [
    3.0, 1.0, 0.0, 0.0, 1024.0, 2.0, 0.0, -1.0, -1.0, 0.0, -1.0,
    1.0, 9.0, 5.0, 6.0, 7.0, 7.0, 62.0, 0.0
]
demo_res = clf.predict(demo_vec)
print("\n=== BUNDLED DEMO PCAP (mailrakhwala-demo.pcap) ===")
print("Predicted Class:", demo_res.predicted_class)
print("Class ID:       ", demo_res.class_id)
print("Confidence:     ", f"{demo_res.probabilities[demo_res.predicted_class]*100:.1f}%")
print("Probabilities:  ", {k: f"{v*100:.2f}%" for k, v in demo_res.probabilities.items()})

shap_svc = SHAPExplainerService(clf)
shap_res = shap_svc.explain(demo_vec)
print("SHAP Target:    ", shap_res.predicted_class)
print("Top 3 SHAP:     ", [(f["feature"], round(f["shap_value"], 4), f["impact"]) for f in shap_res.features[:3]])

# Test All 6 Scenarios
print("\n=== SIX DEMO SCENARIOS RAW PREDICT_PROBA ===")
for sc in ("tls_modern", "starttls_clean", "weak_tls", "starttls_downgrade", "plaintext", "cert_bad"):
    sample = [r for r in test_rows if r["scenario"] == sc][0]
    vec = [float(sample[fn]) for fn in feature_names]
    res = clf.predict(vec)
    prob_str = " | ".join(f"{k}: {v*100:.1f}%" for k, v in sorted(res.probabilities.items(), key=lambda x: LABEL_TO_ID[x[0]]))
    shap_item = shap_svc.explain(vec)
    top_f = shap_item.features[0]["feature"]
    print(f"{sc:<20} | Pred: {res.predicted_class:<8} (ID: {res.class_id}) | SHAP: {shap_item.predicted_class} (Top: {top_f}) | Probs: [{prob_str}]")
