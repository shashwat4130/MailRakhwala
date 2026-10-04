import sys
from pathlib import Path
import csv
import numpy as np

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.risk_classifier import XGBoostRiskClassifier, LABEL_TO_ID, ID_TO_LABEL
from app.services.shap_explainer import SHAPExplainerService
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

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

print(f"Loaded {len(rows)} samples from extracted_features.csv")

# Also check class counts
from collections import Counter
counts = Counter(r["demo_risk_label"] for r in rows)
print("Class counts:", counts)

# Train/Val/Test Split
from collections import defaultdict
rng = np.random.RandomState(20261002)
by_sc = defaultdict(list)
for r in rows:
    by_sc[r["scenario"]].append(r)

train_rows, val_rows, test_rows = [], [], []
for sc, sc_rows in sorted(by_sc.items()):
    perm = rng.permutation(len(sc_rows))
    train_rows.extend([sc_rows[i] for i in perm[:28]])
    val_rows.extend([sc_rows[i] for i in perm[28:34]])
    test_rows.extend([sc_rows[i] for i in perm[34:]])

print(f"Split: Train={len(train_rows)}, Val={len(val_rows)}, Test={len(test_rows)}")
print("Train Class Distribution:", Counter(r["demo_risk_label"] for r in train_rows))
print("Val Class Distribution:  ", Counter(r["demo_risk_label"] for r in val_rows))
print("Test Class Distribution: ", Counter(r["demo_risk_label"] for r in test_rows))

X_train = [[float(r[fn]) for fn in feature_names] for r in train_rows]
y_train = [r["demo_risk_label"] for r in train_rows]

X_val = [[float(r[fn]) for fn in feature_names] for r in val_rows]
y_val = [r["demo_risk_label"] for r in val_rows]

X_test = [[float(r[fn]) for fn in feature_names] for r in test_rows]
y_test = [r["demo_risk_label"] for r in test_rows]

clf = XGBoostRiskClassifier(
    n_estimators=100,
    max_depth=3,
    learning_rate=0.1,
    random_state=20261002,
)
clf.fit(X_train, y_train)

val_preds = [clf.predict(vec).predicted_class for vec in X_val]
val_acc = accuracy_score(y_val, val_preds)
val_f1 = f1_score(y_val, val_preds, average="macro")

test_preds = [clf.predict(vec).predicted_class for vec in X_test]
test_acc = accuracy_score(y_test, test_preds)
test_f1 = f1_score(y_test, test_preds, average="macro")
cm = confusion_matrix(y_test, test_preds, labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"])

print(f"\nValidation Accuracy: {val_acc*100:.2f}%, Macro F1: {val_f1:.4f}")
print(f"Test Accuracy:       {test_acc*100:.2f}%, Macro F1: {test_f1:.4f}")
print(f"Confusion Matrix:\n{cm}")

shap_svc = SHAPExplainerService(clf)

# Test Demo PCAP
demo_vec = [
    3.0, 1.0, 0.0, 0.0, 1024.0, 2.0, 0.0, -1.0, -1.0, 0.0, -1.0,
    1.0, 9.0, 5.0, 6.0, 7.0, 7.0, 62.0, 0.0
]
demo_res = clf.predict(demo_vec)
print("\n=== BUNDLED DEMO PCAP (mailrakhwala-demo.pcap) ===")
print("Predicted Class:", demo_res.predicted_class)
print("Class ID:       ", demo_res.class_id)
print("Probabilities:  ", {k: f"{v*100:.2f}%" for k, v in demo_res.probabilities.items()})

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
