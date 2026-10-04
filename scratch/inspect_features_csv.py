import sys
from pathlib import Path
import numpy as np

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.risk_classifier import XGBoostRiskClassifier, LABEL_TO_ID, ID_TO_LABEL
from app.services.shap_explainer import SHAPExplainerService

# Feature index 11 is starttls_downgrade
# Feature index 4 is certificate_key_size
# Feature index 17 is cryptographic_security_score

# Let's inspect current extracted_features.csv
import csv
with open("data/demo_dataset/extracted_features.csv", "r") as f:
    rows = list(csv.DictReader(f))

print(f"Total rows in extracted_features.csv: {len(rows)}")
scenarios = set(r["scenario"] for r in rows)
print(f"Scenarios: {scenarios}")
for sc in sorted(scenarios):
    sc_rows = [r for r in rows if r["scenario"] == sc]
    print(f"  {sc} ({len(sc_rows)} rows): label={sc_rows[0]['demo_risk_label']}, score={sc_rows[0]['posture_score']}, downgrade={sc_rows[0]['starttls_downgrade']}, key_size={sc_rows[0]['certificate_key_size']}")
