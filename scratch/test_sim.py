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

print("Feature names loaded, count =", len(feature_names))
