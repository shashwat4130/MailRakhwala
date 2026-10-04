import sys
from pathlib import Path
import numpy as np

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from app.services.risk_classifier import XGBoostRiskClassifier, LABEL_TO_ID, ID_TO_LABEL
from app.services.shap_explainer import SHAPExplainerService
from app.schemas.risk_classification import RiskClassificationResult

# Demo PCAP feature vector
demo_vec = [
    3.0,   # tls_version_numeric (TLS 1.2)
    1.0,   # cipher_security_score (CBC)
    0.0,   # key_exchange_strength (Static RSA)
    0.0,   # pfs_enabled (False)
    1024.0,# certificate_key_size
    2.0,   # certificate_signature_strength (SHA-256)
    0.0,   # certificate_validity_status (Expired)
    -1.0,  # san_present
    -1.0,  # hostname_match_status
    0.0,   # trust_validation_status (Untrusted)
    -1.0,  # revocation_status
    1.0,   # starttls_downgrade (ACTIVE DOWNGRADE)
    9.0,   # compliance_violation_count
    5.0,   # unknown_finding_count
    6.0,   # high_critical_finding_count
    7.0,   # vulnerability_count
    7.0,   # threat_mapping_count
    62.0,  # cryptographic_security_score (Score 62/100)
    0.0,   # ja4_available
]

print("Demo vector length:", len(demo_vec))
