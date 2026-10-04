import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

import numpy as np
from app.services.risk_classifier import XGBoostRiskClassifier, LABEL_TO_ID, ID_TO_LABEL
from app.services.shap_explainer import SHAPExplainerService

print("Testing ML calibration...")
