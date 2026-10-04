from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
import numpy as np

from app.schemas.ml_features import MLFeatureVector
from app.services.anomaly_detector import IsolationForestDetector, EXPECTED_FEATURE_COUNT
from app.services.risk_classifier import XGBoostRiskClassifier, ALLOWED_CLASSES
from app.services.shap_explainer import SHAPExplainerService
from app.services.ml_model_loader import MLModelManager


def _create_synthetic_reference_data():
    """Generates deterministic numerical feature vectors for testing serialization & math."""
    rng = np.random.RandomState(42)
    X = []
    y = []
    class_names = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    # 4 classes: LOW (0), MEDIUM (1), HIGH (2), CRITICAL (3)
    for class_id, class_name in enumerate(class_names):
        for _ in range(10):
            # 19 features
            vec = [float(rng.uniform(0.0, 1.0)) for _ in range(EXPECTED_FEATURE_COUNT)]
            # make class-specific distinction
            vec[1] = float(class_id * 30.0)  # cipher_security_score
            vec[17] = float(100.0 - class_id * 25.0)  # cryptographic_security_score
            X.append(vec)
            y.append(class_name)
    return X, y


def test_ml_manager_graceful_degradation_missing_artifacts(tmp_path):
    """When model artifacts do not exist, manager must return available=False with honest reason."""
    mgr = MLModelManager(models_dir=tmp_path)
    sample_vector = [0.0] * EXPECTED_FEATURE_COUNT

    # Anomaly
    ad_res = mgr.run_anomaly_detection(sample_vector, stream_id="test-stream-1")
    assert ad_res.available is False
    assert ad_res.is_anomalous is None
    assert ad_res.prediction is None
    assert ad_res.anomaly_score is None
    assert ad_res.reason == "trained_model_artifact_unavailable"
    assert ad_res.stream_id == "test-stream-1"

    # Risk Classification
    rc_res = mgr.run_risk_classification(sample_vector, stream_id="test-stream-1")
    assert rc_res.available is False
    assert rc_res.predicted_class is None
    assert rc_res.class_id is None
    assert rc_res.probabilities is None
    assert rc_res.reason == "trained_model_artifact_unavailable"

    # SHAP
    shap_res = mgr.run_shap_explanation(sample_vector, stream_id="test-stream-1")
    assert shap_res.available is False
    assert shap_res.prediction is None
    assert shap_res.features == []
    assert shap_res.base_value is None
    assert shap_res.reason == "risk_model_unavailable"


def test_isolation_forest_save_load_lifecycle(tmp_path):
    """IsolationForestDetector can be fitted, saved to disk, loaded, and produce identical predictions."""
    X, _ = _create_synthetic_reference_data()
    detector = IsolationForestDetector(n_estimators=50, random_state=42)
    detector.fit(X)
    assert detector._is_fitted is True

    test_vec = [0.5] * EXPECTED_FEATURE_COUNT
    orig_res = detector.predict(test_vec)
    assert orig_res.is_anomalous is not None
    assert isinstance(orig_res.anomaly_score, float)

    # Save to disk
    model_file = tmp_path / "isolation_forest.joblib"
    detector.save(model_file)
    assert model_file.is_file()
    assert model_file.stat().st_size > 0

    # Load from disk
    loaded = IsolationForestDetector.load(model_file)
    assert loaded._is_fitted is True
    assert len(loaded._imputation_values) == EXPECTED_FEATURE_COUNT

    loaded_res = loaded.predict(test_vec)
    assert loaded_res.is_anomalous == orig_res.is_anomalous
    assert loaded_res.prediction == orig_res.prediction
    assert abs(loaded_res.anomaly_score - orig_res.anomaly_score) < 1e-6


def test_xgboost_classifier_save_load_lifecycle(tmp_path):
    """XGBoostRiskClassifier can be fitted, saved, loaded, and produce identical predictions & probs."""
    X, y = _create_synthetic_reference_data()
    classifier = XGBoostRiskClassifier(n_estimators=30, max_depth=3, random_state=42)
    classifier.fit(X, y)
    assert classifier._is_fitted is True

    test_vec = [0.2] * EXPECTED_FEATURE_COUNT
    test_vec[1] = 90.0  # high cipher score -> lower risk
    test_vec[17] = 95.0
    orig_res = classifier.predict(test_vec)
    assert orig_res.predicted_class in ALLOWED_CLASSES
    assert orig_res.class_probabilities is not None

    # Save
    model_file = tmp_path / "xgboost_risk.joblib"
    classifier.save(model_file)
    assert model_file.is_file()

    # Load
    loaded = XGBoostRiskClassifier.load(model_file)
    assert loaded._is_fitted is True
    assert loaded.model is not None

    loaded_res = loaded.predict(test_vec)
    assert loaded_res.predicted_class == orig_res.predicted_class
    assert loaded_res.class_id == orig_res.class_id
    for cls_name in ALLOWED_CLASSES:
        assert abs(loaded_res.class_probabilities[cls_name] - orig_res.class_probabilities[cls_name]) < 1e-6


def test_shap_explainer_with_loaded_model(tmp_path):
    """SHAPExplainerService operates reliably against a loaded XGBoost artifact."""
    X, y = _create_synthetic_reference_data()
    classifier = XGBoostRiskClassifier(n_estimators=20, max_depth=3, random_state=42)
    classifier.fit(X, y)

    model_file = tmp_path / "xgboost_risk.joblib"
    classifier.save(model_file)

    loaded_clf = XGBoostRiskClassifier.load(model_file)
    explainer = SHAPExplainerService(loaded_clf)

    test_vec = [0.3] * EXPECTED_FEATURE_COUNT
    explanation = explainer.explain(test_vec, stream_id="shap-test-stream")

    assert explanation.available is True
    assert explanation.stream_id == "shap-test-stream"
    assert explanation.predicted_class in ALLOWED_CLASSES
    assert explanation.prediction == explanation.predicted_class
    assert len(explanation.features) == EXPECTED_FEATURE_COUNT
    assert len(explanation.feature_contributions) == EXPECTED_FEATURE_COUNT
    assert len(explanation.top_contributions) == 5

    # Check top feature is ranked by absolute SHAP descending
    assert explanation.features[0]["shap_value"] is not None
    assert "direction" in explanation.features[0]
    assert "impact" in explanation.features[0]
    assert "value" in explanation.features[0]


def test_ml_manager_full_operational_flow(tmp_path):
    """When valid artifacts are in models_dir, manager serves real inference for all three services."""
    X, y = _create_synthetic_reference_data()

    # Save detector
    detector = IsolationForestDetector(n_estimators=25, random_state=42)
    detector.fit(X)
    detector.save(tmp_path / "isolation_forest.joblib")

    # Save classifier
    classifier = XGBoostRiskClassifier(n_estimators=25, max_depth=3, random_state=42)
    classifier.fit(X, y)
    classifier.save(tmp_path / "xgboost_risk.joblib")

    mgr = MLModelManager(models_dir=tmp_path)
    sample_vec = [0.4] * EXPECTED_FEATURE_COUNT

    # Anomaly
    ad = mgr.run_anomaly_detection(sample_vec, stream_id="stream-42")
    assert ad.available is True
    assert ad.is_anomalous in (True, False)
    assert isinstance(ad.anomaly_score, float)
    assert ad.reason is None

    # Risk
    rc = mgr.run_risk_classification(sample_vec, stream_id="stream-42")
    assert rc.available is True
    assert rc.predicted_class in ALLOWED_CLASSES
    assert rc.class_probabilities is not None
    assert rc.probabilities is not None
    assert rc.reason is None

    # SHAP
    shap = mgr.run_shap_explanation(sample_vec, stream_id="stream-42")
    assert shap.available is True
    assert shap.prediction == rc.predicted_class
    assert len(shap.features) == EXPECTED_FEATURE_COUNT
    assert shap.reason is None
