from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union

from app.core.config import settings
from app.schemas.anomaly_detection import AnomalyDetectionResult
from app.schemas.ml_features import MLFeatureVector
from app.schemas.risk_classification import RiskClassificationResult
from app.schemas.shap_explainability import SHAPExplanationResult
from app.services.anomaly_detector import (
    EXPECTED_FEATURE_COUNT,
    IsolationForestDetector,
    ModelNotFittedError,
)
from app.services.risk_classifier import (
    XGBoostRiskClassifier,
    ModelNotFittedError as ClassifierNotFittedError,
)
from app.services.shap_explainer import SHAPExplainerService

logger = logging.getLogger(__name__)


class MLModelManager:
    """
    Thread-safe manager for loading, caching, and running ML models.
    
    Guarantees:
    - Never crashes analysis when models are missing, invalid, or corrupted.
    - Accurately reports availability and machine-readable reasons.
    - Never generates synthetic predictions, fake anomaly scores, or fabricated SHAP attributions.
    - Caches loaded models in memory to avoid per-request filesystem I/O.
    """

    def __init__(self, models_dir: Optional[Path] = None) -> None:
        self.models_dir = models_dir or settings.MODELS_DIR
        self._lock = threading.Lock()
        self._isolation_forest: Optional[IsolationForestDetector] = None
        self._xgboost_classifier: Optional[XGBoostRiskClassifier] = None
        self._shap_explainer: Optional[SHAPExplainerService] = None
        self._if_checked: bool = False
        self._xgb_checked: bool = False

    def reset_cache(self) -> None:
        """Clears cached models, forcing re-load on next inference."""
        with self._lock:
            self._isolation_forest = None
            self._xgboost_classifier = None
            self._shap_explainer = None
            self._if_checked = False
            self._xgb_checked = False

    def _find_model_path(self, base_name: str) -> Optional[Path]:
        """Looks for .joblib or .pkl artifact in models_dir."""
        for ext in (".joblib", ".pkl", ".model"):
            candidate = self.models_dir / f"{base_name}{ext}"
            if candidate.is_file() and candidate.stat().st_size > 0:
                return candidate
        return None

    def get_isolation_forest(self) -> Optional[IsolationForestDetector]:
        with self._lock:
            if self._if_checked:
                return self._isolation_forest

            self._if_checked = True
            model_path = self._find_model_path("isolation_forest")
            if not model_path:
                logger.info(f"Isolation Forest artifact not found in {self.models_dir}")
                self._isolation_forest = None
                return None

            try:
                detector = IsolationForestDetector.load(model_path)
                logger.info(f"Loaded Isolation Forest detector from {model_path}")
                self._isolation_forest = detector
                return detector
            except Exception as e:
                logger.warning(f"Failed to load Isolation Forest from {model_path}: {e}")
                self._isolation_forest = None
                return None

    def get_xgboost_classifier(self) -> Optional[XGBoostRiskClassifier]:
        with self._lock:
            if self._xgb_checked:
                return self._xgboost_classifier

            self._xgb_checked = True
            model_path = self._find_model_path("xgboost_risk")
            if not model_path:
                logger.info(f"XGBoost risk classifier artifact not found in {self.models_dir}")
                self._xgboost_classifier = None
                return None

            try:
                classifier = XGBoostRiskClassifier.load(model_path)
                logger.info(f"Loaded XGBoost classifier from {model_path}")
                self._xgboost_classifier = classifier
                return classifier
            except Exception as e:
                logger.warning(f"Failed to load XGBoost classifier from {model_path}: {e}")
                self._xgboost_classifier = None
                return None

    def get_shap_explainer(self) -> Optional[SHAPExplainerService]:
        with self._lock:
            if self._shap_explainer is not None:
                return self._shap_explainer

        # Need classifier outside lock or under lock
        classifier = self.get_xgboost_classifier()
        if not classifier:
            return None

        with self._lock:
            if self._shap_explainer is not None:
                return self._shap_explainer
            try:
                explainer = SHAPExplainerService(classifier)
                self._shap_explainer = explainer
                return explainer
            except Exception as e:
                logger.warning(f"Failed to initialize SHAPExplainerService: {e}")
                return None

    def run_anomaly_detection(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> AnomalyDetectionResult:
        s_id = stream_id or (feature_vector.stream_id if isinstance(feature_vector, MLFeatureVector) else None)
        raw_vec = feature_vector.to_feature_list() if isinstance(feature_vector, MLFeatureVector) else list(feature_vector)

        detector = self.get_isolation_forest()
        if detector is None:
            return AnomalyDetectionResult(
                available=False,
                stream_id=s_id,
                is_anomalous=None,
                prediction=None,
                anomaly_score=None,
                status_text="Isolation Forest model artifact unavailable.",
                feature_count=EXPECTED_FEATURE_COUNT,
                model_metadata=None,
                feature_vector=raw_vec,
                reason="trained_model_artifact_unavailable",
            )

        try:
            res = detector.predict(feature_vector, stream_id=s_id)
            res.available = True
            res.reason = None
            return res
        except Exception as e:
            logger.warning(f"Isolation Forest inference error: {e}")
            return AnomalyDetectionResult(
                available=False,
                stream_id=s_id,
                is_anomalous=None,
                prediction=None,
                anomaly_score=None,
                status_text=f"Anomaly detection failed during inference: {e}",
                feature_count=EXPECTED_FEATURE_COUNT,
                model_metadata=None,
                feature_vector=raw_vec,
                reason="inference_execution_failed",
            )

    def run_risk_classification(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> RiskClassificationResult:
        s_id = stream_id or (feature_vector.stream_id if isinstance(feature_vector, MLFeatureVector) else None)
        raw_vec = feature_vector.to_feature_list() if isinstance(feature_vector, MLFeatureVector) else list(feature_vector)

        classifier = self.get_xgboost_classifier()
        if classifier is None:
            return RiskClassificationResult(
                available=False,
                stream_id=s_id,
                predicted_class=None,
                class_id=None,
                class_probabilities=None,
                probabilities=None,
                feature_count=EXPECTED_FEATURE_COUNT,
                status_text="XGBoost risk classification model artifact unavailable.",
                model_metadata=None,
                feature_vector=raw_vec,
                reason="trained_model_artifact_unavailable",
            )

        try:
            res = classifier.predict(feature_vector, stream_id=s_id)
            res.available = True
            res.reason = None
            return res
        except Exception as e:
            logger.warning(f"XGBoost risk classification inference error: {e}")
            return RiskClassificationResult(
                available=False,
                stream_id=s_id,
                predicted_class=None,
                class_id=None,
                class_probabilities=None,
                probabilities=None,
                feature_count=EXPECTED_FEATURE_COUNT,
                status_text=f"Risk classification failed during inference: {e}",
                model_metadata=None,
                feature_vector=raw_vec,
                reason="inference_execution_failed",
            )

    def run_shap_explanation(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> SHAPExplanationResult:
        s_id = stream_id or (feature_vector.stream_id if isinstance(feature_vector, MLFeatureVector) else None)

        classifier = self.get_xgboost_classifier()
        if classifier is None:
            return SHAPExplanationResult(
                available=False,
                stream_id=s_id,
                base_value=None,
                prediction=None,
                predicted_class=None,
                predicted_class_id=None,
                class_probabilities={},
                features=[],
                feature_contributions=[],
                top_contributions=[],
                feature_count=EXPECTED_FEATURE_COUNT,
                model_metadata=None,
                status_text="SHAP explanation unavailable: risk model artifact unavailable.",
                reason="risk_model_unavailable",
            )

        explainer = self.get_shap_explainer()
        if explainer is None:
            return SHAPExplanationResult(
                available=False,
                stream_id=s_id,
                base_value=None,
                prediction=None,
                predicted_class=None,
                predicted_class_id=None,
                class_probabilities={},
                features=[],
                feature_contributions=[],
                top_contributions=[],
                feature_count=EXPECTED_FEATURE_COUNT,
                model_metadata=None,
                status_text="SHAP explainer initialization unavailable.",
                reason="risk_model_unavailable",
            )

        try:
            res = explainer.explain(feature_vector, stream_id=s_id)
            res.available = True
            res.reason = None
            return res
        except Exception as e:
            logger.warning(f"SHAP explanation inference error: {e}")
            return SHAPExplanationResult(
                available=False,
                stream_id=s_id,
                base_value=None,
                prediction=None,
                predicted_class=None,
                predicted_class_id=None,
                class_probabilities={},
                features=[],
                feature_contributions=[],
                top_contributions=[],
                feature_count=EXPECTED_FEATURE_COUNT,
                model_metadata=None,
                status_text=f"SHAP explanation failed during inference: {e}",
                reason="explanation_execution_failed",
            )


# Global singleton instance
ml_model_manager = MLModelManager()
