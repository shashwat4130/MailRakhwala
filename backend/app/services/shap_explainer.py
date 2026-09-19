from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
import shap

from app.schemas.ml_features import MLFeatureVector
from app.schemas.risk_classification import RiskClassificationResult
from app.schemas.shap_explainability import (
    BatchSHAPExplanationResult,
    ContributionDirection,
    GlobalFeatureImportance,
    SHAPExplanationResult,
    SHAPFeatureContribution,
    SHAPMetadata,
)
from app.services.risk_classifier import (
    ALLOWED_CLASSES,
    EXPECTED_FEATURE_COUNT,
    FeatureValidationError,
    ID_TO_LABEL,
    ModelNotFittedError,
    UNKNOWN_SENTINEL,
    XGBoostRiskClassifier,
)

STEP_25_FEATURE_NAMES: List[str] = [
    "tls_version_numeric",
    "cipher_security_score",
    "key_exchange_strength",
    "pfs_enabled",
    "certificate_key_size",
    "certificate_signature_strength",
    "certificate_validity_status",
    "san_present",
    "hostname_match_status",
    "trust_validation_status",
    "revocation_status",
    "starttls_downgrade",
    "compliance_violation_count",
    "unknown_finding_count",
    "high_critical_finding_count",
    "vulnerability_count",
    "threat_mapping_count",
    "cryptographic_security_score",
    "ja4_available",
]

assert len(STEP_25_FEATURE_NAMES) == EXPECTED_FEATURE_COUNT


class SHAPExplainerError(RuntimeError):
    """Raised when SHAP explanation fails due to incompatible library structures or dimensions."""
    pass


class SHAPExplainerService:
    """
    Step 28: SHAP Explainability Service.
    
    Explains predictions made by a pre-trained Step 27 XGBoostRiskClassifier
    using shap.TreeExplainer.
    Reuses Step 27 reference median imputation without mutating original vectors.
    """

    def __init__(self, classifier: XGBoostRiskClassifier) -> None:
        if not getattr(classifier, "_is_fitted", False) or classifier.model is None:
            raise ModelNotFittedError("Cannot create SHAPExplainerService with an unfitted XGBoostRiskClassifier.")
        
        self.classifier = classifier
        self.model = classifier.model
        self.explainer = shap.TreeExplainer(self.model)

    def _extract_shap_matrix(self, X: np.ndarray) -> np.ndarray:
        """
        Executes tree explainability and normalizes output shape across SHAP versions.
        Standardizes output to shape: (n_samples, n_features, n_classes).
        """
        raw_values = self.explainer.shap_values(X)
        n_samples = X.shape[0]
        n_features = EXPECTED_FEATURE_COUNT
        n_classes = len(ALLOWED_CLASSES)

        if isinstance(raw_values, list):
            # Version format: list of n_classes arrays, each of shape (n_samples, n_features)
            if len(raw_values) != n_classes:
                raise SHAPExplainerError(
                    f"Expected list of {n_classes} arrays from SHAP, got {len(raw_values)}"
                )
            # Stack along last axis -> (n_samples, n_features, n_classes)
            return np.stack(raw_values, axis=-1)

        elif isinstance(raw_values, np.ndarray):
            if raw_values.shape == (n_samples, n_features, n_classes):
                return raw_values
            elif raw_values.shape == (n_samples, n_classes, n_features):
                return np.transpose(raw_values, (0, 2, 1))
            elif raw_values.ndim == 2 and n_classes == 2:
                # Binary fallback if model only had 2 classes, expanded for 2 classes
                return np.stack([-raw_values, raw_values], axis=-1)
            else:
                raise SHAPExplainerError(
                    f"Unsupported SHAP array shape: {raw_values.shape}. "
                    f"Expected ({n_samples}, {n_features}, {n_classes})"
                )
        else:
            raise SHAPExplainerError(f"Unexpected SHAP values type: {type(raw_values).__name__}")

    def _get_base_value(self, class_id: int) -> Optional[float]:
        """Safely extracts expected base value for a specific class ID."""
        try:
            expected = self.explainer.expected_value
            if isinstance(expected, (list, tuple, np.ndarray)):
                return float(expected[class_id])
            elif isinstance(expected, (int, float, np.number)):
                return float(expected)
        except Exception:
            pass
        return None

    def explain(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> SHAPExplanationResult:
        """Explains a single Step 25 feature vector using the Step 27 model."""
        batch_res = self.explain_batch([feature_vector])
        res = batch_res.results[0]
        if stream_id:
            res.stream_id = stream_id
        return res

    def explain_batch(
        self,
        feature_vectors: Sequence[Union[MLFeatureVector, Sequence[float]]],
    ) -> BatchSHAPExplanationResult:
        """Explains multiple Step 25 feature vectors preserving order, providing local and global attribution."""
        if not feature_vectors:
            return BatchSHAPExplanationResult(
                results=[],
                total_evaluated=0,
                global_importance=[],
            )

        # 1. Run Step 27 batch prediction to obtain predictions and probabilities
        pred_batch = self.classifier.predict_batch(feature_vectors)

        # 2. Extract original and imputed matrices
        original_matrix: List[List[float]] = []
        imputed_matrix: List[List[float]] = []
        stream_ids: List[Optional[str]] = []

        for idx, vec in enumerate(feature_vectors):
            orig_vec = self.classifier._extract_and_validate_vector(vec, vector_index=idx)
            imputed_vec = self.classifier._impute_vector(orig_vec)
            original_matrix.append(orig_vec)
            imputed_matrix.append(imputed_vec)
            s_id = vec.stream_id if isinstance(vec, MLFeatureVector) else None
            stream_ids.append(s_id)

        X = np.array(imputed_matrix, dtype=np.float64)

        # 3. Compute SHAP values with shape (n_samples, 19, 4)
        shap_3d = self._extract_shap_matrix(X)

        results: List[SHAPExplanationResult] = []
        all_abs_shaps: List[np.ndarray] = []

        for i in range(len(feature_vectors)):
            pred_item: RiskClassificationResult = pred_batch.results[i]
            class_id = pred_item.class_id
            pred_class = pred_item.predicted_class

            # Extract SHAP contributions for the PREDICTED class
            class_shaps = shap_3d[i, :, class_id]  # length 19
            all_abs_shaps.append(np.abs(class_shaps))

            contributions: List[SHAPFeatureContribution] = []
            for feat_idx in range(EXPECTED_FEATURE_COUNT):
                s_val = float(class_shaps[feat_idx])
                abs_val = abs(s_val)

                if s_val > 1e-6:
                    direction = ContributionDirection.INCREASES_PREDICTED_CLASS
                elif s_val < -1e-6:
                    direction = ContributionDirection.DECREASES_PREDICTED_CLASS
                else:
                    direction = ContributionDirection.NEUTRAL

                contributions.append(
                    SHAPFeatureContribution(
                        feature_name=STEP_25_FEATURE_NAMES[feat_idx],
                        feature_index=feat_idx,
                        original_value=original_matrix[i][feat_idx],
                        model_input_value=imputed_matrix[i][feat_idx],
                        shap_value=s_val,
                        absolute_shap_value=abs_val,
                        direction=direction,
                    )
                )

            # Deterministic Top-5: sort by absolute_shap_value desc, then feature_index asc for tie-breaking
            top_5 = sorted(
                contributions,
                key=lambda item: (-item.absolute_shap_value, item.feature_index),
            )[:5]

            base_val = self._get_base_value(class_id)
            meta = SHAPMetadata(
                model_name="XGBoost",
                explainer_name="TreeExplainer",
                feature_count=EXPECTED_FEATURE_COUNT,
                base_value=base_val,
            )

            status_text = (
                f"SHAP feature contributions evaluated for model prediction '{pred_class}'. "
                f"Top contributing feature: {top_5[0].feature_name}."
            )

            results.append(
                SHAPExplanationResult(
                    stream_id=stream_ids[i],
                    predicted_class=pred_class,
                    predicted_class_id=class_id,
                    class_probabilities=pred_item.class_probabilities,
                    feature_contributions=contributions,
                    top_contributions=top_5,
                    feature_count=EXPECTED_FEATURE_COUNT,
                    model_metadata=meta,
                    status_text=status_text,
                )
            )

        # 4. Compute Global Mean Absolute SHAP Importance across batch
        mean_abs = np.mean(all_abs_shaps, axis=0)  # shape: (19,)
        global_importance: List[GlobalFeatureImportance] = []
        for feat_idx in range(EXPECTED_FEATURE_COUNT):
            global_importance.append(
                GlobalFeatureImportance(
                    feature_name=STEP_25_FEATURE_NAMES[feat_idx],
                    feature_index=feat_idx,
                    mean_absolute_shap_value=float(mean_abs[feat_idx]),
                )
            )

        global_importance.sort(key=lambda item: (-item.mean_absolute_shap_value, item.feature_index))

        return BatchSHAPExplanationResult(
            results=results,
            total_evaluated=len(results),
            global_importance=global_importance,
        )