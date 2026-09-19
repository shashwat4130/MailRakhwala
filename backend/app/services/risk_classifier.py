from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
from xgboost import XGBClassifier

from app.schemas.ml_features import MLFeatureVector
from app.schemas.risk_classification import (
    BatchRiskClassificationResult,
    RiskClassificationMetadata,
    RiskClassificationResult,
)

EXPECTED_FEATURE_COUNT = 19
UNKNOWN_SENTINEL = -1.0
ALL_UNKNOWN_FALLBACK = 0.0

LABEL_TO_ID: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

ID_TO_LABEL: Dict[int, str] = {v: k for k, v in LABEL_TO_ID.items()}
ALLOWED_CLASSES = set(LABEL_TO_ID.keys())


class ModelNotFittedError(RuntimeError):
    """Raised when prediction is attempted before fitting the classifier."""
    pass


class FeatureValidationError(ValueError):
    """Raised when an input feature vector fails dimension, type, or finiteness checks."""
    pass


class TrainingDataError(ValueError):
    """Raised when training data is empty, inconsistent, or missing required risk classes."""
    pass


class XGBoostRiskClassifier:
    """
    Step 27: Supervised XGBoost risk classifier for cryptographic configurations.
    
    Consumes Step 25's 19-dimensional numerical feature vectors.
    Classifies configurations into LOW, MEDIUM, HIGH, or CRITICAL categories.
    Handles -1.0 unknown values using learned reference-column medians without
    altering the original feature vector for output traceability.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 4,
        learning_rate: float = 0.1,
        subsample: float = 1.0,
        colsample_bytree: float = 1.0,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.subsample = subsample
        self.colsample_bytree = colsample_bytree
        self.random_state = random_state

        self.model: Optional[XGBClassifier] = None
        self._is_fitted: bool = False
        self._imputation_values: Optional[List[float]] = None

    @property
    def metadata(self) -> RiskClassificationMetadata:
        return RiskClassificationMetadata(
            model_name="XGBoost",
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            random_state=self.random_state,
            feature_count=EXPECTED_FEATURE_COUNT,
            label_mapping={str(k): v for k, v in ID_TO_LABEL.items()},
        )

    def _extract_and_validate_vector(
        self,
        raw_vector: Union[MLFeatureVector, Sequence[float]],
        vector_index: Optional[int] = None,
    ) -> List[float]:
        """
        Extracts 19 features, verifies exact dimensionality, numeric types, and finiteness.
        Preserves original values (including -1.0) without mutation.
        """
        prefix = f"Vector at index {vector_index}: " if vector_index is not None else "Feature vector: "

        if isinstance(raw_vector, MLFeatureVector):
            features = raw_vector.to_feature_list()
        elif isinstance(raw_vector, (list, tuple, np.ndarray)):
            features = [float(x) if isinstance(x, (int, float, np.number)) else x for x in raw_vector]
        else:
            raise FeatureValidationError(
                f"{prefix}Expected MLFeatureVector or numerical sequence, received {type(raw_vector).__name__}"
            )

        if len(features) != EXPECTED_FEATURE_COUNT:
            raise FeatureValidationError(
                f"{prefix}Expected exactly {EXPECTED_FEATURE_COUNT} features, received {len(features)}"
            )

        cleaned: List[float] = []
        for i, val in enumerate(features):
            if not isinstance(val, (int, float, np.number)):
                raise FeatureValidationError(
                    f"{prefix}Feature at position {i} is not numeric: {val!r}"
                )
            f_val = float(val)
            if math.isnan(f_val):
                raise FeatureValidationError(
                    f"{prefix}Feature at position {i} contains NaN"
                )
            if math.isinf(f_val):
                raise FeatureValidationError(
                    f"{prefix}Feature at position {i} contains infinite value: {f_val}"
                )
            cleaned.append(f_val)

        return cleaned

    def _compute_imputation_values(self, matrix: List[List[float]]) -> List[float]:
        """
        Calculates per-column medians of reference values that are NOT -1.0.
        Falls back to 0.0 if an entire column contains only -1.0.
        """
        arr = np.array(matrix, dtype=np.float64)
        imputation: List[float] = []

        for col_idx in range(EXPECTED_FEATURE_COUNT):
            col_vals = arr[:, col_idx]
            known_vals = col_vals[col_vals != UNKNOWN_SENTINEL]
            if len(known_vals) > 0:
                imputation.append(float(np.median(known_vals)))
            else:
                imputation.append(ALL_UNKNOWN_FALLBACK)

        return imputation

    def _impute_vector(self, original_vector: List[float]) -> List[float]:
        """
        Replaces -1.0 with stored reference imputation values for model ingestion only.
        """
        if self._imputation_values is None:
            raise ModelNotFittedError("Imputation values not computed; classifier must be fitted first.")

        return [
            self._imputation_values[i] if math.isclose(val, UNKNOWN_SENTINEL, abs_tol=1e-6) else val
            for i, val in enumerate(original_vector)
        ]

    def fit(
        self,
        training_features: Sequence[Union[MLFeatureVector, Sequence[float]]],
        training_labels: Sequence[str],
    ) -> XGBoostRiskClassifier:
        """
        Fits the XGBClassifier on labeled feature vectors.
        Validates completeness, finite dimensions, and representation of all 4 required classes.
        """
        if not training_features or len(training_features) == 0:
            raise TrainingDataError("Cannot fit classifier with empty training features.")

        if not training_labels or len(training_labels) == 0:
            raise TrainingDataError("Cannot fit classifier with empty training labels.")

        if len(training_features) != len(training_labels):
            raise TrainingDataError(
                f"Mismatch between sample count ({len(training_features)}) and label count ({len(training_labels)})."
            )

        # Validate labels and check full class representation
        encoded_labels: List[int] = []
        observed_classes = set()
        for idx, lbl in enumerate(training_labels):
            if not isinstance(lbl, str) or lbl.upper() not in ALLOWED_CLASSES:
                raise TrainingDataError(
                    f"Label at index {idx} ('{lbl}') is invalid. Allowed classes: {sorted(ALLOWED_CLASSES)}"
                )
            norm_lbl = lbl.upper()
            observed_classes.add(norm_lbl)
            encoded_labels.append(LABEL_TO_ID[norm_lbl])

        missing_classes = ALLOWED_CLASSES - observed_classes
        if missing_classes:
            raise TrainingDataError(
                f"Training dataset is missing required risk classes: {sorted(missing_classes)}. "
                "All 4 classes (LOW, MEDIUM, HIGH, CRITICAL) must be represented."
            )

        # Validate feature vectors
        validated_matrix: List[List[float]] = []
        for idx, vec in enumerate(training_features):
            validated_matrix.append(self._extract_and_validate_vector(vec, vector_index=idx))

        # Store deterministic reference medians and prepare model matrix
        self._imputation_values = self._compute_imputation_values(validated_matrix)
        imputed_matrix = [self._impute_vector(v) for v in validated_matrix]

        X = np.array(imputed_matrix, dtype=np.float64)
        y = np.array(encoded_labels, dtype=np.int32)

        self.model = XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            subsample=self.subsample,
            colsample_bytree=self.colsample_bytree,
            random_state=self.random_state,
            objective="multi:softprob",
            num_class=len(ALLOWED_CLASSES),
            eval_metric="mlogloss",
        )
        self.model.fit(X, y)
        self._is_fitted = True
        return self

    def predict(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> RiskClassificationResult:
        """
        Classifies risk for a single 19-dimensional feature vector.
        Uses stored training-set medians for imputation during inference.
        Returns the original un-imputed vector in feature_vector for auditability.
        """
        if not self._is_fitted or self.model is None or self._imputation_values is None:
            raise ModelNotFittedError("Classifier must be fitted on training data before running predict().")

        original_features = self._extract_and_validate_vector(feature_vector)
        s_id = stream_id or (feature_vector.stream_id if isinstance(feature_vector, MLFeatureVector) else None)

        imputed_features = self._impute_vector(original_features)
        X = np.array([imputed_features], dtype=np.float64)

        prob_array = self.model.predict_proba(X)[0]
        class_id = int(np.argmax(prob_array))
        predicted_class = ID_TO_LABEL[class_id]

        class_probabilities: Dict[str, float] = {}
        for idx in range(len(ALLOWED_CLASSES)):
            class_name = ID_TO_LABEL[idx]
            class_probabilities[class_name] = float(prob_array[idx])

        status_text = f"Risk classification predicted as {predicted_class} by the trained XGBoost model."

        return RiskClassificationResult(
            stream_id=s_id,
            predicted_class=predicted_class,
            class_id=class_id,
            class_probabilities=class_probabilities,
            feature_count=EXPECTED_FEATURE_COUNT,
            status_text=status_text,
            model_metadata=self.metadata,
            feature_vector=original_features,
        )

    def predict_batch(
        self,
        feature_vectors: Sequence[Union[MLFeatureVector, Sequence[float]]],
    ) -> BatchRiskClassificationResult:
        """
        Classifies risk over multiple vectors in batch mode, preserving ordering.
        """
        if not self._is_fitted or self.model is None or self._imputation_values is None:
            raise ModelNotFittedError("Classifier must be fitted on training data before running predict_batch().")

        if not feature_vectors:
            return BatchRiskClassificationResult(
                results=[],
                total_evaluated=0,
                class_distribution={c: 0 for c in sorted(ALLOWED_CLASSES)},
            )

        original_matrix: List[List[float]] = []
        stream_ids: List[Optional[str]] = []
        for idx, vec in enumerate(feature_vectors):
            original_matrix.append(self._extract_and_validate_vector(vec, vector_index=idx))
            if isinstance(vec, MLFeatureVector):
                stream_ids.append(vec.stream_id)
            else:
                stream_ids.append(None)

        imputed_matrix = [self._impute_vector(v) for v in original_matrix]
        X = np.array(imputed_matrix, dtype=np.float64)

        prob_matrix = self.model.predict_proba(X)
        pred_indices = np.argmax(prob_matrix, axis=1)

        results: List[RiskClassificationResult] = []
        distribution: Dict[str, int] = {c: 0 for c in sorted(ALLOWED_CLASSES)}

        for idx in range(len(feature_vectors)):
            class_id = int(pred_indices[idx])
            predicted_class = ID_TO_LABEL[class_id]
            distribution[predicted_class] += 1

            probs: Dict[str, float] = {}
            for c_idx in range(len(ALLOWED_CLASSES)):
                c_name = ID_TO_LABEL[c_idx]
                probs[c_name] = float(prob_matrix[idx][c_idx])

            status_text = f"Risk classification predicted as {predicted_class} by the trained XGBoost model."

            results.append(
                RiskClassificationResult(
                    stream_id=stream_ids[idx],
                    predicted_class=predicted_class,
                    class_id=class_id,
                    class_probabilities=probs,
                    feature_count=EXPECTED_FEATURE_COUNT,
                    status_text=status_text,
                    model_metadata=self.metadata,
                    feature_vector=original_matrix[idx],
                )
            )

        return BatchRiskClassificationResult(
            results=results,
            total_evaluated=len(results),
            class_distribution=distribution,
        )