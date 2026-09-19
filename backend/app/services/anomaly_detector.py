from __future__ import annotations

import math
from typing import Any, List, Optional, Sequence, Union

import numpy as np
from sklearn.ensemble import IsolationForest

from app.schemas.anomaly_detection import (
    AnomalyDetectionMetadata,
    AnomalyDetectionResult,
    BatchAnomalyDetectionResult,
)
from app.schemas.ml_features import MLFeatureVector

EXPECTED_FEATURE_COUNT = 19
MINIMUM_REFERENCE_SAMPLES = 2
UNKNOWN_SENTINEL = -1.0
ALL_UNKNOWN_FALLBACK = 0.0


class ModelNotFittedError(RuntimeError):
    """Raised when inference is attempted before fitting the detector."""
    pass


class FeatureValidationError(ValueError):
    """Raised when an input feature vector fails dimension, type, or finiteness checks."""
    pass


class ReferenceDataError(ValueError):
    """Raised when reference training data is empty, insufficient, or malformed."""
    pass


class IsolationForestDetector:
    """
    Step 26: Simple, deterministic Isolation Forest anomaly detector.
    
    Consumes Step 25's 19-dimensional feature vectors.
    Identifies configurations that statistically diverge from reference distributions.
    
    Handles Step 25's explicit -1.0 unknown values using reference-column medians
    for model input while preserving the original vectors with -1.0 for output traceability.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: Union[str, float] = "auto",
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self._is_fitted: bool = False
        self._imputation_values: Optional[List[float]] = None

    @property
    def metadata(self) -> AnomalyDetectionMetadata:
        return AnomalyDetectionMetadata(
            model_name="IsolationForest",
            n_estimators=self.n_estimators,
            contamination=str(self.contamination),
            random_state=self.random_state,
            feature_count=EXPECTED_FEATURE_COUNT,
        )

    def _extract_and_validate_vector(
        self,
        raw_vector: Union[MLFeatureVector, Sequence[float]],
        vector_index: Optional[int] = None,
    ) -> List[float]:
        """
        Extracts 19 features, verifies exact length, numerical types, and finiteness.
        Preserves original values (including -1.0) without modification.
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
        If an entire column contains only -1.0, falls back to 0.0 as a neutral numerical value.
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
        Replaces -1.0 with stored reference-derived imputation values.
        Returns a separate model-input vector; does not mutate the original.
        """
        if self._imputation_values is None:
            raise ModelNotFittedError("Imputation values not computed; model must be fitted first.")

        return [
            self._imputation_values[i] if math.isclose(val, UNKNOWN_SENTINEL, abs_tol=1e-6) else val
            for i, val in enumerate(original_vector)
        ]

    def fit(
        self,
        reference_vectors: Sequence[Union[MLFeatureVector, Sequence[float]]],
    ) -> IsolationForestDetector:
        """
        Fits IsolationForest on reference vectors.
        Computes deterministic column medians ignoring -1.0, replaces -1.0 for model input,
        and trains IsolationForest on the imputed representation.
        """
        if not reference_vectors or len(reference_vectors) == 0:
            raise ReferenceDataError("Cannot fit detector with empty reference dataset.")

        if len(reference_vectors) < MINIMUM_REFERENCE_SAMPLES:
            raise ReferenceDataError(
                f"Insufficient reference samples: received {len(reference_vectors)}, "
                f"minimum required is {MINIMUM_REFERENCE_SAMPLES}."
            )

        validated_matrix: List[List[float]] = []
        for idx, vec in enumerate(reference_vectors):
            validated_matrix.append(self._extract_and_validate_vector(vec, vector_index=idx))

        # 1. Store deterministic reference imputation values
        self._imputation_values = self._compute_imputation_values(validated_matrix)

        # 2. Transform reference matrix for model ingestion
        imputed_matrix = [self._impute_vector(v) for v in validated_matrix]
        X = np.array(imputed_matrix, dtype=np.float64)

        # 3. Fit Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X)
        self._is_fitted = True
        return self

    def predict(
        self,
        feature_vector: Union[MLFeatureVector, Sequence[float]],
        stream_id: Optional[str] = None,
    ) -> AnomalyDetectionResult:
        """
        Predicts anomaly status for a single feature vector.
        Uses stored reference imputation values for model input.
        Returns the original un-imputed vector in feature_vector for traceability.
        """
        if not self._is_fitted or self.model is None or self._imputation_values is None:
            raise ModelNotFittedError("Detector must be fitted on reference data before running predict().")

        original_features = self._extract_and_validate_vector(feature_vector)
        s_id = stream_id or (feature_vector.stream_id if isinstance(feature_vector, MLFeatureVector) else None)

        # Impute only for model input
        imputed_features = self._impute_vector(original_features)
        X = np.array([imputed_features], dtype=np.float64)

        pred = int(self.model.predict(X)[0])
        score = float(self.model.decision_function(X)[0])
        is_anomalous = (pred == -1)

        if is_anomalous:
            status_text = "Anomalous configuration detected relative to the learned reference distribution."
        else:
            status_text = "No statistical anomaly detected relative to the learned reference distribution."

        return AnomalyDetectionResult(
            stream_id=s_id,
            is_anomalous=is_anomalous,
            prediction=pred,
            anomaly_score=score,
            status_text=status_text,
            feature_count=EXPECTED_FEATURE_COUNT,
            model_metadata=self.metadata,
            feature_vector=original_features,
        )

    def predict_batch(
        self,
        feature_vectors: Sequence[Union[MLFeatureVector, Sequence[float]]],
    ) -> BatchAnomalyDetectionResult:
        """
        Predicts anomaly status over multiple vectors, preserving order.
        Returns original un-imputed vectors in feature_vector for traceability.
        """
        if not self._is_fitted or self.model is None or self._imputation_values is None:
            raise ModelNotFittedError("Detector must be fitted on reference data before running predict_batch().")

        if not feature_vectors:
            return BatchAnomalyDetectionResult(results=[], total_evaluated=0, total_anomalies=0)

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

        raw_preds = self.model.predict(X)
        raw_scores = self.model.decision_function(X)

        results: List[AnomalyDetectionResult] = []
        anomaly_count = 0

        for idx in range(len(feature_vectors)):
            pred = int(raw_preds[idx])
            score = float(raw_scores[idx])
            is_anomalous = (pred == -1)
            if is_anomalous:
                anomaly_count += 1
                status_text = "Anomalous configuration detected relative to the learned reference distribution."
            else:
                status_text = "No statistical anomaly detected relative to the learned reference distribution."

            results.append(
                AnomalyDetectionResult(
                    stream_id=stream_ids[idx],
                    is_anomalous=is_anomalous,
                    prediction=pred,
                    anomaly_score=score,
                    status_text=status_text,
                    feature_count=EXPECTED_FEATURE_COUNT,
                    model_metadata=self.metadata,
                    feature_vector=original_matrix[idx],
                )
            )

        return BatchAnomalyDetectionResult(
            results=results,
            total_evaluated=len(results),
            total_anomalies=anomaly_count,
        )