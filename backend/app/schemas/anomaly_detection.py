from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnomalyDetectionMetadata(BaseModel):
    """Metadata regarding the Isolation Forest model configuration."""
    model_name: str = Field(default="IsolationForest", description="Underlying ML model algorithm")
    n_estimators: int = Field(default=100, description="Number of isolation trees")
    contamination: str = Field(default="auto", description="Contamination strategy or float proportion")
    random_state: int = Field(default=42, description="Random state seed for reproducibility")
    feature_count: int = Field(default=19, description="Expected dimensionality of input feature vectors")


class AnomalyDetectionResult(BaseModel):
    """
    Result of Isolation Forest statistical anomaly detection.
    
    IMPORTANT:
    An anomaly is a statistical outlier relative to the reference distribution.
    Anomalous does NOT indicate an attack, intrusion, or confirmed exploit.
    """
    available: bool = Field(
        default=True,
        description="Whether anomaly detection model was available and evaluated"
    )
    stream_id: Optional[str] = Field(default=None, description="Identifier of the evaluated session/stream")
    is_anomalous: Optional[bool] = Field(
        default=None,
        description="True if configuration is statistically anomalous relative to reference set, False otherwise, or None if unavailable"
    )
    prediction: Optional[int] = Field(
        default=None,
        description="Raw Isolation Forest prediction: +1 for normal, -1 for anomalous, None if unavailable"
    )
    anomaly_score: Optional[float] = Field(
        default=None,
        description="Continuous outlier score from decision_function(). Lower values indicate higher abnormality. Not a probability. None if unavailable."
    )
    status_text: str = Field(
        default="Anomaly detection evaluated.",
        description="Neutral, factual explanation of whether statistical anomaly was detected"
    )
    feature_count: int = Field(
        default=19,
        description="Total feature dimensions verified for this prediction"
    )
    model_metadata: Optional[AnomalyDetectionMetadata] = Field(
        default_factory=AnomalyDetectionMetadata,
        description="Configuration of the fitted detector"
    )
    feature_vector: Optional[List[float]] = Field(
        default=None,
        description="Exact 19-dimensional feature vector evaluated for complete auditability"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Machine-readable reason if anomaly detection is unavailable"
    )


class BatchAnomalyDetectionResult(BaseModel):
    """Batch evaluation result for multiple feature vectors."""
    results: List[AnomalyDetectionResult] = Field(..., description="Ordered list of anomaly evaluations")
    total_evaluated: int = Field(..., description="Total vectors evaluated")
    total_anomalies: int = Field(..., description="Count of anomalous vectors identified")