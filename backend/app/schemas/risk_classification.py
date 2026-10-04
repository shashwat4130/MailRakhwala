from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskClassificationMetadata(BaseModel):
    """Metadata regarding the XGBoost classifier configuration and label mapping."""
    model_name: str = Field(default="XGBoost", description="Underlying ML algorithm name")
    n_estimators: int = Field(default=100, description="Number of gradient boosted trees")
    max_depth: int = Field(default=4, description="Maximum tree depth for base learners")
    learning_rate: float = Field(default=0.1, description="Boosting learning rate (eta)")
    random_state: int = Field(default=42, description="Random state seed for reproducibility")
    feature_count: int = Field(default=19, description="Expected dimensionality of input feature vectors")
    label_mapping: Dict[str, str] = Field(
        default_factory=lambda: {
            "0": "LOW",
            "1": "MEDIUM",
            "2": "HIGH",
            "3": "CRITICAL",
        },
        description="Explicit mapping from class ID to risk category string",
    )


class RiskClassificationResult(BaseModel):
    """
    Result of supervised XGBoost configuration risk classification.
    
    IMPORTANT:
    The predicted risk category reflects the statistical risk profile learned
    from training labels. It does NOT denote a confirmed attack, active intrusion,
    system compromise, or real-world exploitation.
    """
    available: bool = Field(
        default=True,
        description="Whether risk classification model was available and evaluated"
    )
    stream_id: Optional[str] = Field(default=None, description="Identifier of the evaluated session/stream")
    prediction: Optional[str] = Field(
        default=None,
        description="Canonical predicted risk category: LOW, MEDIUM, HIGH, or CRITICAL",
    )
    predicted_class: Optional[str] = Field(
        default=None,
        description="Predicted risk classification alias for backward compatibility",
    )
    class_name: Optional[str] = Field(
        default=None,
        description="Canonical class name matching prediction",
    )
    class_id: Optional[int] = Field(
        default=None,
        description="Integer class index corresponding to explicit label mapping (0 to 3), or None if unavailable",
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Predicted class continuous probability (0.0 to 1.0)",
    )
    class_probabilities: Optional[Dict[str, float]] = Field(
        default=None,
        description="Estimated probability distribution across LOW, MEDIUM, HIGH, and CRITICAL. None if unavailable.",
    )
    probabilities: Optional[Dict[str, float]] = Field(
        default=None,
        description="Alias for class_probabilities for direct client consumption",
    )
    classes: List[str] = Field(
        default_factory=lambda: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        description="Canonical class list ordered by class ID (0 to 3)",
    )
    feature_count: int = Field(
        default=19,
        description="Total feature dimensions verified for this classification",
    )
    status_text: str = Field(
        default="Risk classification evaluated.",
        description="Neutral, non-accusatory summary of the predicted configuration risk category",
    )
    model_metadata: Optional[RiskClassificationMetadata] = Field(
        default_factory=RiskClassificationMetadata,
        description="Configuration and label encoding metadata of the classifier",
    )
    feature_vector: Optional[List[float]] = Field(
        default=None,
        description="Exact 19-dimensional feature vector evaluated for auditability and traceability",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Machine-readable reason why risk classification is unavailable",
    )


class BatchRiskClassificationResult(BaseModel):
    """Batch evaluation result for multiple feature vectors."""
    results: List[RiskClassificationResult] = Field(..., description="Ordered list of classification results")
    total_evaluated: int = Field(..., description="Total feature vectors evaluated")
    class_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Summary count of classifications per risk level",
    )