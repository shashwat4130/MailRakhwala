from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContributionDirection(str, Enum):
    INCREASES_PREDICTED_CLASS = "INCREASES_PREDICTED_CLASS"
    DECREASES_PREDICTED_CLASS = "DECREASES_PREDICTED_CLASS"
    NEUTRAL = "NEUTRAL"


class SHAPFeatureContribution(BaseModel):
    """Local SHAP contribution for a single feature dimension."""
    feature_name: str = Field(..., description="Canonical feature name")
    feature_index: int = Field(..., description="0-based feature index (0 to 18)")
    original_value: float = Field(..., description="Original feature value prior to imputation (may be -1.0)")
    model_input_value: float = Field(..., description="Actual value fed into XGBoost after reference imputation")
    shap_value: float = Field(..., description="Raw SHAP contribution value for the predicted class")
    absolute_shap_value: float = Field(..., description="Magnitude |shap_value| used for ranking")
    direction: ContributionDirection = Field(
        ...,
        description="Neutral indicator of whether this feature increased or decreased model confidence for the predicted class",
    )


class GlobalFeatureImportance(BaseModel):
    """Mean absolute SHAP value across evaluated batch samples."""
    feature_name: str = Field(..., description="Canonical feature name")
    feature_index: int = Field(..., description="0-based index (0 to 18)")
    mean_absolute_shap_value: float = Field(..., description="Mean absolute SHAP value across batch")


class SHAPMetadata(BaseModel):
    """Metadata regarding the explainer and underlying model."""
    model_name: str = Field(default="XGBoost", description="Name of the explained classifier")
    explainer_name: str = Field(default="TreeExplainer", description="SHAP explainer implementation")
    feature_count: int = Field(default=19, description="Feature dimensions verified")
    base_value: Optional[float] = Field(
        default=None,
        description="Expected model base margin / log-odds baseline for the predicted class prior to feature attribution",
    )


class SHAPExplanationResult(BaseModel):
    """
    Explanation of XGBoost risk classification using SHAP.
    
    IMPORTANT:
    SHAP values describe statistical feature contributions to the machine learning model prediction.
    They do NOT constitute causal proof of an attack, active intrusion, or security failure.
    """
    available: bool = Field(default=True, description="Whether SHAP explanation was successfully computed")
    reason: Optional[str] = Field(default=None, description="Machine-readable reason when explanation is unavailable")
    stream_id: Optional[str] = Field(default=None, description="Identifier of the evaluated session/stream")
    base_value: Optional[float] = Field(
        default=None,
        description="Expected model base margin / log-odds baseline for the predicted class prior to feature attribution",
    )
    prediction: Optional[str] = Field(
        default=None,
        description="Predicted risk classification string alias (e.g. LOW, MEDIUM, HIGH, CRITICAL)",
    )
    predicted_class: Optional[str] = Field(
        default=None,
        description="Predicted risk classification (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    predicted_class_id: Optional[int] = Field(
        default=None,
        description="Integer class index (0 to 3)",
    )
    target_class: Optional[str] = Field(
        default=None,
        description="Canonical target class name explained by SHAP",
    )
    target_class_id: Optional[int] = Field(
        default=None,
        description="Integer target class index explained by SHAP (0 to 3)",
    )
    class_probabilities: Dict[str, float] = Field(
        default_factory=dict,
        description="Model probability distribution",
    )
    features: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of feature attributions containing feature, value, shap_value, and direction/impact",
    )
    feature_contributions: List[SHAPFeatureContribution] = Field(
        default_factory=list,
        description="All 19 feature contributions in canonical order",
    )
    top_contributions: List[SHAPFeatureContribution] = Field(
        default_factory=list,
        description="Top 5 feature contributions ranked deterministically by absolute SHAP magnitude",
    )
    feature_count: int = Field(default=19, description="Total features analyzed")
    model_metadata: Optional[SHAPMetadata] = Field(default_factory=SHAPMetadata)
    status_text: Optional[str] = Field(
        default="SHAP explanation computed.",
        description="Neutral explanation of model attribution",
    )


class BatchSHAPExplanationResult(BaseModel):
    """Batch explanation containing individual local results and global feature importance."""
    results: List[SHAPExplanationResult] = Field(..., description="Ordered list of local explanations")
    total_evaluated: int = Field(..., description="Total samples explained")
    global_importance: List[GlobalFeatureImportance] = Field(
        default_factory=list,
        description="Global feature ranking sorted by mean absolute SHAP value descending across the batch",
    )