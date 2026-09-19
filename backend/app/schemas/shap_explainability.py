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
    feature_name: str = Field(..., description="Canonical Step 25 feature name")
    feature_index: int = Field(..., description="0-based index according to Step 25 layout (0 to 18)")
    original_value: float = Field(..., description="Original Step 25 value prior to imputation (may be -1.0)")
    model_input_value: float = Field(..., description="Actual value fed into XGBoost after reference imputation")
    shap_value: float = Field(..., description="Raw SHAP contribution value for the predicted class")
    absolute_shap_value: float = Field(..., description="Magnitude |shap_value| used for ranking")
    direction: ContributionDirection = Field(
        ...,
        description="Neutral indicator of whether this feature increased or decreased model confidence for the predicted class",
    )


class GlobalFeatureImportance(BaseModel):
    """Mean absolute SHAP value across evaluated batch samples."""
    feature_name: str = Field(..., description="Canonical Step 25 feature name")
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
    Step 28: Explanation of XGBoost risk classification using SHAP.
    
    IMPORTANT:
    SHAP values describe statistical feature contributions to the machine learning model prediction.
    They do NOT constitute causal proof of an attack, active intrusion, or security failure.
    """
    stream_id: Optional[str] = Field(default=None, description="Identifier of the evaluated session/stream")
    predicted_class: str = Field(..., description="Predicted risk classification (LOW, MEDIUM, HIGH, CRITICAL)")
    predicted_class_id: int = Field(..., description="Integer class index (0 to 3)")
    class_probabilities: Dict[str, float] = Field(..., description="Model probability distribution from Step 27")
    feature_contributions: List[SHAPFeatureContribution] = Field(
        ...,
        description="All 19 feature contributions in canonical Step 25 order",
    )
    top_contributions: List[SHAPFeatureContribution] = Field(
        ...,
        description="Top 5 feature contributions ranked deterministically by absolute SHAP magnitude",
    )
    feature_count: int = Field(default=19, description="Total features analyzed")
    model_metadata: SHAPMetadata = Field(default_factory=SHAPMetadata)
    status_text: str = Field(..., description="Neutral explanation of model attribution")


class BatchSHAPExplanationResult(BaseModel):
    """Batch explanation containing individual local results and global feature importance."""
    results: List[SHAPExplanationResult] = Field(..., description="Ordered list of local explanations")
    total_evaluated: int = Field(..., description="Total samples explained")
    global_importance: List[GlobalFeatureImportance] = Field(
        default_factory=list,
        description="Global feature ranking sorted by mean absolute SHAP value descending across the batch",
    )