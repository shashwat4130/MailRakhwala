import math
import pytest
from app.schemas.ml_features import MLFeatureVector
from app.schemas.shap_explainability import (
    BatchSHAPExplanationResult,
    ContributionDirection,
    SHAPExplanationResult,
    SHAPFeatureContribution,
)
from app.services.risk_classifier import (
    FeatureValidationError,
    ModelNotFittedError,
    XGBoostRiskClassifier,
)
from app.services.shap_explainer import (
    EXPECTED_FEATURE_COUNT,
    SHAPExplainerError,
    SHAPExplainerService,
    STEP_25_FEATURE_NAMES,
)

# ==============================================================================
# SYNTHETIC TEST FIXTURES ONLY
# These fixtures are deterministic synthetic matrices designed solely to test
# SHAP tree-explainability mechanics. They are NOT real cybersecurity data.
# ==============================================================================

@pytest.fixture
def clean_low_vector():
    return [
        4.0, 3.0, 2.0, 1.0, 2048.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0, 1.0
    ]

@pytest.fixture
def critical_vector():
    return [
        0.0, 0.0, 0.0, 0.0, 512.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        1.0, 15.0, 3.0, 10.0, 8.0, 6.0, 10.0, 0.0
    ]

@pytest.fixture
def synthetic_classifier(clean_low_vector, critical_vector):
    medium_vector = [
        3.0, 2.0, 2.0, 1.0, 2048.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        0.0, 2.0, 0.0, 0.0, 1.0, 0.0, 75.0, 1.0
    ]
    high_vector = [
        2.0, 1.0, 0.0, 0.0, 1024.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 5.0, 1.0, 3.0, 4.0, 2.0, 40.0, 0.0
    ]
    X, y = [], []
    for _ in range(15):
        X.append(list(clean_low_vector)); y.append("LOW")
        X.append(list(medium_vector)); y.append("MEDIUM")
        X.append(list(high_vector)); y.append("HIGH")
        X.append(list(critical_vector)); y.append("CRITICAL")

    clf = XGBoostRiskClassifier(n_estimators=30, max_depth=3, random_state=42)
    clf.fit(X, y)
    return clf

@pytest.fixture
def shap_service(synthetic_classifier):
    return SHAPExplainerService(synthetic_classifier)


# ==============================================================================
# TESTS
# ==============================================================================

def test_schema_instantiation():
    item = SHAPFeatureContribution(
        feature_name="tls_version_numeric",
        feature_index=0,
        original_value=4.0,
        model_input_value=4.0,
        shap_value=0.45,
        absolute_shap_value=0.45,
        direction=ContributionDirection.INCREASES_PREDICTED_CLASS,
    )
    assert item.feature_name == "tls_version_numeric"
    assert item.direction == ContributionDirection.INCREASES_PREDICTED_CLASS


def test_rejects_unfitted_classifier():
    unfitted = XGBoostRiskClassifier()
    with pytest.raises(ModelNotFittedError):
        SHAPExplainerService(unfitted)


def test_single_explanation_returns_result(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    assert isinstance(res, SHAPExplanationResult)
    assert res.feature_count == 19
    assert len(res.feature_contributions) == 19


def test_predicted_class_and_id_consistency_with_step27(shap_service, synthetic_classifier, clean_low_vector):
    step27_res = synthetic_classifier.predict(clean_low_vector)
    shap_res = shap_service.explain(clean_low_vector)

    assert shap_res.predicted_class == step27_res.predicted_class
    assert shap_res.predicted_class_id == step27_res.class_id
    assert shap_res.class_probabilities == step27_res.class_probabilities


def test_all_19_canonical_feature_names_present(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    names = [c.feature_name for c in res.feature_contributions]
    assert names == STEP_25_FEATURE_NAMES


def test_feature_indices_in_canonical_order(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    for idx, item in enumerate(res.feature_contributions):
        assert item.feature_index == idx


def test_shap_values_are_numeric_and_finite(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    for item in res.feature_contributions:
        assert isinstance(item.shap_value, float)
        assert not math.isnan(item.shap_value)
        assert not math.isinf(item.shap_value)


def test_absolute_shap_value_calculation(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    for item in res.feature_contributions:
        assert math.isclose(item.absolute_shap_value, abs(item.shap_value), abs_tol=1e-8)


def test_contribution_direction_assignment(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    for item in res.feature_contributions:
        if item.shap_value > 1e-6:
            assert item.direction == ContributionDirection.INCREASES_PREDICTED_CLASS
        elif item.shap_value < -1e-6:
            assert item.direction == ContributionDirection.DECREASES_PREDICTED_CLASS
        else:
            assert item.direction == ContributionDirection.NEUTRAL


def test_top_contributions_count_and_sorting(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    top_5 = res.top_contributions
    assert len(top_5) == 5
    for i in range(len(top_5) - 1):
        assert top_5[i].absolute_shap_value >= top_5[i + 1].absolute_shap_value


def test_deterministic_top_contributions_tie_breaking(shap_service, clean_low_vector):
    res1 = shap_service.explain(clean_low_vector)
    res2 = shap_service.explain(clean_low_vector)
    assert [c.feature_index for c in res1.top_contributions] == [c.feature_index for c in res2.top_contributions]


def test_base_value_populated(shap_service, clean_low_vector):
    res = shap_service.explain(clean_low_vector)
    assert res.model_metadata.base_value is not None
    assert isinstance(res.model_metadata.base_value, float)


def test_unknown_minus_one_value_handling_and_preservation(shap_service, synthetic_classifier, clean_low_vector):
    vec_with_unknown = list(clean_low_vector)
    vec_with_unknown[0] = -1.0  # TLS version is unknown

    res = shap_service.explain(vec_with_unknown)
    tls_contrib = res.feature_contributions[0]

    expected_median_col0 = synthetic_classifier._imputation_values[0]

    # Original value must stay -1.0
    assert tls_contrib.original_value == -1.0
    # Model input value must be the Step 27 computed reference median
    assert math.isclose(tls_contrib.model_input_value, expected_median_col0, abs_tol=1e-6)
    assert tls_contrib.model_input_value != -1.0


def test_rejects_wrong_feature_count(shap_service):
    with pytest.raises(FeatureValidationError):
        shap_service.explain([1.0] * 18)
    with pytest.raises(FeatureValidationError):
        shap_service.explain([1.0] * 20)


def test_rejects_nan_in_feature_vector(shap_service, clean_low_vector):
    bad = list(clean_low_vector)
    bad[5] = float("nan")
    with pytest.raises(FeatureValidationError):
        shap_service.explain(bad)


def test_rejects_inf_in_feature_vector(shap_service, clean_low_vector):
    bad = list(clean_low_vector)
    bad[5] = float("inf")
    with pytest.raises(FeatureValidationError):
        shap_service.explain(bad)


def test_rejects_non_numeric_feature(shap_service, clean_low_vector):
    bad = list(clean_low_vector)
    bad[2] = "string_invalid"
    with pytest.raises(FeatureValidationError):
        shap_service.explain(bad)


def test_batch_explanation_preserves_count_and_ordering(shap_service, clean_low_vector, critical_vector):
    batch_res = shap_service.explain_batch([clean_low_vector, critical_vector, clean_low_vector])
    assert batch_res.total_evaluated == 3
    assert len(batch_res.results) == 3
    assert batch_res.results[0].predicted_class == "LOW"
    assert batch_res.results[1].predicted_class == "CRITICAL"
    assert batch_res.results[2].predicted_class == "LOW"


def test_batch_stream_id_preserved(shap_service, clean_low_vector):
    v1 = MLFeatureVector(
        stream_id="stream-1234",
        tls_version_numeric=4.0, cipher_security_score=3.0, key_exchange_strength=2.0, pfs_enabled=1.0,
        certificate_key_size=2048.0, certificate_signature_strength=2.0, certificate_validity_status=1.0,
        san_present=1.0, hostname_match_status=1.0, trust_validation_status=1.0, revocation_status=1.0,
        starttls_downgrade=0.0, compliance_violation_count=0.0, unknown_finding_count=0.0,
        high_critical_finding_count=0.0, vulnerability_count=0.0, threat_mapping_count=0.0,
        cryptographic_security_score=100.0, ja4_available=1.0,
    )
    res = shap_service.explain_batch([v1])
    assert res.results[0].stream_id == "stream-1234"


def test_global_importance_calculation(shap_service, clean_low_vector, critical_vector):
    batch_res = shap_service.explain_batch([clean_low_vector, critical_vector])
    global_imp = batch_res.global_importance
    assert len(global_imp) == 19
    for i in range(len(global_imp) - 1):
        assert global_imp[i].mean_absolute_shap_value >= global_imp[i + 1].mean_absolute_shap_value


def test_empty_batch_handling(shap_service):
    res = shap_service.explain_batch([])
    assert res.total_evaluated == 0
    assert len(res.results) == 0
    assert len(res.global_importance) == 0


def test_neutral_status_text_no_malicious_claims(shap_service, critical_vector):
    res = shap_service.explain(critical_vector)
    forbidden_terms = ["malicious", "attack", "compromised", "exploit", "intrusion"]
    for word in forbidden_terms:
        assert word not in res.status_text.lower()


def test_step25_ml_feature_vector_compatibility(shap_service):
    vec = MLFeatureVector(
        stream_id="stream-compat",
        tls_version_numeric=4.0, cipher_security_score=3.0, key_exchange_strength=2.0, pfs_enabled=1.0,
        certificate_key_size=2048.0, certificate_signature_strength=2.0, certificate_validity_status=1.0,
        san_present=1.0, hostname_match_status=1.0, trust_validation_status=1.0, revocation_status=1.0,
        starttls_downgrade=0.0, compliance_violation_count=0.0, unknown_finding_count=0.0,
        high_critical_finding_count=0.0, vulnerability_count=0.0, threat_mapping_count=0.0,
        cryptographic_security_score=100.0, ja4_available=1.0,
    )
    res = shap_service.explain(vec)
    assert res.stream_id == "stream-compat"
    assert res.predicted_class == "LOW"


def test_deterministic_repeated_runs(shap_service, clean_low_vector):
    r1 = shap_service.explain(clean_low_vector)
    r2 = shap_service.explain(clean_low_vector)
    for i in range(19):
        assert math.isclose(
            r1.feature_contributions[i].shap_value,
            r2.feature_contributions[i].shap_value,
            rel_tol=1e-9,
        )


def test_all_four_class_explanations(synthetic_classifier, clean_low_vector, critical_vector):
    service = SHAPExplainerService(synthetic_classifier)
    med_vec = list(clean_low_vector); med_vec[17] = 75.0; med_vec[12] = 2.0
    high_vec = list(clean_low_vector); high_vec[17] = 40.0; high_vec[4] = 1024.0

    res_low = service.explain(clean_low_vector)
    res_crit = service.explain(critical_vector)

    assert res_low.predicted_class == "LOW"
    assert res_crit.predicted_class == "CRITICAL"
    assert len(res_low.top_contributions) == 5
    assert len(res_crit.top_contributions) == 5

def test_global_importance_deterministic_tie_breaking(shap_service, clean_low_vector, critical_vector):
    """Verifies deterministic sorting by absolute value with feature index tie-breaking."""
    res1 = shap_service.explain_batch([clean_low_vector, critical_vector])
    res2 = shap_service.explain_batch([clean_low_vector, critical_vector])
    indices1 = [item.feature_index for item in res1.global_importance]
    indices2 = [item.feature_index for item in res2.global_importance]
    assert indices1 == indices2


def test_explainer_does_not_retrain_model(synthetic_classifier, clean_low_vector):
    """Verifies that SHAPExplainerService reuses the exact model instance without retraining."""
    original_model = synthetic_classifier.model
    service = SHAPExplainerService(synthetic_classifier)
    service.explain(clean_low_vector)
    assert service.model is original_model


def test_metadata_explainer_name(shap_service, clean_low_vector):
    """Verifies that model metadata exposes TreeExplainer."""
    res = shap_service.explain(clean_low_vector)
    assert res.model_metadata.explainer_name == "TreeExplainer"
    assert res.model_metadata.model_name == "XGBoost"


def test_top_contributions_have_highest_magnitudes(shap_service, clean_low_vector):
    """Verifies that the top 5 contributions are strictly greater than or equal to the remaining 14."""
    res = shap_service.explain(clean_low_vector)
    top_5_min_abs = min(c.absolute_shap_value for c in res.top_contributions)
    top_5_indices = {c.feature_index for c in res.top_contributions}
    remaining_abs = [c.absolute_shap_value for c in res.feature_contributions if c.feature_index not in top_5_indices]
    for val in remaining_abs:
        assert top_5_min_abs >= val - 1e-9


def test_batch_total_evaluated_matches_result_length(shap_service, clean_low_vector, critical_vector):
    """Verifies that total_evaluated reflects the exact length of the batch."""
    res = shap_service.explain_batch([clean_low_vector, critical_vector])
    assert res.total_evaluated == len(res.results) == 2


def test_step27_probabilities_sum_to_one_in_explanation(shap_service, clean_low_vector):
    """Verifies that class probabilities attached to the explanation sum to ~1.0."""
    res = shap_service.explain(clean_low_vector)
    total_prob = sum(res.class_probabilities.values())
    assert math.isclose(total_prob, 1.0, abs_tol=1e-5)