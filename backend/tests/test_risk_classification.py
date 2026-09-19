import math
import pytest
from app.schemas.ml_features import MLFeatureVector
from app.schemas.risk_classification import (
    BatchRiskClassificationResult,
    RiskClassificationMetadata,
    RiskClassificationResult,
)
from app.services.risk_classifier import (
    ALLOWED_CLASSES,
    FeatureValidationError,
    ModelNotFittedError,
    TrainingDataError,
    XGBoostRiskClassifier,
)

# ==============================================================================
# SYNTHETIC TEST FIXTURES ONLY
# These fixtures are deterministic synthetic data created solely to test the
# software mechanics of the XGBoost classifier. They are NOT real cybersecurity
# data and do not represent genuine attack or threat intelligence profiles.
# ==============================================================================

@pytest.fixture
def clean_low_vector():
    return [
        4.0, 3.0, 2.0, 1.0, 2048.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0, 1.0
    ]

@pytest.fixture
def medium_vector():
    return [
        3.0, 2.0, 2.0, 1.0, 2048.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        0.0, 2.0, 0.0, 0.0, 1.0, 0.0, 75.0, 1.0
    ]

@pytest.fixture
def high_vector():
    return [
        2.0, 1.0, 0.0, 0.0, 1024.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0,
        0.0, 5.0, 1.0, 3.0, 4.0, 2.0, 40.0, 0.0
    ]

@pytest.fixture
def critical_vector():
    return [
        0.0, 0.0, 0.0, 0.0, 512.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        1.0, 15.0, 3.0, 10.0, 8.0, 6.0, 10.0, 0.0
    ]

@pytest.fixture
def synthetic_training_data(clean_low_vector, medium_vector, high_vector, critical_vector):
    """Generates balanced synthetic training set representing all 4 classes."""
    X = []
    y = []
    for _ in range(15):
        X.append(list(clean_low_vector))
        y.append("LOW")
        X.append(list(medium_vector))
        y.append("MEDIUM")
        X.append(list(high_vector))
        y.append("HIGH")
        X.append(list(critical_vector))
        y.append("CRITICAL")
    return X, y

@pytest.fixture
def fitted_classifier(synthetic_training_data):
    X, y = synthetic_training_data
    clf = XGBoostRiskClassifier(n_estimators=30, max_depth=3, random_state=42)
    clf.fit(X, y)
    return clf


# ==============================================================================
# TESTS
# ==============================================================================

def test_schema_instantiation_defaults():
    res = RiskClassificationResult(
        predicted_class="LOW",
        class_id=0,
        class_probabilities={"LOW": 0.95, "MEDIUM": 0.03, "HIGH": 0.01, "CRITICAL": 0.01},
        status_text="Risk classification predicted as LOW by the trained XGBoost model.",
    )
    assert res.predicted_class == "LOW"
    assert res.class_id == 0
    assert res.feature_count == 19
    assert res.model_metadata.model_name == "XGBoost"


def test_accepts_exactly_19_features(fitted_classifier, clean_low_vector):
    res = fitted_classifier.predict(clean_low_vector)
    assert res.feature_count == 19
    assert len(res.feature_vector) == 19


def test_rejects_wrong_feature_dimension_too_few(fitted_classifier):
    with pytest.raises(FeatureValidationError) as exc:
        fitted_classifier.predict([1.0] * 18)
    assert "Expected exactly 19 features" in str(exc.value)


def test_rejects_wrong_feature_dimension_too_many(fitted_classifier):
    with pytest.raises(FeatureValidationError) as exc:
        fitted_classifier.predict([1.0] * 20)
    assert "Expected exactly 19 features" in str(exc.value)


def test_rejects_empty_training_features():
    clf = XGBoostRiskClassifier()
    with pytest.raises(TrainingDataError) as exc:
        clf.fit([], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    assert "empty training features" in str(exc.value)


def test_rejects_empty_training_labels(clean_low_vector):
    clf = XGBoostRiskClassifier()
    with pytest.raises(TrainingDataError) as exc:
        clf.fit([clean_low_vector], [])
    assert "empty training labels" in str(exc.value)


def test_rejects_mismatched_feature_and_label_counts(clean_low_vector):
    clf = XGBoostRiskClassifier()
    with pytest.raises(TrainingDataError) as exc:
        clf.fit([clean_low_vector, clean_low_vector], ["LOW"])
    assert "Mismatch between sample count" in str(exc.value)


def test_rejects_non_numeric_feature_in_prediction(fitted_classifier, clean_low_vector):
    bad = list(clean_low_vector)
    bad[4] = "invalid_string"
    with pytest.raises(FeatureValidationError) as exc:
        fitted_classifier.predict(bad)
    assert "not numeric" in str(exc.value)


def test_rejects_nan_feature_in_prediction(fitted_classifier, clean_low_vector):
    bad = list(clean_low_vector)
    bad[1] = float("nan")
    with pytest.raises(FeatureValidationError) as exc:
        fitted_classifier.predict(bad)
    assert "contains NaN" in str(exc.value)


def test_rejects_infinite_feature_in_prediction(fitted_classifier, clean_low_vector):
    bad = list(clean_low_vector)
    bad[1] = float("inf")
    with pytest.raises(FeatureValidationError) as exc:
        fitted_classifier.predict(bad)
    assert "contains infinite value" in str(exc.value)


def test_rejects_invalid_label_during_fit(clean_low_vector):
    clf = XGBoostRiskClassifier()
    X = [clean_low_vector] * 4
    y = ["LOW", "MEDIUM", "HIGH", "SUPER_CRITICAL"]
    with pytest.raises(TrainingDataError) as exc:
        clf.fit(X, y)
    assert "is invalid" in str(exc.value)


def test_rejects_missing_required_risk_class(clean_low_vector, medium_vector, high_vector):
    clf = XGBoostRiskClassifier()
    # Omitting "CRITICAL"
    X = [clean_low_vector, medium_vector, high_vector]
    y = ["LOW", "MEDIUM", "HIGH"]
    with pytest.raises(TrainingDataError) as exc:
        clf.fit(X, y)
    assert "missing required risk classes" in str(exc.value)


def test_successful_model_fitting(synthetic_training_data):
    X, y = synthetic_training_data
    clf = XGBoostRiskClassifier(n_estimators=10, random_state=42)
    assert clf._is_fitted is False
    clf.fit(X, y)
    assert clf._is_fitted is True
    assert len(clf._imputation_values) == 19


def test_prediction_before_fitting_raises_error(clean_low_vector):
    clf = XGBoostRiskClassifier()
    with pytest.raises(ModelNotFittedError):
        clf.predict(clean_low_vector)


def test_predict_batch_before_fitting_raises_error(clean_low_vector):
    clf = XGBoostRiskClassifier()
    with pytest.raises(ModelNotFittedError):
        clf.predict_batch([clean_low_vector])


def test_predict_low_risk(fitted_classifier, clean_low_vector):
    res = fitted_classifier.predict(clean_low_vector)
    assert res.predicted_class == "LOW"
    assert res.class_id == 0


def test_predict_medium_risk(fitted_classifier, medium_vector):
    res = fitted_classifier.predict(medium_vector)
    assert res.predicted_class == "MEDIUM"
    assert res.class_id == 1


def test_predict_high_risk(fitted_classifier, high_vector):
    res = fitted_classifier.predict(high_vector)
    assert res.predicted_class == "HIGH"
    assert res.class_id == 2


def test_predict_critical_risk(fitted_classifier, critical_vector):
    res = fitted_classifier.predict(critical_vector)
    assert res.predicted_class == "CRITICAL"
    assert res.class_id == 3


def test_predicted_class_strictly_in_allowed_classes(fitted_classifier, medium_vector):
    res = fitted_classifier.predict(medium_vector)
    assert res.predicted_class in ALLOWED_CLASSES


def test_class_probabilities_structure(fitted_classifier, clean_low_vector):
    res = fitted_classifier.predict(clean_low_vector)
    probs = res.class_probabilities
    assert set(probs.keys()) == ALLOWED_CLASSES
    total_prob = sum(probs.values())
    assert math.isclose(total_prob, 1.0, abs_tol=1e-5)


def test_probabilities_are_not_described_as_certainty(fitted_classifier, clean_low_vector):
    res = fitted_classifier.predict(clean_low_vector)
    for p in res.class_probabilities.values():
        assert 0.0 <= p <= 1.0


def test_deterministic_predictions_and_probabilities(synthetic_training_data, clean_low_vector):
    X, y = synthetic_training_data
    clf1 = XGBoostRiskClassifier(n_estimators=30, random_state=42).fit(X, y)
    clf2 = XGBoostRiskClassifier(n_estimators=30, random_state=42).fit(X, y)

    res1 = clf1.predict(clean_low_vector)
    res2 = clf2.predict(clean_low_vector)

    assert res1.predicted_class == res2.predicted_class
    assert res1.class_id == res2.class_id
    for c in ALLOWED_CLASSES:
        assert math.isclose(res1.class_probabilities[c], res2.class_probabilities[c], rel_tol=1e-9)


def test_batch_prediction_matches_single_predictions(fitted_classifier, clean_low_vector, critical_vector):
    batch = fitted_classifier.predict_batch([clean_low_vector, critical_vector])
    single1 = fitted_classifier.predict(clean_low_vector)
    single2 = fitted_classifier.predict(critical_vector)

    assert batch.total_evaluated == 2
    assert batch.results[0].predicted_class == single1.predicted_class
    assert batch.results[1].predicted_class == single2.predicted_class
    assert batch.class_distribution["LOW"] >= 1
    assert batch.class_distribution["CRITICAL"] >= 1


def test_batch_ordering_preserved(fitted_classifier, clean_low_vector, critical_vector):
    vectors = [clean_low_vector, critical_vector, clean_low_vector]
    batch = fitted_classifier.predict_batch(vectors)
    assert len(batch.results) == 3
    assert batch.results[0].predicted_class == "LOW"
    assert batch.results[1].predicted_class == "CRITICAL"
    assert batch.results[2].predicted_class == "LOW"


def test_empty_batch_returns_empty_result(fitted_classifier):
    batch = fitted_classifier.predict_batch([])
    assert batch.total_evaluated == 0
    assert len(batch.results) == 0
    assert sum(batch.class_distribution.values()) == 0


def test_feature_count_metadata_and_model_metadata(fitted_classifier):
    meta = fitted_classifier.metadata
    assert meta.model_name == "XGBoost"
    assert meta.feature_count == 19
    assert meta.label_mapping["0"] == "LOW"
    assert meta.label_mapping["3"] == "CRITICAL"


def test_original_feature_vector_traceability(fitted_classifier, clean_low_vector):
    res = fitted_classifier.predict(clean_low_vector)
    assert res.feature_vector == clean_low_vector


def test_unknown_values_handled_via_imputation(fitted_classifier, clean_low_vector):
    # Vector with -1.0 unknown sentinel
    unknown_vec = list(clean_low_vector)
    unknown_vec[0] = -1.0

    res = fitted_classifier.predict(unknown_vec)
    assert res.feature_count == 19
    # Traceability vector retains the original -1.0 sentinel
    assert res.feature_vector[0] == -1.0


def test_reference_column_median_imputation_computation():
    clf = XGBoostRiskClassifier()
    ref_vectors = [
        [4.0, 3.0] + [1.0] * 17,
        [2.0, -1.0] + [1.0] * 17,
        [4.0, 1.0] + [1.0] * 17,
        [4.0, 1.0] + [1.0] * 17,
    ]
    labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    clf.fit(ref_vectors, labels)
    # Col 0 median([4.0, 2.0, 4.0, 4.0]) = 4.0
    assert math.isclose(clf._imputation_values[0], 4.0)
    # Col 1 median of non -1.0 values [3.0, 1.0, 1.0] = 1.0
    assert math.isclose(clf._imputation_values[1], 1.0)


def test_all_unknown_column_falls_back_to_zero():
    clf = XGBoostRiskClassifier()
    ref_vectors = [[-1.0] * 19 for _ in range(4)]
    labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    clf.fit(ref_vectors, labels)
    for val in clf._imputation_values:
        assert val == 0.0


def test_stored_imputation_reused_during_prediction(synthetic_training_data, clean_low_vector):
    X, y = synthetic_training_data
    clf = XGBoostRiskClassifier(n_estimators=20, random_state=42).fit(X, y)

    median_col0 = clf._imputation_values[0]

    vec_known = list(clean_low_vector)
    vec_known[0] = median_col0

    vec_unknown = list(clean_low_vector)
    vec_unknown[0] = -1.0

    res_known = clf.predict(vec_known)
    res_unknown = clf.predict(vec_unknown)

    # Imputation replaces -1.0 with median_col0 prior to inference -> identical probabilities
    for c in ALLOWED_CLASSES:
        assert math.isclose(
            res_known.class_probabilities[c],
            res_unknown.class_probabilities[c],
            rel_tol=1e-9,
        )


def test_neutral_status_text_no_malicious_claims(fitted_classifier, critical_vector):
    res = fitted_classifier.predict(critical_vector)
    forbidden_terms = ["attack", "malicious", "compromised", "intrusion", "exploit"]
    text_lower = res.status_text.lower()
    for term in forbidden_terms:
        assert term not in text_lower
    assert "Risk classification predicted as CRITICAL" in res.status_text


def test_step_25_ml_feature_vector_compatibility(fitted_classifier):
    step25_vec = MLFeatureVector(
        stream_id="stream-email-42",
        tls_version_numeric=4.0,
        cipher_security_score=3.0,
        key_exchange_strength=2.0,
        pfs_enabled=1.0,
        certificate_key_size=2048.0,
        certificate_signature_strength=2.0,
        certificate_validity_status=1.0,
        san_present=1.0,
        hostname_match_status=1.0,
        trust_validation_status=1.0,
        revocation_status=1.0,
        starttls_downgrade=0.0,
        compliance_violation_count=0.0,
        unknown_finding_count=0.0,
        high_critical_finding_count=0.0,
        vulnerability_count=0.0,
        threat_mapping_count=0.0,
        cryptographic_security_score=100.0,
        ja4_available=1.0,
    )
    res = fitted_classifier.predict(step25_vec)
    assert res.stream_id == "stream-email-42"
    assert res.predicted_class == "LOW"
    assert res.feature_count == 19