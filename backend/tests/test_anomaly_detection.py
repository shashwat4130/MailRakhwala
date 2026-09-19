import math
import pytest
from app.schemas.anomaly_detection import (
    AnomalyDetectionMetadata,
    AnomalyDetectionResult,
    BatchAnomalyDetectionResult,
)
from app.schemas.ml_features import MLFeatureVector
from app.services.anomaly_detector import (
    FeatureValidationError,
    IsolationForestDetector,
    ModelNotFittedError,
    ReferenceDataError,
)


@pytest.fixture
def standard_normal_vector():
    """Clean reference vector matching typical production TLS email traffic."""
    return [
        4.0,    # 0: tls_version_numeric (TLS 1.3)
        3.0,    # 1: cipher_security_score (Modern AEAD)
        2.0,    # 2: key_exchange_strength (ECDHE)
        1.0,    # 3: pfs_enabled
        2048.0, # 4: certificate_key_size
        2.0,    # 5: certificate_signature_strength
        1.0,    # 6: certificate_validity_status
        1.0,    # 7: san_present
        1.0,    # 8: hostname_match_status
        1.0,    # 9: trust_validation_status
        1.0,    # 10: revocation_status (clean)
        0.0,    # 11: starttls_downgrade (no)
        0.0,    # 12: compliance_violation_count
        0.0,    # 13: unknown_finding_count
        0.0,    # 14: high_critical_finding_count
        0.0,    # 15: vulnerability_count
        0.0,    # 16: threat_mapping_count
        100.0,  # 17: cryptographic_security_score
        1.0,    # 18: ja4_available
    ]


@pytest.fixture
def synthetic_reference_dataset(standard_normal_vector):
    """
    Diverse reference dataset of clean email traffic.
    Having standard_normal_vector represented in the core distribution ensures
    scikit-learn learns it as a definitive inlier (+1).
    """
    dataset = []
    # Dominant standard baseline profiles
    for i in range(50):
        vec = list(standard_normal_vector)
        vec[4] = 2048.0 if i % 2 == 0 else 4096.0
        vec[17] = 95.0 + float(i % 6)  # Scores between 95 and 100
        dataset.append(vec)

    # Valid TLS 1.2 variants
    for i in range(25):
        vec = list(standard_normal_vector)
        vec[0] = 3.0   # TLS 1.2
        vec[4] = 2048.0
        vec[17] = 90.0 + float(i % 6)
        dataset.append(vec)

    return dataset


@pytest.fixture
def fitted_detector(synthetic_reference_dataset):
    # Setting contamination to 0.1 establishes a properly calibrated offset threshold
    detector = IsolationForestDetector(n_estimators=100, contamination=0.1, random_state=42)
    detector.fit(synthetic_reference_dataset)
    return detector


def test_schema_instantiation_defaults():
    result = AnomalyDetectionResult(
        is_anomalous=False,
        prediction=1,
        anomaly_score=0.125,
        status_text="No statistical anomaly detected relative to the learned reference distribution.",
    )
    assert result.is_anomalous is False
    assert result.prediction == 1
    assert result.feature_count == 19
    assert result.model_metadata.model_name == "IsolationForest"


def test_accepts_exactly_19_features(fitted_detector, standard_normal_vector):
    res = fitted_detector.predict(standard_normal_vector)
    assert res.feature_count == 19
    assert len(res.feature_vector) == 19


def test_rejects_wrong_feature_dimension_too_few(fitted_detector):
    with pytest.raises(FeatureValidationError) as exc:
        fitted_detector.predict([1.0] * 18)
    assert "Expected exactly 19 features" in str(exc.value)


def test_rejects_wrong_feature_dimension_too_many(fitted_detector):
    with pytest.raises(FeatureValidationError) as exc:
        fitted_detector.predict([1.0] * 20)
    assert "Expected exactly 19 features" in str(exc.value)


def test_rejects_empty_reference_data():
    detector = IsolationForestDetector()
    with pytest.raises(ReferenceDataError) as exc:
        detector.fit([])
    assert "empty reference dataset" in str(exc.value)


def test_rejects_insufficient_reference_data(standard_normal_vector):
    detector = IsolationForestDetector()
    with pytest.raises(ReferenceDataError) as exc:
        detector.fit([standard_normal_vector])
    assert "Insufficient reference samples" in str(exc.value)


def test_rejects_non_numeric_input(fitted_detector, standard_normal_vector):
    bad = list(standard_normal_vector)
    bad[2] = "not_a_number"
    with pytest.raises(FeatureValidationError) as exc:
        fitted_detector.predict(bad)
    assert "not numeric" in str(exc.value)


def test_rejects_nan_input(fitted_detector, standard_normal_vector):
    bad = list(standard_normal_vector)
    bad[5] = float("nan")
    with pytest.raises(FeatureValidationError) as exc:
        fitted_detector.predict(bad)
    assert "contains NaN" in str(exc.value)


def test_rejects_infinity_input(fitted_detector, standard_normal_vector):
    bad = list(standard_normal_vector)
    bad[5] = float("inf")
    with pytest.raises(FeatureValidationError) as exc:
        fitted_detector.predict(bad)
    assert "contains infinite value" in str(exc.value)


def test_cannot_predict_before_fit(standard_normal_vector):
    detector = IsolationForestDetector()
    with pytest.raises(ModelNotFittedError):
        detector.predict(standard_normal_vector)


def test_cannot_batch_predict_before_fit(standard_normal_vector):
    detector = IsolationForestDetector()
    with pytest.raises(ModelNotFittedError):
        detector.predict_batch([standard_normal_vector])


def test_successful_fit(synthetic_reference_dataset):
    detector = IsolationForestDetector(n_estimators=20, random_state=42)
    assert detector._is_fitted is False
    assert detector._imputation_values is None
    detector.fit(synthetic_reference_dataset)
    assert detector._is_fitted is True
    assert len(detector._imputation_values) == 19


def test_normal_prediction_convention(fitted_detector, standard_normal_vector):
    res = fitted_detector.predict(standard_normal_vector)
    assert res.prediction == 1
    assert res.is_anomalous is False
    assert "No statistical anomaly" in res.status_text


def test_anomalous_outlier_prediction(fitted_detector):
    # Completely broken / anomalous profile drastically far from reference baseline
    outlier = [
        0.0,     # SSL 3.0 (reference is 3.0 / 4.0)
        0.0,     # Broken cipher (reference is 3.0)
        0.0,     # Static RSA (reference is 2.0)
        0.0,     # No PFS (reference is 1.0)
        512.0,   # 512-bit key (reference is 2048 / 4096)
        0.0,     # MD5 (reference is 2.0)
        0.0,     # Expired
        0.0,     # No SAN
        0.0,     # Host mismatch
        0.0,     # Untrusted
        0.0,     # Revoked
        1.0,     # Downgrade detected (reference is 0.0)
        25.0,    # 25 violations (reference is 0.0)
        10.0,    # 10 unknown findings (reference is 0.0)
        15.0,    # 15 critical findings (reference is 0.0)
        12.0,    # 12 CVEs (reference is 0.0)
        9.0,     # 9 threats (reference is 0.0)
        5.0,     # Score 5 (reference is 90 - 100)
        0.0,     # No JA4 (reference is 1.0)
    ]
    res = fitted_detector.predict(outlier)
    assert res.prediction == -1
    assert res.is_anomalous is True
    assert "Anomalous configuration detected" in res.status_text


def test_anomaly_score_is_decision_function_not_probability(fitted_detector, standard_normal_vector):
    res = fitted_detector.predict(standard_normal_vector)
    assert isinstance(res.anomaly_score, float)
    assert not (0.0 <= res.anomaly_score <= 1.0 and math.isclose(res.anomaly_score, 0.5))


def test_deterministic_output_with_fixed_random_state(synthetic_reference_dataset, standard_normal_vector):
    d1 = IsolationForestDetector(n_estimators=50, random_state=42).fit(synthetic_reference_dataset)
    d2 = IsolationForestDetector(n_estimators=50, random_state=42).fit(synthetic_reference_dataset)

    r1 = d1.predict(standard_normal_vector)
    r2 = d2.predict(standard_normal_vector)

    assert r1.prediction == r2.prediction
    assert r1.is_anomalous == r2.is_anomalous
    assert math.isclose(r1.anomaly_score, r2.anomaly_score, rel_tol=1e-9)


def test_batch_prediction_matches_single_predictions(fitted_detector, standard_normal_vector):
    v1 = list(standard_normal_vector)
    v2 = list(standard_normal_vector)
    v2[0] = 3.0  # TLS 1.2

    batch_res = fitted_detector.predict_batch([v1, v2])
    single_res1 = fitted_detector.predict(v1)
    single_res2 = fitted_detector.predict(v2)

    assert batch_res.total_evaluated == 2
    assert batch_res.results[0].prediction == single_res1.prediction
    assert batch_res.results[1].prediction == single_res2.prediction
    assert math.isclose(batch_res.results[0].anomaly_score, single_res1.anomaly_score, rel_tol=1e-9)
    assert math.isclose(batch_res.results[1].anomaly_score, single_res2.anomaly_score, rel_tol=1e-9)


def test_batch_ordering_preserved(fitted_detector, standard_normal_vector):
    vectors = []
    for i in range(5):
        v = list(standard_normal_vector)
        v[4] = 1024.0 + (i * 512.0)
        vectors.append(v)

    batch_res = fitted_detector.predict_batch(vectors)
    assert len(batch_res.results) == 5
    for i in range(5):
        assert batch_res.results[i].feature_vector[4] == 1024.0 + (i * 512.0)


def test_empty_batch_returns_empty_summary(fitted_detector):
    batch_res = fitted_detector.predict_batch([])
    assert batch_res.total_evaluated == 0
    assert batch_res.total_anomalies == 0
    assert len(batch_res.results) == 0


def test_step_25_feature_vector_compatibility(fitted_detector):
    step25_vec = MLFeatureVector(
        stream_id="stream-test-42",
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
        cryptographic_security_score=98.0,
        ja4_available=1.0,
    )
    res = fitted_detector.predict(step25_vec)
    assert res.stream_id == "stream-test-42"
    assert res.feature_count == 19
    assert res.prediction in (1, -1)


def test_model_metadata_exposed(fitted_detector):
    meta = fitted_detector.metadata
    assert meta.model_name == "IsolationForest"
    assert meta.n_estimators == 100
    assert meta.random_state == 42
    assert meta.feature_count == 19


def test_neutral_status_text_no_malicious_claims(fitted_detector, standard_normal_vector):
    res = fitted_detector.predict(standard_normal_vector)
    forbidden_terms = ["attack", "malicious", "intrusion", "exploit", "compromised"]
    text_lower = res.status_text.lower()
    for term in forbidden_terms:
        assert term not in text_lower


def test_fit_validates_dimensions_in_reference_matrix():
    detector = IsolationForestDetector()
    invalid_matrix = [
        [1.0] * 19,
        [1.0] * 18,
    ]
    with pytest.raises(FeatureValidationError) as exc:
        detector.fit(invalid_matrix)
    assert "Vector at index 1" in str(exc.value)


def test_repeated_identical_runs_produce_identical_scores(fitted_detector, standard_normal_vector):
    score1 = fitted_detector.predict(standard_normal_vector).anomaly_score
    score2 = fitted_detector.predict(standard_normal_vector).anomaly_score
    assert score1 == score2


def test_feature_vector_traceability(fitted_detector, standard_normal_vector):
    res = fitted_detector.predict(standard_normal_vector)
    assert res.feature_vector == standard_normal_vector


def test_batch_stream_id_propagation(fitted_detector):
    v1 = MLFeatureVector(
        stream_id="stream-1",
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
    batch_res = fitted_detector.predict_batch([v1])
    assert batch_res.results[0].stream_id == "stream-1"


def test_reference_column_median_computation():
    detector = IsolationForestDetector(n_estimators=10, random_state=42)
    ref_vectors = [
        [4.0, 3.0] + [1.0] * 17,
        [2.0, -1.0] + [1.0] * 17,
        [4.0, 1.0] + [1.0] * 17,
    ]
    detector.fit(ref_vectors)
    # Column 0: median([4.0, 2.0, 4.0]) = 4.0
    assert math.isclose(detector._imputation_values[0], 4.0)
    # Column 1: median of knowns [3.0, 1.0] = 2.0 (-1.0 ignored)
    assert math.isclose(detector._imputation_values[1], 2.0)


def test_all_unknown_column_falls_back_to_zero():
    detector = IsolationForestDetector(n_estimators=10, random_state=42)
    ref_vectors = [
        [-1.0] * 19,
        [-1.0] * 19,
    ]
    detector.fit(ref_vectors)
    for val in detector._imputation_values:
        assert val == 0.0


def test_original_feature_vector_traceability_preserved_with_unknowns(fitted_detector):
    unknown_input = [-1.0] * 19
    res = fitted_detector.predict(unknown_input)
    # The output feature_vector must remain exactly -1.0 for audit/traceability
    assert res.feature_vector == unknown_input
    assert res.feature_vector[0] == -1.0


def test_unknown_values_imputed_identically_to_reference_median(synthetic_reference_dataset, standard_normal_vector):
    detector = IsolationForestDetector(n_estimators=50, random_state=42)
    detector.fit(synthetic_reference_dataset)

    # Use the exact computed reference median for column 0
    expected_median_col0 = detector._imputation_values[0]

    vec_known = list(standard_normal_vector)
    vec_known[0] = expected_median_col0

    vec_unknown = list(standard_normal_vector)
    vec_unknown[0] = -1.0

    res_known = detector.predict(vec_known)
    res_unknown = detector.predict(vec_unknown)

    # Since -1.0 is imputed to expected_median_col0, the model receives identical inputs
    assert math.isclose(res_known.anomaly_score, res_unknown.anomaly_score, rel_tol=1e-9)
    assert res_known.prediction == res_unknown.prediction
    # Audit vector retains original values
    assert res_unknown.feature_vector[0] == -1.0
    assert res_known.feature_vector[0] == expected_median_col0


def test_step_25_explicit_unknown_values_handled(fitted_detector):
    unknown_vector = [-1.0] * 19
    res = fitted_detector.predict(unknown_vector)
    assert res.feature_count == 19
    assert res.feature_vector == unknown_vector