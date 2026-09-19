import pytest
from app.schemas.ml_features import MLFeatureVector
from app.services.ml_features import MLFeatureEngineeringService


class MockFinding:
    def __init__(self, status: str, severity: str):
        self.status = status
        self.severity = severity


class MockPostureReport:
    def __init__(self, posture_score):
        self.posture_score = posture_score


@pytest.fixture
def service():
    return MLFeatureEngineeringService()


def test_feature_vector_dimension_is_exactly_19(service):
    vec = service.extract_features("s1")
    features = vec.to_feature_list()
    assert len(features) == 19
    assert len(vec.to_feature_dict()) == 19


def test_deterministic_output(service):
    ctx = {
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "certificate_key_size": 2048,
    }
    vec1 = service.extract_features("s1", session_context=ctx).to_feature_list()
    vec2 = service.extract_features("s1", session_context=ctx).to_feature_list()
    assert vec1 == vec2


def test_tls_version_encoding_original_contract(service):
    assert service.encode_tls_version("TLS 1.3") == 4.0
    assert service.encode_tls_version("TLSv1.3") == 4.0
    assert service.encode_tls_version("TLS 1.2") == 3.0
    assert service.encode_tls_version("TLSv1.2") == 3.0
    assert service.encode_tls_version("TLS 1.1") == 2.0
    assert service.encode_tls_version("TLS 1.0") == 1.0
    assert service.encode_tls_version("SSL 3.0") == 0.0
    assert service.encode_tls_version("SSLv3") == 0.0
    assert service.encode_tls_version("SSL 2.0") == 0.0
    assert service.encode_tls_version("SSLv2") == 0.0
    assert service.encode_tls_version("TLS 0.9") == -1.0
    assert service.encode_tls_version("RANDOM_SSL_STRING") == -1.0
    assert service.encode_tls_version("") == -1.0
    assert service.encode_tls_version(None) == -1.0


def test_unknown_cipher_remains_unknown(service):
    vec = service.extract_features(
        "s1", session_context={"cipher_suite": "SOME_UNKNOWN_CIPHER"}
    )
    assert vec.cipher_security_score == -1.0


def test_cipher_suite_encodings(service):
    assert service.encode_cipher_suite("TLS_AES_256_GCM_SHA384") == 3.0
    assert service.encode_cipher_suite("TLS_CHACHA20_POLY1305_SHA256") == 3.0
    assert service.encode_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == 1.0
    assert service.encode_cipher_suite("TLS_RSA_WITH_RC4_128_MD5") == 0.0
    assert service.encode_cipher_suite("TLS_RSA_WITH_NULL_SHA") == 0.0
    assert service.encode_cipher_suite("MY_CUSTOM_CIPHER") == -1.0
    assert service.encode_cipher_suite("") == -1.0
    assert service.encode_cipher_suite(None) == -1.0


def test_missing_step_24_posture_score_is_negative_one(service):
    vec = service.extract_features("s1", posture_report=None)
    assert vec.cryptographic_security_score == -1.0


def test_valid_step_24_score_propagates(service):
    report = MockPostureReport(posture_score=78.5)
    vec = service.extract_features("s1", posture_report=report)
    assert vec.cryptographic_security_score == 78.5


def test_ed25519_does_not_imply_pfs(service):
    vec = service.extract_features(
        "s1", session_context={"key_exchange": "ED25519"}
    )
    assert vec.key_exchange_strength == -1.0
    assert vec.pfs_enabled == -1.0


def test_key_exchange_encodings(service):
    vec_ecdhe = service.extract_features("s1", session_context={"key_exchange": "ECDHE"})
    assert vec_ecdhe.key_exchange_strength == 2.0
    assert vec_ecdhe.pfs_enabled == 1.0

    vec_dhe = service.extract_features("s1", session_context={"key_exchange": "DHE"})
    assert vec_dhe.key_exchange_strength == 2.0
    assert vec_dhe.pfs_enabled == 1.0

    vec_x25519 = service.extract_features("s1", session_context={"key_exchange": "X25519"})
    assert vec_x25519.key_exchange_strength == 2.0
    assert vec_x25519.pfs_enabled == 1.0

    vec_rsa = service.extract_features("s1", session_context={"key_exchange": "RSA"})
    assert vec_rsa.key_exchange_strength == 0.0
    assert vec_rsa.pfs_enabled == 0.0

    vec_unknown = service.extract_features("s1", session_context={"key_exchange": "UNKNOWN_KEX"})
    assert vec_unknown.key_exchange_strength == -1.0
    assert vec_unknown.pfs_enabled == -1.0


def test_missing_optional_information_stays_unknown(service):
    vec = service.extract_features("s1")
    assert vec.tls_version_numeric == -1.0
    assert vec.cipher_security_score == -1.0
    assert vec.key_exchange_strength == -1.0
    assert vec.pfs_enabled == -1.0
    assert vec.certificate_key_size == -1.0
    assert vec.certificate_signature_strength == -1.0
    assert vec.certificate_validity_status == -1.0
    assert vec.san_present == -1.0
    assert vec.hostname_match_status == -1.0
    assert vec.trust_validation_status == -1.0
    assert vec.revocation_status == -1.0
    assert vec.starttls_downgrade == -1.0
    assert vec.cryptographic_security_score == -1.0


def test_finding_aggregation_uses_status(service):
    findings = [
        MockFinding(status="NON_COMPLIANT", severity="CRITICAL"),
        MockFinding(status="NON_COMPLIANT", severity="HIGH"),
        MockFinding(status="NON_COMPLIANT", severity="LOW"),
        MockFinding(status="COMPLIANT", severity="CRITICAL"),
        MockFinding(status="COMPLIANT", severity="HIGH"),
        MockFinding(status="UNKNOWN", severity="HIGH"),
        MockFinding(status="NOT_APPLICABLE", severity="HIGH"),
    ]
    vec = service.extract_features(
        "s1",
        compliance_findings=findings,
        weakness_mappings=[1, 2, 3],
        threat_mappings=[1, 2],
    )
    # Only NON_COMPLIANT counts as violation
    assert vec.compliance_violation_count == 3.0
    # Only NON_COMPLIANT + (HIGH or CRITICAL) counts
    assert vec.high_critical_finding_count == 2.0
    # Only UNKNOWN status counts as unknown
    assert vec.unknown_finding_count == 1.0
    # Steps 22 and 23 counts
    assert vec.vulnerability_count == 3.0
    assert vec.threat_mapping_count == 2.0


def test_ja4_fingerprint_flag(service):
    vec_with = service.extract_features("s1", session_context={"ja4": "t13d1516h2_..."})
    assert vec_with.ja4_available == 1.0

    vec_without = service.extract_features("s1", session_context={})
    assert vec_without.ja4_available == 0.0