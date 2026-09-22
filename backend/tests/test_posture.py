from types import SimpleNamespace

from app.services.posture import PostureEngineService


def _finding():
    return SimpleNamespace(
        finding_id="F-STARTTLS-002",
        rule_id="RULE-STARTTLS-002",
        status="NON_COMPLIANT",
        evidence=SimpleNamespace(
            observed_property="starttls.state",
            observed_value="CAPABILITY_ADVERTISED_PLAINTEXT_CONTINUATION",
            certificate_index=None,
        ),
    )


def test_starttls_plaintext_without_auth_remains_75():
    report = PostureEngineService().evaluate_posture(
        session_id="test",
        stream_id="stream-1",
        findings=[_finding()],
        scoring_context={"plaintext_auth_observed": False},
    )
    assert report.total_penalty == 25
    assert report.posture_score == 75


def test_starttls_plaintext_with_observed_auth_scores_55():
    report = PostureEngineService().evaluate_posture(
        session_id="test",
        stream_id="stream-1",
        findings=[_finding()],
        scoring_context={"plaintext_auth_observed": True},
    )
    assert report.total_penalty == 45
    assert report.posture_score == 55
    assert len(report.deductions) == 1
    assert "+20 points" in report.deductions[0].description
