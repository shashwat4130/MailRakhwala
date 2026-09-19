"""
Unit and regression test suite for Step 24 Cryptographic Posture & Risk Engine.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from app.schemas.posture import (
    CryptographicPostureReport,
    PostureDeduction,
    PostureSeverity,
)
from app.schemas.threat_mapping import (
    ThreatCategory,
    ThreatContextMapping,
    ThreatEvidence,
    ThreatMappingStatus,
)
from app.schemas.vulnerability_mapping import MappingType, WeaknessMapping
from app.services.posture import PostureEngineService, PostureRuleCatalog


def make_compliance_finding(
    rule_id: str,
    finding_id: str | None = None,
    status: str = "NON_COMPLIANT",
    observed_property: str | None = "tls.version",
    observed_value: str | None = "TLS 1.0",
    stream_id: str = "stream-1",
    certificate_index: int | None = None,
    omit_evidence: bool = False,
) -> SimpleNamespace:
    if omit_evidence:
        ev = None
    else:
        ev = SimpleNamespace(
            stream_id=stream_id,
            observed_property=observed_property,
            observed_value=observed_value,
            certificate_index=certificate_index,
        )
    fid = finding_id or f"FINDING-{rule_id}-{stream_id}"
    return SimpleNamespace(
        finding_id=fid,
        compliance_finding_id=fid,
        rule_id=rule_id,
        status=status,
        evidence=ev,
    )


def make_weakness(
    source_rule_id: str,
    finding_id: str | None = None,
    stream_id: str = "stream-1",
    certificate_index: int | None = None,
    mapping_type: MappingType = MappingType.WEAKNESS,
    observed_property: str | None = "tls.version",
    observed_value: str | None = "TLS 1.0",
    omit_evidence: bool = False,
) -> WeaknessMapping:
    if omit_evidence:
        ev = None
    else:
        ev = SimpleNamespace(
            stream_id=stream_id,
            observed_property=observed_property,
            observed_value=observed_value,
            certificate_index=certificate_index,
        )
    fid = finding_id or f"FINDING-{source_rule_id}-{stream_id}"
    return WeaknessMapping.model_construct(
        mapping_id=f"MAP-{source_rule_id}-{stream_id}",
        mapping_type=mapping_type,
        identifier="CWE-326",
        source_rule_id=source_rule_id,
        finding_id=fid,
        compliance_finding_id=fid,
        evidence=ev,
    )


# --- Catalog & Fail-Closed Validation Tests ---

def test_load_default_catalog():
    catalog = PostureRuleCatalog()
    assert catalog.rule_count == 17


def test_catalog_fail_closed_on_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        PostureRuleCatalog(catalog_path=tmp_path / "non_existent.json")


def test_catalog_fail_closed_on_malformed_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse"):
        PostureRuleCatalog(catalog_path=bad)


def test_catalog_fail_closed_on_missing_total_rules(tmp_path: Path):
    bad = tmp_path / "no_total.json"
    bad.write_text(
        json.dumps({
            "catalog_version": "1.0.0",
            "base_score": 100,
            "rules": []
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="'total_rules' is mandatory"):
        PostureRuleCatalog(catalog_path=bad)


def test_catalog_fail_closed_on_invalid_base_score(tmp_path: Path):
    bad = tmp_path / "bad_base.json"
    bad.write_text(
        json.dumps({
            "catalog_version": "1.0.0",
            "base_score": 80,
            "total_rules": 0,
            "rules": []
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid catalog base_score"):
        PostureRuleCatalog(catalog_path=bad)


def test_catalog_fail_closed_on_duplicate_rule_id(tmp_path: Path):
    dup = tmp_path / "dup_rule.json"
    dup.write_text(
        json.dumps({
            "base_score": 100,
            "total_rules": 2,
            "rules": [
                {"rule_id": "DUP-1", "upstream_rule_id": "R1", "title": "T1", "penalty": 10, "severity": "HIGH", "description": "D"},
                {"rule_id": "DUP-1", "upstream_rule_id": "R2", "title": "T2", "penalty": 10, "severity": "HIGH", "description": "D"},
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate posture rule_id"):
        PostureRuleCatalog(catalog_path=dup)


def test_catalog_fail_closed_on_duplicate_upstream_rule_id(tmp_path: Path):
    dup = tmp_path / "dup_upstream.json"
    dup.write_text(
        json.dumps({
            "base_score": 100,
            "total_rules": 2,
            "rules": [
                {"rule_id": "POSTURE-1", "upstream_rule_id": "SAME-R1", "title": "T1", "penalty": 10, "severity": "HIGH", "description": "D"},
                {"rule_id": "POSTURE-2", "upstream_rule_id": "SAME-R1", "title": "T2", "penalty": 10, "severity": "HIGH", "description": "D"},
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate upstream_rule_id detected"):
        PostureRuleCatalog(catalog_path=dup)


def test_catalog_fail_closed_on_missing_or_empty_upstream_rule_id(tmp_path: Path):
    bad = tmp_path / "bad_upstream.json"
    bad.write_text(
        json.dumps({
            "base_score": 100,
            "total_rules": 1,
            "rules": [
                {"rule_id": "P-1", "upstream_rule_id": "   ", "title": "T", "penalty": 10, "severity": "HIGH", "description": "D"}
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid or empty upstream_rule_id"):
        PostureRuleCatalog(catalog_path=bad)


def test_catalog_fail_closed_on_invalid_severity(tmp_path: Path):
    bad = tmp_path / "bad_sev.json"
    bad.write_text(
        json.dumps({
            "base_score": 100,
            "total_rules": 1,
            "rules": [
                {"rule_id": "P-1", "upstream_rule_id": "R-1", "title": "T", "penalty": 10, "severity": "EXTREME", "description": "D"}
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid severity"):
        PostureRuleCatalog(catalog_path=bad)


# --- Score & Severity Threshold Tests ---

def test_severity_thresholds():
    engine = PostureEngineService()
    assert engine.calculate_severity(100) == PostureSeverity.LOW
    assert engine.calculate_severity(80) == PostureSeverity.LOW
    assert engine.calculate_severity(79) == PostureSeverity.MEDIUM
    assert engine.calculate_severity(60) == PostureSeverity.MEDIUM
    assert engine.calculate_severity(59) == PostureSeverity.HIGH
    assert engine.calculate_severity(30) == PostureSeverity.HIGH
    assert engine.calculate_severity(29) == PostureSeverity.CRITICAL
    assert engine.calculate_severity(0) == PostureSeverity.CRITICAL


def test_empty_findings_gives_perfect_score():
    engine = PostureEngineService()
    report = engine.evaluate_posture("sess-1", "stream-1", [])
    assert report.posture_score == 100
    assert report.severity == PostureSeverity.LOW
    assert report.total_penalty == 0
    assert len(report.deductions) == 0


def test_only_compliant_findings_gives_perfect_score():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding("RULE-TLS-002", status="COMPLIANT"),
        make_compliance_finding("RULE-CIPHER-001", status="COMPLIANT"),
    ]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert report.posture_score == 100
    assert report.severity == PostureSeverity.LOW
    assert report.compliant_findings_count == 2
    assert report.total_penalty == 0


def test_unknown_findings_induce_zero_penalty():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding("RULE-TLS-002", status="UNKNOWN"),
        make_compliance_finding("RULE-CERT-001", status="NOT_APPLICABLE"),
    ]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert report.posture_score == 100
    assert report.total_penalty == 0
    assert report.unknown_findings_count == 2
    assert len(report.deductions) == 0


# --- Evidence Verification & Placeholder Rejection Tests ---

def test_non_compliant_with_valid_evidence_applies_penalty():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding(
            "RULE-TLS-002",
            status="NON_COMPLIANT",
            observed_property="tls.version",
            observed_value="TLS 1.0",
        )
    ]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert report.total_penalty == 15
    assert report.posture_score == 85
    assert len(report.deductions) == 1
    assert report.deductions[0].observed_property == "tls.version"
    assert report.deductions[0].observed_value == "TLS 1.0"


def test_non_compliant_with_missing_evidence_induces_zero_penalty():
    engine = PostureEngineService()
    findings = [make_compliance_finding("RULE-TLS-002", status="NON_COMPLIANT", omit_evidence=True)]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert report.total_penalty == 0
    assert report.posture_score == 100
    assert report.severity == PostureSeverity.LOW
    assert len(report.deductions) == 0
    assert report.unknown_findings_count == 1


def test_placeholder_evidence_produces_zero_penalty():
    engine = PostureEngineService()
    placeholders = ["property", "value", "invalid", "unknown", "  UNKNOWN  ", "Property"]
    for ph in placeholders:
        findings = [
            make_compliance_finding(
                "RULE-TLS-002",
                status="NON_COMPLIANT",
                observed_property=ph,
                observed_value="TLS 1.0",
            )
        ]
        report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
        assert report.total_penalty == 0
        assert report.posture_score == 100
        assert len(report.deductions) == 0

        findings2 = [
            make_compliance_finding(
                "RULE-TLS-002",
                status="NON_COMPLIANT",
                observed_property="tls.version",
                observed_value=ph,
            )
        ]
        report2 = engine.evaluate_posture("sess-1", "stream-1", findings=findings2)
        assert report2.total_penalty == 0
        assert report2.posture_score == 100
        assert len(report2.deductions) == 0


# --- Finding-ID Cross-Step Deduplication Tests ---

def test_same_finding_id_across_step21_and_step22_produces_one_deduction():
    engine = PostureEngineService()
    shared_fid = "FINDING-TLS-10-STREAM-1-PKT-4"
    f = make_compliance_finding(
        "RULE-TLS-002",
        finding_id=shared_fid,
        status="NON_COMPLIANT",
        observed_property="tls.version",
        observed_value="TLS 1.0",
        stream_id="stream-1",
    )
    ev = SimpleNamespace(
        stream_id="stream-1",
        observed_property="tls.version",
        observed_value="TLS 1.0",
        certificate_index=None,
    )
    w = WeaknessMapping.model_construct(
        mapping_id="MAP-RULE-TLS-002-stream-1",
        mapping_type=MappingType.WEAKNESS,
        identifier="CWE-326",
        source_rule_id="RULE-TLS-002",
        finding_id=shared_fid,
        compliance_finding_id=shared_fid,
        evidence=ev,
    )

    report = engine.evaluate_posture("sess-1", "stream-1", findings=[f], weaknesses=[w])
    assert report.total_penalty == 15
    assert report.posture_score == 85
    assert len(report.deductions) == 1
    assert report.deductions[0].finding_id == shared_fid
    assert report.deductions[0].weakness_id == "MAP-RULE-TLS-002-stream-1"


def test_different_finding_ids_same_rule_produce_separate_deductions():
    engine = PostureEngineService()
    f1 = make_compliance_finding("RULE-TLS-002", finding_id="FINDING-TLS-PKT-10", status="NON_COMPLIANT")
    f2 = make_compliance_finding("RULE-TLS-002", finding_id="FINDING-TLS-PKT-55", status="NON_COMPLIANT")

    report = engine.evaluate_posture("sess-1", "stream-1", findings=[f1, f2])
    assert report.total_penalty == 30  # 15 + 15
    assert report.posture_score == 70
    assert len(report.deductions) == 2


# --- Step 22 Fallback & Step 23 Context Constraints ---

def test_step22_fallback_confirmed_weakness_applies_penalty():
    engine = PostureEngineService()
    w = make_weakness("RULE-TLS-002", mapping_type=MappingType.WEAKNESS)
    report = engine.evaluate_posture("sess-1", "stream-1", weaknesses=[w])
    assert report.total_penalty == 15
    assert report.posture_score == 85
    assert len(report.deductions) == 1


def test_step23_potential_relevance_does_not_create_independent_penalty():
    engine = PostureEngineService()
    ev = ThreatEvidence(
        stream_id="stream-1",
        upstream_finding_id="F-1",
        upstream_rule_id="RULE-TLS-002",
        upstream_mapping_id="M-1",
        upstream_identifier="CWE-326",
        observed_property="tls.version",
        observed_value="TLS 1.0",
        threat_rule_id="THREAT-RULE-TLS-002",
    )
    threat = ThreatContextMapping(
        threat_mapping_id="THREAT-1",
        rule_id="THREAT-RULE-TLS-002",
        category=ThreatCategory.LEGACY_PROTOCOL_EXPOSURE,
        title="TLS 1.0",
        description="Desc",
        status=ThreatMappingStatus.POTENTIAL_RELEVANCE,
        evidence=ev,
        upstream_finding_id="F-1",
        upstream_mapping_id="M-1",
        limitations="None",
    )
    report = engine.evaluate_posture("sess-1", "stream-1", threats=[threat])
    assert report.total_penalty == 0
    assert report.posture_score == 100


# --- Deductions, Clamping, and Ordering Tests ---

def test_score_clamping_to_zero():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding("RULE-CIPHER-001", finding_id="F-1", status="NON_COMPLIANT"),  # -35
        make_compliance_finding("RULE-TLS-001", finding_id="F-2", status="NON_COMPLIANT"),     # -30
        make_compliance_finding("RULE-REVOC-001", finding_id="F-3", status="NON_COMPLIANT"),   # -30
        make_compliance_finding("RULE-STARTTLS-001", finding_id="F-4", status="NON_COMPLIANT") # -25
    ]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert report.total_penalty == 120
    assert report.posture_score == 0
    assert report.severity == PostureSeverity.CRITICAL


def test_deterministic_scoring_runs():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding("RULE-CIPHER-002", finding_id="F-RC4", status="NON_COMPLIANT"),
        make_compliance_finding("RULE-KEX-001", finding_id="F-RSA", status="NON_COMPLIANT"),
    ]
    r1 = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    r2 = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    assert r1.posture_score == r2.posture_score
    assert r1.total_penalty == r2.total_penalty
    assert [d.rule_id for d in r1.deductions] == [d.rule_id for d in r2.deductions]


def test_sorted_deduction_ordering():
    engine = PostureEngineService()
    findings = [
        make_compliance_finding("RULE-CIPHER-004", finding_id="F-CBC", status="NON_COMPLIANT"),  # -10
        make_compliance_finding("RULE-CIPHER-001", finding_id="F-NULL", status="NON_COMPLIANT"), # -35
        make_compliance_finding("RULE-TLS-002", finding_id="F-TLS10", status="NON_COMPLIANT"),   # -15
    ]
    report = engine.evaluate_posture("sess-1", "stream-1", findings=findings)
    penalties = [d.penalty for d in report.deductions]
    assert penalties == [35, 15, 10]