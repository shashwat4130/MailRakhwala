"""
Unit and regression test suite for Step 23 Threat Mapping & Evidence Correlation.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from app.schemas.threat_mapping import (
    MitreAttackReference,
    SessionThreatReport,
    ThreatCategory,
    ThreatContextMapping,
    ThreatEvidence,
    ThreatMappingStatus,
)
from app.schemas.vulnerability_mapping import (
    MappingType,
    WeaknessMapping,
)
from app.services.threat_mapping import ThreatMappingCatalog, ThreatMappingService


def make_weakness(
    source_rule_id: str,
    identifier: str = "CWE-326",
    mapping_type: MappingType = MappingType.WEAKNESS,
    observed_property: str = "tls.version",
    observed_value: str = "TLS 1.0",
    stream_id: str = "stream-1",
    certificate_index: int | None = None,
    raw_der_sha256: str | None = None,
) -> WeaknessMapping:
    ev = SimpleNamespace(
        stream_id=stream_id,
        packet_number=10,
        timestamp=1600000000.0,
        certificate_index=certificate_index,
        raw_der_sha256=raw_der_sha256,
        observed_property=observed_property,
        observed_value=observed_value,
        reference_value="TLS 1.3",
    )
    
    return WeaknessMapping.model_construct(
        mapping_id=f"MAP-{source_rule_id}-{stream_id}",
        mapping_type=mapping_type,
        identifier=identifier,
        name=f"Weakness from {source_rule_id}",
        description="Observed weak configuration",
        source_rule_id=source_rule_id,
        finding_id=f"FINDING-{source_rule_id}-{stream_id}",
        compliance_finding_id=f"FINDING-{source_rule_id}-{stream_id}",
        evidence=ev,
        cwe_id=identifier if identifier.startswith("CWE") else None,
        cve_id=identifier if identifier.startswith("CVE") else None,
        limitations="Passive network observation only",
    )


# --- Catalog & Validation Tests ---

def test_load_default_catalog():
    catalog = ThreatMappingCatalog()
    assert catalog.rule_count == 17


def test_catalog_rule_count_matches_inventory():
    catalog = ThreatMappingCatalog()
    assert catalog.rule_count == 17
    assert len(set(catalog.rules.keys())) == 17


def test_catalog_fail_closed_on_missing_file(tmp_path: Path):
    missing_file = tmp_path / "non_existent.json"
    with pytest.raises(FileNotFoundError):
        ThreatMappingCatalog(catalog_path=missing_file)


def test_catalog_fail_closed_on_invalid_json(tmp_path: Path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{malformed json", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse"):
        ThreatMappingCatalog(catalog_path=bad_file)


def test_catalog_fail_closed_on_duplicate_id(tmp_path: Path):
    dup_file = tmp_path / "dup.json"
    catalog_dict = {
        "rules": [
            {
                "rule_id": "DUP-001",
                "category": "WEAK_CRYPTOGRAPHY",
                "title": "Title 1",
                "description": "Desc 1",
                "upstream_rule_id": "RULE-1",
                "status": "POTENTIAL_RELEVANCE",
                "limitations": "None",
            },
            {
                "rule_id": "DUP-001",
                "category": "WEAK_CRYPTOGRAPHY",
                "title": "Title 2",
                "description": "Desc 2",
                "upstream_rule_id": "RULE-2",
                "status": "POTENTIAL_RELEVANCE",
                "limitations": "None",
            },
        ]
    }
    dup_file.write_text(json.dumps(catalog_dict), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate threat rule_id"):
        ThreatMappingCatalog(catalog_path=dup_file)


def test_catalog_fail_closed_on_invalid_category(tmp_path: Path):
    bad_file = tmp_path / "bad_cat.json"
    catalog_dict = {
        "rules": [
            {
                "rule_id": "TEST-001",
                "category": "NON_EXISTENT_CATEGORY",
                "title": "Title",
                "description": "Desc",
                "upstream_rule_id": "RULE-1",
                "status": "POTENTIAL_RELEVANCE",
                "limitations": "None",
            }
        ]
    }
    bad_file.write_text(json.dumps(catalog_dict), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid ThreatCategory"):
        ThreatMappingCatalog(catalog_path=bad_file)


def test_catalog_fail_closed_on_invalid_mitre_id(tmp_path: Path):
    bad_file = tmp_path / "bad_mitre.json"
    catalog_dict = {
        "rules": [
            {
                "rule_id": "TEST-001",
                "category": "WEAK_CRYPTOGRAPHY",
                "title": "Title",
                "description": "Desc",
                "upstream_rule_id": "RULE-1",
                "status": "POTENTIAL_RELEVANCE",
                "limitations": "None",
                "mitre_attack": {
                    "technique_id": "INVALID_FORMAT",
                    "technique_name": "Test",
                },
            }
        ]
    }
    bad_file.write_text(json.dumps(catalog_dict), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid MITRE technique ID format"):
        ThreatMappingCatalog(catalog_path=bad_file)


# --- Semantic Grounding & Blocker Regression Tests ---

def test_tls10_downgrade_threat_mapping():
    service = ThreatMappingService()
    weakness = make_weakness("RULE-TLS-002", observed_property="tls.version", observed_value="TLS 1.0")
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.category == ThreatCategory.LEGACY_PROTOCOL_EXPOSURE
    assert m.status == ThreatMappingStatus.POTENTIAL_RELEVANCE
    assert m.mitre_attack is None


def test_tls10_does_not_map_to_t1573_002():
    service = ThreatMappingService()
    weakness = make_weakness("RULE-TLS-002", observed_property="tls.version", observed_value="TLS 1.0")
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].mitre_attack is None


def test_expired_cert_does_not_map_to_t1588_004():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-CERT-001",
        identifier="CWE-298",
        observed_property="cert.notAfter",
        observed_value="2020-01-01",
        certificate_index=0,
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].category == ThreatCategory.CERTIFICATE_TRUST_ABUSE_RELEVANCE
    assert mappings[0].mitre_attack is None


def test_not_yet_valid_cert_does_not_map_to_t1588_004():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-CERT-002",
        identifier="CWE-298",
        observed_property="cert.notBefore",
        observed_value="2035-01-01",
        certificate_index=0,
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].category == ThreatCategory.CERTIFICATE_TRUST_ABUSE_RELEVANCE
    assert mappings[0].mitre_attack is None


def test_self_signed_cert_has_non_attribution_limitation():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-PKI-001",
        identifier="CWE-295",
        observed_property="cert.is_self_signed",
        observed_value=True,
        certificate_index=0,
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.status == ThreatMappingStatus.POTENTIAL_RELEVANCE
    assert m.mitre_attack is not None
    assert m.mitre_attack.technique_id == "T1587.003"
    assert "Adversary certificate creation is NOT established" in m.limitations
    assert "Legitimate internal PKI" in m.limitations


def test_hostname_mismatch_does_not_map_to_t1557():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-IDENTITY-001",
        identifier="CWE-297",
        observed_property="cert.san_match",
        observed_value="MISMATCH",
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.category == ThreatCategory.CERTIFICATE_TRUST_ABUSE_RELEVANCE
    assert m.mitre_attack is None
    assert "Adversary-in-the-Middle" in m.limitations


def test_trust_path_failure_does_not_map_to_t1587_003():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-TRUST-001",
        identifier="CWE-295",
        observed_property="cert.path_valid",
        observed_value=False,
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].category == ThreatCategory.CERTIFICATE_TRUST_ABUSE_RELEVANCE
    assert mappings[0].mitre_attack is None
    assert "does not prove adversarial certificate creation" in mappings[0].limitations


def test_sweet32_3des_does_not_claim_confirmed_attack():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-CIPHER-003",
        identifier="CWE-327",
        observed_property="cipher.suite",
        observed_value="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.category == ThreatCategory.WEAK_CRYPTOGRAPHY
    assert m.status == ThreatMappingStatus.POTENTIAL_RELEVANCE
    assert "does not confirm birthday collision execution" in m.limitations


def test_null_cipher_maps_to_t1040():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-CIPHER-001",
        identifier="CWE-319",
        observed_property="cipher.suite",
        observed_value="TLS_RSA_WITH_NULL_SHA",
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].category == ThreatCategory.INTERCEPTION_RELEVANCE
    assert mappings[0].mitre_attack is not None
    assert mappings[0].mitre_attack.technique_id == "T1040"


def test_starttls_downgrade_maps_to_t1565_002():
    service = ThreatMappingService()
    weakness = make_weakness(
        "RULE-STARTTLS-001",
        identifier="CWE-319",
        observed_property="starttls.status",
        observed_value="STRIPPED",
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    assert mappings[0].category == ThreatCategory.DOWNGRADE_RELEVANCE
    assert mappings[0].mitre_attack is not None
    assert mappings[0].mitre_attack.technique_id == "T1565.002"


# --- Determinism & Evidence Linkage Tests ---

def test_deterministic_ids_are_stable():
    service = ThreatMappingService()
    weakness = make_weakness("RULE-TLS-002")
    m1 = service.map_weakness(weakness)[0]
    m2 = service.map_weakness(weakness)[0]
    assert m1.threat_mapping_id == m2.threat_mapping_id
    assert not m1.threat_mapping_id.startswith("UUID")


def test_deduplication_in_session_report():
    service = ThreatMappingService()
    w1 = make_weakness("RULE-TLS-002")
    w2 = make_weakness("RULE-TLS-002")
    report = service.build_session_threat_report("session-1", "stream-1", [w1, w2])
    assert report.total_threat_mappings == 1


def test_evidence_propagation_preserves_hashes():
    service = ThreatMappingService()
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    weakness = make_weakness(
        "RULE-CERT-003",
        identifier="CWE-326",
        observed_property="cert.public_key_bits",
        observed_value=1024,
        certificate_index=1,
        raw_der_sha256=sha,
    )
    mappings = service.map_weakness(weakness)
    assert len(mappings) == 1
    ev = mappings[0].evidence
    assert ev.certificate_index == 1
    assert ev.raw_der_sha256 == sha
    assert ev.observed_value == 1024


def test_benign_weakness_produces_no_mapping():
    service = ThreatMappingService()
    benign_enum = getattr(MappingType, "BENIGN", None)
    if benign_enum is not None:
        weakness = make_weakness("RULE-TLS-002", mapping_type=benign_enum)
        mappings = service.map_weakness(weakness)
        assert len(mappings) == 0


def test_empty_session_report():
    service = ThreatMappingService()
    report = service.build_session_threat_report("session-1", "stream-1", [])
    assert report.total_threat_mappings == 0
    assert report.threat_mappings == []