"""
Focused tests verifying Substep 21A Authoritative Step 4 Rule Loader.
Verifies fail-closed validation, missing file handling, malformed JSON detection,
metadata completeness, duplicate prevention, and JSON mutation responsiveness without fallback mocks.
"""

import json
from pathlib import Path
import shutil
import pytest

from app.schemas.domain import SeverityLevel
from app.services.rule_loader import RuleCatalog, RuleCatalogError, rule_catalog


def test_all_four_step_4_files_load_successfully():
    catalog = RuleCatalog()
    assert catalog.is_loaded is True
    assert len(catalog.rules) >= 10
    assert len(catalog.approved_ciphers) > 0
    assert len(catalog.severity_definitions) > 0


def test_missing_rules_directory_fails(tmp_path):
    missing_dir = tmp_path / "nonexistent_rules"
    with pytest.raises(RuleCatalogError, match="Authoritative rules directory not found"):
        RuleCatalog(rules_dir=missing_dir)


def test_missing_mandatory_file_fails(tmp_path):
    (tmp_path / "tls_rules.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuleCatalogError, match="Missing mandatory Step 4 rule file: severity_rules.json"):
        RuleCatalog(rules_dir=tmp_path)


def test_malformed_json_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    (tmp_path / "tls_rules.json").write_text("{ broken json content", encoding="utf-8")
    with pytest.raises(RuleCatalogError, match="malformed JSON"):
        RuleCatalog(rules_dir=tmp_path)


def test_invalid_category_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0]["category"] = "UNRECOGNIZED_CATEGORY_FAKE"
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="has invalid category"):
        RuleCatalog(rules_dir=tmp_path)


def test_invalid_severity_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0]["severity"] = "NONEXISTENT_SEVERITY_LEVEL"
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="has invalid severity"):
        RuleCatalog(rules_dir=tmp_path)


def test_severity_not_present_in_severity_rules_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "severity_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["severity_levels"].pop("CRITICAL", None)
    with open(tmp_path / "severity_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="not in severity_rules.json"):
        RuleCatalog(rules_dir=tmp_path)


def test_missing_rule_id_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0].pop("rule_id", None)
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="Missing or empty 'rule_id'"):
        RuleCatalog(rules_dir=tmp_path)


def test_require_rule_works_for_existing_rule():
    rule = rule_catalog.require_rule("RULE-TLS-002")
    assert rule.rule_id == "RULE-TLS-002"
    assert rule.severity == SeverityLevel.HIGH
    assert "RFC 8996" in rule.standard


def test_require_rule_fails_for_unknown_rule():
    with pytest.raises(RuleCatalogError, match="is not defined in the Step 4 specification"):
        rule_catalog.require_rule("RULE-NONEXISTENT-UNKNOWN")


def test_approved_cipher_data_comes_from_cipher_rules_json(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "cipher_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["approved_ciphers"] = ["TLS_TEST_CIPHER_ONLY_FROM_JSON"]
    with open(tmp_path / "cipher_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    catalog = RuleCatalog(rules_dir=tmp_path)
    assert catalog.approved_ciphers == {"TLS_TEST_CIPHER_ONLY_FROM_JSON"}


def test_mutating_temporary_json_file_changes_loaded_catalog(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    rule = next(r for r in data["rules"] if r["rule_id"] == "RULE-TLS-001")
    rule["title"] = "MUTATED_TEST_TITLE_CONFIRMED"
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    catalog = RuleCatalog(rules_dir=tmp_path)
    loaded = catalog.require_rule("RULE-TLS-001")
    assert loaded.title == "MUTATED_TEST_TITLE_CONFIRMED"


def test_invalid_rule_item_type_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"].append("INVALID_STRING_RULE_ENTRY")
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="Invalid rule entry type 'str'"):
        RuleCatalog(rules_dir=tmp_path)


def test_missing_description_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0].pop("description", None)
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="missing required 'description'"):
        RuleCatalog(rules_dir=tmp_path)


def test_missing_remediation_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0].pop("remediation", None)
    data["rules"][0].pop("recommendation", None)
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="missing required 'remediation' or 'recommendation'"):
        RuleCatalog(rules_dir=tmp_path)


def test_missing_standard_reference_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    data["rules"][0].pop("standard", None)
    data["rules"][0].pop("reference", None)
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="missing required 'standard' or 'reference'"):
        RuleCatalog(rules_dir=tmp_path)


def test_duplicate_rule_id_fails(tmp_path):
    source_dir = Path(__file__).resolve().parent.parent.parent / "rules"
    for f in ["severity_rules.json", "tls_rules.json", "cipher_rules.json", "certificate_rules.json"]:
        shutil.copy(source_dir / f, tmp_path / f)

    with open(tmp_path / "tls_rules.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    dup_rule = dict(data["rules"][0])
    data["rules"].append(dup_rule)
    with open(tmp_path / "tls_rules.json", "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(RuleCatalogError, match="Duplicate rule ID .* detected"):
        RuleCatalog(rules_dir=tmp_path)