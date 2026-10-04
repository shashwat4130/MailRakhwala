"""Tests validating the Security Rules Specification."""

import re
from pathlib import Path
import pytest

DOCS_DIR = Path(__file__).resolve().parent.parent.parent / "docs"
SPEC_FILE = DOCS_DIR / "security-rules.md"


def test_rule_spec_exists():
    assert SPEC_FILE.exists(), "docs/security-rules.md must exist."


def test_rule_ids_unique_and_consistent():
    content = SPEC_FILE.read_text(encoding="utf-8")
    
    rule_ids = re.findall(r"RULE-[A-Z]+-\d{3}", content)
    assert len(rule_ids) > 0, "At least one rule ID must be defined."
    
    unique_ids = set(rule_ids)
    assert len(rule_ids) == len(unique_ids), f"Duplicate rule IDs detected: {[x for x in rule_ids if rule_ids.count(x) > 1]}"


def test_mandatory_spec_sections():
    content = SPEC_FILE.read_text(encoding="utf-8")
    assert "Passive Forensics Limitations" in content
    assert "Evidence Confidence Model" in content
    assert "Severity Policy Framework" in content
    assert "NIST SP 800-52 Rev. 2 is under review" in content


def test_rule_formatting_elements():
    content = SPEC_FILE.read_text(encoding="utf-8")
    assert "Must NOT Claim" in content
    assert "CONFIRMED_OBSERVED" in content
    assert "SUSPECTED" in content