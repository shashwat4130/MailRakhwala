"""
MailRakhwala Authoritative Step 4 Rule Specification Loader (Substep 21A)
Directly parses, validates, and indexes rules from the canonical rules/ directory.
Strictly disallows hard-coded fallback rulebooks, silent defaults, or unvalidated rule objects.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.schemas.domain import FindingCategory, SeverityLevel

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"


class RuleCatalogError(Exception):
    """Raised when an authoritative Step 4 rule specification cannot be loaded or is invalid."""
    pass


class SecurityRuleDefinition(BaseModel):
    """Normalized rule specification entry derived directly from Step 4 JSON specifications."""
    rule_id: str
    category: FindingCategory
    title: str
    severity: SeverityLevel
    standard: str
    confidence: str = "CONFIRMED_OBSERVED"
    description: str
    remediation: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuleCatalog:
    """Authoritative in-memory index of Step 4 security rules."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or RULES_DIR
        self.rules: Dict[str, SecurityRuleDefinition] = {}
        self.approved_ciphers: Set[str] = set()
        self.prohibited_cipher_patterns: List[Dict[str, Any]] = []
        self.severity_definitions: Dict[str, Any] = {}
        self.is_loaded = False
        self.load_rules()

    def load_rules(self):
        """Loads and strictly validates all four authoritative Step 4 JSON rule files."""
        self.rules.clear()
        self.approved_ciphers.clear()
        self.prohibited_cipher_patterns.clear()
        self.severity_definitions.clear()

        if not self.rules_dir.exists():
            raise RuleCatalogError(f"Authoritative rules directory not found at: {self.rules_dir}")

        severity_file = self.rules_dir / "severity_rules.json"
        tls_file = self.rules_dir / "tls_rules.json"
        cipher_file = self.rules_dir / "cipher_rules.json"
        cert_file = self.rules_dir / "certificate_rules.json"

        for req in (severity_file, tls_file, cipher_file, cert_file):
            if not req.exists():
                raise RuleCatalogError(f"Missing mandatory Step 4 rule file: {req.name}")

        self._load_severity_rules(severity_file)
        self._load_tls_rules(tls_file)
        self._load_cipher_rules(cipher_file)
        self._load_cert_rules(cert_file)

        self.is_loaded = True

    def get_rule(self, rule_id: str) -> Optional[SecurityRuleDefinition]:
        return self.rules.get(rule_id)

    def require_rule(self, rule_id: str) -> SecurityRuleDefinition:
        rule = self.rules.get(rule_id)
        if not rule:
            raise RuleCatalogError(f"Authoritative rule '{rule_id}' is not defined in the Step 4 specification.")
        return rule

    def _load_severity_rules(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            levels = data.get("severity_levels")
            if not levels or not isinstance(levels, dict):
                raise RuleCatalogError("severity_rules.json missing valid 'severity_levels' dictionary.")
            for level in levels:
                if not hasattr(SeverityLevel, level):
                    raise RuleCatalogError(f"Unrecognized severity level '{level}' in {path.name}")
            self.severity_definitions = levels
        except json.JSONDecodeError as e:
            raise RuleCatalogError(f"Failed loading {path.name}: malformed JSON ({str(e)})") from e

    def _load_tls_rules(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules")
            if not isinstance(rules, list):
                raise RuleCatalogError("tls_rules.json missing 'rules' list.")
            for r in rules:
                self._index_rule_dict(r, path.name)
        except json.JSONDecodeError as e:
            raise RuleCatalogError(f"Failed loading {path.name}: malformed JSON ({str(e)})") from e

    def _load_cipher_rules(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            raw_approved = data.get("approved_ciphers", [])
            if not isinstance(raw_approved, list):
                raise RuleCatalogError("cipher_rules.json 'approved_ciphers' must be a list.")
            for c in raw_approved:
                name = c.get("name") if isinstance(c, dict) else str(c)
                if name:
                    self.approved_ciphers.add(name.strip().upper())

            raw_prohibited = data.get("prohibited_ciphers", [])
            if not isinstance(raw_prohibited, list):
                raise RuleCatalogError("cipher_rules.json 'prohibited_ciphers' must be a list.")
            for p in raw_prohibited:
                if isinstance(p, dict):
                    pattern = p.get("pattern") or p.get("name") or p.get("cipher")
                    rule_id = p.get("rule_id")
                    if pattern:
                        self.prohibited_cipher_patterns.append({
                            "pattern": str(pattern).strip().upper(),
                            "rule_id": rule_id,
                        })
                elif p:
                    self.prohibited_cipher_patterns.append({
                        "pattern": str(p).strip().upper(),
                        "rule_id": None,
                    })

            rules = data.get("rules")
            if not isinstance(rules, list):
                raise RuleCatalogError("cipher_rules.json missing 'rules' list.")
            for r in rules:
                self._index_rule_dict(r, path.name)
        except json.JSONDecodeError as e:
            raise RuleCatalogError(f"Failed loading {path.name}: malformed JSON ({str(e)})") from e

    def _load_cert_rules(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules")
            if not isinstance(rules, list):
                raise RuleCatalogError("certificate_rules.json missing 'rules' list.")
            for r in rules:
                self._index_rule_dict(r, path.name)
        except json.JSONDecodeError as e:
            raise RuleCatalogError(f"Failed loading {path.name}: malformed JSON ({str(e)})") from e

    def _index_rule_dict(self, r: Any, source_file: str):
        if not isinstance(r, dict):
            raise RuleCatalogError(
                f"Invalid rule entry type '{type(r).__name__}' in {source_file}: expected JSON object, got {r!r}"
            )

        rule_id = r.get("rule_id") or r.get("id")
        if not rule_id or not isinstance(rule_id, str) or not rule_id.strip():
            raise RuleCatalogError(f"Missing or empty 'rule_id' in rule definition inside {source_file}")
        rule_id = rule_id.strip()

        if rule_id in self.rules:
            existing_source = self.rules[rule_id].metadata.get("source_file", "unknown")
            raise RuleCatalogError(
                f"Duplicate rule ID '{rule_id}' detected in {source_file}; already loaded from {existing_source}"
            )

        category_str = r.get("category")
        if not category_str or not isinstance(category_str, str) or not category_str.strip():
            raise RuleCatalogError(f"Rule '{rule_id}' in {source_file} missing required 'category'")
        category_str = category_str.strip().upper()
        if not hasattr(FindingCategory, category_str):
            raise RuleCatalogError(f"Rule '{rule_id}' in {source_file} has invalid category: '{category_str}'")
        category = getattr(FindingCategory, category_str)

        severity_str = r.get("severity")
        if not severity_str or not isinstance(severity_str, str) or not severity_str.strip():
            raise RuleCatalogError(f"Rule '{rule_id}' in {source_file} missing required 'severity'")
        severity_str = severity_str.strip().upper()
        if severity_str not in self.severity_definitions or not hasattr(SeverityLevel, severity_str):
            raise RuleCatalogError(
                f"Rule '{rule_id}' in {source_file} has invalid severity '{severity_str}' (not in severity_rules.json)."
            )
        severity = getattr(SeverityLevel, severity_str)

        title = r.get("title") or r.get("name")
        if not title or not isinstance(title, str) or not title.strip():
            raise RuleCatalogError(f"Rule '{rule_id}' in {source_file} missing required 'title'")
        title = title.strip()

        description = r.get("description")
        if not description or not isinstance(description, str) or not description.strip():
            raise RuleCatalogError(f"Rule '{rule_id}' in {source_file} missing required 'description'")
        description = description.strip()

        remediation = r.get("remediation") or r.get("recommendation")
        if not remediation or not isinstance(remediation, str) or not remediation.strip():
            raise RuleCatalogError(
                f"Rule '{rule_id}' in {source_file} missing required 'remediation' or 'recommendation'"
            )
        remediation = remediation.strip()

        standard = r.get("standard") or r.get("reference")
        if not standard or not isinstance(standard, str) or not standard.strip():
            raise RuleCatalogError(
                f"Rule '{rule_id}' in {source_file} missing required 'standard' or 'reference'"
            )
        standard = standard.strip()

        metadata = dict(r.get("metadata", {}))
        metadata["source_file"] = source_file

        self.rules[rule_id] = SecurityRuleDefinition(
            rule_id=rule_id,
            category=category,
            title=title,
            severity=severity,
            standard=standard,
            confidence=r.get("confidence", "CONFIRMED_OBSERVED"),
            description=description,
            remediation=remediation,
            metadata=metadata,
        )


rule_catalog = RuleCatalog()