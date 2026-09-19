"""
Service implementation for Step 24 - Cryptographic Posture & Risk Engine.

Translates findings from Steps 21-23 into a transparent 0-100 posture score.
Enforces fail-safe evidence verification: penalties require verified observable evidence.
Eliminates cross-step double-counting using canonical finding IDs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.schemas.posture import (
    CryptographicPostureReport,
    PostureDeduction,
    PostureSeverity,
)
from app.schemas.threat_mapping import ThreatContextMapping
from app.schemas.vulnerability_mapping import MappingType, WeaknessMapping

ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
REJECTED_PLACEHOLDER_VALUES = {"property", "value", "invalid", "unknown"}


class PostureRuleCatalog:
    """Loads and validates the posture deduction rule configuration (fail-closed)."""

    def __init__(self, catalog_path: Optional[Path] = None) -> None:
        if catalog_path is None:
            catalog_path = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "posture_rules.json"
        self.catalog_path = catalog_path
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.upstream_index: Dict[str, Dict[str, Any]] = {}
        self._load_and_validate()

    def _load_and_validate(self) -> None:
        if not self.catalog_path.exists():
            raise FileNotFoundError(f"Posture rule catalog not found at {self.catalog_path}")

        try:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise ValueError(f"Failed to parse posture rule JSON: {exc}") from exc

        # Base score validation
        base_score = data.get("base_score")
        if base_score != 100:
            raise ValueError(f"Invalid catalog base_score: expected 100, got {base_score}")

        rules_list = data.get("rules", [])
        if not isinstance(rules_list, list):
            raise ValueError("Invalid catalog: 'rules' must be a list")

        # total_rules is mandatory
        if "total_rules" not in data or not isinstance(data["total_rules"], int):
            raise ValueError("Invalid catalog: 'total_rules' is mandatory and must be an integer")

        expected_count = data["total_rules"]
        if len(rules_list) != expected_count:
            raise ValueError(
                f"Catalog total_rules count mismatch: declared {expected_count}, found {len(rules_list)}"
            )

        seen_rule_ids: Set[str] = set()
        seen_upstream_rule_ids: Set[str] = set()

        for rule in rules_list:
            rule_id = rule.get("rule_id")
            if not rule_id or not isinstance(rule_id, str):
                raise ValueError(f"Rule missing mandatory string 'rule_id': {rule}")
            if rule_id in seen_rule_ids:
                raise ValueError(f"Duplicate posture rule_id detected: {rule_id}")
            seen_rule_ids.add(rule_id)

            for field in ("upstream_rule_id", "title", "penalty", "severity", "description"):
                if field not in rule:
                    raise ValueError(f"Rule {rule_id} missing mandatory field: {field}")

            upstream_rule_id = rule.get("upstream_rule_id")
            if not upstream_rule_id or not isinstance(upstream_rule_id, str) or upstream_rule_id.strip() == "":
                raise ValueError(f"Rule {rule_id} has invalid or empty upstream_rule_id")
            if upstream_rule_id in seen_upstream_rule_ids:
                raise ValueError(f"Duplicate upstream_rule_id detected: {upstream_rule_id}")
            seen_upstream_rule_ids.add(upstream_rule_id)

            severity = rule.get("severity")
            if severity not in ALLOWED_SEVERITIES:
                raise ValueError(f"Rule {rule_id} has invalid severity '{severity}'. Must be one of {ALLOWED_SEVERITIES}")

            if not isinstance(rule["penalty"], int) or rule["penalty"] < 0:
                raise ValueError(f"Rule {rule_id} penalty must be a non-negative integer")

            self.rules[rule_id] = rule
            self.upstream_index[upstream_rule_id] = rule

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def get_rule_for_upstream(self, upstream_rule_id: str) -> Optional[Dict[str, Any]]:
        return self.upstream_index.get(upstream_rule_id)


class PostureEngineService:
    """Deterministic score engine calculating posture from security findings."""

    def __init__(self, catalog: Optional[PostureRuleCatalog] = None) -> None:
        self.catalog = catalog or PostureRuleCatalog()

    @staticmethod
    def calculate_severity(score: int) -> PostureSeverity:
        """
        Calculates Overall Session Posture Severity from the final 0-100 score:
          80 - 100 -> LOW posture risk
          60 - 79  -> MEDIUM posture risk
          30 - 59  -> HIGH posture risk
          0  - 29  -> CRITICAL posture risk
        """
        if score >= 80:
            return PostureSeverity.LOW
        elif score >= 60:
            return PostureSeverity.MEDIUM
        elif score >= 30:
            return PostureSeverity.HIGH
        else:
            return PostureSeverity.CRITICAL

    @staticmethod
    def _normalize_value(val: Any) -> str:
        """Normalize observed value for stable, evidence-aware keying."""
        return str(val).strip().lower()

    @staticmethod
    def _has_sufficient_evidence(ev: Any) -> Tuple[bool, Optional[str], Any, Optional[int]]:
        """
        Verifies that actual, non-fabricated forensic evidence exists.
        Rejects empty/whitespace values and obvious placeholders case-insensitively.
        Returns (is_valid, observed_property, observed_value, certificate_index).
        """
        if ev is None:
            return False, None, None, None

        if isinstance(ev, dict):
            prop = ev.get("observed_property")
            val = ev.get("observed_value")
            c_idx = ev.get("certificate_index")
        else:
            prop = getattr(ev, "observed_property", None)
            val = getattr(ev, "observed_value", None)
            c_idx = getattr(ev, "certificate_index", None)

        if prop is None:
            return False, None, None, None
        prop_str = str(prop).strip()
        if prop_str == "" or prop_str.lower() in REJECTED_PLACEHOLDER_VALUES:
            return False, None, None, None

        if val is None:
            return False, None, None, None
        val_str = str(val).strip()
        if val_str == "" or val_str.lower() in REJECTED_PLACEHOLDER_VALUES:
            return False, None, None, None

        return True, prop_str, val, c_idx

    def evaluate_posture(
        self,
        session_id: str,
        stream_id: str,
        findings: Optional[List[Any]] = None,
        weaknesses: Optional[List[WeaknessMapping]] = None,
        threats: Optional[List[ThreatContextMapping]] = None,
    ) -> CryptographicPostureReport:
        """
        Calculates a transparent 0-100 posture score.
        Guarantees:
          1. Verified Evidence Required: Missing/incomplete/placeholder evidence incurs 0 deduction.
          2. Finding ID Deduplication: Canonical finding_id prevents cross-step double counting.
          3. UNKNOWN / NOT_APPLICABLE / COMPLIANT have 0 deduction.
          4. Clamped to [0, 100].
        """
        findings = findings or []
        weaknesses = weaknesses or []
        threats = threats or []

        # Index Step 22 and Step 23 metadata by canonical finding_id and rule_id fallback
        weakness_by_finding: Dict[str, str] = {}
        threat_by_finding: Dict[str, str] = {}

        for w in weaknesses:
            mid = getattr(w, "mapping_id", "") or ""
            fid = (
                getattr(w, "compliance_finding_id", None)
                or getattr(w, "finding_id", None)
                or getattr(w, "upstream_finding_id", None)
            )
            if fid:
                weakness_by_finding[str(fid).strip()] = mid
            if hasattr(w, "source_rule_id") and w.source_rule_id:
                weakness_by_finding[str(w.source_rule_id).strip()] = mid

        for t in threats:
            tid = getattr(t, "threat_mapping_id", "") or ""
            fid = (
                getattr(t, "upstream_finding_id", None)
                or getattr(t, "finding_id", None)
            )
            if fid:
                threat_by_finding[str(fid).strip()] = tid
            if hasattr(t, "rule_id") and t.rule_id:
                threat_by_finding[str(t.rule_id).strip()] = tid

        applied_finding_ids: Set[str] = set()
        deductions: List[PostureDeduction] = []

        compliant_count = 0
        non_compliant_count = 0
        unknown_count = 0

        # 1. Process Step 21 Findings
        for f in findings:
            status = getattr(f, "status", None)
            st_val = getattr(status, "value", status)
            st_str = str(st_val).upper() if st_val else "UNKNOWN"

            if "NON_COMPLIANT" in st_str or st_str == "FAIL":
                ev = getattr(f, "evidence", None)
                is_valid, prop, val, c_idx = self._has_sufficient_evidence(ev)

                if not is_valid:
                    unknown_count += 1
                    continue

                non_compliant_count += 1
                rule_id = getattr(f, "rule_id", None) or getattr(f, "compliance_rule_id", "UNKNOWN")
                finding_id = str(
                    getattr(f, "finding_id", None)
                    or getattr(f, "compliance_finding_id", None)
                    or f"FINDING-{rule_id}-{stream_id}"
                )

                if finding_id not in applied_finding_ids:
                    rule = self.catalog.get_rule_for_upstream(rule_id)
                    if rule:
                        applied_finding_ids.add(finding_id)
                        w_id = weakness_by_finding.get(finding_id) or weakness_by_finding.get(rule_id)
                        t_id = threat_by_finding.get(finding_id) or threat_by_finding.get(rule_id)
                        deductions.append(
                            PostureDeduction(
                                rule_id=rule["rule_id"],
                                title=rule["title"],
                                penalty=rule["penalty"],
                                upstream_rule_id=rule_id,
                                finding_id=finding_id,
                                weakness_id=w_id,
                                threat_mapping_id=t_id,
                                observed_property=prop,
                                observed_value=val,
                                certificate_index=c_idx,
                                stream_id=stream_id,
                                description=rule["description"],
                            )
                        )
            elif "COMPLIANT" in st_str or st_str == "PASS":
                compliant_count += 1
            else:
                unknown_count += 1

        # 2. Step 22 Weakness fallback (used when Step 21 findings are omitted)
        if not findings and weaknesses:
            for w in weaknesses:
                m_type = getattr(w, "mapping_type", None)
                m_str = getattr(m_type, "value", m_type)
                m_str_upper = str(m_str).upper()

                if m_str_upper in ("BENIGN", "UNKNOWN", "NOT_APPLICABLE"):
                    compliant_count += 1
                    continue

                ev = getattr(w, "evidence", None)
                is_valid, prop, val, c_idx = self._has_sufficient_evidence(ev)

                if not is_valid:
                    unknown_count += 1
                    continue

                rule_id = getattr(w, "source_rule_id", None) or getattr(w, "rule_id", "UNKNOWN")
                finding_id = str(
                    getattr(w, "compliance_finding_id", None)
                    or getattr(w, "finding_id", None)
                    or f"FINDING-{rule_id}-{stream_id}"
                )

                if finding_id not in applied_finding_ids:
                    rule = self.catalog.get_rule_for_upstream(rule_id)
                    if rule:
                        non_compliant_count += 1
                        applied_finding_ids.add(finding_id)
                        t_id = threat_by_finding.get(finding_id) or threat_by_finding.get(rule_id)
                        deductions.append(
                            PostureDeduction(
                                rule_id=rule["rule_id"],
                                title=rule["title"],
                                penalty=rule["penalty"],
                                upstream_rule_id=rule_id,
                                finding_id=finding_id,
                                weakness_id=getattr(w, "mapping_id", None),
                                threat_mapping_id=t_id,
                                observed_property=prop,
                                observed_value=val,
                                certificate_index=c_idx,
                                stream_id=stream_id,
                                description=rule["description"],
                            )
                        )

        # Sort breakdown deterministically by penalty descending, then rule_id ascending
        deductions.sort(
            key=lambda d: (
                -d.penalty,
                d.rule_id,
                d.certificate_index if d.certificate_index is not None else -1,
            )
        )

        total_penalty = sum(d.penalty for d in deductions)
        final_score = max(0, min(100, 100 - total_penalty))
        severity = self.calculate_severity(final_score)

        return CryptographicPostureReport(
            session_id=session_id,
            stream_id=stream_id,
            posture_score=final_score,
            severity=severity,
            base_score=100,
            total_penalty=total_penalty,
            deductions=deductions,
            evaluated_findings_count=compliant_count + non_compliant_count + unknown_count,
            compliant_findings_count=compliant_count,
            non_compliant_findings_count=non_compliant_count,
            unknown_findings_count=unknown_count,
            deterministic=True,
        )