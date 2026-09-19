"""
Service implementation for Step 23 - Threat Mapping & Evidence Correlation.

Consumes structured findings from Step 22 and adds a deterministic threat-context layer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas.threat_mapping import (
    MitreAttackReference,
    SessionThreatReport,
    ThreatCategory,
    ThreatContextMapping,
    ThreatEvidence,
    ThreatMappingStatus,
)
from app.schemas.vulnerability_mapping import MappingType, WeaknessMapping


class ThreatMappingCatalog:
    """Loads and validates the threat mapping rule catalog (fail-closed)."""

    def __init__(self, catalog_path: Optional[Path] = None) -> None:
        if catalog_path is None:
            catalog_path = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "threat_mapping_rules.json"
        self.catalog_path = catalog_path
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.upstream_rule_index: Dict[str, List[Dict[str, Any]]] = {}
        self._load_and_validate()

    def _load_and_validate(self) -> None:
        if not self.catalog_path.exists():
            raise FileNotFoundError(f"Threat mapping catalog not found at {self.catalog_path}")

        try:
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise ValueError(f"Failed to parse threat mapping catalog JSON: {exc}") from exc

        rules_list = data.get("rules", [])
        if not isinstance(rules_list, list):
            raise ValueError("Invalid catalog: 'rules' must be a list")

        expected_count = data.get("total_rules")
        if expected_count is not None and len(rules_list) != expected_count:
            raise ValueError(
                f"Catalog total_rules count mismatch: declared {expected_count}, found {len(rules_list)}"
            )

        seen_ids = set()
        for rule in rules_list:
            rule_id = rule.get("rule_id")
            if not rule_id or not isinstance(rule_id, str):
                raise ValueError(f"Rule missing mandatory string 'rule_id': {rule}")
            if rule_id in seen_ids:
                raise ValueError(f"Duplicate threat rule_id detected: {rule_id}")
            seen_ids.add(rule_id)

            category = rule.get("category")
            if not category or category not in ThreatCategory.__members__:
                raise ValueError(f"Rule {rule_id} has invalid ThreatCategory: {category}")

            for field in ("title", "description", "upstream_rule_id", "status", "limitations"):
                if not rule.get(field):
                    raise ValueError(f"Rule {rule_id} missing mandatory field: {field}")

            mitre = rule.get("mitre_attack")
            if mitre is not None:
                if not isinstance(mitre, dict) or "technique_id" not in mitre or "technique_name" not in mitre:
                    raise ValueError(f"Rule {rule_id} has malformed mitre_attack specification: {mitre}")
                tid = mitre["technique_id"]
                if not (tid.startswith("T") and (len(tid) == 5 or (len(tid) == 9 and tid[5] == "."))):
                    raise ValueError(f"Rule {rule_id} has invalid MITRE technique ID format: {tid}")

            self.rules[rule_id] = rule
            upstream_id = rule["upstream_rule_id"]
            self.upstream_rule_index.setdefault(upstream_id, []).append(rule)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def get_rules_for_upstream(self, upstream_rule_id: str) -> List[Dict[str, Any]]:
        return self.upstream_rule_index.get(upstream_rule_id, [])


class ThreatMappingService:
    """Deterministic threat mapping and evidence correlation service."""

    def __init__(self, catalog: Optional[ThreatMappingCatalog] = None) -> None:
        self.catalog = catalog or ThreatMappingCatalog()

    @staticmethod
    def _generate_threat_mapping_id(
        rule_id: str,
        stream_id: str,
        upstream_mapping_id: str,
        cert_index: Optional[int],
        observed_prop: str,
        observed_val: Any,
    ) -> str:
        cert_suffix = f"-c{cert_index}" if cert_index is not None else ""
        content = f"{rule_id}:{stream_id}:{upstream_mapping_id}:{cert_index}:{observed_prop}:{str(observed_val)}"
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
        return f"THREAT-ID-{rule_id}-{stream_id}{cert_suffix}-{digest}"

    def map_weakness(self, weakness: WeaknessMapping) -> List[ThreatContextMapping]:
        """Correlate a single WeaknessMapping to threat context mappings."""
        m_type = getattr(weakness, "mapping_type", None)
        benign_enum = getattr(MappingType, "BENIGN", None)
        if benign_enum is not None and m_type == benign_enum:
            return []
        if isinstance(m_type, str) and m_type.upper() == "BENIGN":
            return []

        upstream_rule_id = getattr(weakness, "source_rule_id", None) or getattr(weakness, "rule_id", "UNKNOWN_RULE")
        candidate_rules = self.catalog.get_rules_for_upstream(upstream_rule_id)
        if not candidate_rules:
            return []

        results: List[ThreatContextMapping] = []
        ev = getattr(weakness, "evidence", None)

        def _get_field(attr: str, default: Any = None) -> Any:
            if ev is None:
                return default
            if isinstance(ev, dict):
                return ev.get(attr, default)
            return getattr(ev, attr, default)

        stream_id = _get_field("stream_id", "unknown_stream")
        cert_idx = _get_field("certificate_index")
        observed_prop = _get_field("observed_property", "unknown_property")
        observed_val = _get_field("observed_value")
        pkt_num = _get_field("packet_number")
        ts = _get_field("timestamp")
        raw_der = _get_field("raw_der_sha256")
        ref_val = _get_field("reference_value")

        # Resolves without crashing regardless of Step 22 finding attribute naming
        resolved_finding_id = (
            getattr(weakness, "finding_id", None)
            or getattr(weakness, "compliance_finding_id", None)
            or getattr(weakness, "upstream_finding_id", None)
            or f"FINDING-{upstream_rule_id}-{stream_id}"
        )

        resolved_mapping_id = (
            getattr(weakness, "mapping_id", None)
            or getattr(weakness, "weakness_id", None)
            or getattr(weakness, "upstream_mapping_id", None)
            or f"MAP-{upstream_rule_id}-{stream_id}"
        )

        for rule in candidate_rules:
            threat_id = self._generate_threat_mapping_id(
                rule["rule_id"], stream_id, resolved_mapping_id, cert_idx, observed_prop, observed_val
            )

            mitre_ref: Optional[MitreAttackReference] = None
            if rule.get("mitre_attack") is not None:
                m_data = rule["mitre_attack"]
                mitre_ref = MitreAttackReference(
                    technique_id=m_data["technique_id"],
                    technique_name=m_data["technique_name"],
                    tactic=m_data.get("tactic"),
                    url=m_data.get("url"),
                )

            threat_ev = ThreatEvidence(
                stream_id=stream_id,
                packet_number=pkt_num,
                timestamp=ts,
                certificate_index=cert_idx,
                raw_der_sha256=raw_der,
                upstream_finding_id=resolved_finding_id,
                upstream_rule_id=upstream_rule_id,
                upstream_mapping_id=resolved_mapping_id,
                upstream_identifier=getattr(weakness, "identifier", "UNKNOWN"),
                observed_property=observed_prop,
                observed_value=observed_val,
                reference_value=ref_val,
                threat_rule_id=rule["rule_id"],
            )

            cve_enum = getattr(MappingType, "CVE", None)
            is_cve = (m_type == cve_enum) if cve_enum is not None else (str(m_type).upper() == "CVE")
            cve_id_propagated = (
                weakness.identifier if is_cve else getattr(weakness, "cve_id", None)
            )

            is_weakness = (m_type == getattr(MappingType, "WEAKNESS", None)) if hasattr(MappingType, "WEAKNESS") else (str(m_type).upper() == "WEAKNESS")

            mapping = ThreatContextMapping(
                threat_mapping_id=threat_id,
                rule_id=rule["rule_id"],
                category=ThreatCategory(rule["category"]),
                title=rule["title"],
                description=rule["description"],
                status=ThreatMappingStatus(rule["status"]),
                evidence=threat_ev,
                upstream_finding_id=resolved_finding_id,
                upstream_mapping_id=resolved_mapping_id,
                cwe_id=getattr(weakness, "cwe_id", None) or (weakness.identifier if is_weakness else None),
                cve_id=cve_id_propagated,
                mitre_attack=mitre_ref,
                limitations=rule["limitations"],
                references=rule.get("references", []),
                deterministic=True,
            )
            results.append(mapping)

        return results

    def build_session_threat_report(
        self,
        session_id: str,
        stream_id: str,
        weaknesses: List[WeaknessMapping],
    ) -> SessionThreatReport:
        """Process multiple weakness mappings for a session into a deduplicated, deterministically ordered report."""
        seen_keys = set()
        deduped_mappings: List[ThreatContextMapping] = []

        for weakness in weaknesses:
            threat_mappings = self.map_weakness(weakness)
            for m in threat_mappings:
                dedup_key = (
                    m.rule_id,
                    m.evidence.stream_id,
                    m.upstream_mapping_id,
                    m.evidence.certificate_index,
                    m.evidence.raw_der_sha256,
                    m.evidence.observed_property,
                )
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    deduped_mappings.append(m)

        # Deterministic sorting
        deduped_mappings.sort(
            key=lambda item: (
                item.rule_id,
                item.evidence.certificate_index if item.evidence.certificate_index is not None else -1,
                item.evidence.stream_id,
                item.threat_mapping_id,
            )
        )

        category_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        technique_counts: Dict[str, int] = {}

        for item in deduped_mappings:
            cat = item.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

            st = item.status.value
            status_counts[st] = status_counts.get(st, 0) + 1

            if item.mitre_attack:
                tid = item.mitre_attack.technique_id
                technique_counts[tid] = technique_counts.get(tid, 0) + 1

        return SessionThreatReport(
            session_id=session_id,
            stream_id=stream_id,
            engine_version="1.0.0",
            threat_mappings=deduped_mappings,
            total_threat_mappings=len(deduped_mappings),
            category_counts=category_counts,
            status_counts=status_counts,
            mitre_technique_counts=technique_counts,
            deterministic=True,
        )