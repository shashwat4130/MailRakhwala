/**
 * Canonical Report Data Model and Normalization Layer for MailRakhwala.
 * 
 * Provides authoritative, immutable accessors for backend report schemas:
 * - session
 * - protocol_summary
 * - posture_report
 * - compliance_findings
 * - vulnerability_mappings
 * - threat_mappings
 * - recommendations
 * - feature_vector (19 canonical dimensions)
 * - anomaly_detection
 * - risk_classification
 * - shap_explanation
 * 
 * Strict Semantic Rules:
 * - Missing values remain null / undefined (never fabricated into fake zeroes).
 * - posture_score = 0 means the actual score is 0 if and only if returned as 0.
 * - -1.0 means explicitly "Unavailable from capture" as per canonical sentinel.
 * - 0.0 means actual measured zero / false / absent.
 * - ML models return null when un-fitted / baseline mode.
 * - When an authoritative deterministic finding contradicts a vector dimension
 *   (e.g., RULE-STARTTLS-002 High Severity deduction vs starttls_downgrade = 0.0),
 *   the frontend preserves the raw backend value (0.0) but flags and renders
 *   a clear "Backend vector mismatch" state without fabricating data.
 */

/**
 * Detect authoritative STARTTLS downgrade finding from compliance findings.
 * Must strictly be NON_COMPLIANT (rules with NOT_APPLICABLE or COMPLIANT are not violations).
 */
export function getAuthoritativeStarttlsFinding(report) {
  const findings = Array.isArray(report?.compliance_findings) ? report.compliance_findings : [];
  return findings.find((f) => {
    const isRuleMatch = f.rule_id === 'RULE-STARTTLS-002' || f.rule_id?.startsWith('RULE-STARTTLS');
    const isCategoryMatch = f.category === 'STARTTLS_SECURITY';
    const isStateMatch = f.evidence?.observed_property === 'starttls.state' &&
      String(f.evidence?.observed_value).toUpperCase().includes('PLAINTEXT');
    const isNonCompliant = f.status === 'NON_COMPLIANT';
    return (isRuleMatch || isCategoryMatch || isStateMatch) && isNonCompliant;
  }) || null;
}

/**
 * Detect authoritative STARTTLS deduction from posture report.
 * Must strictly have a positive penalty.
 */
export function getAuthoritativeStarttlsDeduction(report) {
  const deductions = Array.isArray(report?.posture_report?.deductions) ? report.posture_report.deductions : [];
  return deductions.find((d) => {
    const isRule = d.rule_id?.includes('STARTTLS') || d.upstream_rule_id?.includes('STARTTLS');
    const isProperty = d.observed_property === 'starttls.state';
    const hasPenalty = typeof d.penalty === 'number' && d.penalty > 0;
    return (isRule || isProperty) && hasPenalty;
  }) || null;
}

/**
 * 19-Dimensional Deterministic Feature Vector Specification.
 * Matches backend/app/schemas/ml_features.py exactly in order and naming.
 */
export const CANONICAL_FEATURES = [
  // 1. Protocol & Handshake (Features 1 - 4)
  {
    key: 'tls_version_numeric',
    name: 'TLS Version (Numeric)',
    domain: 'Protocol & Handshake',
    description: 'Encoded TLS version (TLS 1.3: 4.0, TLS 1.2: 3.0, TLS 1.1: 2.0, TLS 1.0: 1.0, SSL: 0.0, Unavailable: -1.0)',
    interpret: (v) => {
      if (v === 4.0) return 'TLS 1.3 (Modern)';
      if (v === 3.0) return 'TLS 1.2 (Standard)';
      if (v === 2.0) return 'TLS 1.1 (Deprecated)';
      if (v === 1.0) return 'TLS 1.0 (Insecure)';
      if (v === 0.0) return 'SSL 2.0 / 3.0 (Broken)';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return `Rating: ${v}`;
    },
  },
  {
    key: 'cipher_security_score',
    name: 'Cipher Security Score',
    domain: 'Protocol & Handshake',
    description: 'Cipher security rating (Modern: 3.0, Legacy/Weak: 1.0, Broken/Insecure: 0.0, Unavailable: -1.0)',
    interpret: (v) => {
      if (v >= 3.0) return 'Modern / Strong (Score: 3.0)';
      if (v >= 1.0) return 'Legacy / Weak (Score: 1.0)';
      if (v === 0.0) return 'Insecure / Broken (Score: 0.0)';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return `Score: ${v}`;
    },
  },
  {
    key: 'key_exchange_strength',
    name: 'Key Exchange Strength',
    domain: 'Protocol & Handshake',
    description: 'Key exchange mechanism rating (ECDHE/DHE: 2.0, Static RSA: 0.0, Unavailable: -1.0)',
    interpret: (v) => {
      if (v >= 2.0) return 'Ephemeral (ECDHE / DHE, PFS active)';
      if (v === 0.0) return 'Static RSA (No forward secrecy)';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return `Strength: ${v}`;
    },
  },
  {
    key: 'pfs_enabled',
    name: 'Perfect Forward Secrecy (PFS)',
    domain: 'Protocol & Handshake',
    description: 'Perfect Forward Secrecy flag (1.0: Enabled, 0.0: Disabled, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — Enabled (PFS active)';
      if (v === 0.0) return '0.0 — Disabled (No forward secrecy)';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },

  // 2. Certificate & Identity Validation (Features 5 - 11)
  {
    key: 'certificate_key_size',
    name: 'Certificate Key Size',
    domain: 'Certificate & PKI Identity',
    description: 'Public key size in bits (e.g. 2048, 4096; missing: -1.0)',
    interpret: (v) => {
      if (typeof v === 'number' && v > 0) return `${v} bits`;
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return 'Unavailable from capture';
    },
  },
  {
    key: 'certificate_signature_strength',
    name: 'Signature Algorithm Strength',
    domain: 'Certificate & PKI Identity',
    description: 'Signature security rating (SHA-2/Edwards: 2.0, SHA-1/MD5: 0.0, Unavailable: -1.0)',
    interpret: (v) => {
      if (v >= 2.0) return 'Strong signature (SHA-2 / Edwards)';
      if (v === 0.0) return 'Weak signature (SHA-1 / MD5)';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return `Rating: ${v}`;
    },
  },
  {
    key: 'certificate_validity_status',
    name: 'Certificate Validity Status',
    domain: 'Certificate & PKI Identity',
    description: 'Temporal validity status (1.0: Valid, 0.0: Expired / NotYetValid, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — Valid temporal window';
      if (v === 0.0) return '0.0 — Invalid / Expired / Not yet valid';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'san_present',
    name: 'Subject Alternative Name (SAN)',
    domain: 'Certificate & PKI Identity',
    description: 'SAN extension presence flag (1.0: Present, 0.0: Absent, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — SAN extension present';
      if (v === 0.0) return '0.0 — SAN extension absent';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'hostname_match_status',
    name: 'Hostname Match Status',
    domain: 'Certificate & PKI Identity',
    description: 'Hostname matching certificate identity (1.0: Match, 0.0: Mismatch, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — Hostname matches certificate identity';
      if (v === 0.0) return '0.0 — Hostname identity mismatch';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'trust_validation_status',
    name: 'Trust Chain Validation',
    domain: 'Certificate & PKI Identity',
    description: 'Trust chain status (1.0: Trusted root, 0.0: Untrusted / Self-signed, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — Trusted root CA';
      if (v === 0.0) return '0.0 — Untrusted / Self-signed certificate';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'revocation_status',
    name: 'Revocation Check Status',
    domain: 'Certificate & PKI Identity',
    description: 'Revocation check (1.0: Good / Not Revoked, 0.0: Revoked, -1.0: Unavailable / Unchecked)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — Good / Not revoked';
      if (v === 0.0) return '0.0 — Revoked certificate';
      if (v === -1.0) return 'Unavailable / Unchecked from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },

  // 3. Protocol Downgrade / Exploits (Feature 12)
  {
    key: 'starttls_downgrade',
    name: 'STARTTLS Downgrade Anomaly',
    domain: 'Protocol Downgrade & Exploits',
    description: 'STARTTLS downgrade anomaly flag in ML feature vector (1.0: Anomaly detected, 0.0: No anomaly in vector, -1.0: Unavailable)',
    interpret: (v, report) => {
      const authFinding = getAuthoritativeStarttlsFinding(report);
      const authDeduction = getAuthoritativeStarttlsDeduction(report);

      if (v === 1.0) {
        return '1.0 — Downgrade anomaly detected in vector';
      }
      if (v === 0.0) {
        if (authFinding || authDeduction) {
          const ruleId = authFinding?.rule_id || authDeduction?.upstream_rule_id || authDeduction?.rule_id || 'RULE-STARTTLS-002';
          return `0.0 in vector (Mismatch: Authoritative finding ${ruleId} reports suspected downgrade)`;
        }
        return '0.0 — No downgrade anomaly recorded in vector';
      }
      if (v === -1.0) {
        return 'Unavailable from capture';
      }
      if (v === null || v === undefined) {
        return 'Not evaluated';
      }
      return String(v);
    },
    checkMismatch: (v, report) => {
      const authFinding = getAuthoritativeStarttlsFinding(report);
      const authDeduction = getAuthoritativeStarttlsDeduction(report);
      if (v === 0.0 && (authFinding || authDeduction)) {
        const ruleId = authFinding?.rule_id || authDeduction?.upstream_rule_id || authDeduction?.rule_id || 'RULE-STARTTLS-002';
        const penalty = authDeduction?.penalty ? ` (-${authDeduction.penalty} pts)` : '';
        return {
          hasMismatch: true,
          featureKey: 'starttls_downgrade',
          vectorValue: 0.0,
          authoritativeSource: ruleId,
          authoritativeSeverity: authFinding?.severity || 'HIGH',
          authoritativeTitle: authFinding?.title || authDeduction?.title || 'Suspected STARTTLS Stripping / Downgrade',
          message: `Backend vector mismatch: Vector records starttls_downgrade = 0.0, but authoritative deterministic analysis identified ${ruleId}${penalty} with ${authFinding?.severity || 'HIGH'} severity for unencrypted plaintext continuation.`,
        };
      }
      return null;
    },
  },

  // 4. Pipeline Aggregations (Features 13 - 18)
  {
    key: 'compliance_violation_count',
    name: 'Compliance Violations Count',
    domain: 'Pipeline Deterministic Counts',
    description: 'Total confirmed NON_COMPLIANT compliance findings',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} non-compliant violations`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'unknown_finding_count',
    name: 'Unknown Findings Count',
    domain: 'Pipeline Deterministic Counts',
    description: 'Total compliance findings flagged with UNKNOWN status',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} unknown status findings`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'high_critical_finding_count',
    name: 'High & Critical Findings Count',
    domain: 'Pipeline Deterministic Counts',
    description: 'Count of NON_COMPLIANT findings with HIGH or CRITICAL severity',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} high / critical findings`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'vulnerability_count',
    name: 'Mapped Vulnerabilities (CWE/CVE)',
    domain: 'Pipeline Deterministic Counts',
    description: 'Count of mapped CWEs and CVEs',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} mapped vulnerabilities (CWE/CVE)`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'threat_mapping_count',
    name: 'ATT&CK Threat Mappings',
    domain: 'Pipeline Deterministic Counts',
    description: 'Count of mapped ATT&CK adversarial techniques',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} ATT&CK techniques mapped`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
  {
    key: 'cryptographic_security_score',
    name: 'Propagated Posture Score',
    domain: 'Pipeline Deterministic Counts',
    description: 'Propagated Posture Score (0.0 to 100.0, -1.0 if unavailable)',
    interpret: (v) => {
      if (typeof v === 'number' && v >= 0) return `${v} / 100 base posture score`;
      if (v === -1.0) return 'Unavailable';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },

  // 5. Client Metadata (Feature 19)
  {
    key: 'ja4_available',
    name: 'JA4 Client Fingerprint Available',
    domain: 'Client Telemetry',
    description: 'JA4 / TLS client fingerprint presence (1.0: Present, 0.0: Absent, -1.0: Unavailable)',
    interpret: (v) => {
      if (v === 1.0) return '1.0 — JA4 client fingerprint present';
      if (v === 0.0) return '0.0 — JA4 client fingerprint absent';
      if (v === -1.0) return 'Unavailable from capture';
      if (v === null || v === undefined) return 'Not evaluated';
      return String(v);
    },
  },
];

/**
 * Access session metadata safely.
 */
export const getSession = (report) => {
  return report?.session || null;
};

export const getSessionId = (report) => {
  return report?.session?.session_id || null;
};

/**
 * Access protocol security summary safely.
 */
export const getProtocolSummary = (report) => {
  return report?.protocol_summary || null;
};

/**
 * Access posture report safely.
 */
export const getPostureReport = (report) => {
  return report?.posture_report || null;
};

/**
 * Helper to determine if captured traffic contains observable email protocols.
 */
export const hasEmailProtocol = (report) => {
  const proto = String(report?.protocol_summary?.detected_protocol || '').trim().toUpperCase();
  return ['SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S'].includes(proto);
};

/**
 * Authoritative Applicability Check.
 * Returns true only if the capture contains a supported email assessment target.
 */
export const isReportApplicable = (report) => {
  if (!report) return false;
  if (report.applicability === 'NOT_APPLICABLE') return false;
  if (report.session?.applicability === 'NOT_APPLICABLE') return false;
  if (report.applicability === 'APPLICABLE') return true;
  return hasEmailProtocol(report);
};

/**
 * Authoritative Posture Score Accessor.
 * Strictly checks report.posture_report.posture_score (or score).
 * Returns null if not applicable or missing. Returns 0 ONLY if backend explicitly provided 0.
 * NEVER fabricates an independent calculation.
 */
export const getPostureScore = (report) => {
  if (!isReportApplicable(report)) return null;
  const pr = report?.posture_report;
  if (!pr) return null;
  if (typeof pr.posture_score === 'number' && Number.isFinite(pr.posture_score)) {
    return pr.posture_score;
  }
  if (typeof pr.score === 'number' && Number.isFinite(pr.score)) {
    return pr.score;
  }
  return null;
};

/**
 * Authoritative Compliance Findings Accessor.
 */
export const getComplianceFindings = (report) => {
  return Array.isArray(report?.compliance_findings) ? report.compliance_findings : [];
};

/**
 * Authoritative Vulnerability & Weakness Mappings Accessor.
 */
export const getVulnerabilityMappings = (report) => {
  return Array.isArray(report?.vulnerability_mappings) ? report.vulnerability_mappings : [];
};

/**
 * Authoritative Threat Context Mappings Accessor.
 */
export const getThreatMappings = (report) => {
  return Array.isArray(report?.threat_mappings) ? report.threat_mappings : [];
};

/**
 * Authoritative Posture Deductions Accessor.
 */
export const getPostureDeductions = (report) => {
  return Array.isArray(report?.posture_report?.deductions)
    ? report.posture_report.deductions
    : [];
};

/**
 * Authoritative Practical Recommendations Accessor.
 */
export const getRecommendations = (report) => {
  return Array.isArray(report?.recommendations) ? report.recommendations : [];
};

/**
 * Feature Vector Accessor.
 * Returns null if not present in report.
 */
export const getFeatureVector = (report) => {
  return report?.feature_vector || null;
};

/**
 * Extract canonical 19-dimensional feature entries strictly by key.
 * Does NOT rely on Object.values(), Object.keys(), or iteration ordering.
 * Returns array of objects with canonical metadata, exact value, interpretation,
 * and contextual mismatch flag when authoritative findings contradict vector data.
 */
export const getCanonicalFeatures = (report) => {
  const fv = getFeatureVector(report);
  if (!fv) return [];

  return CANONICAL_FEATURES.map((def, index) => {
    const rawVal = fv[def.key];
    const hasValue = typeof rawVal === 'number' && Number.isFinite(rawVal);
    const value = hasValue ? rawVal : null;
    const mismatch = def.checkMismatch ? def.checkMismatch(value, report) : null;

    return {
      index: index + 1,
      key: def.key,
      name: def.name,
      domain: def.domain,
      description: def.description,
      value,
      interpretation: def.interpret(value, report),
      isAvailable: hasValue && value !== -1.0,
      mismatch,
    };
  });
};

/**
 * Authoritative Anomaly Detection Accessor.
 * Returns null if model was not fitted / baseline mode.
 */
export const getAnomalyDetection = (report) => {
  return report?.anomaly_detection || null;
};

/**
 * Authoritative Supervised Risk Classification Accessor.
 * Returns null if model was not fitted.
 */
export const getRiskClassification = (report) => {
  return report?.risk_classification || null;
};

/**
 * Authoritative SHAP Explainability Accessor.
 * Returns null if model was not fitted.
 */
export const getShapExplanation = (report) => {
  return report?.shap_explanation || null;
};


/**
 * Authoritative Assessment Status.
 * Returns 'APPLICABLE', 'NOT_APPLICABLE', 'NOT_EVALUATED', or 'EVALUATED'.
 */
export const getAssessmentStatus = (report) => {
  if (!report) return 'NOT_EVALUATED';
  if (!isReportApplicable(report)) return 'NOT_APPLICABLE';
  return report.assessment_status || 'EVALUATED';
};

/**
 * Authoritative Applicability Reason.
 */
export const getApplicabilityReason = (report) => {
  return report?.applicability_reason || report?.session?.applicability_reason || null;
};

/**
 * Authoritative Posture Severity.
 * Returns 'NOT_APPLICABLE' if not applicable.
 */
export const getPostureSeverity = (report) => {
  if (!isReportApplicable(report)) return 'NOT_APPLICABLE';
  return report?.posture_report?.severity || null;
};

/**
 * Authoritative Analysis State Selector.
 * Single source of truth across all pages.
 */
export const getAuthoritativeAnalysisState = (report) => {
  const isApplicable = isReportApplicable(report);
  const applicability = isApplicable ? 'APPLICABLE' : 'NOT_APPLICABLE';
  const assessmentStatus = isApplicable ? (report?.assessment_status || 'EVALUATED') : 'NOT_APPLICABLE';
  const score = isApplicable ? getPostureScore(report) : null;
  const severity = isApplicable ? (report?.posture_report?.severity || null) : 'NOT_APPLICABLE';
  const findings = isApplicable ? getComplianceFindings(report) : [];
  const evaluatedFindingsCount = isApplicable
    ? (report?.posture_report?.evaluated_findings_count ?? findings.length)
    : 0;

  return {
    sessionId: getSessionId(report),
    isApplicable,
    applicability,
    assessmentStatus,
    applicabilityReason: getApplicabilityReason(report),
    postureScore: score,
    postureSeverity: severity,
    evaluatedFindingsCount,
    deductions: isApplicable ? getPostureDeductions(report) : [],
    findings,
    vulnerabilities: isApplicable ? getVulnerabilityMappings(report) : [],
    threats: isApplicable ? getThreatMappings(report) : [],
    recommendations: isApplicable ? getRecommendations(report) : [],
    featureVector: isApplicable ? getFeatureVector(report) : null,
    anomalyDetection: isApplicable ? getAnomalyDetection(report) : null,
    riskClassification: isApplicable ? getRiskClassification(report) : null,
    shapExplanation: isApplicable ? getShapExplanation(report) : null,
  };
};

/**
 * Canonical Report Normalization Function.
 * Produces a single, consistent, immutable frontend representation.
 * All pages and Risk Intelligence tabs consume this normalized object.
 */
export function normalizeReport(rawReport) {
  if (!rawReport || typeof rawReport !== 'object') {
    return null;
  }

  const isApplicable = rawReport.applicability !== 'NOT_APPLICABLE' &&
    (rawReport.applicability === 'APPLICABLE' || hasEmailProtocol(rawReport));
  const applicability = isApplicable ? 'APPLICABLE' : 'NOT_APPLICABLE';
  const assessmentStatus = isApplicable ? (rawReport.assessment_status || 'EVALUATED') : 'NOT_APPLICABLE';
  const applicabilityReason = rawReport.applicability_reason ||
    (!isApplicable ? 'No supported email protocol/security assessment was observed in this capture.' : null);

  const session = rawReport.session ? {
    ...rawReport.session,
    applicability,
    assessment_status: assessmentStatus,
    applicability_reason: applicabilityReason,
  } : null;

  const protocolSummary = rawReport.protocol_summary || null;
  const postureReport = rawReport.posture_report ? {
    ...rawReport.posture_report,
    applicability,
    assessment_status: assessmentStatus,
    posture_score: isApplicable ? rawReport.posture_report.posture_score : null,
    severity: isApplicable ? rawReport.posture_report.severity : null,
  } : null;

  const complianceFindings = isApplicable && Array.isArray(rawReport.compliance_findings)
    ? rawReport.compliance_findings
    : [];
  const vulnerabilityMappings = isApplicable && Array.isArray(rawReport.vulnerability_mappings)
    ? rawReport.vulnerability_mappings
    : [];
  const threatMappings = isApplicable && Array.isArray(rawReport.threat_mappings)
    ? rawReport.threat_mappings
    : [];
  const recommendations = isApplicable && Array.isArray(rawReport.recommendations)
    ? rawReport.recommendations
    : [];
  const featureVector = isApplicable && rawReport.feature_vector && typeof rawReport.feature_vector === 'object'
    ? rawReport.feature_vector
    : null;
  const anomalyDetection = isApplicable && rawReport.anomaly_detection && typeof rawReport.anomaly_detection === 'object'
    ? rawReport.anomaly_detection
    : (rawReport.anomaly_detection ? { ...rawReport.anomaly_detection, available: false } : null);
  const riskClassification = isApplicable && rawReport.risk_classification && typeof rawReport.risk_classification === 'object'
    ? rawReport.risk_classification
    : (rawReport.risk_classification ? { ...rawReport.risk_classification, available: false } : null);
  const shapExplanation = isApplicable && rawReport.shap_explanation && typeof rawReport.shap_explanation === 'object'
    ? rawReport.shap_explanation
    : (rawReport.shap_explanation ? { ...rawReport.shap_explanation, available: false } : null);

  return {
    ...rawReport,
    applicability,
    assessment_status: assessmentStatus,
    applicability_reason: applicabilityReason,
    session,
    protocol_summary: protocolSummary,
    posture_report: postureReport,
    compliance_findings: complianceFindings,
    vulnerability_mappings: vulnerabilityMappings,
    threat_mappings: threatMappings,
    recommendations,
    feature_vector: featureVector,
    anomaly_detection: anomalyDetection,
    risk_classification: riskClassification,
    shap_explanation: shapExplanation,
  };
}

export const normalizeAnalysisReport = normalizeReport;

