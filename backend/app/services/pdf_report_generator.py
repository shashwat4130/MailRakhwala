"""
MailRakhwala PDF Report Generator.
Step 29 Enterprise Reporting: Generates human-readable audit PDF reports
directly from the authoritative ComprehensiveAnalysisReport model.

Important semantic rule:
A TCP stream count alone does not establish an email-security assessment.
Cryptographic posture, ML risk, anomaly, SHAP, findings, and recommendations
are rendered as assessed only when an identifiable email protocol is present.
"""

from __future__ import annotations

import io
import re
from typing import Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.report_export import ComprehensiveAnalysisReport


EMAIL_PROTOCOLS = {
    "SMTP",
    "SMTPS",
    "IMAP",
    "IMAPS",
    "POP3",
    "POP3S",
}


class PDFReportGenerator:
    """Generates standard enterprise-grade PDF audit reports."""

    def __init__(self, report: ComprehensiveAnalysisReport) -> None:
        self.report = report
        self.buffer = io.BytesIO()
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self) -> None:
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#0f172a"),
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=16,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=12,
                spaceAfter=6,
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="MetaLabel",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#475569"),
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="MetaValue",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#0f172a"),
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="TableBody",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#334155"),
            )
        )

        self.styles.add(
            ParagraphStyle(
                name="DisclaimerStyle",
                parent=self.styles["Normal"],
                fontName="Helvetica-Oblique",
                fontSize=7,
                leading=9,
                textColor=colors.HexColor("#64748b"),
            )
        )

    @staticmethod
    def _text(value: Any, fallback: str = "Unavailable") -> str:
        if value is None or value == "":
            return fallback
        return str(value)

    @staticmethod
    def _enum_text(value: Any, fallback: str = "Unavailable") -> str:
        if value is None:
            return fallback
        return str(getattr(value, "value", value))

    def _assessment_context(self) -> dict[str, Any]:
        """
        Determine whether this capture is actually in scope for
        MailRakhwala's email cryptographic assessment.

        A reconstructed TCP stream is transport evidence, not proof of
        SMTP/IMAP/POP3 traffic.
        """
        session = self.report.session
        protocol_summary = getattr(self.report, "protocol_summary", None)

        total_streams = int(getattr(session, "total_streams", 0) or 0)
        detected_protocol = self._enum_text(
            getattr(protocol_summary, "detected_protocol", None),
            fallback="",
        ).strip().upper()

        has_email_signals = (
            total_streams > 0
            and detected_protocol in EMAIL_PROTOCOLS
        )

        return {
            "total_streams": total_streams,
            "detected_protocol": detected_protocol,
            "has_email_signals": has_email_signals,
            "protocol_summary": protocol_summary,
        }

    def _score_text(self, assessed: bool) -> str:
        if not assessed:
            return "Not Assessed"

        posture = getattr(self.report, "posture_report", None)
        if posture is None:
            return "Unavailable"

        score = getattr(posture, "posture_score", None)
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            score = getattr(posture, "total_score", None)

        if not isinstance(score, (int, float)) or isinstance(score, bool):
            return "Unavailable"

        # Keep posture-score classification separate from finding severity.
        # These are the exact labels currently used by the Dashboard.
        if score >= 85:
            score_status = "Strong posture"
        elif score >= 60:
            score_status = "Needs attention"
        else:
            score_status = "Review required"

        return f"{score} / 100 — {score_status}"

    def generate(self) -> bytes:
        doc = SimpleDocTemplate(
            self.buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        story: List[Any] = []

        context = self._assessment_context()
        assessed = context["has_email_signals"]
        protocol_summary = context["protocol_summary"]

        # 1. Header
        story.append(
            Paragraph(
                "MailRakhwala Security Audit Report",
                self.styles["ReportTitle"],
            )
        )
        story.append(
            Paragraph(
                "Enterprise Email Cryptographic Security & Inspection Analysis",
                self.styles["MetaLabel"],
            )
        )
        story.append(Spacer(1, 8))
        story.append(
            HRFlowable(
                width="100%",
                thickness=1.5,
                color=colors.HexColor("#7c3aed"),
                spaceAfter=12,
            )
        )

        # 2. Session Information
        session = self.report.session

        session_data = [
            [
                Paragraph("Session ID:", self.styles["MetaLabel"]),
                Paragraph(
                    self._text(getattr(session, "session_id", None)),
                    self.styles["MetaValue"],
                ),
                Paragraph("Target File:", self.styles["MetaLabel"]),
                Paragraph(
                    self._text(getattr(session, "filename", None)),
                    self.styles["MetaValue"],
                ),
            ],
            [
                Paragraph("Status:", self.styles["MetaLabel"]),
                Paragraph(
                    self._text(getattr(session, "status", None)),
                    self.styles["MetaValue"],
                ),
                Paragraph("Generated UTC:", self.styles["MetaLabel"]),
                Paragraph(
                    self._text(getattr(session, "created_at", None)),
                    self.styles["MetaValue"],
                ),
            ],
        ]

        sess_table = Table(
            session_data,
            colWidths=[80, 185, 80, 195],
        )
        sess_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(sess_table)
        story.append(Spacer(1, 12))

        # 3. Assessment Scope
        story.append(
            Paragraph(
                "Assessment Scope",
                self.styles["SectionHeader"],
            )
        )

        if assessed:
            scope_title = "Email Security Assessment: APPLICABLE"
            scope_text = (
                "Identifiable email traffic was observed in the capture. "
                "MailRakhwala's email cryptographic assessment is applicable "
                "to the available evidence."
            )
            scope_color = "#ecfdf5"
            scope_border = "#a7f3d0"
            scope_text_color = "#047857"
        else:
            scope_title = "Email Security Assessment: NOT ASSESSED"
            scope_text = (
                "No identifiable SMTP, SMTPS, IMAP, IMAPS, POP3, or POP3S "
                "traffic was detected. A reconstructed TCP stream alone does "
                "not establish an email-security session. Cryptographic "
                "posture, ML risk, anomaly analysis, and email findings are "
                "therefore not assessed for this capture."
            )
            scope_color = "#f5f3ff"
            scope_border = "#ddd6fe"
            scope_text_color = "#6d28d9"

        scope_data = [
            [
                Paragraph(scope_title, self.styles["MetaLabel"]),
                Paragraph(
                    scope_text,
                    self.styles["TableBody"],
                ),
            ]
        ]

        scope_table = Table(scope_data, colWidths=[180, 360])
        scope_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(scope_color)),
                    ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(scope_border)),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor(scope_text_color)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(scope_table)
        story.append(Spacer(1, 10))

        # 4. Executive Security Summary
        story.append(
            Paragraph(
                "Executive Security Summary",
                self.styles["SectionHeader"],
            )
        )

        score_text = self._score_text(assessed)

        risk_val = "Not Assessed"
        model_prob_text = "Not Assessed"
        anomaly_val = "Not Assessed"

        if assessed and self.report.risk_classification:
            rc = self.report.risk_classification
            predicted_class = getattr(rc, "predicted_class", None)

            if predicted_class is None:
                predicted_class = getattr(
                    rc,
                    "predicted_risk_class",
                    None,
                )

            class_id = getattr(rc, "class_id", None)

            if predicted_class is not None:
                risk_val = (
                    f"{predicted_class}"
                    + (f" (ID: {class_id})" if class_id is not None else "")
                )

            probabilities = getattr(
                rc,
                "class_probabilities",
                None,
            )

            if isinstance(probabilities, dict) and probabilities:
                model_prob_text = ", ".join(
                    f"{key}: {value:.2f}"
                    for key, value in probabilities.items()
                )

        if assessed and self.report.anomaly_detection:
            ad = self.report.anomaly_detection
            is_anomaly = getattr(ad, "is_anomaly", None)
            anomaly_score = getattr(ad, "anomaly_score", None)

            if isinstance(is_anomaly, bool):
                if isinstance(anomaly_score, (int, float)):
                    anomaly_val = (
                        f"{'ANOMALOUS' if is_anomaly else 'NORMAL'} "
                        f"(Score: {anomaly_score:.3f})"
                    )
                else:
                    anomaly_val = (
                        "ANOMALOUS"
                        if is_anomaly
                        else "NORMAL"
                    )

        exec_data = [
            [
                Paragraph(
                    "Cryptographic Posture Score",
                    self.styles["MetaLabel"],
                ),
                Paragraph(score_text, self.styles["MetaValue"]),
            ],
            [
                Paragraph(
                    "Predicted Risk Class (XGBoost)",
                    self.styles["MetaLabel"],
                ),
                Paragraph(risk_val, self.styles["MetaValue"]),
            ],
            [
                Paragraph(
                    "XGBoost Model Probabilities",
                    self.styles["MetaLabel"],
                ),
                Paragraph(model_prob_text, self.styles["TableBody"]),
            ],
            [
                Paragraph(
                    "Anomaly Status (Isolation Forest)",
                    self.styles["MetaLabel"],
                ),
                Paragraph(anomaly_val, self.styles["MetaValue"]),
            ],
        ]

        exec_table = Table(exec_data, colWidths=[200, 340])
        exec_table.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(exec_table)
        story.append(Spacer(1, 10))

        # 5. Capture / Protocol Context
        story.append(
            Paragraph(
                "Capture & Protocol Context",
                self.styles["SectionHeader"],
            )
        )

        tls_value = "Not Assessed"
        if assessed and protocol_summary is not None:
            has_tls = getattr(protocol_summary, "has_tls", None)
            if isinstance(has_tls, bool):
                tls_value = "TLS evidence observed" if has_tls else "No TLS evidence observed"
            else:
                tls_value = "Unavailable from captured evidence"

        context_data = [
            [
                Paragraph("Reassembled Streams", self.styles["MetaLabel"]),
                Paragraph(
                    str(context["total_streams"]),
                    self.styles["MetaValue"],
                ),
            ],
            [
                Paragraph("Detected Email Protocol", self.styles["MetaLabel"]),
                Paragraph(
                    context["detected_protocol"]
                    if context["detected_protocol"]
                    else "No email protocol detected",
                    self.styles["MetaValue"],
                ),
            ],
            [
                Paragraph("TLS Evidence", self.styles["MetaLabel"]),
                Paragraph(tls_value, self.styles["MetaValue"]),
            ],
        ]

        context_table = Table(context_data, colWidths=[200, 340])
        context_table.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(context_table)
        story.append(Spacer(1, 10))

        # 6. SHAP is only meaningful when ML assessment is applicable.
        if (
            assessed
            and self.report.shap_explanation
            and self.report.shap_explanation.top_contributions
        ):
            story.append(
                Paragraph(
                    "Why did the model predict this? (Top 5 Model Attributions)",
                    self.styles["SectionHeader"],
                )
            )

            shap_headers = [
                Paragraph("Feature Name", self.styles["MetaLabel"]),
                Paragraph("Observed Value", self.styles["MetaLabel"]),
                Paragraph("Model Input", self.styles["MetaLabel"]),
                Paragraph("SHAP Magnitude", self.styles["MetaLabel"]),
                Paragraph("Direction", self.styles["MetaLabel"]),
            ]

            shap_rows = [shap_headers]

            for contribution in self.report.shap_explanation.top_contributions:
                shap_rows.append(
                    [
                        Paragraph(
                            self._text(
                                getattr(contribution, "feature_name", None),
                            ),
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            f"{getattr(contribution, 'original_value', 0):.2f}",
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            f"{getattr(contribution, 'model_input_value', 0):.2f}",
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            f"{getattr(contribution, 'shap_value', 0):+.3f}",
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            self._enum_text(
                                getattr(contribution, "direction", None),
                            ),
                            self.styles["TableBody"],
                        ),
                    ]
                )

            shap_table = Table(
                shap_rows,
                colWidths=[150, 80, 80, 80, 150],
            )
            shap_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(shap_table)
            story.append(Spacer(1, 10))

        # 7. Deterministic Compliance Findings
        findings = (
            self.report.compliance_findings
            if assessed
            else []
        )

        if findings:
            story.append(
                Paragraph(
                    f"Deterministic Compliance Findings ({len(findings)})",
                    self.styles["SectionHeader"],
                )
            )

            find_headers = [
                Paragraph("Rule ID", self.styles["MetaLabel"]),
                Paragraph("Severity", self.styles["MetaLabel"]),
                Paragraph("Finding Description", self.styles["MetaLabel"]),
                Paragraph("Deterministic Status", self.styles["MetaLabel"]),
            ]

            find_rows = [find_headers]

            for finding in findings[:8]:
                find_rows.append(
                    [
                        Paragraph(
                            self._text(getattr(finding, "rule_id", None)),
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            self._enum_text(
                                getattr(finding, "severity", None),
                            ),
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            self._text(
                                getattr(finding, "description", None),
                            ),
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            self._enum_text(
                                getattr(finding, "status", None),
                            ),
                            self.styles["TableBody"],
                        ),
                    ]
                )

            find_table = Table(
                find_rows,
                colWidths=[110, 55, 285, 90],
            )
            find_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(find_table)
            story.append(Spacer(1, 10))

        # 8. Remediation recommendations
        recommendations = (
            self.report.recommendations
            if assessed
            else []
        )

        if recommendations:
            story.append(
                Paragraph(
                    "Deterministic Remediation Actions",
                    self.styles["SectionHeader"],
                )
            )

            rec_rows = [
                [
                    Paragraph("Finding Title", self.styles["MetaLabel"]),
                    Paragraph("Remediation Advisory", self.styles["MetaLabel"]),
                ]
            ]

            for recommendation in recommendations[:6]:
                rec_rows.append(
                    [
                        Paragraph(
                            f"[{self._text(getattr(recommendation, 'severity', None))}] "
                            f"{self._text(getattr(recommendation, 'title', None))}",
                            self.styles["TableBody"],
                        ),
                        Paragraph(
                            self._text(
                                getattr(recommendation, "recommendation", None),
                            ),
                            self.styles["TableBody"],
                        ),
                    ]
                )

            rec_table = Table(
                rec_rows,
                colWidths=[160, 380],
            )
            rec_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(rec_table)
            story.append(Spacer(1, 14))

        # 9. Explicit no-email conclusion
        if not assessed:
            story.append(
                Paragraph(
                    "Assessment Conclusion",
                    self.styles["SectionHeader"],
                )
            )

            conclusion_data = [
                [
                    Paragraph(
                        "No Email/TLS Security Assessment Performed",
                        self.styles["MetaLabel"],
                    ),
                    Paragraph(
                        "The capture contains network traffic, but the "
                        "available evidence does not establish an email "
                        "protocol session. Therefore no cryptographic "
                        "security score, ML risk classification, anomaly "
                        "assessment, or email-security findings are inferred "
                        "from the capture.",
                        self.styles["TableBody"],
                    ),
                ]
            ]

            conclusion_table = Table(
                conclusion_data,
                colWidths=[180, 360],
            )
            conclusion_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f3ff")),
                        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#ddd6fe")),
                        ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor("#6d28d9")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("PADDING", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            story.append(conclusion_table)
            story.append(Spacer(1, 12))

        # 10. Disclaimer footer
        story.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=colors.HexColor("#94a3b8"),
                spaceAfter=6,
            )
        )

        disclaimer = self._text(
            getattr(self.report, "methodology_disclaimer", None),
            fallback=(
                "Cryptographic security measurements are derived from "
                "observed captured evidence. Unavailable or non-applicable "
                "measurements are not inferred."
            ),
        )

        # Step numbers are implementation details and should not appear in
        # the human-facing PDF. Keep the underlying JSON/report unchanged.
        disclaimer = re.sub(r"\\bStep\\s+\\d+\\b\\s*", "", disclaimer)

        story.append(
            Paragraph(
                disclaimer,
                self.styles["DisclaimerStyle"],
            )
        )

        doc.build(story)
        self.buffer.seek(0)
        return self.buffer.getvalue()
