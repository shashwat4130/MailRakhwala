"""
MailRakhwala PDF Report Generator.
Step 29 Enterprise Reporting: Generates human-readable audit PDF reports
directly from the authoritative ComprehensiveAnalysisReport model.
"""

from __future__ import annotations

import io
from typing import Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.report_export import ComprehensiveAnalysisReport


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

        # 1. Header Banner
        story.append(Paragraph("MailRakhwala Security Audit Report", self.styles["ReportTitle"]))
        story.append(
            Paragraph("Enterprise Email Cryptographic Security & Inspection Analysis", self.styles["MetaLabel"])
        )
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # 2. Session Info Table
        session_data = [
            [
                Paragraph("Session ID:", self.styles["MetaLabel"]),
                Paragraph(self.report.session.session_id, self.styles["MetaValue"]),
                Paragraph("Target File:", self.styles["MetaLabel"]),
                Paragraph(self.report.session.filename, self.styles["MetaValue"]),
            ],
            [
                Paragraph("Status:", self.styles["MetaLabel"]),
                Paragraph(self.report.session.status, self.styles["MetaValue"]),
                Paragraph("Generated UTC:", self.styles["MetaLabel"]),
                Paragraph(self.report.session.created_at, self.styles["MetaValue"]),
            ],
        ]
        sess_table = Table(session_data, colWidths=[80, 185, 80, 195])
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

        # 3. Security Posture & ML Classification
        story.append(Paragraph("Executive Security Summary", self.styles["SectionHeader"]))

        posture = self.report.posture_report
        score = getattr(posture, "posture_score", getattr(posture, "total_score", 0))
        severity = getattr(posture, "severity", getattr(posture, "posture_severity", "UNKNOWN"))
        sev_str = severity.value if hasattr(severity, "value") else str(severity)
        score_val = f"{score} / 100 ({sev_str})"

        risk_val = "Unavailable"
        model_prob_text = "N/A"
        if self.report.risk_classification:
            rc = self.report.risk_classification
            risk_val = f"{rc.predicted_class} (ID: {rc.class_id})"
            probs_str = ", ".join(f"{k}: {v:.2f}" for k, v in rc.class_probabilities.items())
            model_prob_text = probs_str

        anomaly_val = "Unavailable"
        if self.report.anomaly_detection:
            ad = self.report.anomaly_detection
            anomaly_val = f"{'ANOMALOUS' if ad.is_anomaly else 'NORMAL'} (Score: {ad.anomaly_score:.3f})"

        exec_data = [
            [
                Paragraph("Cryptographic Posture Score (Step 24)", self.styles["MetaLabel"]),
                Paragraph(score_val, self.styles["MetaValue"]),
            ],
            [
                Paragraph("Predicted Risk Class (Step 27 XGBoost)", self.styles["MetaLabel"]),
                Paragraph(risk_val, self.styles["MetaValue"]),
            ],
            [
                Paragraph("XGBoost Model Probabilities", self.styles["MetaLabel"]),
                Paragraph(model_prob_text, self.styles["TableBody"]),
            ],
            [
                Paragraph("Anomaly Status (Step 26 Isolation Forest)", self.styles["MetaLabel"]),
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

        # 4. Top SHAP Contributions (Step 28)
        if self.report.shap_explanation and self.report.shap_explanation.top_contributions:
            story.append(
                Paragraph("Why did the model predict this? (Top 5 Model Attributions)", self.styles["SectionHeader"])
            )
            shap_headers = [
                Paragraph("Feature Name", self.styles["MetaLabel"]),
                Paragraph("Observed Value", self.styles["MetaLabel"]),
                Paragraph("Model Input", self.styles["MetaLabel"]),
                Paragraph("SHAP Magnitude", self.styles["MetaLabel"]),
                Paragraph("Direction", self.styles["MetaLabel"]),
            ]
            shap_rows = [shap_headers]
            for c in self.report.shap_explanation.top_contributions:
                shap_rows.append(
                    [
                        Paragraph(c.feature_name, self.styles["TableBody"]),
                        Paragraph(f"{c.original_value:.2f}", self.styles["TableBody"]),
                        Paragraph(f"{c.model_input_value:.2f}", self.styles["TableBody"]),
                        Paragraph(f"{c.shap_value:+.3f}", self.styles["TableBody"]),
                        Paragraph(c.direction.value, self.styles["TableBody"]),
                    ]
                )
            shap_table = Table(shap_rows, colWidths=[150, 80, 80, 80, 150])
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

        # 5. Deterministic Compliance Findings
        if self.report.compliance_findings:
            story.append(
                Paragraph(
                    f"Deterministic Compliance Findings ({len(self.report.compliance_findings)})",
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
            for f in self.report.compliance_findings[:8]:
                find_rows.append(
                    [
                        Paragraph(f.rule_id, self.styles["TableBody"]),
                        Paragraph(f.severity.value, self.styles["TableBody"]),
                        Paragraph(f.description, self.styles["TableBody"]),
                        Paragraph(f.status.value, self.styles["TableBody"]),
                    ]
                )
            find_table = Table(find_rows, colWidths=[90, 60, 300, 90])
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

        # 6. Practical Remediation Recommendations
        if self.report.recommendations:
            story.append(Paragraph("Deterministic Remediation Actions", self.styles["SectionHeader"]))
            rec_rows = [[Paragraph("Finding Title", self.styles["MetaLabel"]), Paragraph("Remediation Advisory", self.styles["MetaLabel"])]]
            for r in self.report.recommendations[:6]:
                rec_rows.append(
                    [
                        Paragraph(f"[{r.severity}] {r.title}", self.styles["TableBody"]),
                        Paragraph(r.recommendation, self.styles["TableBody"]),
                    ]
                )
            rec_table = Table(rec_rows, colWidths=[160, 380])
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

        # 7. Disclaimer Footer
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        story.append(Paragraph(self.report.methodology_disclaimer, self.styles["DisclaimerStyle"]))

        doc.build(story)
        self.buffer.seek(0)
        return self.buffer.getvalue()