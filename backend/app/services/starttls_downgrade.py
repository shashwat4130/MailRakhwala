"""
MailRakhwala STARTTLS Downgrade & Plaintext Fallback Analysis Service (Step 11)
Deterministic analysis engine evaluating Step 8, 9, and 10 models.
"""

import re
from typing import List

from app.schemas.domain import SeverityLevel
from app.schemas.protocol import ConfidenceLevel, EmailProtocol, ProtocolClassification
from app.schemas.starttls import StarttlsAssessment, StarttlsState
from app.schemas.starttls_downgrade import (
    DowngradeAnalysisResult,
    DowngradeAssessmentStatus,
    DowngradeEvidence,
    DowngradeFinding,
    DowngradeIndicatorType,
)
from app.schemas.tcp_stream import ReconstructedStream, ReconstructionStatus

# Regex patterns for plaintext mail commands following STARTTLS acceptance
RE_PLAINTEXT_POST_TLS_COMMANDS = re.compile(
    rb"^(?:AUTH\b|MAIL\s+FROM:|RCPT\s+TO:|DATA\b|RSET\b|NOOP\b|QUIT\b|"
    rb"[A-Z0-9_-]+\s+(?:LOGIN|AUTHENTICATE|SELECT|EXAMINE|CAPABILITY)\b|"
    rb"USER\b|PASS\b|STAT\b|LIST\b|RETR\b|DELE\b)",
    re.IGNORECASE | re.MULTILINE,
)


class StarttlsDowngradeService:
    """Evaluates passive STARTTLS telemetry for downgrade indicators and plaintext fallback."""

    def evaluate_downgrade(
        self,
        stream: ReconstructedStream,
        classification: ProtocolClassification,
        assessment: StarttlsAssessment,
    ) -> DowngradeAnalysisResult:
        stream_id = stream.stream_id
        protocol = classification.protocol

        # 1. Implicit TLS ports (465, 993, 995) or explicit TLS port context
        if classification.is_tls_port_context or stream.server_port in (465, 993, 995):
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.NOT_APPLICABLE,
                confidence=ConfidenceLevel.HIGH,
                is_downgrade_suspected=False,
                findings=[],
                summary=f"Direct implicit TLS port ({stream.server_port}) in use; STARTTLS downgrade analysis is not applicable."
            )

        # 2. Unsupported / Unknown Protocol
        if protocol == EmailProtocol.UNKNOWN:
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=EmailProtocol.UNKNOWN,
                status=DowngradeAssessmentStatus.NOT_APPLICABLE,
                confidence=ConfidenceLevel.UNKNOWN,
                is_downgrade_suspected=False,
                findings=[],
                summary="Protocol is UNKNOWN; cannot perform STARTTLS downgrade analysis."
            )

        # Build basic forensic evidence container
        evidence = DowngradeEvidence(
            stream_id=stream_id,
            protocol=protocol,
            client_endpoint=f"{stream.client_ip}:{stream.client_port}",
            server_endpoint=f"{stream.server_ip}:{stream.server_port}",
            starttls_state=assessment.starttls_state,
            reconstruction_status=stream.reconstruction_status,
            has_unresolved_gaps=stream.has_unresolved_gaps,
            tls_transition_detected=assessment.tls_transition_detected,
            observed_events=[f"{t.from_state.value} -> {t.to_state.value} ({t.trigger})" for t in assessment.transitions],
            observed_commands=[t.observed_text for t in assessment.transitions if t.observed_text],
        )

        # 3. Handle streams with unresolved sequence gaps or incomplete capture before negotiation
        if stream.has_unresolved_gaps or stream.reconstruction_status in (
            ReconstructionStatus.INCOMPLETE,
            ReconstructionStatus.AMBIGUOUS,
        ):
            if assessment.starttls_state not in (
                StarttlsState.SUCCEEDED,
                StarttlsState.SERVER_REJECTED,
                StarttlsState.CAPABILITY_ADVERTISED,
                StarttlsState.SERVER_ACCEPTED,
            ):
                return DowngradeAnalysisResult(
                    stream_id=stream_id,
                    protocol=protocol,
                    status=DowngradeAssessmentStatus.INCOMPLETE,
                    confidence=ConfidenceLevel.LOW,
                    is_downgrade_suspected=False,
                    findings=[],
                    summary="Stream contains sequence gaps or incomplete capture before STARTTLS exchange finished."
                )

        # 4. Normal Successful STARTTLS -> Benign
        if assessment.starttls_state == StarttlsState.SUCCEEDED and assessment.tls_transition_detected:
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.BENIGN,
                confidence=ConfidenceLevel.HIGH,
                is_downgrade_suspected=False,
                findings=[],
                summary=f"{protocol.value} STARTTLS negotiated normally and transitioned into TLS."
            )

        findings: List[DowngradeFinding] = []

        # 5. Check strongest indicator: STARTTLS Accepted followed by Plaintext Application Commands
        has_post_accept_plaintext = self._has_plaintext_post_acceptance(stream, assessment)
        if has_post_accept_plaintext:
            finding = DowngradeFinding(
                finding_id=f"DWN-{stream_id}-PLAINTEXT-POST-ACCEPT",
                indicator_type=DowngradeIndicatorType.PLAINTEXT_CONTINUATION_POST_ACCEPTANCE,
                title="Plaintext Continuation After Accepted STARTTLS",
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH if not stream.has_unresolved_gaps else ConfidenceLevel.MEDIUM,
                status=DowngradeAssessmentStatus.DOWNGRADE_SUSPECTED,
                description=(
                    f"Server accepted STARTTLS, but client proceeded with cleartext {protocol.value} commands "
                    "instead of initiating the expected TLS handshake."
                ),
                evidence=evidence,
                recommendation="Investigate client/proxy configuration or network path for potential STARTTLS stripping."
            )
            findings.append(finding)
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.DOWNGRADE_SUSPECTED,
                confidence=finding.confidence,
                is_downgrade_suspected=True,
                findings=findings,
                summary=f"Suspicious STARTTLS downgrade indicator: cleartext {protocol.value} traffic observed after STARTTLS was accepted."
            )

        # 6. Accepted STARTTLS but no TLS transition observed (truncation / abrupt close)
        if assessment.starttls_state == StarttlsState.SERVER_ACCEPTED and not assessment.tls_transition_detected:
            finding = DowngradeFinding(
                finding_id=f"DWN-{stream_id}-NO-TRANSITION",
                indicator_type=DowngradeIndicatorType.ACCEPTED_NO_TLS_TRANSITION,
                title="STARTTLS Accepted Without TLS Handshake Transition",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM if not stream.has_unresolved_gaps else ConfidenceLevel.LOW,
                status=DowngradeAssessmentStatus.INCOMPLETE,
                description=(
                    f"{protocol.value} STARTTLS was accepted by the server, but no TLS record was observed before stream termination."
                ),
                evidence=evidence,
                recommendation="Verify whether capture was prematurely truncated or client terminated connection prior to handshake."
            )
            findings.append(finding)
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.INCOMPLETE,
                confidence=finding.confidence,
                is_downgrade_suspected=False,
                findings=findings,
                summary=f"{protocol.value} STARTTLS was accepted by server, but TLS handshake records were not captured."
            )

        # 7. STARTTLS Server Rejection (454, NO, BAD, -ERR)
        if assessment.starttls_state in (StarttlsState.SERVER_REJECTED, StarttlsState.FAILED):
            finding = DowngradeFinding(
                finding_id=f"DWN-{stream_id}-SERVER-REJECTED",
                indicator_type=DowngradeIndicatorType.STARTTLS_SERVER_REJECTED,
                title="STARTTLS Requested but Rejected by Server",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH if not stream.has_unresolved_gaps else ConfidenceLevel.MEDIUM,
                status=DowngradeAssessmentStatus.NEGOTIATION_REJECTED,
                description=(
                    f"Client requested STARTTLS, but server issued an error/rejection response. "
                    "Passive capture cannot determine whether rejection was due to adversary tampering or benign server misconfiguration."
                ),
                evidence=evidence,
                recommendation="Review mail server logs to identify why STARTTLS upgrade was rejected."
            )
            findings.append(finding)
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.NEGOTIATION_REJECTED,
                confidence=finding.confidence,
                is_downgrade_suspected=False,
                findings=findings,
                summary=f"{protocol.value} STARTTLS was requested by client but rejected by server."
            )

        # 8. STARTTLS Capability Advertised but Client Did Not Request It (Plaintext Fallback)
        if assessment.starttls_state == StarttlsState.CAPABILITY_ADVERTISED:
            finding = DowngradeFinding(
                finding_id=f"DWN-{stream_id}-NOT-REQUESTED",
                indicator_type=DowngradeIndicatorType.STARTTLS_ADVERTISED_NOT_REQUESTED,
                title="STARTTLS Advertised but Not Requested by Client",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH if not stream.has_unresolved_gaps else ConfidenceLevel.MEDIUM,
                status=DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED,
                description=(
                    f"{protocol.value} server advertised STARTTLS capability, but client continued communicating in plaintext. "
                    "This observation indicates plaintext fallback or client non-use, not confirmed tampering."
                ),
                evidence=evidence,
                recommendation="Enforce mandatory STARTTLS in mail client configuration."
            )
            findings.append(finding)
            return DowngradeAnalysisResult(
                stream_id=stream_id,
                protocol=protocol,
                status=DowngradeAssessmentStatus.PLAINTEXT_FALLBACK_OBSERVED,
                confidence=finding.confidence,
                is_downgrade_suspected=False,
                findings=findings,
                summary=f"{protocol.value} server offered STARTTLS, but client proceeded in cleartext without requesting it."
            )

        # Default fallback
        return DowngradeAnalysisResult(
            stream_id=stream_id,
            protocol=protocol,
            status=DowngradeAssessmentStatus.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            is_downgrade_suspected=False,
            findings=[],
            summary="Insufficient evidence to assess STARTTLS downgrade behavior."
        )

    def _has_plaintext_post_acceptance(
        self, stream: ReconstructedStream, assessment: StarttlsAssessment
    ) -> bool:
        """Checks whether cleartext commands appeared after server acceptance instead of TLS records."""
        has_acceptance = any(t.to_state == StarttlsState.SERVER_ACCEPTED for t in assessment.transitions)
        if not has_acceptance:
            return False

        if assessment.tls_transition_detected:
            return False

        # Inspect client payload for plaintext commands
        if stream.client_payload:
            return bool(RE_PLAINTEXT_POST_TLS_COMMANDS.search(stream.client_payload))

        for frag in stream.client_fragments:
            if frag.data and RE_PLAINTEXT_POST_TLS_COMMANDS.search(frag.data):
                return True

        return False


starttls_downgrade_service = StarttlsDowngradeService()