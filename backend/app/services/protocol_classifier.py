"""
MailRakhwala Email Protocol Classifier Service (Step 09)
Deterministic, multi-signal passive classifier for reconstructed TCP streams.
"""

import re
from typing import List, Optional, Tuple

from app.schemas.protocol import (
    ConfidenceLevel,
    EmailProtocol,
    EvidenceRecord,
    ProtocolClassification,
    SignalType,
)
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    StreamFragment,
)

# Standard Port Mappings
PORT_SMTP_CLEARTEXT = {25, 587}
PORT_SMTP_IMPLICIT_TLS = {465}
PORT_IMAP_CLEARTEXT = {143}
PORT_IMAP_IMPLICIT_TLS = {993}
PORT_POP3_CLEARTEXT = {110}
PORT_POP3_IMPLICIT_TLS = {995}

# Server Banner Patterns (Anchored to line start)
RE_SMTP_BANNER = re.compile(rb"^(?:220[\s-][^\r\n]*)", re.IGNORECASE | re.MULTILINE)
RE_POP3_BANNER = re.compile(rb"^(?:\+OK[\s-][^\r\n]*)", re.IGNORECASE | re.MULTILINE)
RE_IMAP_BANNER = re.compile(rb"^(?:\*\s+(?:OK|PREAUTH)[\s-][^\r\n]*)", re.IGNORECASE | re.MULTILINE)

# Client Command Patterns (Strict line-start verbs)
RE_SMTP_CLIENT_CMDS = re.compile(
    rb"^(?:EHLO|HELO|MAIL\s+FROM:|RCPT\s+TO:|DATA|RSET|NOOP|QUIT|AUTH\s+[A-Z0-9_-]+)\b",
    re.IGNORECASE | re.MULTILINE,
)
RE_POP3_CLIENT_CMDS = re.compile(
    rb"^(?:USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|UIDL|TOP|CAPA)\b",
    re.IGNORECASE | re.MULTILINE,
)
RE_IMAP_CLIENT_CMDS = re.compile(
    rb"^[A-Z0-9_-]+\s+(?:LOGIN|AUTHENTICATE|CAPABILITY|SELECT|EXAMINE|CREATE|DELETE|RENAME|"
    rb"SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|"
    rb"STORE|COPY|UID|NOOP|LOGOUT)\b",
    re.IGNORECASE | re.MULTILINE,
)


class EmailProtocolClassifier:
    """Classifies reconstructed TCP streams using passive evidence."""

    @staticmethod
    def _evaluate_port(port: int) -> Tuple[Optional[EmailProtocol], bool]:
        """Checks whether an endpoint port matches known mail protocol ports."""
        if port in PORT_SMTP_CLEARTEXT:
            return EmailProtocol.SMTP, False
        if port in PORT_SMTP_IMPLICIT_TLS:
            return EmailProtocol.SMTP, True
        if port in PORT_IMAP_CLEARTEXT:
            return EmailProtocol.IMAP, False
        if port in PORT_IMAP_IMPLICIT_TLS:
            return EmailProtocol.IMAP, True
        if port in PORT_POP3_CLEARTEXT:
            return EmailProtocol.POP3, False
        if port in PORT_POP3_IMPLICIT_TLS:
            return EmailProtocol.POP3, True
        return None, False

    def classify_stream(self, stream: ReconstructedStream) -> ProtocolClassification:
        evidence: List[EvidenceRecord] = []
        indicators: List[str] = []

        smtp_score = 0
        imap_score = 0
        pop3_score = 0

        is_tls_context = False

        # 1. Port Evidence Evaluation (Supporting only)
        target_ports = [stream.server_port, stream.client_port]
        port_protocol: Optional[EmailProtocol] = None

        for p in target_ports:
            proto, is_tls = self._evaluate_port(p)
            if proto:
                port_protocol = proto
                is_tls_context = is_tls
                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.IMPLICIT_TLS_PORT if is_tls else SignalType.PORT,
                        description=f"Port {p} corresponds to {'implicit TLS ' if is_tls else ''}{proto.value}",
                        matched_value=str(p),
                    )
                )
                indicators.append(f"PORT_{proto.value}_{p}")
                if proto == EmailProtocol.SMTP:
                    smtp_score += 1
                elif proto == EmailProtocol.IMAP:
                    imap_score += 1
                elif proto == EmailProtocol.POP3:
                    pop3_score += 1
                break

        # 2. Server Banner Evidence (Strictly from server fragments)
        server_data_blocks = self._extract_data_blocks(stream.server_payload, stream.server_fragments)
        for block in server_data_blocks:
            if RE_SMTP_BANNER.search(block):
                smtp_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.SERVER_BANNER,
                    description="SMTP 220 banner observed on server payload",
                    is_server=True
                ))
                indicators.append("BANNER_SMTP_220")
            if RE_IMAP_BANNER.search(block):
                imap_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.SERVER_BANNER,
                    description="IMAP * OK / * PREAUTH banner observed on server payload",
                    is_server=True
                ))
                indicators.append("BANNER_IMAP_OK")
            if RE_POP3_BANNER.search(block):
                pop3_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.SERVER_BANNER,
                    description="POP3 +OK banner observed on server payload",
                    is_server=True
                ))
                indicators.append("BANNER_POP3_PLUS_OK")

        # 3. Client Command Evidence (Strictly from client fragments)
        client_data_blocks = self._extract_data_blocks(stream.client_payload, stream.client_fragments)
        for block in client_data_blocks:
            smtp_cmd = RE_SMTP_CLIENT_CMDS.search(block)
            if smtp_cmd:
                smtp_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.CLIENT_COMMAND,
                    description="SMTP command verb observed on client payload",
                    matched_value=smtp_cmd.group(0).decode("ascii", errors="replace"),
                    is_client=True
                ))
                indicators.append("CMD_SMTP")

            imap_cmd = RE_IMAP_CLIENT_CMDS.search(block)
            if imap_cmd:
                imap_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.CLIENT_COMMAND,
                    description="IMAP tagged command observed on client payload",
                    matched_value=imap_cmd.group(0).decode("ascii", errors="replace"),
                    is_client=True
                ))
                indicators.append("CMD_IMAP")

            pop3_cmd = RE_POP3_CLIENT_CMDS.search(block)
            if pop3_cmd:
                pop3_score += 4
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.CLIENT_COMMAND,
                    description="POP3 command verb observed on client payload",
                    matched_value=pop3_cmd.group(0).decode("ascii", errors="replace"),
                    is_client=True
                ))
                indicators.append("CMD_POP3")

        # 4. Resolve Winning Protocol
        scores = {
            EmailProtocol.SMTP: smtp_score,
            EmailProtocol.IMAP: imap_score,
            EmailProtocol.POP3: pop3_score,
        }
        best_proto = max(scores, key=scores.get)
        max_score = scores[best_proto]

        if max_score == 0:
            return ProtocolClassification(
                stream_id=stream.stream_id,
                protocol=EmailProtocol.UNKNOWN,
                confidence=ConfidenceLevel.UNKNOWN,
                reconstruction_status=stream.reconstruction_status,
                evidence=evidence,
                matched_indicators=indicators,
                is_tls_port_context=is_tls_context,
                has_unresolved_gaps=stream.has_unresolved_gaps,
            )

        # 5. Determine Confidence Level
        has_app_evidence = max_score >= 4
        has_port_match = (port_protocol == best_proto)

        if has_app_evidence and has_port_match:
            confidence = ConfidenceLevel.HIGH
        elif has_app_evidence:
            confidence = ConfidenceLevel.MEDIUM
        elif has_port_match:
            confidence = ConfidenceLevel.LOW
        else:
            confidence = ConfidenceLevel.LOW

        if stream.reconstruction_status == ReconstructionStatus.AMBIGUOUS:
            confidence = ConfidenceLevel.LOW
        elif stream.has_unresolved_gaps and confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.MEDIUM

        return ProtocolClassification(
            stream_id=stream.stream_id,
            protocol=best_proto,
            confidence=confidence,
            reconstruction_status=stream.reconstruction_status,
            evidence=evidence,
            matched_indicators=indicators,
            is_tls_port_context=is_tls_context,
            has_unresolved_gaps=stream.has_unresolved_gaps,
        )

    @staticmethod
    def _extract_data_blocks(contiguous_bytes: bytes, fragments: List[StreamFragment]) -> List[bytes]:
        """Extracts data blocks without concatenating disjoint bytes across unresolved gaps."""
        blocks = []
        if contiguous_bytes:
            blocks.append(contiguous_bytes)
        for frag in fragments:
            if not frag.is_initial_contiguous and frag.data:
                blocks.append(frag.data)
        return blocks


protocol_classifier = EmailProtocolClassifier()