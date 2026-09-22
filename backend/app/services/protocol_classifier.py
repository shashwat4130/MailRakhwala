"""
MailRakhwala Email Protocol Classifier Service

Deterministic, conservative, multi-signal passive classifier for
reconstructed TCP streams.

Design principles:
- Never classify arbitrary TCP/HTTP traffic as email.
- Standard email ports are useful evidence.
- Application payload evidence must be protocol-specific.
- Generic commands shared across protocols are not sufficient by themselves.
- Ties and weak/ambiguous evidence resolve to UNKNOWN.
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


# ============================================================
# Standard Mail Ports
# ============================================================

PORT_SMTP_CLEARTEXT = {25, 587}
PORT_SMTP_IMPLICIT_TLS = {465}

PORT_IMAP_CLEARTEXT = {143}
PORT_IMAP_IMPLICIT_TLS = {993}

PORT_POP3_CLEARTEXT = {110}
PORT_POP3_IMPLICIT_TLS = {995}


# ============================================================
# Server Banner Patterns
# ============================================================

# SMTP:
# A 220 response alone is not unique to SMTP, so we require
# recognizable mail-server wording where possible.
RE_SMTP_BANNER = re.compile(
    rb"^220[\s-][^\r\n]*(?:SMTP|ESMTP|MAIL|POSTFIX|EXIM|SENDMAIL|MICROSOFT|"
    rb"EXCHANGE|QMAIL|HARAKA|OPENDKIM|OPENSWAP)[^\r\n]*",
    re.IGNORECASE | re.MULTILINE,
)

# POP3:
# +OK is strongly associated with POP3, but we additionally look
# for POP3/mail-specific wording rather than treating arbitrary
# text as POP3.
RE_POP3_BANNER = re.compile(
    rb"^\+OK[\s-][^\r\n]*(?:POP3|MAIL|READY|WELCOME|DOVECOT|"
    rb"POSTOFFICE|GREETINGS|SERVICE|SERVER)[^\r\n]*",
    re.IGNORECASE | re.MULTILINE,
)

# IMAP:
RE_IMAP_BANNER = re.compile(
    rb"^\*\s+(?:OK|PREAUTH)[\s-][^\r\n]*(?:IMAP|IMAP4|"
    rb"CAPABILITY|READY|MAIL|DOVECOT|EXCHANGE)[^\r\n]*",
    re.IGNORECASE | re.MULTILINE,
)


# ============================================================
# Strong SMTP Client Commands
# ============================================================

RE_SMTP_CLIENT_CMDS = re.compile(
    rb"^(?:"
    rb"EHLO\b|"
    rb"HELO\b|"
    rb"MAIL\s+FROM\s*:|"
    rb"RCPT\s+TO\s*:|"
    rb"STARTTLS\b|"
    rb"AUTH\s+(?:PLAIN|LOGIN|CRAM-MD5|DIGEST-MD5|NTLM|XOAUTH2|OAUTHBEARER)\b|"
    rb"VRFY\b|"
    rb"EXPN\b|"
    rb"BDAT\b"
    rb")",
    re.IGNORECASE | re.MULTILINE,
)


# ============================================================
# Strong POP3 Client Commands
# ============================================================

RE_POP3_STRONG_CMDS = re.compile(
    rb"^(?:"
    rb"USER\s+\S+|"
    rb"PASS\s+\S+|"
    rb"STAT\b|"
    rb"LIST(?:\s+\d+)?\b|"
    rb"RETR\s+\d+\b|"
    rb"DELE\s+\d+\b|"
    rb"UIDL(?:\s+\d+)?\b|"
    rb"TOP\s+\d+\s+\d+\b|"
    rb"STLS\b|"
    rb"APOP\s+\S+\s+\S+|"
    rb"CAPA\b"
    rb")",
    re.IGNORECASE | re.MULTILINE,
)


# ============================================================
# IMAP Client Commands
# ============================================================

RE_IMAP_CLIENT_CMDS = re.compile(
    rb"^[A-Z0-9_-]+\s+(?:"
    rb"LOGIN\b|"
    rb"AUTHENTICATE\b|"
    rb"CAPABILITY\b|"
    rb"STARTTLS\b|"
    rb"SELECT\b|"
    rb"EXAMINE\b|"
    rb"CREATE\b|"
    rb"DELETE\b|"
    rb"RENAME\b|"
    rb"SUBSCRIBE\b|"
    rb"UNSUBSCRIBE\b|"
    rb"LIST\b|"
    rb"LSUB\b|"
    rb"STATUS\b|"
    rb"APPEND\b|"
    rb"CHECK\b|"
    rb"CLOSE\b|"
    rb"EXPUNGE\b|"
    rb"SEARCH\b|"
    rb"FETCH\b|"
    rb"STORE\b|"
    rb"COPY\b|"
    rb"UID\b|"
    rb"NOOP\b|"
    rb"LOGOUT\b"
    rb")",
    re.IGNORECASE | re.MULTILINE,
)


# ============================================================
# Helpers
# ============================================================

class EmailProtocolClassifier:
    """Conservative passive classifier for SMTP, IMAP and POP3."""

    @staticmethod
    def _evaluate_port(
        port: int,
    ) -> Tuple[Optional[EmailProtocol], bool]:
        """
        Return the protocol associated with a standard mail port.

        Returns:
            (protocol, is_implicit_tls)
        """

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

    @staticmethod
    def _extract_data_blocks(
        contiguous_bytes: bytes,
        fragments: List[StreamFragment],
    ) -> List[bytes]:
        """
        Extract contiguous payload blocks without stitching across
        unresolved TCP sequence gaps.
        """

        blocks: List[bytes] = []

        if contiguous_bytes:
            blocks.append(contiguous_bytes)

        for fragment in fragments:
            if not fragment.is_initial_contiguous and fragment.data:
                blocks.append(fragment.data)

        return blocks

    @staticmethod
    def _decode_match(match: re.Match) -> str:
        return match.group(0).decode(
            "ascii",
            errors="replace",
        )

    def classify_stream(
        self,
        stream: ReconstructedStream,
    ) -> ProtocolClassification:

        evidence: List[EvidenceRecord] = []
        indicators: List[str] = []

        smtp_score = 0
        imap_score = 0
        pop3_score = 0

        is_tls_context = False

        # ----------------------------------------------------
        # 1. PORT EVIDENCE
        # ----------------------------------------------------

        target_ports = [
            stream.server_port,
            stream.client_port,
        ]

        port_protocol: Optional[EmailProtocol] = None

        for port in target_ports:

            protocol, is_tls = self._evaluate_port(port)

            if protocol is None:
                continue

            port_protocol = protocol
            is_tls_context = is_tls

            evidence.append(
                EvidenceRecord(
                    signal_type=(
                        SignalType.IMPLICIT_TLS_PORT
                        if is_tls
                        else SignalType.PORT
                    ),
                    description=(
                        f"Port {port} corresponds to "
                        f"{'implicit TLS ' if is_tls else ''}"
                        f"{protocol.value}"
                    ),
                    matched_value=str(port),
                )
            )

            indicators.append(
                f"PORT_{protocol.value}_{port}"
            )

            if protocol == EmailProtocol.SMTP:
                smtp_score += 1

            elif protocol == EmailProtocol.IMAP:
                imap_score += 1

            elif protocol == EmailProtocol.POP3:
                pop3_score += 1

            break

        # ----------------------------------------------------
        # 2. SERVER BANNER EVIDENCE
        # ----------------------------------------------------

        server_data_blocks = self._extract_data_blocks(
            stream.server_payload,
            stream.server_fragments,
        )

        for block in server_data_blocks:

            smtp_banner = RE_SMTP_BANNER.search(block)

            if smtp_banner:
                smtp_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.SERVER_BANNER,
                        description=(
                            "SMTP server banner observed "
                            "on server payload"
                        ),
                        matched_value=self._decode_match(
                            smtp_banner
                        ),
                        is_server=True,
                    )
                )

                indicators.append("BANNER_SMTP")

            imap_banner = RE_IMAP_BANNER.search(block)

            if imap_banner:
                imap_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.SERVER_BANNER,
                        description=(
                            "IMAP server greeting observed "
                            "on server payload"
                        ),
                        matched_value=self._decode_match(
                            imap_banner
                        ),
                        is_server=True,
                    )
                )

                indicators.append("BANNER_IMAP")

            pop3_banner = RE_POP3_BANNER.search(block)

            if pop3_banner:
                pop3_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.SERVER_BANNER,
                        description=(
                            "POP3 server banner observed "
                            "on server payload"
                        ),
                        matched_value=self._decode_match(
                            pop3_banner
                        ),
                        is_server=True,
                    )
                )

                indicators.append("BANNER_POP3")

        # ----------------------------------------------------
        # 3. CLIENT COMMAND EVIDENCE
        # ----------------------------------------------------

        client_data_blocks = self._extract_data_blocks(
            stream.client_payload,
            stream.client_fragments,
        )

        for block in client_data_blocks:

            smtp_cmd = RE_SMTP_CLIENT_CMDS.search(block)

            if smtp_cmd:
                smtp_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.CLIENT_COMMAND,
                        description=(
                            "SMTP-specific client command "
                            "observed on client payload"
                        ),
                        matched_value=self._decode_match(
                            smtp_cmd
                        ),
                        is_client=True,
                    )
                )

                indicators.append("CMD_SMTP")

            imap_cmd = RE_IMAP_CLIENT_CMDS.search(block)

            if imap_cmd:
                imap_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.CLIENT_COMMAND,
                        description=(
                            "IMAP tagged client command "
                            "observed on client payload"
                        ),
                        matched_value=self._decode_match(
                            imap_cmd
                        ),
                        is_client=True,
                    )
                )

                indicators.append("CMD_IMAP")

            pop3_cmd = RE_POP3_STRONG_CMDS.search(block)

            if pop3_cmd:
                pop3_score += 4

                evidence.append(
                    EvidenceRecord(
                        signal_type=SignalType.CLIENT_COMMAND,
                        description=(
                            "POP3-specific client command "
                            "observed on client payload"
                        ),
                        matched_value=self._decode_match(
                            pop3_cmd
                        ),
                        is_client=True,
                    )
                )

                indicators.append("CMD_POP3")

        # ----------------------------------------------------
        # 4. RESOLVE PROTOCOL
        # ----------------------------------------------------

        scores = {
            EmailProtocol.SMTP: smtp_score,
            EmailProtocol.IMAP: imap_score,
            EmailProtocol.POP3: pop3_score,
        }

        best_score = max(scores.values())

        # No email evidence whatsoever.
        if best_score == 0:

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

        # Find all protocols tied for the highest score.
        best_protocols = [
            protocol
            for protocol, score in scores.items()
            if score == best_score
        ]

        # Never arbitrarily choose between tied protocols.
        if len(best_protocols) != 1:

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

        best_protocol = best_protocols[0]

        has_port_match = (
            port_protocol == best_protocol
        )

        has_banner_evidence = any(
            indicator.startswith("BANNER_")
            for indicator in indicators
        )

        has_command_evidence = any(
            indicator.startswith("CMD_")
            for indicator in indicators
        )

        has_application_evidence = (
            has_banner_evidence
            or has_command_evidence
        )

        # ----------------------------------------------------
        # 5. FALSE-POSITIVE PROTECTION
        # ----------------------------------------------------

        # Application evidence without protocol context is allowed
        # only when it is a strong, protocol-specific signal.
        #
        # A generic HTTP stream should therefore remain UNKNOWN.

        if not has_application_evidence and not has_port_match:

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

        # ----------------------------------------------------
        # 6. CONFIDENCE
        # ----------------------------------------------------

        if has_application_evidence and has_port_match:
            confidence = ConfidenceLevel.HIGH

        elif has_application_evidence:
            confidence = ConfidenceLevel.MEDIUM

        elif has_port_match:
            # Port-only inference remains LOW confidence.
            confidence = ConfidenceLevel.LOW

        else:
            confidence = ConfidenceLevel.UNKNOWN

        # Ambiguous reconstruction must never become HIGH.
        if (
            stream.reconstruction_status
            == ReconstructionStatus.AMBIGUOUS
        ):
            confidence = ConfidenceLevel.LOW

        elif (
            stream.has_unresolved_gaps
            and confidence == ConfidenceLevel.HIGH
        ):
            confidence = ConfidenceLevel.MEDIUM

        # ----------------------------------------------------
        # 7. RETURN CLASSIFICATION
        # ----------------------------------------------------

        return ProtocolClassification(
            stream_id=stream.stream_id,
            protocol=best_protocol,
            confidence=confidence,
            reconstruction_status=stream.reconstruction_status,
            evidence=evidence,
            matched_indicators=indicators,
            is_tls_port_context=is_tls_context,
            has_unresolved_gaps=stream.has_unresolved_gaps,
        )


protocol_classifier = EmailProtocolClassifier()