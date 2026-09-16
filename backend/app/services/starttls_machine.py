"""
MailRakhwala STARTTLS State Machine (Step 10)
Deterministic, chronological protocol state engine for SMTP, IMAP, and POP3 explicit TLS transitions.
Supports wire frame ordering across fragments and dialogue-turn awareness within contiguous streams.
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import List, Optional, Tuple

from app.schemas.protocol import (
    ConfidenceLevel,
    EmailProtocol,
    EvidenceRecord,
    ProtocolClassification,
    SignalType,
)
from app.schemas.starttls import (
    StarttlsAssessment,
    StarttlsState,
    StarttlsTransition,
)
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    StreamFragment,
)

# Regex Patterns for Line-Delimited Commands & Responses
RE_SMTP_GREETING = re.compile(rb"^220[\s-][^\r\n]*", re.IGNORECASE)
RE_SMTP_EHLO = re.compile(rb"^(?:EHLO|HELO)\b", re.IGNORECASE)
RE_SMTP_CAPA_STARTTLS = re.compile(rb"^250[\s-][^\r\n]*\bSTARTTLS\b", re.IGNORECASE)
RE_SMTP_STARTTLS_CMD = re.compile(rb"^STARTTLS\s*$", re.IGNORECASE)
RE_SMTP_STARTTLS_220_READY = re.compile(rb"^220[\s-][^\r\n]*(?:ready|start|tls|2\.0\.0|[^\r\n]*)", re.IGNORECASE)
RE_SMTP_REJECT = re.compile(rb"^(?:454|501|502|503|554)[\s-][^\r\n]*", re.IGNORECASE)

RE_IMAP_GREETING = re.compile(rb"^\*\s+(?:OK|PREAUTH)[\s-][^\r\n]*", re.IGNORECASE)
RE_IMAP_CAPA_STARTTLS = re.compile(rb"^\*\s+CAPABILITY[^\r\n]*\bSTARTTLS\b", re.IGNORECASE)
RE_IMAP_STARTTLS_CMD = re.compile(rb"^([A-Z0-9_-]+)\s+STARTTLS\s*$", re.IGNORECASE)
RE_IMAP_OK = re.compile(rb"^([A-Z0-9_-]+)\s+OK\b[^\r\n]*", re.IGNORECASE)
RE_IMAP_REJECT = re.compile(rb"^([A-Z0-9_-]+)\s+(?:NO|BAD)\b[^\r\n]*", re.IGNORECASE)

RE_POP3_GREETING = re.compile(rb"^\+OK[\s-][^\r\n]*", re.IGNORECASE)
RE_POP3_STLS_CMD = re.compile(rb"^STLS\s*$", re.IGNORECASE)
RE_POP3_OK = re.compile(rb"^\+OK\b[^\r\n]*", re.IGNORECASE)
RE_POP3_REJECT = re.compile(rb"^-(?:ERR)\b[^\r\n]*", re.IGNORECASE)


class EventDirection(str, Enum):
    CLIENT = "CLIENT"
    SERVER = "SERVER"


@dataclass
class ProtocolEvent:
    """Represents a discrete directional protocol event in chronological wire order."""
    direction: EventDirection
    frame_number: Optional[int]
    timestamp: Optional[float]
    seq_number: int
    raw_data: bytes
    is_tls_record: bool = False
    is_post_gap: bool = False
    turn_rank: int = 0

    @property
    def text(self) -> str:
        return self.raw_data.decode("ascii", errors="replace").strip()


def detect_tls_record_prefix(data: bytes) -> bool:
    """Conservative TLS record header check."""
    if len(data) < 5:
        return False
    content_type = data[0]
    version_major = data[1]
    version_minor = data[2]
    length = int.from_bytes(data[3:5], byteorder="big")

    return (
        content_type in (0x14, 0x15, 0x16, 0x17)
        and version_major == 0x03
        and version_minor in (0x00, 0x01, 0x02, 0x03)
        and length > 0
    )


class StarttlsStateMachine:
    """State machine evaluating explicit STARTTLS negotiation across SMTP, IMAP, and POP3."""

    def evaluate_stream(
        self,
        stream: ReconstructedStream,
        classification: ProtocolClassification,
    ) -> StarttlsAssessment:
        protocol = classification.protocol

        if classification.is_tls_port_context:
            return StarttlsAssessment(
                stream_id=stream.stream_id,
                protocol=protocol,
                starttls_state=StarttlsState.NOT_APPLICABLE,
                confidence=ConfidenceLevel.HIGH,
                reconstruction_status=stream.reconstruction_status,
                unresolved_gaps=stream.has_unresolved_gaps,
                tls_transition_detected=False,
                explanation=f"Implicit TLS port ({stream.server_port}) in use; explicit STARTTLS exchange is not applicable.",
            )

        if protocol == EmailProtocol.UNKNOWN:
            return StarttlsAssessment(
                stream_id=stream.stream_id,
                protocol=EmailProtocol.UNKNOWN,
                starttls_state=StarttlsState.UNKNOWN,
                confidence=ConfidenceLevel.UNKNOWN,
                reconstruction_status=stream.reconstruction_status,
                unresolved_gaps=stream.has_unresolved_gaps,
                tls_transition_detected=False,
                explanation="Stream protocol is UNKNOWN; STARTTLS cannot be evaluated.",
            )

        events = self._extract_chronological_events(stream, protocol)

        if protocol == EmailProtocol.SMTP:
            return self._evaluate_smtp_events(stream, events)
        elif protocol == EmailProtocol.IMAP:
            return self._evaluate_imap_events(stream, events)
        elif protocol == EmailProtocol.POP3:
            return self._evaluate_pop3_events(stream, events)

        return StarttlsAssessment(
            stream_id=stream.stream_id,
            protocol=protocol,
            starttls_state=StarttlsState.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            reconstruction_status=stream.reconstruction_status,
            unresolved_gaps=stream.has_unresolved_gaps,
            tls_transition_detected=False,
            explanation="Unsupported protocol configuration.",
        )

    def _extract_chronological_events(self, stream: ReconstructedStream, protocol: EmailProtocol) -> List[ProtocolEvent]:
        raw_events: List[ProtocolEvent] = []

        def parse_fragments(fragments: List[StreamFragment], initial_payload: bytes, direction: EventDirection):
            blocks: List[Tuple[int, bytes, Optional[int], Optional[float], bool]] = []
            if initial_payload:
                frame_num = fragments[0].first_frame_number if fragments else None
                ts = fragments[0].first_timestamp if fragments else stream.first_timestamp
                start_seq = fragments[0].start_seq if fragments and fragments[0].is_initial_contiguous else 0
                blocks.append((start_seq, initial_payload, frame_num, ts, False))

            for frag in fragments:
                if not frag.is_initial_contiguous and frag.data:
                    blocks.append((frag.start_seq, frag.data, frag.first_frame_number, frag.first_timestamp, True))

            for seq, data, frame_num, ts, is_post_gap in blocks:
                offset = 0
                while offset < len(data):
                    chunk = data[offset:]
                    if detect_tls_record_prefix(chunk):
                        raw_events.append(ProtocolEvent(
                            direction=direction,
                            frame_number=frame_num,
                            timestamp=ts,
                            seq_number=seq + offset,
                            raw_data=chunk[:5],
                            is_tls_record=True,
                            is_post_gap=is_post_gap,
                        ))
                        break

                    nl = chunk.find(b"\n")
                    if nl != -1:
                        line = chunk[:nl + 1]
                        raw_events.append(ProtocolEvent(
                            direction=direction,
                            frame_number=frame_num,
                            timestamp=ts,
                            seq_number=seq + offset,
                            raw_data=line.strip(b"\r\n"),
                            is_tls_record=False,
                            is_post_gap=is_post_gap,
                        ))
                        offset += nl + 1
                    else:
                        raw_events.append(ProtocolEvent(
                            direction=direction,
                            frame_number=frame_num,
                            timestamp=ts,
                            seq_number=seq + offset,
                            raw_data=chunk.strip(b"\r\n"),
                            is_tls_record=False,
                            is_post_gap=is_post_gap,
                        ))
                        break

        parse_fragments(stream.client_fragments, stream.client_payload, EventDirection.CLIENT)
        parse_fragments(stream.server_fragments, stream.server_payload, EventDirection.SERVER)

        seen_server_greeting = False
        for ev in raw_events:
            line = ev.raw_data
            if ev.is_tls_record:
                ev.turn_rank = 60
            elif ev.direction == EventDirection.SERVER:
                if not seen_server_greeting and (
                    RE_SMTP_GREETING.match(line)
                    or RE_IMAP_GREETING.match(line)
                    or RE_POP3_GREETING.match(line)
                ):
                    ev.turn_rank = 10
                    seen_server_greeting = True
                elif RE_SMTP_CAPA_STARTTLS.match(line) or RE_IMAP_CAPA_STARTTLS.match(line):
                    ev.turn_rank = 30
                elif (
                    RE_SMTP_STARTTLS_220_READY.match(line)
                    or RE_SMTP_REJECT.match(line)
                    or RE_IMAP_OK.match(line)
                    or RE_IMAP_REJECT.match(line)
                    or RE_POP3_OK.match(line)
                    or RE_POP3_REJECT.match(line)
                    or RE_SMTP_GREETING.match(line)
                ):
                    ev.turn_rank = 50
                else:
                    ev.turn_rank = 35
            else:
                if RE_SMTP_EHLO.match(line):
                    ev.turn_rank = 20
                elif RE_SMTP_STARTTLS_CMD.match(line) or RE_IMAP_STARTTLS_CMD.match(line) or RE_POP3_STLS_CMD.match(line):
                    ev.turn_rank = 40
                else:
                    ev.turn_rank = 25

        has_distinct_frames = len({ev.frame_number for ev in raw_events if ev.frame_number is not None}) > 1

        if has_distinct_frames:
            raw_events.sort(key=lambda ev: (
                ev.frame_number if ev.frame_number is not None else float("inf"),
                ev.timestamp if ev.timestamp is not None else float("inf"),
                ev.turn_rank,
                0 if ev.direction == EventDirection.SERVER else 1,
                ev.seq_number
            ))
        else:
            raw_events.sort(key=lambda ev: (
                ev.turn_rank,
                ev.seq_number
            ))

        return raw_events

    def _evaluate_smtp_events(self, stream: ReconstructedStream, events: List[ProtocolEvent]) -> StarttlsAssessment:
        transitions: List[StarttlsTransition] = []
        evidence: List[EvidenceRecord] = []
        state = StarttlsState.CONNECTED

        capa_advertised = False
        starttls_requested = False
        server_accepted = False
        server_rejected = False
        tls_detected = False

        for ev in events:
            if tls_detected:
                break

            if ev.is_tls_record:
                if state == StarttlsState.SERVER_ACCEPTED:
                    tls_detected = True
                    transitions.append(StarttlsTransition(
                        from_state=state,
                        to_state=StarttlsState.TLS_TRANSITION_DETECTED,
                        trigger="TLS Record Header (0x16)",
                        is_client=(ev.direction == EventDirection.CLIENT),
                    ))
                    state = StarttlsState.SUCCEEDED
                    evidence.append(EvidenceRecord(
                        signal_type=SignalType.CLIENT_COMMAND if ev.direction == EventDirection.CLIENT else SignalType.SERVER_RESPONSE,
                        description="TLS record header observed immediately following server STARTTLS acceptance.",
                        matched_value="TLS_RECORD_0x16",
                    ))
                continue

            line = ev.raw_data
            if not line:
                continue

            if ev.direction == EventDirection.SERVER:
                if state in (StarttlsState.CONNECTED, StarttlsState.UNKNOWN):
                    if RE_SMTP_GREETING.match(line):
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.GREETING_SEEN,
                            trigger="SMTP 220 banner",
                            is_server=True,
                            observed_text=ev.text,
                        ))
                        state = StarttlsState.GREETING_SEEN
                        evidence.append(EvidenceRecord(
                            signal_type=SignalType.SERVER_BANNER,
                            description="SMTP server 220 initial greeting banner observed.",
                            matched_value=ev.text,
                            is_server=True,
                        ))
                        continue

                if state in (StarttlsState.GREETING_SEEN, StarttlsState.CONNECTED):
                    if RE_SMTP_CAPA_STARTTLS.match(line):
                        capa_advertised = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.CAPABILITY_ADVERTISED,
                            trigger="250 STARTTLS",
                            is_server=True,
                            observed_text=ev.text,
                        ))
                        state = StarttlsState.CAPABILITY_ADVERTISED
                        evidence.append(EvidenceRecord(
                            signal_type=SignalType.SERVER_RESPONSE,
                            description="SMTP server advertised STARTTLS capability in 250 response.",
                            matched_value=ev.text,
                            is_server=True,
                        ))
                        continue

                if state == StarttlsState.STARTTLS_REQUESTED:
                    if RE_SMTP_REJECT.match(line):
                        server_rejected = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_REJECTED,
                            trigger="SMTP 4xx/5xx rejection",
                            is_server=True,
                            observed_text=ev.text,
                        ))
                        state = StarttlsState.SERVER_REJECTED
                        evidence.append(EvidenceRecord(
                            signal_type=SignalType.SERVER_RESPONSE,
                            description="Server rejected client STARTTLS request.",
                            matched_value=ev.text,
                            is_server=True,
                        ))
                        continue

                    if RE_SMTP_STARTTLS_220_READY.match(line):
                        server_accepted = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_ACCEPTED,
                            trigger="220 Ready to start TLS",
                            is_server=True,
                            observed_text=ev.text,
                        ))
                        state = StarttlsState.SERVER_ACCEPTED
                        evidence.append(EvidenceRecord(
                            signal_type=SignalType.SERVER_RESPONSE,
                            description="Server accepted STARTTLS with 220 Ready response.",
                            matched_value=ev.text,
                            is_server=True,
                        ))
                        continue

            elif ev.direction == EventDirection.CLIENT:
                if RE_SMTP_STARTTLS_CMD.match(line):
                    if state in (
                        StarttlsState.CAPABILITY_ADVERTISED,
                        StarttlsState.GREETING_SEEN,
                        StarttlsState.CONNECTED,
                    ):
                        starttls_requested = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.STARTTLS_REQUESTED,
                            trigger="STARTTLS",
                            is_client=True,
                            observed_text="STARTTLS",
                        ))
                        state = StarttlsState.STARTTLS_REQUESTED
                        evidence.append(EvidenceRecord(
                            signal_type=SignalType.CLIENT_COMMAND,
                            description="Client issued explicit STARTTLS command.",
                            matched_value="STARTTLS",
                            is_client=True,
                        ))
                        continue

        unadvertised = (state == StarttlsState.SUCCEEDED and not capa_advertised)

        return self._finalize_assessment(
            stream=stream,
            protocol=EmailProtocol.SMTP,
            state=state,
            transitions=transitions,
            evidence=evidence,
            capa_advertised=capa_advertised,
            requested=starttls_requested,
            accepted=server_accepted,
            rejected=server_rejected,
            tls_detected=tls_detected,
            unadvertised_success=unadvertised,
        )

    def _evaluate_imap_events(self, stream: ReconstructedStream, events: List[ProtocolEvent]) -> StarttlsAssessment:
        transitions: List[StarttlsTransition] = []
        evidence: List[EvidenceRecord] = []
        state = StarttlsState.CONNECTED

        capa_advertised = False
        starttls_requested = False
        server_accepted = False
        server_rejected = False
        tls_detected = False
        active_tag: Optional[str] = None

        for ev in events:
            if tls_detected:
                break

            if ev.is_tls_record:
                if state == StarttlsState.SERVER_ACCEPTED:
                    tls_detected = True
                    transitions.append(StarttlsTransition(
                        from_state=state,
                        to_state=StarttlsState.TLS_TRANSITION_DETECTED,
                        trigger="TLS Record Header",
                        is_client=(ev.direction == EventDirection.CLIENT),
                    ))
                    state = StarttlsState.SUCCEEDED
                continue

            line = ev.raw_data
            if not line:
                continue

            if ev.direction == EventDirection.SERVER:
                if state in (StarttlsState.CONNECTED, StarttlsState.UNKNOWN):
                    if RE_IMAP_GREETING.match(line):
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.GREETING_SEEN,
                            trigger="* OK",
                            is_server=True,
                            observed_text=ev.text,
                        ))
                        state = StarttlsState.GREETING_SEEN
                        continue

                if state in (StarttlsState.GREETING_SEEN, StarttlsState.CONNECTED):
                    if RE_IMAP_CAPA_STARTTLS.match(line):
                        capa_advertised = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.CAPABILITY_ADVERTISED,
                            trigger="IMAP CAPABILITY STARTTLS",
                            is_server=True,
                        ))
                        state = StarttlsState.CAPABILITY_ADVERTISED
                        continue

                if state == StarttlsState.STARTTLS_REQUESTED and active_tag:
                    m_rej = RE_IMAP_REJECT.match(line)
                    if m_rej and m_rej.group(1).decode("ascii", errors="replace") == active_tag:
                        server_rejected = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_REJECTED,
                            trigger=ev.text,
                            is_server=True,
                        ))
                        state = StarttlsState.SERVER_REJECTED
                        continue

                    m_ok = RE_IMAP_OK.match(line)
                    if m_ok and m_ok.group(1).decode("ascii", errors="replace") == active_tag:
                        server_accepted = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_ACCEPTED,
                            trigger=ev.text,
                            is_server=True,
                        ))
                        state = StarttlsState.SERVER_ACCEPTED
                        continue

            elif ev.direction == EventDirection.CLIENT:
                m_cmd = RE_IMAP_STARTTLS_CMD.match(line)
                if m_cmd and state in (
                    StarttlsState.CAPABILITY_ADVERTISED,
                    StarttlsState.GREETING_SEEN,
                    StarttlsState.CONNECTED,
                ):
                    starttls_requested = True
                    active_tag = m_cmd.group(1).decode("ascii", errors="replace")
                    transitions.append(StarttlsTransition(
                        from_state=state,
                        to_state=StarttlsState.STARTTLS_REQUESTED,
                        trigger=ev.text,
                        is_client=True,
                    ))
                    state = StarttlsState.STARTTLS_REQUESTED
                    continue

        return self._finalize_assessment(
            stream=stream,
            protocol=EmailProtocol.IMAP,
            state=state,
            transitions=transitions,
            evidence=evidence,
            capa_advertised=capa_advertised,
            requested=starttls_requested,
            accepted=server_accepted,
            rejected=server_rejected,
            tls_detected=tls_detected,
        )

    def _evaluate_pop3_events(self, stream: ReconstructedStream, events: List[ProtocolEvent]) -> StarttlsAssessment:
        transitions: List[StarttlsTransition] = []
        evidence: List[EvidenceRecord] = []
        state = StarttlsState.CONNECTED

        stls_requested = False
        server_accepted = False
        server_rejected = False
        tls_detected = False

        for ev in events:
            if tls_detected:
                break

            if ev.is_tls_record:
                if state == StarttlsState.SERVER_ACCEPTED:
                    tls_detected = True
                    transitions.append(StarttlsTransition(
                        from_state=state,
                        to_state=StarttlsState.TLS_TRANSITION_DETECTED,
                        trigger="TLS Record Header",
                        is_client=(ev.direction == EventDirection.CLIENT),
                    ))
                    state = StarttlsState.SUCCEEDED
                continue

            line = ev.raw_data
            if not line:
                continue

            if ev.direction == EventDirection.SERVER:
                if state in (StarttlsState.CONNECTED, StarttlsState.UNKNOWN):
                    if RE_POP3_GREETING.match(line):
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.GREETING_SEEN,
                            trigger="+OK banner",
                            is_server=True,
                        ))
                        state = StarttlsState.GREETING_SEEN
                        continue

                if state == StarttlsState.STARTTLS_REQUESTED:
                    if RE_POP3_REJECT.match(line):
                        server_rejected = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_REJECTED,
                            trigger="-ERR",
                            is_server=True,
                        ))
                        state = StarttlsState.SERVER_REJECTED
                        continue

                    if RE_POP3_OK.match(line):
                        server_accepted = True
                        transitions.append(StarttlsTransition(
                            from_state=state,
                            to_state=StarttlsState.SERVER_ACCEPTED,
                            trigger="+OK Begin TLS",
                            is_server=True,
                        ))
                        state = StarttlsState.SERVER_ACCEPTED
                        continue

            elif ev.direction == EventDirection.CLIENT:
                if RE_POP3_STLS_CMD.match(line) and state in (
                    StarttlsState.GREETING_SEEN,
                    StarttlsState.CONNECTED,
                ):
                    stls_requested = True
                    transitions.append(StarttlsTransition(
                        from_state=state,
                        to_state=StarttlsState.STARTTLS_REQUESTED,
                        trigger="STLS",
                        is_client=True,
                    ))
                    state = StarttlsState.STARTTLS_REQUESTED
                    continue

        return self._finalize_assessment(
            stream=stream,
            protocol=EmailProtocol.POP3,
            state=state,
            transitions=transitions,
            evidence=evidence,
            capa_advertised=False,
            requested=stls_requested,
            accepted=server_accepted,
            rejected=server_rejected,
            tls_detected=tls_detected,
        )

    def _finalize_assessment(
        self,
        stream: ReconstructedStream,
        protocol: EmailProtocol,
        state: StarttlsState,
        transitions: List[StarttlsTransition],
        evidence: List[EvidenceRecord],
        capa_advertised: bool,
        requested: bool,
        accepted: bool,
        rejected: bool,
        tls_detected: bool,
        unadvertised_success: bool = False,
    ) -> StarttlsAssessment:
        confidence = ConfidenceLevel.HIGH

        if stream.reconstruction_status == ReconstructionStatus.AMBIGUOUS:
            confidence = ConfidenceLevel.LOW
        elif stream.has_unresolved_gaps:
            confidence = ConfidenceLevel.MEDIUM

        if state == StarttlsState.SUCCEEDED:
            if unadvertised_success:
                explanation = (
                    f"{protocol.value} STARTTLS negotiated successfully into TLS; "
                    "capability advertisement was not observed prior to request."
                )
                evidence.append(EvidenceRecord(
                    signal_type=SignalType.SERVER_RESPONSE,
                    description="STARTTLS succeeded without observed prior capability advertisement.",
                    matched_value="UNADVERTISED_STARTTLS",
                ))
            else:
                explanation = f"{protocol.value} STARTTLS negotiated successfully; TLS record header observed."
        elif rejected:
            state = StarttlsState.FAILED
            explanation = f"{protocol.value} STARTTLS requested by client was explicitly rejected by server."
        elif accepted and not tls_detected:
            state = StarttlsState.SERVER_ACCEPTED
            confidence = ConfidenceLevel.LOW if stream.has_unresolved_gaps else ConfidenceLevel.MEDIUM
            explanation = f"{protocol.value} STARTTLS accepted by server, but subsequent TLS record bytes were not captured."
        elif requested and not accepted:
            state = (
                StarttlsState.FAILED
                if stream.reconstruction_status == ReconstructionStatus.COMPLETE
                else StarttlsState.STARTTLS_REQUESTED
            )
            explanation = f"{protocol.value} STARTTLS requested by client; no acceptance response observed."
        elif capa_advertised and not requested:
            state = StarttlsState.CAPABILITY_ADVERTISED
            explanation = f"{protocol.value} STARTTLS capability advertised by server, but client did not request it."
        elif state in (StarttlsState.CONNECTED, StarttlsState.GREETING_SEEN):
            state = StarttlsState.UNKNOWN if stream.has_unresolved_gaps else StarttlsState.GREETING_SEEN
            explanation = f"{protocol.value} connection observed; no STARTTLS negotiation captured."
            confidence = ConfidenceLevel.LOW
        else:
            explanation = f"STARTTLS state resolved to {state.value}."

        return StarttlsAssessment(
            stream_id=stream.stream_id,
            protocol=protocol,
            starttls_state=state,
            confidence=confidence,
            transitions=transitions,
            evidence=evidence,
            reconstruction_status=stream.reconstruction_status,
            unresolved_gaps=stream.has_unresolved_gaps,
            tls_transition_detected=tls_detected,
            explanation=explanation,
        )


starttls_machine = StarttlsStateMachine()