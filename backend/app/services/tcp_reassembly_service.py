"""
MailRakhwala TCP Stream Reconstruction Engine (Step 08)
Scalable, bounded bidirectional TCP stream reassembly from streaming packet metadata.
Features 4-tuple primary identification, connection reuse isolation, out-of-order sequencing,
wire frame numbering, and gap-aware fragment tracking.
"""

from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterator, Generator, List, Optional, Tuple

from app.core.config import settings
from app.schemas.packet import DissectedPacket
from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    SequenceGap,
    StreamFragment,
    StreamLifecycle,
    TerminationReason,
)

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20


@dataclass
class TCPSegment:
    """Represents a discrete unreassembled TCP payload segment."""
    seq: int
    payload: bytes
    timestamp: Optional[float] = None
    frame_number: Optional[int] = None

    @property
    def end_seq(self) -> int:
        return self.seq + len(self.payload)


class DirectionalReassembler:
    """Reassembles a single unidirectional TCP byte stream (e.g. client -> server)."""

    def __init__(self, max_bytes: int = 524288, max_buffered_segments: int = 500):
        self.max_bytes = max_bytes
        self.max_buffered_segments = max_buffered_segments

        self.expected_seq: Optional[int] = None
        self.initial_seq: Optional[int] = None
        self.contiguous_buffer: bytearray = bytearray()
        self.buffered_segments: List[TCPSegment] = []

        self.fragments: List[StreamFragment] = []
        self.gaps: List[SequenceGap] = []
        self.retransmissions: int = 0
        self.overlapping_segments: int = 0
        self.has_conflicting_overlaps: bool = False
        self.is_truncated: bool = False
        self.fin_received: bool = False
        self._syn_established: bool = False

        self.initial_frame_number: Optional[int] = None
        self.initial_timestamp: Optional[float] = None

    def process_segment(
        self,
        seq: Optional[int],
        payload: Optional[bytes],
        flags: Optional[int],
        timestamp: Optional[float] = None,
        frame_number: Optional[int] = None,
    ):
        if flags and (flags & TH_FIN):
            self.fin_received = True

        if flags and (flags & TH_SYN):
            if seq is not None:
                self.initial_seq = seq
                self.expected_seq = (seq + 1) % 0x100000000
                self._syn_established = True
                if self.initial_frame_number is None:
                    self.initial_frame_number = frame_number
                    self.initial_timestamp = timestamp

        if not payload or len(payload) == 0 or seq is None:
            return

        seg = TCPSegment(
            seq=seq,
            payload=payload,
            timestamp=timestamp,
            frame_number=frame_number,
        )

        if self.initial_frame_number is None:
            self.initial_frame_number = frame_number
            self.initial_timestamp = timestamp

        # Baseline initialization when no SYN was captured
        if self.expected_seq is None:
            self.initial_seq = seq
            self.expected_seq = seq
            self._append_contiguous(seg.payload)
            self.expected_seq = (self.expected_seq + len(seg.payload)) % 0x100000000
            return

        # Handle segment arriving earlier than initial_seq when SYN was never observed
        if not self._syn_established and seg.end_seq <= self.initial_seq:
            if seg.end_seq == self.initial_seq:
                old_bytes = bytes(self.contiguous_buffer)
                self.contiguous_buffer.clear()
                self._append_contiguous(seg.payload)
                self._append_contiguous(old_bytes)
                self.initial_seq = seg.seq
                return
            elif seg.end_seq < self.initial_seq:
                self._buffer_out_of_order(seg)
                return

        # 1. Retransmission / old duplicate
        if seg.end_seq <= self.expected_seq:
            self.retransmissions += 1
            return

        # 2. Overlap with existing contiguous stream
        if seg.seq < self.expected_seq and seg.end_seq > self.expected_seq:
            self.overlapping_segments += 1
            overlap_len = self.expected_seq - seg.seq
            overlap_existing = (
                self.contiguous_buffer[-overlap_len:]
                if len(self.contiguous_buffer) >= overlap_len
                else None
            )
            overlap_incoming = seg.payload[:overlap_len]

            if overlap_existing is not None and overlap_existing != overlap_incoming:
                self.has_conflicting_overlaps = True

            seg.payload = seg.payload[overlap_len:]
            seg.seq = self.expected_seq

        # 3. In-order segment
        if seg.seq == self.expected_seq:
            self._append_contiguous(seg.payload)
            self.expected_seq = (self.expected_seq + len(seg.payload)) % 0x100000000
            self._drain_buffered_segments()
        elif seg.seq > self.expected_seq:
            # 4. Out-of-order segment
            self._buffer_out_of_order(seg)

    def _append_contiguous(self, data: bytes):
        remaining = self.max_bytes - len(self.contiguous_buffer)
        if remaining <= 0:
            self.is_truncated = True
            return

        if len(data) > remaining:
            self.contiguous_buffer.extend(data[:remaining])
            self.is_truncated = True
        else:
            self.contiguous_buffer.extend(data)

    def _buffer_out_of_order(self, seg: TCPSegment):
        for existing in self.buffered_segments:
            if existing.seq == seg.seq and len(existing.payload) == len(seg.payload):
                self.retransmissions += 1
                return

        if len(self.buffered_segments) >= self.max_buffered_segments:
            self.buffered_segments.pop(0)
            self.is_truncated = True

        self.buffered_segments.append(seg)
        self.buffered_segments.sort(key=lambda s: s.seq)

    def _drain_buffered_segments(self):
        progress = True
        while progress and self.buffered_segments:
            progress = False
            for idx, seg in enumerate(self.buffered_segments):
                if seg.seq <= self.expected_seq:
                    if seg.end_seq > self.expected_seq:
                        trimmed = seg.payload[self.expected_seq - seg.seq:]
                        self._append_contiguous(trimmed)
                        self.expected_seq = (self.expected_seq + len(trimmed)) % 0x100000000
                    self.buffered_segments.pop(idx)
                    progress = True
                    break

    def finalize_gaps(self):
        """Finalizes reassembly without falsifying contiguity across unresolved sequence gaps."""
        if len(self.contiguous_buffer) > 0:
            self.fragments.append(StreamFragment(
                start_seq=self.initial_seq if self.initial_seq is not None else 0,
                data=bytes(self.contiguous_buffer),
                is_initial_contiguous=True,
                first_frame_number=self.initial_frame_number,
                first_timestamp=self.initial_timestamp,
            ))

        if not self.buffered_segments:
            return

        current_exp = self.expected_seq or 0
        for seg in self.buffered_segments:
            if seg.seq > current_exp:
                gap_size = seg.seq - current_exp
                self.gaps.append(SequenceGap(
                    start_seq=current_exp,
                    end_seq=seg.seq,
                    gap_bytes=gap_size
                ))
            self.fragments.append(StreamFragment(
                start_seq=seg.seq,
                data=seg.payload,
                is_initial_contiguous=False,
                first_frame_number=seg.frame_number,
                first_timestamp=seg.timestamp,
            ))
            current_exp = seg.end_seq

        self.buffered_segments.clear()


class ConversationTracker:
    """Tracks state and bidirectional reconstruction for a normalized TCP conversation."""

    def __init__(
        self,
        stream_id: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        tshark_stream_index: Optional[int] = None,
        max_bytes_per_dir: int = 524288,
        max_buffered_segments: int = 500
    ):
        self.stream_id = stream_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.tshark_stream_index = tshark_stream_index

        self.client_flow = DirectionalReassembler(max_bytes=max_bytes_per_dir, max_buffered_segments=max_buffered_segments)
        self.server_flow = DirectionalReassembler(max_bytes=max_bytes_per_dir, max_buffered_segments=max_buffered_segments)

        self.lifecycle: StreamLifecycle = StreamLifecycle.UNKNOWN
        self.termination_reason: Optional[TerminationReason] = None

        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        self.packet_count: int = 0
        self.client_packet_count: int = 0
        self.server_packet_count: int = 0

        self.syn_seen: bool = False
        self.syn_ack_seen: bool = False
        self.fin_seen: bool = False
        self.rst_seen: bool = False

    def is_closed_or_reset(self) -> bool:
        return self.lifecycle in (StreamLifecycle.GRACEFULLY_CLOSED, StreamLifecycle.RESET)

    def is_client_to_server(self, src_ip: str, src_port: int) -> bool:
        return (src_ip, src_port) == (self.client_ip, self.client_port)

    def add_packet(self, pkt: DissectedPacket):
        self.packet_count += 1
        if self.first_timestamp is None:
            self.first_timestamp = pkt.timestamp_epoch
        self.last_timestamp = pkt.timestamp_epoch

        flags = pkt.tcp_flags or 0

        if (flags & TH_SYN) and not (flags & TH_ACK):
            self.syn_seen = True
            self.lifecycle = StreamLifecycle.ESTABLISHING

        if (flags & TH_SYN) and (flags & TH_ACK):
            self.syn_ack_seen = True

        if self.syn_seen and self.syn_ack_seen and (flags & TH_ACK) and not (flags & TH_SYN):
            if self.lifecycle == StreamLifecycle.ESTABLISHING:
                self.lifecycle = StreamLifecycle.ESTABLISHED

        if flags & TH_RST:
            self.rst_seen = True
            self.lifecycle = StreamLifecycle.RESET
            self.termination_reason = TerminationReason.RST

        if flags & TH_FIN:
            self.fin_seen = True
            if self.lifecycle != StreamLifecycle.RESET:
                self.lifecycle = StreamLifecycle.GRACEFULLY_CLOSED
                self.termination_reason = TerminationReason.FIN

        if self.is_client_to_server(pkt.src_ip, pkt.src_port):
            self.client_packet_count += 1
            self.client_flow.process_segment(
                seq=pkt.tcp_seq,
                payload=pkt.payload,
                flags=flags,
                timestamp=pkt.timestamp_epoch,
                frame_number=pkt.frame_number,
            )
        else:
            self.server_packet_count += 1
            self.server_flow.process_segment(
                seq=pkt.tcp_seq,
                payload=pkt.payload,
                flags=flags,
                timestamp=pkt.timestamp_epoch,
                frame_number=pkt.frame_number,
            )

    def finalize(self, reason: Optional[TerminationReason] = None) -> ReconstructedStream:
        if reason in (TerminationReason.CONNECTION_REUSED, TerminationReason.PURGED):
            final_reason = reason
        elif self.termination_reason is not None:
            final_reason = self.termination_reason
        else:
            final_reason = reason or TerminationReason.END_OF_CAPTURE

        self.client_flow.finalize_gaps()
        self.server_flow.finalize_gaps()

        has_gaps = bool(self.client_flow.gaps or self.server_flow.gaps)
        is_truncated = self.client_flow.is_truncated or self.server_flow.is_truncated
        has_conflicts = self.client_flow.has_conflicting_overlaps or self.server_flow.has_conflicting_overlaps
        has_unbuffered = bool(self.client_flow.buffered_segments or self.server_flow.buffered_segments)

        if has_conflicts:
            status = ReconstructionStatus.AMBIGUOUS
        elif is_truncated:
            status = ReconstructionStatus.TRUNCATED
        elif has_gaps or has_unbuffered:
            status = ReconstructionStatus.INCOMPLETE
        elif (
            self.lifecycle in (StreamLifecycle.ESTABLISHED, StreamLifecycle.GRACEFULLY_CLOSED)
            or (self.syn_seen and not has_gaps and not has_unbuffered)
        ):
            status = ReconstructionStatus.COMPLETE
        else:
            status = ReconstructionStatus.PARTIAL

        return ReconstructedStream(
            stream_id=self.stream_id,
            tshark_stream_index=self.tshark_stream_index,
            client_ip=self.client_ip,
            client_port=self.client_port,
            server_ip=self.server_ip,
            server_port=self.server_port,
            lifecycle=self.lifecycle,
            reconstruction_status=status,
            termination_reason=final_reason,
            first_timestamp=self.first_timestamp,
            last_timestamp=self.last_timestamp,
            packet_count=self.packet_count,
            client_packet_count=self.client_packet_count,
            server_packet_count=self.server_packet_count,
            client_bytes_reassembled=len(self.client_flow.contiguous_buffer),
            server_bytes_reassembled=len(self.server_flow.contiguous_buffer),
            client_payload=bytes(self.client_flow.contiguous_buffer),
            server_payload=bytes(self.server_flow.contiguous_buffer),
            client_fragments=self.client_flow.fragments,
            server_fragments=self.server_flow.fragments,
            client_gaps=self.client_flow.gaps,
            server_gaps=self.server_flow.gaps,
            has_unresolved_gaps=has_gaps,
            client_retransmissions=self.client_flow.retransmissions,
            server_retransmissions=self.server_flow.retransmissions,
            client_overlapping_segments=self.client_flow.overlapping_segments,
            server_overlapping_segments=self.server_flow.overlapping_segments,
            has_conflicting_overlaps=has_conflicts,
            is_truncated=is_truncated,
        )


class TCPReassemblyService:
    """Manages stream pools, canonical 4-tuple normalization, connection reuse, and incremental reassembly."""

    def __init__(
        self,
        max_active_streams: Optional[int] = None,
        max_bytes_per_dir: Optional[int] = None,
        max_buffered_segments: Optional[int] = None,
        inactivity_timeout_sec: Optional[float] = None
    ):
        self.max_active_streams = (
            max_active_streams
            or getattr(settings, "TCP_STREAM_MAX_ACTIVE_STREAMS", 1000)
        )
        self.max_bytes_per_dir = (
            max_bytes_per_dir
            or getattr(settings, "TCP_STREAM_MAX_BYTES_PER_DIR", 524288)
        )
        self.max_buffered_segments = (
            max_buffered_segments
            or getattr(settings, "TCP_STREAM_MAX_SEGMENTS_BUFFERED", 500)
        )
        self.inactivity_timeout_sec = (
            inactivity_timeout_sec
            or getattr(settings, "TCP_STREAM_INACTIVITY_TIMEOUT_SEC", 300.0)
        )

        self.active_streams: OrderedDict[str, ConversationTracker] = OrderedDict()
        self._generation_counters: dict[str, int] = {}

    @staticmethod
    def get_canonical_4tuple_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, bool]:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)

        if ep1 <= ep2:
            return f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}", True
        else:
            return f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}", False

    def process_packet(self, pkt: DissectedPacket) -> Optional[ReconstructedStream]:
        if (
            pkt.transport_protocol != "TCP"
            or not pkt.src_ip
            or not pkt.dst_ip
            or pkt.src_port is None
            or pkt.dst_port is None
        ):
            return None

        canonical_key, _ = self.get_canonical_4tuple_key(
            pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
        )

        finalized_stream: Optional[ReconstructedStream] = None
        flags = pkt.tcp_flags or 0

        # Connection reuse detection on identical 4-tuple
        if canonical_key in self.active_streams:
            current_tracker = self.active_streams[canonical_key]
            is_new_syn = bool((flags & TH_SYN) and not (flags & TH_ACK))
            if current_tracker.is_closed_or_reset() or is_new_syn:
                finalized_stream = current_tracker.finalize(reason=TerminationReason.CONNECTION_REUSED)
                del self.active_streams[canonical_key]

        # Evict oldest stream if capacity exceeded
        if canonical_key not in self.active_streams and len(self.active_streams) >= self.max_active_streams:
            _, oldest_tracker = self.active_streams.popitem(last=False)
            finalized_stream = oldest_tracker.finalize(reason=TerminationReason.PURGED)

        if canonical_key not in self.active_streams:
            gen = self._generation_counters.get(canonical_key, 0) + 1
            self._generation_counters[canonical_key] = gen
            stream_id = f"{canonical_key}#gen{gen}"

            tracker = ConversationTracker(
                stream_id=stream_id,
                client_ip=pkt.src_ip,
                client_port=pkt.src_port,
                server_ip=pkt.dst_ip,
                server_port=pkt.dst_port,
                tshark_stream_index=pkt.tcp_stream,
                max_bytes_per_dir=self.max_bytes_per_dir,
                max_buffered_segments=self.max_buffered_segments
            )
            self.active_streams[canonical_key] = tracker
        else:
            self.active_streams.move_to_end(canonical_key)

        tracker = self.active_streams[canonical_key]
        tracker.add_packet(pkt)

        if tracker.tshark_stream_index is None and pkt.tcp_stream is not None:
            tracker.tshark_stream_index = pkt.tcp_stream

        return finalized_stream

    def reassemble_packet_stream(self, packets: Iterator[DissectedPacket]) -> Generator[ReconstructedStream, None, None]:
        for pkt in packets:
            evicted = self.process_packet(pkt)
            if evicted:
                yield evicted

        while self.active_streams:
            _, tracker = self.active_streams.popitem(last=False)
            yield tracker.finalize(reason=TerminationReason.END_OF_CAPTURE)


tcp_reassembly_service = TCPReassemblyService()