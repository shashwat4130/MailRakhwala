"""
MailRakhwala TLS Record Layer Parser Service (Step 12)
Passive, bounded parser extracting 5-byte TLS record headers and payloads from Step 8 streams.
"""

import struct
from typing import List, Optional, Tuple

from app.schemas.tcp_stream import (
    ReconstructedStream,
    ReconstructionStatus,
    SequenceGap,
    StreamFragment,
)
from app.schemas.tls_record import (
    TLSRecord,
    TLSRecordContentType,
    TLSRecordParseResult,
    TLSRecordParseStatus,
    TLSRecordVersion,
)

TLS_RECORD_MAX_PAYLOAD = 16384
TLS_RECORD_HEADER_LEN = 5


class TLSRecordParser:
    """Bounded, memory-safe TLS record layer parser."""

    def parse_stream(
        self, stream: ReconstructedStream
    ) -> Tuple[TLSRecordParseResult, TLSRecordParseResult]:
        """Parses both directions of a reconstructed TCP stream."""
        client_res = self.parse_payload(
            payload=stream.client_payload,
            stream_id=stream.stream_id,
            direction="client->server",
            fragments=stream.client_fragments,
            gaps=stream.client_gaps,
            reconstruction_status=stream.reconstruction_status,
            has_unresolved_gaps=stream.has_unresolved_gaps or bool(stream.client_gaps),
        )

        server_res = self.parse_payload(
            payload=stream.server_payload,
            stream_id=stream.stream_id,
            direction="server->client",
            fragments=stream.server_fragments,
            gaps=stream.server_gaps,
            reconstruction_status=stream.reconstruction_status,
            has_unresolved_gaps=stream.has_unresolved_gaps or bool(stream.server_gaps),
        )

        return client_res, server_res

    def parse_payload(
        self,
        payload: bytes,
        stream_id: str,
        direction: str,
        fragments: Optional[List[StreamFragment]] = None,
        gaps: Optional[List[SequenceGap]] = None,
        reconstruction_status: ReconstructionStatus = ReconstructionStatus.COMPLETE,
        has_unresolved_gaps: bool = False,
    ) -> TLSRecordParseResult:
        result = TLSRecordParseResult(
            stream_id=stream_id,
            direction=direction,
            has_unresolved_gaps=has_unresolved_gaps or bool(gaps),
        )

        if not payload:
            if result.has_unresolved_gaps and fragments:
                result.has_gap_disruption = True
                result.parse_status = TLSRecordParseStatus.GAP_DISRUPTION
                result.error_message = "No initial contiguous bytes; stream interrupted by sequence gap."
            else:
                result.parse_status = TLSRecordParseStatus.CLEAN_EOF
            result.total_records = len(result.records)
            return result

        offset = 0
        payload_len = len(payload)
        record_idx = 0
        stream_has_gap = result.has_unresolved_gaps

        while offset < payload_len:
            remaining_bytes = payload_len - offset

            # Check for incomplete header (< 5 bytes remaining)
            if remaining_bytes < TLS_RECORD_HEADER_LEN:
                frame_num, ts = self._correlate_metadata(offset, fragments)
                status = (
                    TLSRecordParseStatus.GAP_DISRUPTION
                    if stream_has_gap
                    else TLSRecordParseStatus.INCOMPLETE_HEADER
                )

                rec = TLSRecord(
                    record_index=record_idx,
                    content_type=payload[offset],
                    content_type_name="UNKNOWN",
                    legacy_record_version=0,
                    legacy_record_version_name="UNKNOWN",
                    declared_length=0,
                    payload_length=remaining_bytes,
                    stream_offset=offset,
                    payload=payload[offset:],
                    is_complete=False,
                    parse_status=status,
                    first_frame_number=frame_num,
                    first_timestamp=ts,
                    direction=direction,
                )
                result.records.append(rec)
                result.parse_status = status
                result.has_gap_disruption = stream_has_gap
                result.bytes_consumed = payload_len
                result.total_records = len(result.records)
                if stream_has_gap:
                    result.error_message = (
                        "TLS record header interrupted by unresolved TCP sequence gap."
                    )
                return result

            # Parse 5-byte header
            raw_content_type = payload[offset]
            raw_version = struct.unpack(">H", payload[offset + 1 : offset + 3])[0]
            declared_length = struct.unpack(">H", payload[offset + 3 : offset + 5])[0]

            content_type_enum = TLSRecordContentType.from_int(raw_content_type)
            version_enum = TLSRecordVersion.from_int(raw_version)
            frame_num, ts = self._correlate_metadata(offset, fragments)

            # Security Bound: Check oversized declared length
            if declared_length > TLS_RECORD_MAX_PAYLOAD:
                rec = TLSRecord(
                    record_index=record_idx,
                    content_type=raw_content_type,
                    content_type_name=content_type_enum.name,
                    legacy_record_version=raw_version,
                    legacy_record_version_name=version_enum.name,
                    declared_length=declared_length,
                    payload_length=0,
                    stream_offset=offset,
                    payload=b"",
                    is_complete=False,
                    parse_status=TLSRecordParseStatus.OVERSIZED_RECORD,
                    first_frame_number=frame_num,
                    first_timestamp=ts,
                    direction=direction,
                )
                result.records.append(rec)
                result.parse_status = TLSRecordParseStatus.OVERSIZED_RECORD
                result.error_message = f"Declared record length {declared_length} exceeds limit {TLS_RECORD_MAX_PAYLOAD}."
                result.bytes_consumed = offset + TLS_RECORD_HEADER_LEN
                result.total_records = len(result.records)
                return result

            # Incomplete Payload check
            available_payload = remaining_bytes - TLS_RECORD_HEADER_LEN
            if available_payload < declared_length:
                rec_payload = payload[offset + TLS_RECORD_HEADER_LEN :]
                status = (
                    TLSRecordParseStatus.GAP_DISRUPTION
                    if stream_has_gap
                    else TLSRecordParseStatus.INCOMPLETE_PAYLOAD
                )

                rec = TLSRecord(
                    record_index=record_idx,
                    content_type=raw_content_type,
                    content_type_name=content_type_enum.name,
                    legacy_record_version=raw_version,
                    legacy_record_version_name=version_enum.name,
                    declared_length=declared_length,
                    payload_length=len(rec_payload),
                    stream_offset=offset,
                    payload=rec_payload,
                    is_complete=False,
                    parse_status=status,
                    first_frame_number=frame_num,
                    first_timestamp=ts,
                    direction=direction,
                )
                result.records.append(rec)
                result.parse_status = status
                result.has_gap_disruption = stream_has_gap
                result.bytes_consumed = payload_len
                result.total_records = len(result.records)
                if stream_has_gap:
                    result.error_message = (
                        "TLS record payload interrupted by unresolved TCP sequence gap."
                    )
                return result

            # Full valid record
            rec_payload = payload[
                offset + TLS_RECORD_HEADER_LEN : offset + TLS_RECORD_HEADER_LEN + declared_length
            ]
            status = (
                TLSRecordParseStatus.OK
                if content_type_enum != TLSRecordContentType.UNKNOWN
                else TLSRecordParseStatus.UNKNOWN_CONTENT_TYPE
            )

            rec = TLSRecord(
                record_index=record_idx,
                content_type=raw_content_type,
                content_type_name=content_type_enum.name,
                legacy_record_version=raw_version,
                legacy_record_version_name=version_enum.name,
                declared_length=declared_length,
                payload_length=len(rec_payload),
                stream_offset=offset,
                payload=rec_payload,
                is_complete=True,
                parse_status=status,
                first_frame_number=frame_num,
                first_timestamp=ts,
                direction=direction,
            )
            result.records.append(rec)
            record_idx += 1
            offset += TLS_RECORD_HEADER_LEN + declared_length

        result.total_records = len(result.records)
        result.bytes_consumed = offset
        result.has_gap_disruption = False
        result.parse_status = TLSRecordParseStatus.CLEAN_EOF
        return result

    def _correlate_metadata(
        self, stream_offset: int, fragments: Optional[List[StreamFragment]]
    ) -> Tuple[Optional[int], Optional[float]]:
        if not fragments:
            return None, None

        current_offset = 0
        for frag in fragments:
            frag_len = len(frag.data)
            if current_offset <= stream_offset < current_offset + frag_len:
                # Support both naming conventions seamlessly
                frame_num = getattr(frag, "first_frame_number", None)
                if frame_num is None:
                    frame_num = getattr(frag, "frame_number", None)

                ts = getattr(frag, "first_timestamp", None)
                if ts is None:
                    ts = getattr(frag, "timestamp_epoch", None)

                return frame_num, ts
            current_offset += frag_len

        return None, None


tls_record_parser = TLSRecordParser()