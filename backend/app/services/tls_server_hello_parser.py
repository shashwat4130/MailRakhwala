"""
MailRakhwala TLS ServerHello Parser Service (Step 14)
Extracts, bounds, and structures ServerHello handshakes across reassembled TLS records.
"""

import struct
from typing import List, Optional, Tuple

from app.schemas.tls_client_hello import TLSExtension
from app.schemas.tls_record import TLSRecordContentType, TLSRecordParseResult
from app.schemas.tls_server_hello import (
    ServerHelloKeyShare,
    ServerHelloParseResult,
    ServerHelloParseStatus,
    TLSServerHello,
)

MAX_HANDSHAKE_SIZE = 65536
MAX_EXTENSIONS_LEN = 16384
MAX_KEY_SHARE_KEY_LEN = 2048

TLS_VERSION_NAMES = {
    0x0300: "SSL_3_0",
    0x0301: "TLS_1_0",
    0x0302: "TLS_1_1",
    0x0303: "TLS_1_2",
    0x0304: "TLS_1_3",
}

CIPHER_SUITE_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
}

EXTENSION_NAMES = {
    43: "supported_versions",
    51: "key_share",
}


class TLSServerHelloParser:
    """Bounded, memory-safe parser for TLS ServerHello handshake messages."""

    def parse_server_hello(self, server_record_result: TLSRecordParseResult) -> ServerHelloParseResult:
        stream_id = server_record_result.stream_id

        # 1. Direction Awareness: ServerHello must come from server->client
        if server_record_result.direction != "server->client":
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.WRONG_DIRECTION,
                malformed_reason="ServerHello must originate from the server->client direction."
            )

        # 2. Check for initial gap disruption before parsing
        if server_record_result.has_gap_disruption and not server_record_result.records:
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.GAP_DISRUPTION,
                has_gap_disruption=True,
                malformed_reason="Stream interrupted by unresolved TCP gap before ServerHello."
            )

        # 3. Reassemble contiguous Handshake record payloads
        handshake_payload = bytearray()
        first_frame = None
        first_ts = None
        encountered_gap = False

        for rec in server_record_result.records:
            if rec.content_type == TLSRecordContentType.HANDSHAKE:
                if first_frame is None:
                    first_frame = rec.first_frame_number
                    first_ts = rec.first_timestamp
                handshake_payload.extend(rec.payload)
                if not rec.is_complete:
                    encountered_gap = True
                    break

        if not handshake_payload:
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.NO_SERVER_HELLO,
                malformed_reason="No Handshake records present in server stream."
            )

        # 4. Search for ServerHello (HandshakeType = 0x02)
        offset = 0
        total_len = len(handshake_payload)

        while offset < total_len:
            if total_len - offset < 4:
                if encountered_gap:
                    return ServerHelloParseResult(
                        stream_id=stream_id,
                        status=ServerHelloParseStatus.GAP_DISRUPTION,
                        has_gap_disruption=True,
                        malformed_reason="Handshake header cut short by TCP sequence gap."
                    )
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.INCOMPLETE_CAPTURE,
                    malformed_reason="Incomplete handshake header (< 4 bytes remaining)."
                )

            msg_type = handshake_payload[offset]
            msg_len = int.from_bytes(handshake_payload[offset + 1: offset + 4], byteorder="big")

            if msg_type != 2:  # 0x02 = ServerHello
                # Skip non-ServerHello handshake messages if within bounds
                if msg_len > MAX_HANDSHAKE_SIZE:
                    return ServerHelloParseResult(
                        stream_id=stream_id,
                        status=ServerHelloParseStatus.OVERSIZED_HANDSHAKE,
                        malformed_reason=f"Declared message length {msg_len} exceeds maximum handshake size."
                    )
                offset += 4 + msg_len
                continue

            # ServerHello found
            if msg_len > MAX_HANDSHAKE_SIZE:
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.OVERSIZED_HANDSHAKE,
                    malformed_reason=f"Declared ServerHello length {msg_len} exceeds limit of {MAX_HANDSHAKE_SIZE} bytes."
                )

            # Minimum ServerHello body: legacy_version (2) + random (32) + session_id_len (1) + cipher_suite (2) + compression (1) = 38 bytes
            if msg_len < 38:
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                    malformed_reason=f"Declared ServerHello length {msg_len} is smaller than minimum body size (38 bytes)."
                )

            available_body = total_len - (offset + 4)
            if available_body < msg_len:
                if encountered_gap:
                    return ServerHelloParseResult(
                        stream_id=stream_id,
                        status=ServerHelloParseStatus.GAP_DISRUPTION,
                        has_gap_disruption=True,
                        malformed_reason="ServerHello body interrupted by TCP sequence gap."
                    )
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.INCOMPLETE_CAPTURE,
                    malformed_reason=f"Incomplete ServerHello: received {available_body} bytes, expected {msg_len}."
                )

            body = bytes(handshake_payload[offset + 4: offset + 4 + msg_len])
            return self._parse_body(
                body=body,
                msg_len=msg_len,
                stream_id=stream_id,
                direction=server_record_result.direction,
                first_frame=first_frame,
                first_ts=first_ts,
                handshake_offset=offset,
            )

        return ServerHelloParseResult(
            stream_id=stream_id,
            status=ServerHelloParseStatus.NO_SERVER_HELLO,
            malformed_reason="No ServerHello (type 2) message found in stream."
        )

    def _parse_body(
        self,
        body: bytes,
        msg_len: int,
        stream_id: str,
        direction: str,
        first_frame: Optional[int],
        first_ts: Optional[float],
        handshake_offset: int,
    ) -> ServerHelloParseResult:
        body_len = len(body)
        idx = 0

        # legacy_version (2 bytes) + random (32 bytes)
        legacy_version = struct.unpack(">H", body[0:2])[0]
        legacy_version_name = TLS_VERSION_NAMES.get(legacy_version, f"UNKNOWN (0x{legacy_version:04X})")
        random_bytes = body[2:34]
        idx = 34

        # legacy_session_id_echo (1 byte len + variable)
        session_id_len = body[idx]
        idx += 1

        if session_id_len > 32 or idx + session_id_len > body_len:
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason=f"Invalid session ID echo length ({session_id_len})."
            )

        session_id_echo = body[idx: idx + session_id_len]
        idx += session_id_len

        # cipher_suite (2 bytes)
        if idx + 2 > body_len:
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="Truncated cipher suite field."
            )

        cs_id = struct.unpack(">H", body[idx: idx + 2])[0]
        cs_name = CIPHER_SUITE_NAMES.get(cs_id, f"UNKNOWN_CIPHER_SUITE_0x{cs_id:04X}")
        idx += 2

        # compression_method (1 byte)
        if idx + 1 > body_len:
            return ServerHelloParseResult(
                stream_id=stream_id,
                status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="Truncated compression method field."
            )

        comp_method = body[idx]
        idx += 1

        # Extensions (optional: 2 bytes len + variable)
        raw_extensions: List[TLSExtension] = []
        supported_version = None
        key_share = None

        if idx < body_len:
            if idx + 2 > body_len:
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                    malformed_reason="Truncated extensions length field."
                )

            ext_total_len = struct.unpack(">H", body[idx: idx + 2])[0]
            idx += 2

            if idx + ext_total_len != body_len or ext_total_len > MAX_EXTENSIONS_LEN:
                return ServerHelloParseResult(
                    stream_id=stream_id,
                    status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                    malformed_reason=f"Declared extensions length ({ext_total_len}) exceeds boundary."
                )

            ext_end = idx + ext_total_len
            while idx < ext_end:
                if idx + 4 > ext_end:
                    return ServerHelloParseResult(
                        stream_id=stream_id,
                        status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                        malformed_reason="Truncated extension header in ServerHello."
                    )

                ext_type = struct.unpack(">H", body[idx: idx + 2])[0]
                ext_len = struct.unpack(">H", body[idx + 2: idx + 4])[0]
                idx += 4

                if idx + ext_len > ext_end:
                    return ServerHelloParseResult(
                        stream_id=stream_id,
                        status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                        malformed_reason=f"Extension {ext_type} length {ext_len} extends beyond boundary."
                    )

                ext_data = body[idx: idx + ext_len]
                idx += ext_len

                ext_name = EXTENSION_NAMES.get(ext_type, f"unknown_extension_{ext_type}")
                raw_extensions.append(
                    TLSExtension(
                        extension_type=ext_type,
                        extension_name=ext_name,
                        length=ext_len,
                        data=ext_data,
                    )
                )

                # Parse supported_versions (Type 43) in ServerHello: 2-byte selected version
                if ext_type == 43:
                    if ext_len != 2:
                        return ServerHelloParseResult(
                            stream_id=stream_id,
                            status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="ServerHello supported_versions extension must be exactly 2 bytes."
                        )
                    supported_version = struct.unpack(">H", ext_data)[0]

                # Parse key_share (Type 51) in ServerHello: NamedGroup (2 bytes) + key_exchange length (2 bytes) + data
                elif ext_type == 51:
                    if ext_len < 4:
                        return ServerHelloParseResult(
                            stream_id=stream_id,
                            status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="ServerHello key_share extension header truncated."
                        )
                    group = struct.unpack(">H", ext_data[0:2])[0]
                    ke_len = struct.unpack(">H", ext_data[2:4])[0]
                    if 4 + ke_len != ext_len or ke_len > MAX_KEY_SHARE_KEY_LEN:
                        return ServerHelloParseResult(
                            stream_id=stream_id,
                            status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="ServerHello key_share length mismatch."
                        )
                    ke_data = ext_data[4: 4 + ke_len]
                    key_share = ServerHelloKeyShare(
                        group=group,
                        key_exchange_length=ke_len,
                        key_exchange_hex=ke_data.hex(),
                    )

        # Determine Negotiated TLS Version
        if supported_version is not None:
            negotiated_version = supported_version
            negotiated_version_name = TLS_VERSION_NAMES.get(
                negotiated_version, f"UNKNOWN (0x{negotiated_version:04X})"
            )
        else:
            negotiated_version = legacy_version
            negotiated_version_name = legacy_version_name

        server_hello = TLSServerHello(
            msg_type=2,
            msg_length=msg_len,
            handshake_offset=handshake_offset,
            legacy_version=legacy_version,
            legacy_version_name=legacy_version_name,
            negotiated_version=negotiated_version,
            negotiated_version_name=negotiated_version_name,
            random_hex=random_bytes.hex(),
            session_id_echo_length=session_id_len,
            session_id_echo_hex=session_id_echo.hex(),
            selected_cipher_suite_id=cs_id,
            selected_cipher_suite_name=cs_name,
            compression_method=comp_method,
            supported_version=supported_version,
            key_share=key_share,
            raw_extensions=raw_extensions,
            stream_id=stream_id,
            direction=direction,
            first_frame_number=first_frame,
            first_timestamp=first_ts,
        )

        return ServerHelloParseResult(
            stream_id=stream_id,
            status=ServerHelloParseStatus.COMPLETE,
            server_hello=server_hello,
            has_gap_disruption=False,
        )


tls_server_hello_parser = TLSServerHelloParser()