"""
MailRakhwala TLS ClientHello Parser Service (Step 13)
Extracts, bounds, and structures ClientHello handshakes across reassembled TLS records.
"""

import struct
from typing import List, Optional, Tuple

from app.schemas.tls_client_hello import (
    ClientHelloParseResult,
    ClientHelloParseStatus,
    KeyShareEntry,
    TLSClientHello,
    TLSExtension,
)
from app.schemas.tls_record import TLSRecord, TLSRecordContentType, TLSRecordParseResult

MAX_HANDSHAKE_SIZE = 65536
MAX_EXTENSIONS_LEN = 16384
MAX_CIPHER_SUITES = 512
MAX_SUPPORTED_GROUPS = 128
MAX_SIGNATURE_ALGORITHMS = 128
MAX_KEY_SHARES = 64

TLS_VERSION_NAMES = {
    0x0300: "SSL_3_0",
    0x0301: "TLS_1_0",
    0x0302: "TLS_1_1",
    0x0303: "TLS_1_2",
    0x0304: "TLS_1_3",
}

EXTENSION_NAMES = {
    0: "server_name",
    10: "supported_groups",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    43: "supported_versions",
    51: "key_share",
}


class TLSClientHelloParser:
    """Bounded, memory-safe parser for TLS ClientHello handshake messages."""

    def parse_client_hello(self, client_record_result: TLSRecordParseResult) -> ClientHelloParseResult:
        stream_id = client_record_result.stream_id

        # 1. Check for initial gap disruption before parsing
        if client_record_result.has_gap_disruption and not client_record_result.records:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.GAP_DISRUPTION,
                has_gap_disruption=True,
                malformed_reason="Stream interrupted by unresolved TCP gap before ClientHello."
            )

        # 2. Reassemble contiguous Handshake record payloads
        handshake_payload = bytearray()
        first_frame = None
        first_ts = None
        encountered_gap = False

        for rec in client_record_result.records:
            if rec.content_type == TLSRecordContentType.HANDSHAKE:
                if first_frame is None:
                    first_frame = rec.first_frame_number
                    first_ts = rec.first_timestamp
                handshake_payload.extend(rec.payload)
                if not rec.is_complete:
                    encountered_gap = True
                    break

        if not handshake_payload:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.NO_CLIENT_HELLO,
                malformed_reason="No Handshake records present in client stream."
            )

        # 3. Handshake Header Check (1 byte msg_type + 3 bytes length = 4 bytes)
        if len(handshake_payload) < 4:
            if encountered_gap:
                return ClientHelloParseResult(
                    stream_id=stream_id,
                    status=ClientHelloParseStatus.GAP_DISRUPTION,
                    has_gap_disruption=True,
                    malformed_reason="Handshake header cut short by TCP sequence gap."
                )
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.INCOMPLETE_CAPTURE,
                malformed_reason="Incomplete handshake message header (< 4 bytes)."
            )

        msg_type = handshake_payload[0]
        msg_len = int.from_bytes(handshake_payload[1:4], byteorder="big")

        if msg_type != 1:  # 0x01 = ClientHello
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.NO_CLIENT_HELLO,
                malformed_reason=f"Expected ClientHello (type 1), found type {msg_type}."
            )

        if msg_len > MAX_HANDSHAKE_SIZE:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.OVERSIZED_HANDSHAKE,
                malformed_reason=f"Declared handshake length {msg_len} exceeds limit of {MAX_HANDSHAKE_SIZE} bytes."
            )
        if msg_len < 34:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason=f"Declared handshake length {msg_len} is smaller than minimum ClientHello size (34 bytes)."
            )

      

        body = bytes(handshake_payload[4:])
        if len(body) < msg_len:
            if encountered_gap:
                return ClientHelloParseResult(
                    stream_id=stream_id,
                    status=ClientHelloParseStatus.GAP_DISRUPTION,
                    has_gap_disruption=True,
                    malformed_reason="ClientHello body interrupted by TCP sequence gap."
                )
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.INCOMPLETE_CAPTURE,
                malformed_reason=f"Incomplete ClientHello: received {len(body)} bytes, expected {msg_len}."
            )

        # Slice exact body up to declared msg_len
        body = body[:msg_len]

        # 4. Parse ClientHello Fields
        offset = 0
        body_len = len(body)

        # legacy_version (2 bytes) + random (32 bytes) = 34 bytes minimum
        if body_len < 34:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="ClientHello body too short to contain version and random."
            )

        legacy_version = struct.unpack(">H", body[0:2])[0]
        legacy_version_name = TLS_VERSION_NAMES.get(legacy_version, f"UNKNOWN (0x{legacy_version:04X})")
        random_bytes = body[2:34]
        offset = 34

        # legacy_session_id (1 byte len + variable data)
        if offset >= body_len:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="Truncated session ID length field."
            )

        session_id_len = body[offset]
        offset += 1

        if session_id_len > 32 or offset + session_id_len > body_len:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason=f"Invalid session ID length ({session_id_len})."
            )

        session_id = body[offset: offset + session_id_len]
        offset += session_id_len

        # cipher_suites (2 bytes len + variable 2-byte IDs)
        if offset + 2 > body_len:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="Truncated cipher suites length field."
            )

        cs_len = struct.unpack(">H", body[offset: offset + 2])[0]
        offset += 2

        if cs_len % 2 != 0 or offset + cs_len > body_len or (cs_len // 2) > MAX_CIPHER_SUITES:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason=f"Malformed cipher suites length ({cs_len})."
            )

        cipher_suite_ids = []
        for i in range(offset, offset + cs_len, 2):
            cs_id = struct.unpack(">H", body[i: i + 2])[0]
            cipher_suite_ids.append(cs_id)
        offset += cs_len

        # compression_methods (1 byte len + variable methods)
        if offset >= body_len:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason="Truncated compression methods length."
            )

        comp_len = body[offset]
        offset += 1

        if comp_len == 0 or offset + comp_len > body_len:
            return ClientHelloParseResult(
                stream_id=stream_id,
                status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                malformed_reason=f"Malformed compression methods length ({comp_len})."
            )

        compression_methods = list(body[offset: offset + comp_len])
        offset += comp_len

        # Extensions (optional: 2 bytes len + variable data)
        raw_extensions: List[TLSExtension] = []
        sni_host = None
        supported_groups: List[int] = []
        sig_algs: List[int] = []
        alpn_protocols: List[str] = []
        supported_versions: List[int] = []
        key_shares: List[KeyShareEntry] = []

        if offset < body_len:
            if offset + 2 > body_len:
                return ClientHelloParseResult(
                    stream_id=stream_id,
                    status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                    malformed_reason="Truncated extensions total length field."
                )

            ext_total_len = struct.unpack(">H", body[offset: offset + 2])[0]
            offset += 2

            if offset + ext_total_len != body_len or ext_total_len > MAX_EXTENSIONS_LEN:
                return ClientHelloParseResult(
                    stream_id=stream_id,
                    status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                    malformed_reason=f"Declared extensions total length ({ext_total_len}) exceeds body boundary."
                )

            ext_end = offset + ext_total_len
            while offset < ext_end:
                if offset + 4 > ext_end:
                    return ClientHelloParseResult(
                        stream_id=stream_id,
                        status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                        malformed_reason="Truncated individual extension header."
                    )

                ext_type = struct.unpack(">H", body[offset: offset + 2])[0]
                ext_len = struct.unpack(">H", body[offset + 2: offset + 4])[0]
                offset += 4

                if offset + ext_len > ext_end:
                    return ClientHelloParseResult(
                        stream_id=stream_id,
                        status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                        malformed_reason=f"Extension {ext_type} declared length {ext_len} extends beyond boundary."
                    )

                ext_data = body[offset: offset + ext_len]
                offset += ext_len

                ext_name = EXTENSION_NAMES.get(ext_type, f"unknown_extension_{ext_type}")
                raw_extensions.append(
                    TLSExtension(
                        extension_type=ext_type,
                        extension_name=ext_name,
                        length=ext_len,
                        data=ext_data,
                    )
                )

                # Parse specific extensions
                if ext_type == 0:  # server_name (SNI)
                    sni_val, ok = self._parse_sni(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed SNI extension payload."
                        )
                    sni_host = sni_val

                elif ext_type == 10:  # supported_groups
                    groups, ok = self._parse_supported_groups(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed supported_groups extension payload."
                        )
                    supported_groups = groups

                elif ext_type == 13:  # signature_algorithms
                    sigs, ok = self._parse_signature_algorithms(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed signature_algorithms extension payload."
                        )
                    sig_algs = sigs

                elif ext_type == 16:  # ALPN
                    alpns, ok = self._parse_alpn(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed ALPN extension payload."
                        )
                    alpn_protocols = alpns

                elif ext_type == 43:  # supported_versions
                    versions, ok = self._parse_supported_versions(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed supported_versions extension payload."
                        )
                    supported_versions = versions

                elif ext_type == 51:  # key_share
                    shares, ok = self._parse_key_shares(ext_data)
                    if not ok:
                        return ClientHelloParseResult(
                            stream_id=stream_id,
                            status=ClientHelloParseStatus.MALFORMED_HANDSHAKE,
                            malformed_reason="Malformed key_share extension payload."
                        )
                    key_shares = shares

        client_hello = TLSClientHello(
            msg_type=msg_type,
            msg_length=msg_len,
            handshake_offset=0,
            legacy_version=legacy_version,
            legacy_version_name=legacy_version_name,
            random_hex=random_bytes.hex(),
            session_id_length=session_id_len,
            session_id_hex=session_id.hex(),
            cipher_suite_ids=cipher_suite_ids,
            compression_methods=compression_methods,
            server_name=sni_host,
            supported_groups=supported_groups,
            signature_algorithms=sig_algs,
            alpn_protocols=alpn_protocols,
            supported_versions=supported_versions,
            key_shares=key_shares,
            raw_extensions=raw_extensions,
            stream_id=stream_id,
            first_frame_number=first_frame,
            first_timestamp=first_ts,
        )

        return ClientHelloParseResult(
            stream_id=stream_id,
            status=ClientHelloParseStatus.COMPLETE,
            client_hello=client_hello,
            has_gap_disruption=False,
        )

    def _parse_sni(self, data: bytes) -> Tuple[Optional[str], bool]:
        if len(data) < 2:
            return None, False
        list_len = struct.unpack(">H", data[0:2])[0]
        if list_len + 2 != len(data):
            return None, False

        offset = 2
        while offset < len(data):
            if offset + 3 > len(data):
                return None, False
            name_type = data[offset]
            name_len = struct.unpack(">H", data[offset + 1: offset + 3])[0]
            offset += 3
            if offset + name_len > len(data):
                return None, False
            if name_type == 0:  # host_name
                try:
                    return data[offset: offset + name_len].decode("utf-8"), True
                except UnicodeDecodeError:
                    return None, False
            offset += name_len

        return None, True

    def _parse_supported_groups(self, data: bytes) -> Tuple[List[int], bool]:
        if len(data) < 2:
            return [], False
        list_len = struct.unpack(">H", data[0:2])[0]
        if list_len % 2 != 0 or list_len + 2 != len(data) or (list_len // 2) > MAX_SUPPORTED_GROUPS:
            return [], False

        groups = []
        for i in range(2, len(data), 2):
            groups.append(struct.unpack(">H", data[i: i + 2])[0])
        return groups, True

    def _parse_signature_algorithms(self, data: bytes) -> Tuple[List[int], bool]:
        if len(data) < 2:
            return [], False
        list_len = struct.unpack(">H", data[0:2])[0]
        if list_len % 2 != 0 or list_len + 2 != len(data) or (list_len // 2) > MAX_SIGNATURE_ALGORITHMS:
            return [], False

        sigs = []
        for i in range(2, len(data), 2):
            sigs.append(struct.unpack(">H", data[i: i + 2])[0])
        return sigs, True

    def _parse_alpn(self, data: bytes) -> Tuple[List[str], bool]:
        if len(data) < 2:
            return [], False
        list_len = struct.unpack(">H", data[0:2])[0]
        if list_len + 2 != len(data):
            return [], False

        offset = 2
        alpns = []
        while offset < len(data):
            str_len = data[offset]
            offset += 1
            if offset + str_len > len(data):
                return [], False
            try:
                alpns.append(data[offset: offset + str_len].decode("utf-8"))
            except UnicodeDecodeError:
                return [], False
            offset += str_len
        return alpns, True

    def _parse_supported_versions(self, data: bytes) -> Tuple[List[int], bool]:
        if len(data) < 1:
            return [], False
        list_len = data[0]
        if list_len % 2 != 0 or list_len + 1 != len(data):
            return [], False

        versions = []
        for i in range(1, len(data), 2):
            versions.append(struct.unpack(">H", data[i: i + 2])[0])
        return versions, True

    def _parse_key_shares(self, data: bytes) -> Tuple[List[KeyShareEntry], bool]:
        if len(data) < 2:
            return [], False
        list_len = struct.unpack(">H", data[0:2])[0]
        if list_len + 2 != len(data):
            return [], False

        offset = 2
        shares = []
        while offset < len(data):
            if offset + 4 > len(data):
                return [], False
            group = struct.unpack(">H", data[offset: offset + 2])[0]
            ke_len = struct.unpack(">H", data[offset + 2: offset + 4])[0]
            offset += 4
            if offset + ke_len > len(data) or len(shares) >= MAX_KEY_SHARES:
                return [], False
            ke_bytes = data[offset: offset + ke_len]
            shares.append(
                KeyShareEntry(
                    group=group,
                    key_exchange_length=ke_len,
                    key_exchange_hex=ke_bytes.hex(),
                )
            )
            offset += ke_len
        return shares, True


tls_client_hello_parser = TLSClientHelloParser()