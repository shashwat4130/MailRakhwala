"""
MailRakhwala Key Exchange & PFS Analysis Service (Step 15)
Evaluates negotiated key exchange mechanisms and Perfect Forward Secrecy (PFS)
characteristics from structured Step 13 ClientHello and Step 14 ServerHello evidence.
"""

from typing import Dict, List, Optional

from app.schemas.domain import ConfidenceLevel, KeyExchangeAnalysis, KeyExchangeType, TriState
from app.schemas.tls_client_hello import ClientHelloParseResult, ClientHelloParseStatus
from app.schemas.tls_server_hello import ServerHelloParseResult, ServerHelloParseStatus

NAMED_GROUPS: Dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}

# TLS 1.2/pre-1.3 Cipher Suite to Key Exchange Type mapping
CIPHER_SUITE_KEX_MAP: Dict[int, KeyExchangeType] = {
    # ECDHE suites
    0xC02B: KeyExchangeType.ECDHE,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02C: KeyExchangeType.ECDHE,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02F: KeyExchangeType.ECDHE,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030: KeyExchangeType.ECDHE,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA8: KeyExchangeType.ECDHE,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA9: KeyExchangeType.ECDHE,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xC013: KeyExchangeType.ECDHE,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014: KeyExchangeType.ECDHE,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    # DHE suites
    0x009E: KeyExchangeType.DHE,    # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x009F: KeyExchangeType.DHE,    # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    0x0033: KeyExchangeType.DHE,    # TLS_DHE_RSA_WITH_DHE_RSA_EXPORT_...
    0x0035: KeyExchangeType.DHE,    # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    # RSA key transport suites (no PFS)
    0x002F: KeyExchangeType.RSA,    # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035: KeyExchangeType.RSA,    # TLS_RSA_WITH_AES_256_CBC_SHA
    0x009C: KeyExchangeType.RSA,    # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D: KeyExchangeType.RSA,    # TLS_RSA_WITH_AES_256_GCM_SHA384
    0x000A: KeyExchangeType.RSA,    # TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

TLS_1_3_CIPHER_SUITES = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}


class KeyExchangeAnalyzer:
    """Deterministic analyzer evaluating TLS key exchange and forward secrecy."""

    def analyze(
        self,
        client_hello_result: Optional[ClientHelloParseResult],
        server_hello_result: Optional[ServerHelloParseResult],
    ) -> KeyExchangeAnalysis:
        stream_id = (
            server_hello_result.stream_id
            if server_hello_result
            else (client_hello_result.stream_id if client_hello_result else "unknown_stream")
        )

        # 1. Missing or disrupted ServerHello
        if not server_hello_result or server_hello_result.status != ServerHelloParseStatus.COMPLETE:
            reason = (
                server_hello_result.malformed_reason
                if server_hello_result and server_hello_result.malformed_reason
                else "ServerHello evidence was missing or incomplete."
            )
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.UNKNOWN,
                has_forward_secrecy=TriState.UNKNOWN,
                stream_id=stream_id,
                confidence=ConfidenceLevel.LOW,
                evidence=[f"Analysis halted: {reason}"],
                limitations=[
                    "Key exchange cannot be determined without a complete ServerHello message.",
                    "PFS status remains UNKNOWN due to missing server negotiation parameters."
                ],
            )

        sh = server_hello_result.server_hello
        if not sh:
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.UNKNOWN,
                has_forward_secrecy=TriState.UNKNOWN,
                stream_id=stream_id,
                confidence=ConfidenceLevel.LOW,
                evidence=["ServerHello record parsed without payload."],
            )

        # 2. TLS 1.3 Key Exchange Analysis
        if sh.negotiated_version == 0x0304:
            return self._analyze_tls_1_3(sh, client_hello_result, stream_id)

        # 3. TLS 1.2 and earlier Key Exchange Analysis
        return self._analyze_pre_tls_1_3(sh, client_hello_result, stream_id)

    def _analyze_tls_1_3(
        self,
        sh,
        client_hello_result: Optional[ClientHelloParseResult],
        stream_id: str,
    ) -> KeyExchangeAnalysis:
        evidence: List[str] = [
            f"Negotiated TLS version: TLS_1_3 (0x{sh.negotiated_version:04X}) via ServerHello.",
            f"Selected cipher suite: {sh.selected_cipher_suite_name} (0x{sh.selected_cipher_suite_id:04X}).",
        ]

        if not sh.key_share:
            evidence.append(
                "ServerHello omitted key_share extension; key exchange group cannot be established."
            )
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.UNKNOWN,
                has_forward_secrecy=TriState.UNKNOWN,
                stream_id=stream_id,
                negotiated_version=sh.negotiated_version,
                selected_cipher_suite_id=sh.selected_cipher_suite_id,
                selected_cipher_suite_name=sh.selected_cipher_suite_name,
                confidence=ConfidenceLevel.MEDIUM,
                evidence=evidence,
                limitations=[
                    "TLS 1.3 record protection cipher suite does not specify key agreement mechanism.",
                    "Server key_share was not observed in the ServerHello message."
                ],
            )

        group_id = sh.key_share.group
        group_name = NAMED_GROUPS.get(group_id, f"UNKNOWN_GROUP_0x{group_id:04X}")
        evidence.append(
            f"ServerHello selected key_share named group: {group_name} (0x{group_id:04X})."
        )

        # Check if group is DH (finite field) or ECDH (elliptic curve)
        if group_id in (0x0100, 0x0101, 0x0102):
            kex_type = KeyExchangeType.DHE
            evidence.append("Negotiated ephemeral finite-field Diffie-Hellman (DHE) key exchange.")
        else:
            kex_type = KeyExchangeType.ECDHE
            evidence.append("Negotiated ephemeral elliptic-curve Diffie-Hellman (ECDHE) key exchange.")

        return KeyExchangeAnalysis(
            exchange_type=kex_type,
            has_forward_secrecy=TriState.TRUE,
            named_group=group_name,
            named_group_id=group_id,
            stream_id=stream_id,
            negotiated_version=sh.negotiated_version,
            selected_cipher_suite_id=sh.selected_cipher_suite_id,
            selected_cipher_suite_name=sh.selected_cipher_suite_name,
            confidence=ConfidenceLevel.HIGH,
            evidence=evidence,
        )

    def _analyze_pre_tls_1_3(
        self,
        sh,
        client_hello_result: Optional[ClientHelloParseResult],
        stream_id: str,
    ) -> KeyExchangeAnalysis:
        cs_id = sh.selected_cipher_suite_id
        cs_name = sh.selected_cipher_suite_name

        evidence: List[str] = [
            f"Negotiated TLS version: {sh.negotiated_version_name} (0x{sh.negotiated_version:04X}).",
            f"ServerHello selected cipher suite: {cs_name} (0x{cs_id:04X}).",
        ]

        kex_type = CIPHER_SUITE_KEX_MAP.get(cs_id)

        # Pattern-based heuristic fallback for known standard naming
        if kex_type is None:
            if cs_name.startswith("TLS_ECDHE_"):
                kex_type = KeyExchangeType.ECDHE
            elif cs_name.startswith("TLS_DHE_"):
                kex_type = KeyExchangeType.DHE
            elif cs_name.startswith("TLS_RSA_"):
                kex_type = KeyExchangeType.RSA

        if kex_type == KeyExchangeType.ECDHE:
            evidence.append("ECDHE key exchange indicated by negotiated cipher suite prefix.")
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.ECDHE,
                has_forward_secrecy=TriState.TRUE,
                stream_id=stream_id,
                negotiated_version=sh.negotiated_version,
                selected_cipher_suite_id=cs_id,
                selected_cipher_suite_name=cs_name,
                confidence=ConfidenceLevel.HIGH,
                evidence=evidence,
            )

        elif kex_type == KeyExchangeType.DHE:
            evidence.append("DHE key exchange indicated by negotiated cipher suite prefix.")
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.DHE,
                has_forward_secrecy=TriState.TRUE,
                stream_id=stream_id,
                negotiated_version=sh.negotiated_version,
                selected_cipher_suite_id=cs_id,
                selected_cipher_suite_name=cs_name,
                confidence=ConfidenceLevel.HIGH,
                evidence=evidence,
            )

        elif kex_type == KeyExchangeType.RSA:
            evidence.append("Static RSA key transport indicated by cipher suite (no forward secrecy).")
            return KeyExchangeAnalysis(
                exchange_type=KeyExchangeType.RSA,
                has_forward_secrecy=TriState.FALSE,
                stream_id=stream_id,
                negotiated_version=sh.negotiated_version,
                selected_cipher_suite_id=cs_id,
                selected_cipher_suite_name=cs_name,
                confidence=ConfidenceLevel.HIGH,
                evidence=evidence,
                limitations=[
                    "Static RSA key transport does not provide Perfect Forward Secrecy (PFS).",
                    "Past sessions are subject to retroactive decryption if the server private key is compromised."
                ],
            )

        # Unknown or unmapped cipher suite
        evidence.append("Selected cipher suite is unmapped or does not clearly identify key agreement.")
        return KeyExchangeAnalysis(
            exchange_type=KeyExchangeType.UNKNOWN,
            has_forward_secrecy=TriState.UNKNOWN,
            stream_id=stream_id,
            negotiated_version=sh.negotiated_version,
            selected_cipher_suite_id=cs_id,
            selected_cipher_suite_name=cs_name,
            confidence=ConfidenceLevel.LOW,
            evidence=evidence,
            limitations=["Key exchange mechanism could not be identified from the cipher suite ID."],
        )


key_exchange_analyzer = KeyExchangeAnalyzer()