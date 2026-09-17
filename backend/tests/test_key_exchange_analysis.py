"""
Unit tests for Step 15: Advanced Key Exchange & PFS Analysis.
Verifies deterministic assessment of ECDHE, DHE, and static RSA key exchange,
TLS 1.3 key_share evaluation, client-offer vs server-selection priority,
and explicit tri-state handling on gap disruptions or missing ServerHello.
"""

from typing import List, Optional
import pytest

from app.schemas.domain import ConfidenceLevel, KeyExchangeType, TriState
from app.schemas.tls_client_hello import (
    ClientHelloParseResult,
    ClientHelloParseStatus,
    KeyShareEntry,
    TLSClientHello,
)
from app.schemas.tls_server_hello import (
    ServerHelloKeyShare,
    ServerHelloParseResult,
    ServerHelloParseStatus,
    TLSServerHello,
)
from app.services.key_exchange_analyzer import key_exchange_analyzer


def make_client_hello_result(
    cipher_suites: Optional[List[int]] = None,
    supported_groups: Optional[List[int]] = None,
    key_shares: Optional[List[KeyShareEntry]] = None,
    status: ClientHelloParseStatus = ClientHelloParseStatus.COMPLETE,
) -> ClientHelloParseResult:
    ch = TLSClientHello(
        msg_type=1,
        msg_length=100,
        legacy_version=0x0303,
        legacy_version_name="TLS_1_2",
        random_hex="01" * 32,
        session_id_length=0,
        session_id_hex="",
        cipher_suite_ids=cipher_suites or [0xC02B, 0xC02F, 0x002F],
        supported_groups=supported_groups or [0x001D, 0x0017],
        key_shares=key_shares or [KeyShareEntry(group=0x001D, key_exchange_length=32, key_exchange_hex="aa" * 32)],
        stream_id="stream#test",
    )
    return ClientHelloParseResult(
        stream_id="stream#test",
        status=status,
        client_hello=ch,
    )


def make_server_hello_result(
    negotiated_version: int = 0x0303,
    selected_cipher_suite_id: int = 0xC02F,
    selected_cipher_suite_name: str = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    key_share: Optional[ServerHelloKeyShare] = None,
    status: ServerHelloParseStatus = ServerHelloParseStatus.COMPLETE,
    malformed_reason: Optional[str] = None,
) -> ServerHelloParseResult:
    version_name = "TLS_1_3" if negotiated_version == 0x0304 else "TLS_1_2"
    sh = TLSServerHello(
        msg_type=2,
        msg_length=80,
        legacy_version=0x0303,
        legacy_version_name="TLS_1_2",
        negotiated_version=negotiated_version,
        negotiated_version_name=version_name,
        random_hex="02" * 32,
        session_id_echo_length=0,
        session_id_echo_hex="",
        selected_cipher_suite_id=selected_cipher_suite_id,
        selected_cipher_suite_name=selected_cipher_suite_name,
        compression_method=0,
        key_share=key_share,
        stream_id="stream#test",
    )
    return ServerHelloParseResult(
        stream_id="stream#test",
        status=status,
        server_hello=sh,
        malformed_reason=malformed_reason,
    )


# ==========================================================
# 1. TLS 1.2 / PRE-TLS 1.3 CIPHER SUITE EVALUATION
# ==========================================================

def test_tls_1_2_ecdhe_rsa_cipher_suite():
    """1. TLS 1.2 ECDHE_RSA -> ECDHE key exchange + PFS TRUE."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        negotiated_version=0x0303,
        selected_cipher_suite_id=0xC02F,
        selected_cipher_suite_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.ECDHE
    assert res.has_forward_secrecy == TriState.TRUE
    assert res.confidence == ConfidenceLevel.HIGH
    assert any("ECDHE" in ev for ev in res.evidence)


def test_tls_1_2_ecdhe_ecdsa_cipher_suite():
    """2. TLS 1.2 ECDHE_ECDSA -> ECDHE key exchange + PFS TRUE."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        negotiated_version=0x0303,
        selected_cipher_suite_id=0xC02B,
        selected_cipher_suite_name="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.ECDHE
    assert res.has_forward_secrecy == TriState.TRUE


def test_tls_1_2_dhe_rsa_cipher_suite():
    """3. TLS 1.2 DHE_RSA -> DHE key exchange + PFS TRUE."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        negotiated_version=0x0303,
        selected_cipher_suite_id=0x009E,
        selected_cipher_suite_name="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.DHE
    assert res.has_forward_secrecy == TriState.TRUE


def test_tls_1_2_rsa_key_transport_cipher_suite():
    """4. TLS 1.2 RSA key-transport cipher suite -> RSA key exchange + PFS FALSE."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        negotiated_version=0x0303,
        selected_cipher_suite_id=0x002F,
        selected_cipher_suite_name="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.RSA
    assert res.has_forward_secrecy == TriState.FALSE
    assert res.confidence == ConfidenceLevel.HIGH


# ==========================================================
# 2. TLS 1.3 KEY SHARE & GROUP EVALUATION
# ==========================================================

def test_tls_1_3_x25519_key_share():
    """5. TLS 1.3 x25519 key share -> ECDHE + PFS TRUE + x25519 named group."""
    ch = make_client_hello_result()
    ks = ServerHelloKeyShare(group=0x001D, key_exchange_length=32, key_exchange_hex="bb" * 32)
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1301,
        selected_cipher_suite_name="TLS_AES_128_GCM_SHA256",
        key_share=ks,
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.ECDHE
    assert res.has_forward_secrecy == TriState.TRUE
    assert res.named_group == "x25519"
    assert res.named_group_id == 0x001D


def test_tls_1_3_secp256r1_key_share():
    """6. TLS 1.3 secp256r1 key share -> ECDHE + PFS TRUE + secp256r1 group."""
    ch = make_client_hello_result()
    ks = ServerHelloKeyShare(group=0x0017, key_exchange_length=65, key_exchange_hex="04" + ("cc" * 64))
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1302,
        selected_cipher_suite_name="TLS_AES_256_GCM_SHA384",
        key_share=ks,
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.ECDHE
    assert res.has_forward_secrecy == TriState.TRUE
    assert res.named_group == "secp256r1"


def test_tls_1_3_cipher_suite_alone_does_not_determine_key_exchange():
    """7. TLS 1.3 cipher suite alone without key_share cannot determine key exchange."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1301,
        selected_cipher_suite_name="TLS_AES_128_GCM_SHA256",
        key_share=None,
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN


# ==========================================================
# 3. CLIENT OFFER VS SERVER SELECTION PRECEDENCE
# ==========================================================

def test_client_offered_ecdhe_server_selected_rsa():
    """8. Client offered ECDHE, but Server selected RSA -> Classify as RSA + PFS FALSE."""
    ch = make_client_hello_result(cipher_suites=[0xC02F, 0x002F])
    sh = make_server_hello_result(
        negotiated_version=0x0303,
        selected_cipher_suite_id=0x002F,
        selected_cipher_suite_name="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.RSA
    assert res.has_forward_secrecy == TriState.FALSE


def test_ecdhe_rsa_not_classified_as_rsa_key_transport():
    """9. ECDHE_RSA is classified as ECDHE, not RSA key transport."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        selected_cipher_suite_id=0xC030,
        selected_cipher_suite_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.ECDHE
    assert res.exchange_type != KeyExchangeType.RSA
    assert res.has_forward_secrecy == TriState.TRUE


def test_unknown_cipher_suite_yields_unknown_kex():
    """10. Unmapped cipher suite returns KeyExchangeType.UNKNOWN."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        selected_cipher_suite_id=0xFFFF,
        selected_cipher_suite_name="TLS_UNKNOWN_0xFFFF",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN
    assert res.confidence == ConfidenceLevel.LOW


def test_unknown_named_group_preserved():
    """11. Unknown named group preserved with explicit ID and UNKNOWN label."""
    ks = ServerHelloKeyShare(group=0xFAFA, key_exchange_length=32, key_exchange_hex="aa" * 32)
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1301,
        key_share=ks,
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.named_group_id == 0xFAFA
    assert "UNKNOWN_GROUP_0xFAFA" in res.named_group


# ==========================================================
# 4. GAPS, TRUNCATION & UNCERTAINTY HANDLING
# ==========================================================

def test_missing_server_hello_yields_unknown():
    """12. Missing ServerHello yields UNKNOWN key exchange and UNKNOWN PFS."""
    ch = make_client_hello_result()
    res = key_exchange_analyzer.analyze(ch, None)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN
    assert res.confidence == ConfidenceLevel.LOW


def test_incomplete_server_hello_yields_unknown():
    """13. Incomplete ServerHello yields UNKNOWN key exchange."""
    ch = make_client_hello_result()
    sh = make_server_hello_result(
        status=ServerHelloParseStatus.INCOMPLETE_CAPTURE,
        malformed_reason="Capture truncated before ServerHello completed.",
    )
    res = key_exchange_analyzer.analyze(ch, sh)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN


def test_server_hello_gap_disruption():
    """14. ServerHello interrupted by TCP sequence gap yields UNKNOWN."""
    sh = make_server_hello_result(
        status=ServerHelloParseStatus.GAP_DISRUPTION,
        malformed_reason="ServerHello body interrupted by TCP sequence gap.",
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN


def test_tls_1_3_missing_key_share_no_fabrication():
    """15. TLS 1.3 without key_share does not fabricate selected group."""
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1302,
        key_share=None,
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.named_group is None
    assert res.named_group_id is None
    assert res.has_forward_secrecy == TriState.UNKNOWN


def test_client_hello_key_share_without_server_hello_selection():
    """16. Client offered x25519, but ServerHello missing -> Not treated as selected."""
    ch = make_client_hello_result(
        key_shares=[KeyShareEntry(group=0x001D, key_exchange_length=32, key_exchange_hex="11" * 32)]
    )
    res = key_exchange_analyzer.analyze(ch, None)

    assert res.named_group is None
    assert res.has_forward_secrecy == TriState.UNKNOWN


# ==========================================================
# 5. INTEGRATION & TRACEABILITY
# ==========================================================

def test_negotiated_tls_version_comes_from_step_14():
    """17. Negotiated version from Step 14 propagated accurately."""
    sh = make_server_hello_result(negotiated_version=0x0304)
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.negotiated_version == 0x0304


def test_selected_cipher_suite_comes_from_step_14():
    """18. Selected cipher suite from Step 14 propagated accurately."""
    sh = make_server_hello_result(
        selected_cipher_suite_id=0xC02F,
        selected_cipher_suite_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.selected_cipher_suite_id == 0xC02F
    assert res.selected_cipher_suite_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_evidence_fields_preserved():
    """19. Observed evidence items recorded in result."""
    sh = make_server_hello_result()
    res = key_exchange_analyzer.analyze(None, sh)

    assert len(res.evidence) >= 2


def test_limitations_preserved():
    """20. Forensic limitations attached to result."""
    sh = make_server_hello_result()
    res = key_exchange_analyzer.analyze(None, sh)

    assert len(res.limitations) >= 2
    assert any("passive" in lim.lower() for lim in res.limitations)


def test_stream_correlation_preserved():
    """21. Stream ID preserved from input results."""
    sh = make_server_hello_result()
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.stream_id == "stream#test"


def test_confidence_reflects_evidence_quality():
    """22. Complete handshake yields HIGH; incomplete yields LOW."""
    sh_good = make_server_hello_result(status=ServerHelloParseStatus.COMPLETE)
    sh_bad = make_server_hello_result(status=ServerHelloParseStatus.INCOMPLETE_CAPTURE)

    r_good = key_exchange_analyzer.analyze(None, sh_good)
    r_bad = key_exchange_analyzer.analyze(None, sh_bad)

    assert r_good.confidence == ConfidenceLevel.HIGH
    assert r_bad.confidence == ConfidenceLevel.LOW


def test_malformed_input_does_not_crash():
    """23. Malformed ServerHello status returns safe structured result without exception."""
    sh = make_server_hello_result(
        status=ServerHelloParseStatus.MALFORMED_HANDSHAKE,
        malformed_reason="Invalid session ID echo length.",
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN


def test_tls_1_3_ffdhe_key_share_classified_as_dhe():
    """24. TLS 1.3 ffdhe2048 key share classified as DHE."""
    ks = ServerHelloKeyShare(group=0x0100, key_exchange_length=256, key_exchange_hex="ee" * 256)
    sh = make_server_hello_result(
        negotiated_version=0x0304,
        selected_cipher_suite_id=0x1301,
        key_share=ks,
    )
    res = key_exchange_analyzer.analyze(None, sh)

    assert res.exchange_type == KeyExchangeType.DHE
    assert res.has_forward_secrecy == TriState.TRUE
    assert res.named_group == "ffdhe2048"


def test_empty_inputs_handled_cleanly():
    """25. Completely None inputs handled safely without raising exceptions."""
    res = key_exchange_analyzer.analyze(None, None)

    assert res.exchange_type == KeyExchangeType.UNKNOWN
    assert res.has_forward_secrecy == TriState.UNKNOWN
    assert res.confidence == ConfidenceLevel.LOW