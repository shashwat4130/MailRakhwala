from pathlib import Path

from app.services.tshark_service import tshark_service


def test_tshark_command_contains_frame_protocols_and_no_ws_col():
    """Verify that build_command uses valid fields and excludes invalid variants."""
    dummy_pcap = Path("dummy.pcap")
    cmd = tshark_service._build_command(dummy_pcap)

    assert "frame.number" in cmd
    assert cmd[cmd.index("-E") + 1] == "separator=\t"
    assert "frame.protocols" in cmd
    assert "ip.src" in cmd
    assert "ip.dst" in cmd

    assert "tls.handshake.extensions_supported_version" not in cmd
    assert "tls.handshake.extensions_alpn_str" not in cmd
    assert "tls.alpn_string" not in cmd
    assert "tls.handshake.alpn_str" not in cmd
    assert "tls.handshake.extension.supported_version" not in cmd
    assert "ws.col.Protocol" not in cmd
    assert "ws.col.protocol" not in cmd
    assert "ws.col.DstProto" not in cmd
    assert "_ws.col.Protocol" not in cmd


def test_tshark_parse_tcp_tls_stack():
    """Verify dissection of a TCP/TLS protocol stack."""
    line = (
        "1\t1710000000.123456\t128\t"
        "192.168.1.10\t\t"
        "192.168.1.20\t\t"
        "eth:ethertype:ip:tcp:tls\t"
        "54321\t\t"
        "443\t\t"
        "0"
        + "\t" * 13
    )

    packet = tshark_service.parse_line(line)

    assert packet is not None
    assert packet.src_ip == "192.168.1.10"
    assert packet.dst_ip == "192.168.1.20"
    assert packet.src_port == 54321
    assert packet.dst_port == 443
    assert packet.transport_protocol == "TCP"
    assert packet.highest_layer == "TLS"
    assert packet.tcp_stream == 0


def test_tshark_parse_udp_dns_stack():
    """Verify dissection of a UDP protocol stack."""
    line = (
        "2\t1710000001.000000\t64\t"
        "10.0.0.1\t\t"
        "10.0.0.2\t\t"
        "eth:ethertype:ip:udp:dns\t\t"
        "5353\t\t"
        "53\t"
        + "\t" * 13
    )

    packet = tshark_service.parse_line(line)

    assert packet is not None
    assert packet.src_ip == "10.0.0.1"
    assert packet.dst_ip == "10.0.0.2"
    assert packet.src_port == 5353
    assert packet.dst_port == 53
    assert packet.transport_protocol == "UDP"
    assert packet.highest_layer == "DNS"


def test_tshark_parse_empty_protocols():
    """Verify missing or empty frame.protocols does not crash parsing."""
    line = (
        "3\t1710000002.000000\t40\t"
        "192.168.1.5\t\t"
        "192.168.1.1\t\t\t\t\t\t\t"
        + "\t" * 13
    )

    packet = tshark_service.parse_line(line)

    assert packet is not None
    assert packet.src_ip == "192.168.1.5"
    assert packet.highest_layer == "RAW"