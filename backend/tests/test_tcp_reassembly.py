"""
MailRakhwala TCP Stream Reconstruction Tests (Step 08)
Verifies out-of-order sequencing, port reuse isolation, gap accounting,
and non-contiguous fragment isolation.
"""

import pytest

from app.schemas.packet import DissectedPacket
from app.schemas.tcp_stream import ReconstructionStatus, TerminationReason
from app.services.tcp_reassembly_service import TCPReassemblyService

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_ACK = 0x10


def make_packet(
    frame_number: int = 1,
    src_ip: str = "192.168.1.10",
    src_port: int = 50000,
    dst_ip: str = "192.168.1.20",
    dst_port: int = 25,
    tcp_seq: int = 1000,
    payload: bytes = b"",
    flags: int = 0,
    tcp_stream: int = 0,
    timestamp: float = 100.0,
    frame_len: int = 64,
) -> DissectedPacket:
    return DissectedPacket(
        frame_number=frame_number,
        frame_len=(
            frame_len
            if frame_len >= len(payload)
            else len(payload) + 54
        ),
        timestamp_epoch=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        transport_protocol="TCP",
        tcp_seq=tcp_seq,
        tcp_flags=flags,
        tcp_stream=tcp_stream,
        payload=payload,
    )


def test_gap_marks_stream_incomplete_and_exposes_fragments():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_seq=100,
        payload=b"AAA",
    )
    service.process_packet(p1)

    p2 = make_packet(
        frame_number=2,
        tcp_seq=120,
        payload=b"CCC",
    )
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))

    assert len(streams) == 1
    stream = streams[0]

    assert stream.reconstruction_status == ReconstructionStatus.INCOMPLETE
    assert stream.has_unresolved_gaps is True

    assert len(stream.client_gaps) == 1
    assert stream.client_gaps[0].start_seq == 103
    assert stream.client_gaps[0].end_seq == 120
    assert stream.client_gaps[0].gap_bytes == 17

    assert len(stream.client_fragments) == 2
    assert stream.client_fragments[0].data == b"AAA"
    assert stream.client_fragments[0].is_initial_contiguous is True

    assert stream.client_fragments[1].data == b"CCC"
    assert stream.client_fragments[1].is_initial_contiguous is False


def test_out_of_order_sequence_reconstruction():
    service = TCPReassemblyService()

    p_syn = make_packet(
        frame_number=1,
        tcp_seq=1000,
        flags=TH_SYN,
    )
    service.process_packet(p_syn)

    p_late = make_packet(
        frame_number=2,
        tcp_seq=1007,
        payload=b"WORLD",
    )
    service.process_packet(p_late)

    p_early = make_packet(
        frame_number=3,
        tcp_seq=1001,
        payload=b"HELLO_",
    )
    service.process_packet(p_early)

    streams = list(service.reassemble_packet_stream([]))

    assert len(streams) == 1
    stream = streams[0]

    assert stream.client_payload == b"HELLO_WORLD"
    assert stream.has_unresolved_gaps is False
    assert stream.reconstruction_status == ReconstructionStatus.COMPLETE


def test_tshark_stream_is_metadata_not_sole_identity():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_stream=0,
        payload=b"PING",
    )

    p2 = make_packet(
        frame_number=2,
        tcp_stream=99,
        tcp_seq=1004,
        payload=b"PONG",
    )

    service.process_packet(p1)
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))

    assert len(streams) == 1
    assert streams[0].client_payload == b"PINGPONG"


def test_same_4tuple_reused_after_connection_closed():
    service = TCPReassemblyService()

    p_fin = make_packet(
        frame_number=1,
        flags=TH_FIN,
        payload=b"DONE",
    )
    service.process_packet(p_fin)

    p_new_syn = make_packet(
        frame_number=2,
        flags=TH_SYN,
    )

    evicted = service.process_packet(p_new_syn)

    assert evicted is not None
    assert evicted.termination_reason == TerminationReason.CONNECTION_REUSED
    assert "#gen1" in evicted.stream_id

    remaining = list(service.reassemble_packet_stream([]))

    assert len(remaining) == 1
    assert "#gen2" in remaining[0].stream_id


def test_unresolved_sequence_gaps_do_not_fabricate_contiguous_bytes():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_seq=50,
        payload=b"TEST",
    )
    service.process_packet(p1)

    p2 = make_packet(
        frame_number=2,
        tcp_seq=200,
        payload=b"DATA",
    )
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))
    stream = streams[0]

    assert stream.client_payload == b"TEST"
    assert b"DATA" not in stream.client_payload
    assert stream.has_unresolved_gaps is True


def test_retransmission_ignored_cleanly():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_seq=100,
        payload=b"HELLO",
    )

    p2 = make_packet(
        frame_number=2,
        tcp_seq=100,
        payload=b"HELLO",
    )

    service.process_packet(p1)
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))

    assert streams[0].client_payload == b"HELLO"
    assert streams[0].client_retransmissions == 1


def test_overlapping_segment_trimmed():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_seq=100,
        payload=b"HELLO",
    )

    p2 = make_packet(
        frame_number=2,
        tcp_seq=103,
        payload=b"LO_ALL",
    )

    service.process_packet(p1)
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))

    assert streams[0].client_payload == b"HELLO_ALL"
    assert streams[0].client_overlapping_segments == 1
    assert streams[0].has_conflicting_overlaps is False


def test_conflicting_overlap_marks_ambiguous():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        tcp_seq=100,
        payload=b"HELLO",
    )

    p2 = make_packet(
        frame_number=2,
        tcp_seq=103,
        payload=b"XX_CONFLICT",
    )

    service.process_packet(p1)
    service.process_packet(p2)

    streams = list(service.reassemble_packet_stream([]))

    assert streams[0].has_conflicting_overlaps is True
    assert streams[0].reconstruction_status == ReconstructionStatus.AMBIGUOUS


def test_bidirectional_traffic_separated():
    service = TCPReassemblyService()

    # Client -> Server
    p_cli = make_packet(
        frame_number=1,
        src_ip="192.168.1.10",
        src_port=50000,
        dst_ip="192.168.1.20",
        dst_port=25,
        tcp_seq=10,
        payload=b"CLIENT_CMD",
    )

    # Server -> Client
    p_srv = make_packet(
        frame_number=2,
        src_ip="192.168.1.20",
        src_port=25,
        dst_ip="192.168.1.10",
        dst_port=50000,
        tcp_seq=200,
        payload=b"SERVER_RSP",
    )

    service.process_packet(p_cli)
    service.process_packet(p_srv)

    streams = list(service.reassemble_packet_stream([]))

    assert len(streams) == 1
    assert streams[0].client_payload == b"CLIENT_CMD"
    assert streams[0].server_payload == b"SERVER_RSP"


def test_rst_packet_sets_lifecycle_reset():
    service = TCPReassemblyService()

    p_syn = make_packet(
        frame_number=1,
        flags=TH_SYN,
    )

    p_rst = make_packet(
        frame_number=2,
        flags=TH_RST,
    )

    service.process_packet(p_syn)
    service.process_packet(p_rst)

    streams = list(service.reassemble_packet_stream([]))

    assert streams[0].termination_reason == TerminationReason.RST


def test_bounded_stream_buffer_enforces_truncation():
    service = TCPReassemblyService(max_bytes_per_dir=10)

    p1 = make_packet(
        frame_number=1,
        tcp_seq=100,
        payload=b"1234567890EXTRA_BYTES",
    )

    service.process_packet(p1)

    streams = list(service.reassemble_packet_stream([]))

    assert streams[0].is_truncated is True
    assert len(streams[0].client_payload) == 10


def test_active_stream_lru_eviction():
    service = TCPReassemblyService(max_active_streams=2)

    service.process_packet(
        make_packet(
            src_port=50001,
            dst_port=25,
        )
    )

    service.process_packet(
        make_packet(
            src_port=50002,
            dst_port=25,
        )
    )

    evicted = service.process_packet(
        make_packet(
            src_port=50003,
            dst_port=25,
        )
    )

    assert evicted is not None
    assert evicted.termination_reason == TerminationReason.PURGED
    assert "50001" in evicted.stream_id


def test_non_tcp_packets_ignored():
    service = TCPReassemblyService()

    pkt = DissectedPacket(
        frame_number=1,
        frame_len=60,
        timestamp_epoch=1.0,
        src_ip="10.0.0.1",
        src_port=53,
        dst_ip="10.0.0.2",
        dst_port=53,
        transport_protocol="UDP",
        payload=b"DNS",
    )

    result = service.process_packet(pkt)

    assert result is None


def test_ipv6_endpoints_supported():
    service = TCPReassemblyService()

    p1 = make_packet(
        frame_number=1,
        src_ip="2001:db8::1",
        src_port=40000,
        dst_ip="2001:db8::2",
        dst_port=587,
        tcp_seq=1000,
        payload=b"STARTTLS\r\n",
    )

    streams = list(service.reassemble_packet_stream([p1]))

    assert len(streams) == 1
    assert streams[0].client_ip == "2001:db8::1"
    assert streams[0].server_ip == "2001:db8::2"
    assert streams[0].client_payload == b"STARTTLS\r\n"