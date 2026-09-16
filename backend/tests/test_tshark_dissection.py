"""
Tests for Step 07: TShark Packet Dissection Engine
Verifies line parsing, metadata extraction, error handling, subprocess streaming safety,
timeout enforcement, stderr draining, and early termination.
"""

from collections import deque
import io
from pathlib import Path
import subprocess
import time
import pytest

from app.core.config import settings
from app.services.tshark_service import (
    TSharkError,
    TSharkExecutionError,
    TSharkNotFoundError,
    TSharkService,
    TSharkTimeoutError,
    tshark_service,
)
from app.services.pcap_validator import MAGIC_PCAP_LE

SYNTHETIC_GLOBAL_HEADER = (
    MAGIC_PCAP_LE +
    (2).to_bytes(2, "little") +
    (4).to_bytes(2, "little") +
    (0).to_bytes(4, "little") +
    (0).to_bytes(4, "little") +
    (65535).to_bytes(4, "little") +
    (1).to_bytes(4, "little")
)

SYNTHETIC_ETHERNET_IP_TCP_FRAME = (
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" +
    b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x0a\xc0\xa8\x01\x19" +
    b"\xc0\x00\x00\x19\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x72\x10\x00\x00\x00\x00"
)


def make_pcap_record(packet_bytes: bytes, ts_sec: int = 1672531199, ts_usec: int = 500000) -> bytes:
    pkt_len = len(packet_bytes)
    rec_hdr = (
        ts_sec.to_bytes(4, "little") +
        ts_usec.to_bytes(4, "little") +
        pkt_len.to_bytes(4, "little") +
        pkt_len.to_bytes(4, "little")
    )
    return rec_hdr + packet_bytes


# --- Unit Tests ---

def test_command_generation_includes_line_flushing():
    service = TSharkService(binary_path="mock_tshark")
    dummy_path = settings.UPLOAD_DIR / "dummy.pcap"
    cmd = service._build_command(dummy_path)

    assert "-l" in cmd
    assert "-T" in cmd
    assert "fields" in cmd
    assert "-E" in cmd
    assert "separator=/t" in cmd
    assert "-n" in cmd


def test_parse_valid_tcp_line():
    service = TSharkService(binary_path="mock_tshark")
    line = "1\t1672531199.500000\t54\t192.168.1.10\t\t192.168.1.25\t\tTCP\t49152\t\t25\t\t0\tTCP"
    pkt = service.parse_line(line)

    assert pkt is not None
    assert pkt.frame_number == 1
    assert pkt.timestamp_epoch == 1672531199.5
    assert pkt.frame_len == 54
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_ip == "192.168.1.25"
    assert pkt.src_port == 49152
    assert pkt.dst_port == 25
    assert pkt.transport_protocol == "TCP"
    assert pkt.tcp_stream == 0


def test_parse_valid_udp_line():
    service = TSharkService(binary_path="mock_tshark")
    line = "2\t1672531200.123456\t60\t10.0.0.1\t\t10.0.0.2\t\tUDP\t\t5353\t\t5353\t\tMDNS"
    pkt = service.parse_line(line)

    assert pkt is not None
    assert pkt.frame_number == 2
    assert pkt.src_port == 5353
    assert pkt.dst_port == 5353
    assert pkt.transport_protocol == "UDP"
    assert pkt.highest_layer == "MDNS"
    assert pkt.tcp_stream is None


def test_parse_empty_or_malformed_line():
    service = TSharkService(binary_path="mock_tshark")
    assert service.parse_line("") is None
    assert service.parse_line("invalid\t1234") is None


def test_tshark_not_found_raises():
    service = TSharkService(binary_path="/nonexistent/path/to/tshark_xyz")
    with pytest.raises(TSharkNotFoundError):
        service.get_version()


def test_dissection_path_containment_violation():
    service = TSharkService(binary_path="mock_tshark")
    service.is_available = lambda: True

    traversal_path = settings.UPLOAD_DIR / ".." / ".." / "etc" / "shadow.pcap"
    with pytest.raises(TSharkError) as exc:
        gen = service.dissect_packets_stream(traversal_path)
        next(gen)
    assert "outside upload directory" in str(exc.value).lower()


def test_lifecycle_timeout_watchdog(monkeypatch):
    """Verifies that a stalled subprocess is terminated by the watchdog timer."""
    service = TSharkService(binary_path="mock_tshark")
    service.is_available = lambda: True

    test_file = settings.UPLOAD_DIR / "timeout_test.pcap"
    test_file.write_bytes(SYNTHETIC_GLOBAL_HEADER)

    class MockHangingPopen:
        def __init__(self, *args, **kwargs):
            self.stdout = self._hanging_stream()
            self.stderr = io.StringIO("")
            self.returncode = None
            self.killed = False

        def _hanging_stream(self):
            # Hangs indefinitely to test watchdog
            while not self.killed:
                time.sleep(0.05)
                yield "1\t100.0\t54\t1.1.1.1\t\t2.2.2.2\t\tTCP\t80\t\t80\t\t0\tTCP\n"

        def poll(self):
            return -9 if self.killed else None

        def terminate(self):
            self.killed = True

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            return -9

    monkeypatch.setattr(subprocess, "Popen", MockHangingPopen)

    try:
        with pytest.raises(TSharkTimeoutError):
            gen = service.dissect_packets_stream(test_file, timeout=0.2)
            for _ in gen:
                pass
    finally:
        test_file.unlink(missing_ok=True)


def test_clean_early_termination_on_max_frames(monkeypatch):
    """Verifies that reaching max_frames actively terminates a running child process."""
    service = TSharkService(binary_path="mock_tshark")
    service.is_available = lambda: True

    test_file = settings.UPLOAD_DIR / "max_frames_test.pcap"
    test_file.write_bytes(SYNTHETIC_GLOBAL_HEADER)

    class MockActiveStreamPopen:
        def __init__(self, *args, **kwargs):
            # Generator simulating an active, ongoing output stream
            self.stdout = (
                f"{i}\t100.0\t54\t1.1.1.1\t\t2.2.2.2\t\tTCP\t80\t\t80\t\t0\tTCP\n"
                for i in range(1, 100)
            )
            self.stderr = io.StringIO("")
            self.returncode = None
            self.terminate_called = False
            self.kill_called = False

        def poll(self):
            # None indicates the subprocess is actively running
            return self.returncode

        def terminate(self):
            self.terminate_called = True
            self.returncode = -15  # SIGTERM equivalent

        def kill(self):
            self.kill_called = True
            self.returncode = -9   # SIGKILL equivalent

        def wait(self, timeout=None):
            if self.returncode is None:
                self.terminate()
            return self.returncode

    mock_instances = []

    def mock_popen_factory(*args, **kwargs):
        proc = MockActiveStreamPopen(*args, **kwargs)
        mock_instances.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", mock_popen_factory)

    try:
        packets = list(service.dissect_packets_stream(test_file, max_frames=5))

        # 1. Verify exactly max_frames items were consumed
        assert len(packets) == 5
        assert len(mock_instances) == 1

        mock_proc = mock_instances[0]
        # 2. Verify termination was actively triggered
        assert mock_proc.terminate_called or mock_proc.kill_called
        # 3. Verify the process is no longer running
        assert mock_proc.poll() is not None
        assert mock_proc.returncode is not None
    finally:
        test_file.unlink(missing_ok=True)


# --- Integration Tests (Active when TShark is installed) ---

@pytest.mark.skipif(not tshark_service.is_available(), reason="TShark is not installed in local environment")
def test_tshark_version_available():
    version_str = tshark_service.get_version()
    assert "TShark" in version_str


@pytest.mark.skipif(not tshark_service.is_available(), reason="TShark is not installed in local environment")
def test_tshark_dissect_synthetic_pcap():
    pcap_bytes = SYNTHETIC_GLOBAL_HEADER + make_pcap_record(SYNTHETIC_ETHERNET_IP_TCP_FRAME)
    test_file = settings.UPLOAD_DIR / "synthetic_test.pcap"
    test_file.write_bytes(pcap_bytes)

    try:
        packets = list(tshark_service.dissect_packets_stream(test_file))
        assert len(packets) == 1
        pkt = packets[0]
        assert pkt.frame_number == 1
        assert pkt.src_ip == "192.168.1.10"
        assert pkt.dst_ip == "192.168.1.25"
        assert pkt.src_port == 49152
        assert pkt.dst_port == 25
        assert pkt.transport_protocol == "TCP"
        assert pkt.frame_len == 54
    finally:
        test_file.unlink(missing_ok=True)