import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, Generator, List, Optional

from app.core.config import settings
from app.schemas.packet import DissectedPacket

logger = logging.getLogger("mailrakhwala.tshark")


class TSharkError(Exception):
    pass


class TSharkNotFoundError(TSharkError):
    pass


class TSharkTimeoutError(TSharkError):
    pass


class TSharkExecutionError(TSharkError):
    pass


class TSharkService:
    # Only standard, guaranteed core fields across all Wireshark versions.
    # Problematic TLS extension sub-fields that vary by build are excluded.
    DISSECTION_FIELDS: List[str] = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "frame.protocols",
        "tcp.srcport",
        "udp.srcport",
        "tcp.dstport",
        "udp.dstport",
        "tcp.stream",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.flags.fin",
        "tcp.flags.reset",
        "tcp.seq",
        "tcp.ack",
        "tcp.payload",
        "tls.record.version",
        "tls.handshake.type",
        "tls.handshake.version",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions_server_name",
        "tls.handshake.sig_hash_alg",
    ]

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._find_tshark()
        if not self.binary_path:
            raise TSharkNotFoundError("TShark binary could not be found on the system.")

    def _find_tshark(self) -> Optional[str]:
        configured = getattr(settings, "TSHARK_PATH", None)
        if configured and os.path.isfile(configured):
            return configured

        discovered = shutil.which("tshark")
        if discovered:
            return discovered

        windows_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for path in windows_paths:
            if os.path.isfile(path):
                return path

        return None

    def is_available(self) -> bool:
        return self.binary_path is not None and os.path.isfile(self.binary_path)

    def get_version(self) -> str:
        if not self.is_available():
            return "unavailable"
        try:
            result = subprocess.run(
                [self.binary_path, "-v"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            first_line = result.stdout.splitlines()[0] if result.stdout else "unknown"
            return first_line
        except Exception as err:
            logger.warning("Failed to determine TShark version: %s", err)
            return "unknown"

    def _build_command(self, pcap_path: Path) -> List[str]:
        cmd = [
            self.binary_path,
            "-r",
            str(pcap_path),
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
        ]
        for field in self.DISSECTION_FIELDS:
            cmd.extend(["-e", field])
        return cmd

    def build_command(self, pcap_path: Path) -> List[str]:
        return self._build_command(pcap_path)

    def parse_line(self, line: str) -> Optional[DissectedPacket]:
        cols = line.rstrip("\r\n").split("\t")
        if len(cols) < 8:
            return None

        f_num = cols[0]
        f_time = cols[1]
        f_len = cols[2]
        ip_src = cols[3]
        ipv6_src = cols[4]
        ip_dst = cols[5]
        ipv6_dst = cols[6]
        raw_protocols = cols[7].strip()

        tcp_sport = cols[8] if len(cols) > 8 else ""
        udp_sport = cols[9] if len(cols) > 9 else ""
        tcp_dport = cols[10] if len(cols) > 10 else ""
        udp_dport = cols[11] if len(cols) > 11 else ""
        tcp_stream_raw = cols[12] if len(cols) > 12 else ""

        # L4 Transport Resolution
        if tcp_sport or tcp_dport:
            transport_protocol = "TCP"
        elif udp_sport or udp_dport:
            transport_protocol = "UDP"
        elif "tcp" in raw_protocols.lower().split(":"):
            transport_protocol = "TCP"
        elif "udp" in raw_protocols.lower().split(":"):
            transport_protocol = "UDP"
        else:
            transport_protocol = "RAW"

        # Protocol / Highest-Layer Resolution
        if raw_protocols:
            tokens = [tok for tok in raw_protocols.split(":") if tok]
            highest_layer = tokens[-1].upper() if tokens else transport_protocol
        else:
            highest_layer = transport_protocol

        src_ip = ip_src or ipv6_src or None
        dst_ip = ip_dst or ipv6_dst or None
        src_port = int(tcp_sport) if tcp_sport.isdigit() else (int(udp_sport) if udp_sport.isdigit() else None)
        dst_port = int(tcp_dport) if tcp_dport.isdigit() else (int(udp_dport) if udp_dport.isdigit() else None)
        tcp_stream = int(tcp_stream_raw) if tcp_stream_raw.isdigit() else None

        return DissectedPacket(
            frame_number=int(f_num) if f_num.isdigit() else 0,
            timestamp_epoch=float(f_time) if f_time else 0.0,
            frame_len=int(f_len) if f_len.isdigit() else 0,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport_protocol,
            tcp_stream=tcp_stream,
            highest_layer=highest_layer,
        )

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def dissect_packets_stream(self, pcap_path: Path) -> Generator[DissectedPacket, None, None]:
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        cmd = self._build_command(pcap_path)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                packet = self.parse_line(line)
                if packet:
                    yield packet

            proc.wait()
            if proc.returncode != 0:
                stderr_output = proc.stderr.read() if proc.stderr else ""
                if "Some fields aren't valid" in stderr_output or "not valid" in stderr_output:
                    raise TSharkExecutionError(f"TShark field error: {stderr_output.strip()}")
                logger.warning("TShark exited with code %s: %s", proc.returncode, stderr_output.strip())

        except Exception:
            self._terminate_process(proc)
            raise
        finally:
            if proc.poll() is None:
                self._terminate_process(proc)


tshark_service = TSharkService()