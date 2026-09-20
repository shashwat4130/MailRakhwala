import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Generator, List, Optional

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
    """
    TShark-backed packet dissection service.

    The parser intentionally preserves the TCP metadata required by the
    TCP reassembly layer:
      - tcp.stream
      - TCP sequence / acknowledgement numbers
      - TCP flags
      - TCP payload

    TLS metadata is also retained for downstream protocol/TLS analysis.
    """

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

        # TCP reassembly fields
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.flags.fin",
        "tcp.flags.reset",
        "tcp.seq",
        "tcp.ack",
        "tcp.payload",

        # TLS evidence
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
            raise TSharkNotFoundError(
                "TShark binary could not be found on the system."
            )

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
        return (
            self.binary_path is not None
            and os.path.isfile(self.binary_path)
        )

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

            first_line = (
                result.stdout.splitlines()[0]
                if result.stdout
                else "unknown"
            )

            return first_line

        except Exception as err:
            logger.warning(
                "Failed to determine TShark version: %s",
                err,
            )
            return "unknown"

    def _build_command(self, pcap_path: Path) -> List[str]:
        cmd = [
            self.binary_path,
            "-r",
            str(pcap_path),
            "-T",
            "fields",

            # Tab-separated fields.
            "-E",
            "separator=/t",

            # Only the first occurrence of each field.
            "-E",
            "occurrence=f",
        ]

        for field in self.DISSECTION_FIELDS:
            cmd.extend(["-e", field])

        return cmd

    def build_command(self, pcap_path: Path) -> List[str]:
        return self._build_command(pcap_path)

    @staticmethod
    def _parse_int(value: str) -> Optional[int]:
        """
        Parse decimal or hexadecimal TShark numeric output.
        """
        value = (value or "").strip()

        if not value:
            return None

        try:
            if value.lower().startswith("0x"):
                return int(value, 16)

            return int(value, 10)

        except ValueError:
            return None

    @staticmethod
    def _parse_float(value: str) -> Optional[float]:
        value = (value or "").strip()

        if not value:
            return None

        try:
            return float(value)

        except ValueError:
            return None

    @staticmethod
    def _parse_payload(value: str) -> Optional[bytes]:
        """
        Convert TShark tcp.payload output into raw bytes.

        TShark commonly emits payload as hexadecimal octets, for example:

            16:03:03:00:2f:01:00:00:2b

        Some builds may emit continuous hexadecimal:

            160303002f0100002b

        Both representations are accepted.
        """
        value = (value or "").strip()

        if not value:
            return None

        # Remove common separators used by TShark.
        normalized = (
            value.replace(":", "")
            .replace(" ", "")
            .replace("-", "")
        )

        if not normalized:
            return None

        # Hex must contain complete octets.
        if len(normalized) % 2 != 0:
            logger.debug(
                "Ignoring malformed TCP payload with odd hex length: %s",
                value,
            )
            return None

        try:
            return bytes.fromhex(normalized)

        except ValueError:
            logger.debug(
                "Ignoring malformed TCP payload: %s",
                value,
            )
            return None

    @staticmethod
    def _parse_tcp_flags(
        syn_value: str,
        ack_value: str,
        fin_value: str,
        reset_value: str,
    ) -> int:
        """
        Build the TCP control-flag bitmask expected by the reassembly layer.

        The reassembly service uses the standard TCP flag values:

            SYN = 0x02
            ACK = 0x10
            FIN = 0x01
            RST = 0x04
        """

        flags = 0

        syn = TSharkService._parse_int(syn_value)
        ack = TSharkService._parse_int(ack_value)
        fin = TSharkService._parse_int(fin_value)
        reset = TSharkService._parse_int(reset_value)

        if syn:
            flags |= 0x02

        if ack:
            flags |= 0x10

        if fin:
            flags |= 0x01

        if reset:
            flags |= 0x04

        return flags

    def parse_line(self, line: str) -> Optional[DissectedPacket]:
        """
        Parse one tab-separated TShark fields output line.

        Field ordering MUST match DISSECTION_FIELDS exactly.
        """

        cols = line.rstrip("\r\n").split("\t")

        if len(cols) < len(self.DISSECTION_FIELDS):
            logger.debug(
                "Skipping incomplete TShark line: expected %d fields, got %d",
                len(self.DISSECTION_FIELDS),
                len(cols),
            )
            return None

        # ------------------------------------------------------------------
        # Basic frame / addressing fields
        # ------------------------------------------------------------------

        f_num = cols[0]
        f_time = cols[1]
        f_len = cols[2]

        ip_src = cols[3]
        ipv6_src = cols[4]

        ip_dst = cols[5]
        ipv6_dst = cols[6]

        raw_protocols = cols[7].strip()

        # ------------------------------------------------------------------
        # Transport fields
        # ------------------------------------------------------------------

        tcp_sport = cols[8].strip()
        udp_sport = cols[9].strip()

        tcp_dport = cols[10].strip()
        udp_dport = cols[11].strip()

        tcp_stream_raw = cols[12].strip()

        # ------------------------------------------------------------------
        # TCP reassembly fields
        # ------------------------------------------------------------------

        tcp_syn_raw = cols[13].strip()
        tcp_ack_flag_raw = cols[14].strip()
        tcp_fin_raw = cols[15].strip()
        tcp_reset_raw = cols[16].strip()

        tcp_seq_raw = cols[17].strip()
        tcp_ack_raw = cols[18].strip()

        tcp_payload_raw = cols[19].strip()

        # ------------------------------------------------------------------
        # TLS fields
        # ------------------------------------------------------------------

        # These are intentionally parsed/preserved even though the current
        # DissectedPacket schema stores the primary protocol evidence through
        # highest_layer/frame.protocols.
        tls_record_version = cols[20].strip()
        tls_handshake_type = cols[21].strip()
        tls_handshake_version = cols[22].strip()
        tls_ciphersuite = cols[23].strip()
        tls_server_name = cols[24].strip()
        tls_sig_hash_alg = cols[25].strip()

        # Prevent unused-field warnings and make it explicit that these
        # fields are intentionally requested for TShark/TLS evidence.
        _ = (
            tls_record_version,
            tls_handshake_type,
            tls_handshake_version,
            tls_ciphersuite,
            tls_server_name,
            tls_sig_hash_alg,
        )

        # ------------------------------------------------------------------
        # L4 transport resolution
        # ------------------------------------------------------------------

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

        # ------------------------------------------------------------------
        # Highest protocol layer
        # ------------------------------------------------------------------

        if raw_protocols:
            tokens = [
                token
                for token in raw_protocols.split(":")
                if token
            ]

            highest_layer = (
                tokens[-1].upper()
                if tokens
                else transport_protocol
            )

        else:
            highest_layer = transport_protocol

        # ------------------------------------------------------------------
        # Address / port / stream parsing
        # ------------------------------------------------------------------

        src_ip = ip_src or ipv6_src or None
        dst_ip = ip_dst or ipv6_dst or None

        src_port = (
            self._parse_int(tcp_sport)
            if tcp_sport
            else self._parse_int(udp_sport)
        )

        dst_port = (
            self._parse_int(tcp_dport)
            if tcp_dport
            else self._parse_int(udp_dport)
        )

        tcp_stream = self._parse_int(tcp_stream_raw)

        # ------------------------------------------------------------------
        # TCP sequence / flags / payload
        # ------------------------------------------------------------------

        tcp_seq = self._parse_int(tcp_seq_raw)
        tcp_ack = self._parse_int(tcp_ack_raw)

        tcp_flags = self._parse_tcp_flags(
            syn_value=tcp_syn_raw,
            ack_value=tcp_ack_flag_raw,
            fin_value=tcp_fin_raw,
            reset_value=tcp_reset_raw,
        )

        payload = self._parse_payload(tcp_payload_raw)

        payload_len = len(payload) if payload is not None else None

        # ------------------------------------------------------------------
        # Build normalized packet
        # ------------------------------------------------------------------

        frame_number = self._parse_int(f_num)
        frame_len = self._parse_int(f_len)
        timestamp_epoch = self._parse_float(f_time)

        return DissectedPacket(
            frame_number=frame_number if frame_number is not None else 0,
            timestamp_epoch=timestamp_epoch,
            frame_len=frame_len if frame_len is not None else 0,

            src_ip=src_ip,
            dst_ip=dst_ip,

            src_port=src_port,
            dst_port=dst_port,

            transport_protocol=transport_protocol,

            tcp_stream=tcp_stream,
            highest_layer=highest_layer,

            # Step 08 TCP reconstruction data
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_flags=tcp_flags,
            tcp_payload_len=payload_len,
            payload=payload,
        )

    def _terminate_process(
        self,
        proc: subprocess.Popen,
    ) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=2)

        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def dissect_packets_stream(
        self,
        pcap_path: Path,
    ) -> Generator[DissectedPacket, None, None]:
        """
        Stream parsed packets from TShark.

        No filename-specific logic exists here. All protocol evidence comes
        from actual packet fields.
        """

        if not pcap_path.is_file():
            raise FileNotFoundError(
                f"PCAP not found: {pcap_path}"
            )

        cmd = self._build_command(pcap_path)

        logger.info(
            "Starting TShark dissection: %s",
            pcap_path,
        )

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

                if packet is not None:
                    yield packet

            proc.wait()

            if proc.returncode != 0:
                stderr_output = (
                    proc.stderr.read()
                    if proc.stderr
                    else ""
                )

                if (
                    "Some fields aren't valid" in stderr_output
                    or "not valid" in stderr_output
                ):
                    raise TSharkExecutionError(
                        f"TShark field error: {stderr_output.strip()}"
                    )

                logger.warning(
                    "TShark exited with code %s: %s",
                    proc.returncode,
                    stderr_output.strip(),
                )

        except Exception:
            self._terminate_process(proc)
            raise

        finally:
            if proc.poll() is None:
                self._terminate_process(proc)


tshark_service = TSharkService()