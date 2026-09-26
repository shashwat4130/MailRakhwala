import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from collections import deque
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

    The parser preserves the TCP metadata required by the TCP reassembly
    layer and the TLS metadata required by downstream analysis.

    TShark stdout is consumed incrementally so the entire packet capture
    does not have to be loaded into memory at once.
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

        # Keep this configurable without requiring a config.py change yet.
        # Default: 120 seconds of no output / stalled processing.
        self.timeout_sec = float(
            getattr(settings, "TSHARK_TIMEOUT_SEC", 120.0)
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
        """
        Build a deterministic TShark fields command.

        IMPORTANT:
        separator must be an actual TAB character.

        The previous implementation used:
            separator=/t

        which does not produce tab-separated output and can cause the
        parser to reject otherwise valid TShark lines.
        """

        cmd = [
            self.binary_path,
            "-r",
            str(pcap_path),

            # Flush stdout after each dissected packet so the Python
            # streaming reader receives output immediately.
            "-l",

            "-T",
            "fields",

            # Actual tab separator.
            "-E",
            "separator=\t",

            # First occurrence of each field.
            "-E",
            "occurrence=f",
        ]

        for field in self.DISSECTION_FIELDS:
            cmd.extend(["-e", field])

        return cmd

    def build_command(self, pcap_path: Path) -> List[str]:
        """
        Public compatibility wrapper used by tests and callers.
        """
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

        Examples accepted:

            16:03:03:00:2f:01:00:00:2b

        and:

            160303002f0100002b
        """

        value = (value or "").strip()

        if not value:
            return None

        normalized = (
            value.replace(":", "")
            .replace(" ", "")
            .replace("-", "")
        )

        if not normalized:
            return None

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

        tls_record_version = cols[20].strip()
        tls_handshake_type = cols[21].strip()
        tls_handshake_version = cols[22].strip()
        tls_ciphersuite = cols[23].strip()
        tls_server_name = cols[24].strip()
        tls_sig_hash_alg = cols[25].strip()

        # These fields are intentionally requested and retained at the
        # TShark layer for future/downstream TLS evidence handling.
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

            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_flags=tcp_flags,
            tcp_payload_len=payload_len,
            payload=payload,
        )

    @staticmethod
    def _terminate_process(proc: subprocess.Popen) -> None:
        """
        Best-effort process termination.

        terminate() is attempted first, followed by kill() if the process
        does not exit quickly.
        """

        if proc.poll() is not None:
            return

        try:
            proc.terminate()
            proc.wait(timeout=2)

        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass

    @staticmethod
    def _terminate_process(proc: subprocess.Popen) -> None:
        """
        Best-effort process termination.

        terminate() is attempted first, followed by kill() if the process
        does not exit quickly.
        """

        if proc.poll() is not None:
            return

        try:
            proc.terminate()
            proc.wait(timeout=2)

        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass

    def dissect_packets_stream(
        self,
        pcap_path: Path,
    ) -> Generator[DissectedPacket, None, None]:
        """
        Stream parsed packets from TShark.

        stdout is consumed directly by the calling thread using readline().
        stderr is drained independently so its OS pipe cannot block TShark.

        A watchdog guarantees that a stalled TShark process cannot leave the
        analysis hanging indefinitely.
        """

        if not pcap_path.is_file():
            raise FileNotFoundError(
                f"PCAP not found: {pcap_path}"
            )

        if not self.is_available():
            raise TSharkNotFoundError(
                "TShark binary could not be found on the system."
            )

        cmd = self._build_command(pcap_path)

        logger.info(
            "Starting TShark dissection: %s",
            pcap_path,
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

        except FileNotFoundError as err:
            raise TSharkNotFoundError(
                f"Unable to execute TShark: {self.binary_path}"
            ) from err

        except OSError as err:
            raise TSharkExecutionError(
                f"Unable to start TShark: {err}"
            ) from err

        assert proc.stdout is not None
        assert proc.stderr is not None

        # Drain stderr continuously. If stderr fills its OS pipe,
        # TShark can block even while stdout is being consumed.
        stderr_lines = deque(maxlen=200)

        def drain_stderr() -> None:
            try:
                while True:
                    line = proc.stderr.readline()

                    if line == "":
                        break

                    stderr_lines.append(line.rstrip("\r\n"))

            except (ValueError, OSError):
                pass

        stderr_thread = threading.Thread(
            target=drain_stderr,
            daemon=True,
            name="tshark-stderr-reader",
        )
        stderr_thread.start()

        # Hard watchdog. readline() itself can block, so the timeout
        # must live independently of the stdout-consuming thread.
        watchdog_triggered = threading.Event()

        def watchdog() -> None:
            if proc.poll() is None:
                watchdog_triggered.set()
                logger.error(
                    "TShark watchdog triggered after %.1f seconds: %s",
                    self.timeout_sec,
                    pcap_path,
                )
                self._terminate_process(proc)

        watchdog_timer = threading.Timer(
            self.timeout_sec,
            watchdog,
        )
        watchdog_timer.daemon = True
        watchdog_timer.start()

        packet_count = 0

        try:
            # Read stdout directly. This has been verified independently
            # against the installed Windows TShark binary.
            while True:
                line = proc.stdout.readline()

                if line == "":
                    break

                if watchdog_triggered.is_set():
                    raise TSharkTimeoutError(
                        "TShark packet dissection timed out after "
                        f"{self.timeout_sec:.1f} seconds."
                    )

                packet = self.parse_line(line)

                if packet is None:
                    continue

                packet_count += 1
                yield packet

            # Wait briefly for normal TShark termination.
            if proc.poll() is None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._terminate_process(proc)

            if watchdog_triggered.is_set():
                raise TSharkTimeoutError(
                    "TShark packet dissection timed out after "
                    f"{self.timeout_sec:.1f} seconds."
                )

            return_code = proc.returncode
            stderr_output = "\n".join(stderr_lines).strip()

            if return_code != 0:
                raise TSharkExecutionError(
                    "TShark exited with code "
                    f"{return_code}: {stderr_output}"
                )

            if stderr_output:
                logger.debug(
                    "TShark stderr: %s",
                    stderr_output,
                )

            logger.info(
                "TShark dissection completed: %d packets",
                packet_count,
            )

        except TSharkError:
            self._terminate_process(proc)
            raise

        except Exception:
            self._terminate_process(proc)
            raise

        finally:
            watchdog_timer.cancel()

            if proc.poll() is None:
                self._terminate_process(proc)

            try:
                proc.stdout.close()
            except (ValueError, OSError):
                pass

            try:
                proc.stderr.close()
            except (ValueError, OSError):
                pass

            stderr_thread.join(timeout=1)

tshark_service = TSharkService()