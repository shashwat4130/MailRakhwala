"""
MailRakhwala TShark Dissection Service (Step 07 & Step 08)
Safe subprocess-driven packet dissection engine with robust streaming, bounded concurrency, line flushing,
and safe hex payload conversion.
"""

from collections import deque
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Generator, List, Optional

from app.core.config import settings
from app.schemas.packet import DissectedPacket, DissectionSummary


class TSharkError(Exception):
    """Base exception for TShark invocation and parsing errors."""
    pass


class TSharkNotFoundError(TSharkError):
    """Raised when the tshark binary is not found on PATH or configured location."""
    pass


class TSharkExecutionError(TSharkError):
    """Raised when TShark exits with a non-zero code or encounters an unrecoverable error."""
    pass


class TSharkTimeoutError(TSharkError):
    """Raised when packet dissection exceeds the configured timeout."""
    pass


class TSharkService:
    """Service encapsulating defensive execution of TShark."""

    DISSECTION_FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "_ws.col.Protocol",
        "tcp.srcport",
        "udp.srcport",
        "tcp.dstport",
        "udp.dstport",
        "tcp.stream",
        "_ws.col.DefProto",
        "tcp.seq",
        "tcp.ack",
        "tcp.flags",
        "tcp.len",
        "tcp.payload",
    ]

    DEFAULT_TIMEOUT_SECONDS = 60
    MAX_LINE_LENGTH = 65536
    MAX_STDERR_LINES = 50

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._find_tshark()

    @staticmethod
    def _find_tshark() -> Optional[str]:
        found = shutil.which("tshark")
        if found:
            return found

        common_windows_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for p in common_windows_paths:
            if os.path.isfile(p):
                return p

        return None

    def is_available(self) -> bool:
        return self.binary_path is not None and os.path.isfile(self.binary_path)

    def get_version(self) -> str:
        if not self.is_available():
            raise TSharkNotFoundError("TShark binary is not installed or not in PATH.")

        try:
            proc = subprocess.run(
                [self.binary_path, "-v"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            if proc.returncode != 0:
                raise TSharkExecutionError(f"TShark version check failed: {proc.stderr.strip()}")
            first_line = proc.stdout.splitlines()[0] if proc.stdout else "Unknown"
            return first_line.strip()
        except subprocess.TimeoutExpired as exc:
            raise TSharkTimeoutError("TShark version query timed out.") from exc
        except Exception as exc:
            raise TSharkError(f"Failed to inspect TShark: {str(exc)}") from exc

    def _build_command(self, pcap_path: Path) -> List[str]:
        cmd = [
            self.binary_path,
            "-r", str(pcap_path.resolve()),
            "-l",
            "-n",
            "-q",
            "-T", "fields",
            "-E", "separator=/t",
            "-E", "occurrence=f",
        ]
        for f in self.DISSECTION_FIELDS:
            cmd.extend(["-e", f])
        return cmd

    def parse_line(self, line: str) -> Optional[DissectedPacket]:
        line = line.rstrip("\r\n")
        if not line:
            return None

        parts = line.split("\t")
        if len(parts) < len(self.DISSECTION_FIELDS):
            parts.extend([""] * (len(self.DISSECTION_FIELDS) - len(parts)))

        (
            f_num, f_time, f_len,
            ip_src, ipv6_src,
            ip_dst, ipv6_dst,
            protocol_col,
            tcp_sport, udp_sport,
            tcp_dport, udp_dport,
            tcp_stream,
            def_proto,
            t_seq, t_ack, t_flags, t_len, t_payload
        ) = parts[:len(self.DISSECTION_FIELDS)]

        try:
            frame_number = int(f_num)
        except (ValueError, TypeError):
            return None

        try:
            frame_len = int(f_len)
        except (ValueError, TypeError):
            frame_len = 0

        timestamp_epoch = None
        if f_time:
            try:
                timestamp_epoch = float(f_time)
            except ValueError:
                pass

        src_ip = ip_src or ipv6_src or None
        dst_ip = ip_dst or ipv6_dst or None

        src_port = None
        if tcp_sport:
            try:
                src_port = int(tcp_sport)
            except ValueError:
                pass
        elif udp_sport:
            try:
                src_port = int(udp_sport)
            except ValueError:
                pass

        dst_port = None
        if tcp_dport:
            try:
                dst_port = int(tcp_dport)
            except ValueError:
                pass
        elif udp_dport:
            try:
                dst_port = int(udp_dport)
            except ValueError:
                pass

        transport = None
        if tcp_sport or tcp_dport:
            transport = "TCP"
        elif udp_sport or udp_dport:
            transport = "UDP"
        elif protocol_col:
            transport = protocol_col

        stream_idx = None
        if tcp_stream:
            try:
                stream_idx = int(tcp_stream)
            except ValueError:
                pass

        highest_layer = def_proto or protocol_col or transport or None

        tcp_seq = None
        if t_seq:
            try:
                tcp_seq = int(t_seq)
            except ValueError:
                pass

        tcp_ack = None
        if t_ack:
            try:
                tcp_ack = int(t_ack)
            except ValueError:
                pass

        tcp_flags = None
        if t_flags:
            try:
                tcp_flags = int(t_flags, 16) if t_flags.startswith("0x") else int(t_flags)
            except ValueError:
                pass

        tcp_payload_len = None
        if t_len:
            try:
                tcp_payload_len = int(t_len)
            except ValueError:
                pass

        payload_bytes = None
        if t_payload:
            clean_hex = t_payload.replace(":", "").strip()
            try:
                payload_bytes = bytes.fromhex(clean_hex)
            except (ValueError, TypeError):
                payload_bytes = None

        return DissectedPacket(
            frame_number=frame_number,
            timestamp_epoch=timestamp_epoch,
            frame_len=frame_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport,
            tcp_stream=stream_idx,
            highest_layer=highest_layer,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_flags=tcp_flags,
            tcp_payload_len=tcp_payload_len,
            payload=payload_bytes
        )

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except OSError:
                pass

    def dissect_packets_stream(
        self,
        pcap_path: Path,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_frames: Optional[int] = None
    ) -> Generator[DissectedPacket, None, DissectionSummary]:
        if not self.is_available():
            raise TSharkNotFoundError("TShark is not installed or could not be found.")

        resolved_pcap = pcap_path.resolve()
        upload_root = settings.UPLOAD_DIR.resolve()
        if upload_root not in resolved_pcap.parents and resolved_pcap.parent != upload_root:
            raise TSharkError("Illegal capture file location outside upload directory.")

        if not resolved_pcap.is_file():
            raise TSharkError("Capture file does not exist.")

        cmd = self._build_command(resolved_pcap)
        summary = DissectionSummary()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except OSError as exc:
            raise TSharkExecutionError(f"Failed to start TShark process: {str(exc)}") from exc

        stderr_deque: deque = deque(maxlen=self.MAX_STDERR_LINES)

        def _drain_stderr():
            if proc.stderr:
                try:
                    for err_line in proc.stderr:
                        stderr_deque.append(err_line)
                except (ValueError, OSError):
                    pass

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        watchdog_triggered = threading.Event()

        def _watchdog_handler():
            watchdog_triggered.set()
            self._terminate_process(proc)

        watchdog_timer = threading.Timer(float(timeout), _watchdog_handler)
        watchdog_timer.start()

        deadline = time.monotonic() + timeout

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if watchdog_triggered.is_set() or time.monotonic() > deadline:
                    raise TSharkTimeoutError(f"TShark packet dissection timed out after {timeout} seconds.")

                if len(line) > self.MAX_LINE_LENGTH:
                    summary.error_count += 1
                    continue

                packet = self.parse_line(line)
                if packet is None:
                    summary.error_count += 1
                    continue

                summary.total_frames += 1
                if packet.transport_protocol == "TCP":
                    summary.tcp_frames += 1
                elif packet.transport_protocol == "UDP":
                    summary.udp_frames += 1
                else:
                    summary.other_frames += 1

                yield packet

                if max_frames and summary.total_frames >= max_frames:
                    self._terminate_process(proc)
                    break

            if proc.poll() is None:
                proc.wait(timeout=max(0.5, deadline - time.monotonic()))

            stderr_thread.join(timeout=1.0)

            if watchdog_triggered.is_set():
                raise TSharkTimeoutError(f"TShark packet dissection timed out after {timeout} seconds.")

            if proc.returncode != 0 and summary.total_frames == 0:
                err_msg = "".join(stderr_deque).strip()
                raise TSharkExecutionError(f"TShark dissection failed: {err_msg}")

        except subprocess.TimeoutExpired as exc:
            self._terminate_process(proc)
            raise TSharkTimeoutError(f"TShark packet dissection timed out after {timeout} seconds.") from exc
        finally:
            watchdog_timer.cancel()
            self._terminate_process(proc)
            if proc.stdout:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if proc.stderr:
                try:
                    proc.stderr.close()
                except OSError:
                    pass
            stderr_thread.join(timeout=1.0)

        return summary


tshark_service = TSharkService()