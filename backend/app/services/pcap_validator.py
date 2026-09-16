"""
PCAP and PCAPNG Header Validator (Step 06)
Defensive binary inspection for libpcap and pcapng file magic and structures.
"""

from enum import Enum
from typing import Tuple

# Classic PCAP magic bytes
MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAP_NANO_LE = b"\x4d\x3b\xb2\xa1"
MAGIC_PCAP_NANO_BE = b"\xa1\xb2\x3b\x4d"

# PCAPNG magic bytes and byte order magic
MAGIC_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
PCAPNG_BOM_LE = b"\x1a\x2b\x3c\x4d"
PCAPNG_BOM_BE = b"\x4d\x3c\x2b\x1a"

MIN_PCAP_GLOBAL_HEADER_LEN = 24
MIN_PCAPNG_SHB_LEN = 28
MAX_PCAPNG_SHB_LEN = 65536


class ValidationStatus(str, Enum):
    VALID_PCAP = "VALID_PCAP"
    VALID_PCAPNG = "VALID_PCAPNG"
    INVALID_HEADER = "INVALID_HEADER"
    UNSUPPORTED_EXTENSION = "UNSUPPORTED_EXTENSION"
    EMPTY_FILE = "EMPTY_FILE"
    TRUNCATED_HEADER = "TRUNCATED_HEADER"


class CaptureFormat(str, Enum):
    PCAP_MICROSECONDS_LE = "PCAP_MICROSECONDS_LE"
    PCAP_MICROSECONDS_BE = "PCAP_MICROSECONDS_BE"
    PCAP_NANOSECONDS_LE = "PCAP_NANOSECONDS_LE"
    PCAP_NANOSECONDS_BE = "PCAP_NANOSECONDS_BE"
    PCAPNG_LE = "PCAPNG_LE"
    PCAPNG_BE = "PCAPNG_BE"


class PCAPValidationError(Exception):
    def __init__(self, status: ValidationStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def validate_file_extension(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".pcap"):
        return ".pcap"
    elif lower.endswith(".pcapng"):
        return ".pcapng"
    raise PCAPValidationError(
        ValidationStatus.UNSUPPORTED_EXTENSION,
        f"Unsupported file extension. Expected .pcap or .pcapng, got '{filename}'."
    )


def inspect_capture_header(header_bytes: bytes, suffix: str) -> Tuple[ValidationStatus, CaptureFormat]:
    if not header_bytes:
        raise PCAPValidationError(ValidationStatus.EMPTY_FILE, "Capture file is empty.")

    if suffix == ".pcap":
        if len(header_bytes) < MIN_PCAP_GLOBAL_HEADER_LEN:
            raise PCAPValidationError(
                ValidationStatus.TRUNCATED_HEADER,
                f"Truncated PCAP header: expected 24 bytes, received {len(header_bytes)} bytes."
            )

        magic = header_bytes[:4]
        if magic == MAGIC_PCAP_LE:
            return ValidationStatus.VALID_PCAP, CaptureFormat.PCAP_MICROSECONDS_LE
        elif magic == MAGIC_PCAP_BE:
            return ValidationStatus.VALID_PCAP, CaptureFormat.PCAP_MICROSECONDS_BE
        elif magic == MAGIC_PCAP_NANO_LE:
            return ValidationStatus.VALID_PCAP, CaptureFormat.PCAP_NANOSECONDS_LE
        elif magic == MAGIC_PCAP_NANO_BE:
            return ValidationStatus.VALID_PCAP, CaptureFormat.PCAP_NANOSECONDS_BE
        else:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"Invalid PCAP magic bytes: {magic.hex()}"
            )

    elif suffix == ".pcapng":
        if len(header_bytes) < MIN_PCAPNG_SHB_LEN:
            raise PCAPValidationError(
                ValidationStatus.TRUNCATED_HEADER,
                f"Truncated PCAPNG header: expected >= 28 bytes, received {len(header_bytes)} bytes."
            )

        block_type = header_bytes[:4]
        if block_type != MAGIC_PCAPNG_SHB:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"Invalid PCAPNG SHB block type: {block_type.hex()}"
            )

        bom = header_bytes[8:12]
        if bom == PCAPNG_BOM_LE:
            order = "little"
            fmt = CaptureFormat.PCAPNG_LE
        elif bom == PCAPNG_BOM_BE:
            order = "big"
            fmt = CaptureFormat.PCAPNG_BE
        else:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"Invalid PCAPNG Byte Order Magic: {bom.hex()}"
            )

        leading_len = int.from_bytes(header_bytes[4:8], byteorder=order)
        if leading_len < MIN_PCAPNG_SHB_LEN:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"PCAPNG SHB total length ({leading_len}) is smaller than minimum 28 bytes."
            )
        if leading_len % 4 != 0:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"PCAPNG SHB total length ({leading_len}) is not aligned to 32-bit (4-byte) boundary."
            )
        if leading_len > MAX_PCAPNG_SHB_LEN:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"PCAPNG SHB total length ({leading_len}) exceeds defensive limit of {MAX_PCAPNG_SHB_LEN} bytes."
            )

        if len(header_bytes) < leading_len:
            raise PCAPValidationError(
                ValidationStatus.TRUNCATED_HEADER,
                f"PCAPNG SHB is truncated: declared length {leading_len} bytes, but only {len(header_bytes)} bytes available."
            )

        trailing_len = int.from_bytes(header_bytes[leading_len - 4:leading_len], byteorder=order)
        if leading_len != trailing_len:
            raise PCAPValidationError(
                ValidationStatus.INVALID_HEADER,
                f"PCAPNG SHB trailing length ({trailing_len}) does not match leading length ({leading_len})."
            )

        return ValidationStatus.VALID_PCAPNG, fmt

    raise PCAPValidationError(ValidationStatus.UNSUPPORTED_EXTENSION, f"Unrecognized capture extension '{suffix}'.")