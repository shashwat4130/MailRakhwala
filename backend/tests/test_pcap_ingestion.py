"""
Tests for Step 06: Secure PCAP Ingestion
Validates magic numbers, endianness, truncated headers, size bounds, and path containment.
"""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.job_store import job_store
from app.services.pcap_validator import (
    MAGIC_PCAP_BE,
    MAGIC_PCAP_LE,
    MAGIC_PCAPNG_SHB,
    CaptureFormat,
    PCAPValidationError,
    ValidationStatus,
    inspect_capture_header,
    validate_file_extension,
)

client = TestClient(app)

# Standard synthetic 24-byte PCAP header (v2.4, LE)
SYNTHETIC_PCAP_LE_HEADER = (
    MAGIC_PCAP_LE +
    (2).to_bytes(2, "little") +
    (4).to_bytes(2, "little") +
    (0).to_bytes(4, "little") +
    (0).to_bytes(4, "little") +
    (65535).to_bytes(4, "little") +
    (1).to_bytes(4, "little")
)

# Standard synthetic 24-byte PCAP header (v2.4, BE)
SYNTHETIC_PCAP_BE_HEADER = (
    MAGIC_PCAP_BE +
    (2).to_bytes(2, "big") +
    (4).to_bytes(2, "big") +
    (0).to_bytes(4, "big") +
    (0).to_bytes(4, "big") +
    (65535).to_bytes(4, "big") +
    (1).to_bytes(4, "big")
)

# Valid synthetic 28-byte PCAPNG Section Header Block (SHB, LE)
SYNTHETIC_PCAPNG_SHB_LE = (
    MAGIC_PCAPNG_SHB +
    (28).to_bytes(4, "little") +                      # Block Total Length = 28
    b"\x1a\x2b\x3c\x4d" +                             # Byte Order Magic (LE)
    (1).to_bytes(2, "little") +                       # Major Version = 1
    (0).to_bytes(2, "little") +                       # Minor Version = 0
    (-1 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + # Section Length = -1 (unspecified)
    (28).to_bytes(4, "little")                        # Trailing Block Total Length = 28
)

# Valid synthetic 28-byte PCAPNG Section Header Block (SHB, BE)
SYNTHETIC_PCAPNG_SHB_BE = (
    MAGIC_PCAPNG_SHB +
    (28).to_bytes(4, "big") +                         # Block Total Length = 28
    b"\x4d\x3c\x2b\x1a" +                             # Byte Order Magic (BE)
    (1).to_bytes(2, "big") +                          # Major Version = 1
    (0).to_bytes(2, "big") +                          # Minor Version = 0
    (-1 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big") +    # Section Length = -1 (unspecified)
    (28).to_bytes(4, "big")                           # Trailing Block Total Length = 28
)


@pytest.fixture(autouse=True)
def clean_job_store():
    job_store.clear()
    yield
    job_store.clear()


# --- Unit Tests ---

def test_extension_validation_success():
    assert validate_file_extension("traffic.pcap") == ".pcap"
    assert validate_file_extension("TRAFFIC.PCAPNG") == ".pcapng"


def test_extension_validation_failures():
    with pytest.raises(PCAPValidationError) as exc:
        validate_file_extension("malicious.exe")
    assert exc.value.status == ValidationStatus.UNSUPPORTED_EXTENSION


def test_inspect_valid_pcap_le():
    status, fmt = inspect_capture_header(SYNTHETIC_PCAP_LE_HEADER, ".pcap")
    assert status == ValidationStatus.VALID_PCAP
    assert fmt == CaptureFormat.PCAP_MICROSECONDS_LE


def test_inspect_valid_pcap_be():
    status, fmt = inspect_capture_header(SYNTHETIC_PCAP_BE_HEADER, ".pcap")
    assert status == ValidationStatus.VALID_PCAP
    assert fmt == CaptureFormat.PCAP_MICROSECONDS_BE


def test_inspect_valid_pcapng_shb_le():
    status, fmt = inspect_capture_header(SYNTHETIC_PCAPNG_SHB_LE, ".pcapng")
    assert status == ValidationStatus.VALID_PCAPNG
    assert fmt == CaptureFormat.PCAPNG_LE


def test_inspect_valid_pcapng_shb_be():
    status, fmt = inspect_capture_header(SYNTHETIC_PCAPNG_SHB_BE, ".pcapng")
    assert status == ValidationStatus.VALID_PCAPNG
    assert fmt == CaptureFormat.PCAPNG_BE


def test_inspect_empty_file():
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(b"", ".pcap")
    assert exc.value.status == ValidationStatus.EMPTY_FILE


def test_inspect_too_short_file():
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(b"\xd4\xc3", ".pcap")
    assert exc.value.status == ValidationStatus.TRUNCATED_HEADER


def test_inspect_truncated_pcap_header():
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(MAGIC_PCAP_LE + b"123456", ".pcap")
    assert exc.value.status == ValidationStatus.TRUNCATED_HEADER


def test_inspect_truncated_pcapng_shb():
    truncated = SYNTHETIC_PCAPNG_SHB_LE[:16]
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(truncated, ".pcapng")
    assert exc.value.status == ValidationStatus.TRUNCATED_HEADER


def test_inspect_pcapng_invalid_block_length_unaligned():
    unaligned = (
        MAGIC_PCAPNG_SHB +
        (29).to_bytes(4, "little") +
        b"\x1a\x2b\x3c\x4d" +
        (1).to_bytes(2, "little") +
        (0).to_bytes(2, "little") +
        b"\x00" * 8 +
        (29).to_bytes(4, "little") +
        b"\x00"
    )
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(unaligned, ".pcapng")
    assert exc.value.status == ValidationStatus.INVALID_HEADER
    assert "boundary" in exc.value.message.lower()


def test_inspect_pcapng_inconsistent_block_length():
    inconsistent = (
        MAGIC_PCAPNG_SHB +
        (28).to_bytes(4, "little") +
        b"\x1a\x2b\x3c\x4d" +
        (1).to_bytes(2, "little") +
        (0).to_bytes(2, "little") +
        b"\x00" * 8 +
        (32).to_bytes(4, "little")
    )
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(inconsistent, ".pcapng")
    assert exc.value.status == ValidationStatus.INVALID_HEADER
    assert "does not match leading length" in exc.value.message.lower()


def test_inspect_valid_large_pcapng_shb_with_options():
    options_payload = (
        (4).to_bytes(2, "little") +
        (120).to_bytes(2, "little") +
        (b"MailRakhwala Forensic Capture Test Harness" + b"\x00" * 78) +  # 42 + 78 = 120 bytes
        (0).to_bytes(2, "little") +
        (0).to_bytes(2, "little")
    )
    total_len = 28 + len(options_payload)  # 28 + 128 = 156 bytes (156 % 4 == 0)
    assert total_len % 4 == 0

    large_shb = (
        MAGIC_PCAPNG_SHB +
        total_len.to_bytes(4, "little") +
        b"\x1a\x2b\x3c\x4d" +
        (1).to_bytes(2, "little") +
        (0).to_bytes(2, "little") +
        (-1 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") +
        options_payload +
        total_len.to_bytes(4, "little")
    )

    status, fmt = inspect_capture_header(large_shb, ".pcapng")
    assert status == ValidationStatus.VALID_PCAPNG
    assert fmt == CaptureFormat.PCAPNG_LE


def test_inspect_invalid_magic_bytes():
    with pytest.raises(PCAPValidationError) as exc:
        inspect_capture_header(b"NOT_A_PCAP_HEADER_AT_ALL_12345678", ".pcap")
    assert exc.value.status == ValidationStatus.INVALID_HEADER


# --- API Integration Tests ---

def test_api_upload_valid_pcap():
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"\x00" * 64)
    resp = client.post(
        "/analysis/upload",
        files={"file": ("good.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "queued"
    assert data["filename"] == "good.pcap"

    job = job_store.get_job(data["analysis_id"])
    path = Path(job.storage_path)
    assert path.exists()
    path.unlink(missing_ok=True)


def test_api_upload_valid_pcapng():
    payload = io.BytesIO(SYNTHETIC_PCAPNG_SHB_LE + b"\x00" * 64)
    resp = client.post(
        "/analysis/upload",
        files={"file": ("good.pcapng", payload, "application/octet-stream")}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "queued"

    job = job_store.get_job(data["analysis_id"])
    path = Path(job.storage_path)
    assert path.exists()
    path.unlink(missing_ok=True)


def test_api_upload_valid_large_pcapng_shb_accepted():
    options_payload = (
        (4).to_bytes(2, "little") +
        (120).to_bytes(2, "little") +
        (b"MailRakhwala Forensic Capture Test Harness" + b"\x00" * 78) +  # 42 + 78 = 120 bytes
        (0).to_bytes(2, "little") +
        (0).to_bytes(2, "little")
    )
    total_len = 28 + len(options_payload)  # 28 + 128 = 156 bytes (divisible by 4)
    assert total_len % 4 == 0

    large_shb = (
        MAGIC_PCAPNG_SHB +
        total_len.to_bytes(4, "little") +
        b"\x1a\x2b\x3c\x4d" +
        (1).to_bytes(2, "little") +
        (0).to_bytes(2, "little") +
        (-1 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") +
        options_payload +
        total_len.to_bytes(4, "little")
    )

    payload = io.BytesIO(large_shb + b"\x00" * 256)
    resp = client.post(
        "/analysis/upload",
        files={"file": ("large_header.pcapng", payload, "application/octet-stream")}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "queued"

    job = job_store.get_job(data["analysis_id"])
    path = Path(job.storage_path)
    assert path.exists()
    path.unlink(missing_ok=True)


def test_api_upload_fake_pcap_rejected():
    payload = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00not a capture file")
    resp = client.post(
        "/analysis/upload",
        files={"file": ("fake.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400


def test_api_upload_windows_traversal():
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"\x00" * 32)
    traversal_name = "..\\..\\..\\windows\\system32\\evil.pcap"
    resp = client.post(
        "/analysis/upload",
        files={"file": (traversal_name, payload, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["filename"] == "evil.pcap"

    job = job_store.get_job(data["analysis_id"])
    stored_path = Path(job.storage_path).resolve()
    upload_root = settings.UPLOAD_DIR.resolve()

    assert upload_root in stored_path.parents or stored_path.parent == upload_root
    assert stored_path.name == f"{data['analysis_id']}.pcap"
    stored_path.unlink(missing_ok=True)


def test_api_failed_upload_cleans_up_orphans():
    upload_dir = settings.UPLOAD_DIR.resolve()
    initial_files = set(upload_dir.glob("*"))

    payload = io.BytesIO(b"corrupted_header_data")
    resp = client.post(
        "/analysis/upload",
        files={"file": ("corrupt.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert set(upload_dir.glob("*")) == initial_files