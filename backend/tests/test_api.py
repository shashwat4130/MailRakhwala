"""
API Endpoint Integration Tests
Validates health checks, capture ingestion, status queries, and limits.
"""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.job_store import job_store

client = TestClient(app)

# Standard 24-byte PCAP header for valid upload tests
SYNTHETIC_PCAP_LE_HEADER = (
    b"\xd4\xc3\xb2\xa1" +
    (2).to_bytes(2, "little") +
    (4).to_bytes(2, "little") +
    (0).to_bytes(4, "little") +
    (0).to_bytes(4, "little") +
    (65535).to_bytes(4, "little") +
    (1).to_bytes(4, "little")
)

# Standard 28-byte PCAPNG Section Header Block
SYNTHETIC_PCAPNG_SHB_HEADER = (
    b"\x0a\x0d\x0d\x0a" +
    (28).to_bytes(4, "little") +
    b"\x1a\x2b\x3c\x4d" +
    (1).to_bytes(2, "little") +
    (0).to_bytes(2, "little") +
    (-1 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") +
    (28).to_bytes(4, "little")
)


@pytest.fixture(autouse=True)
def clean_job_store():
    job_store.clear()
    yield
    job_store.clear()


def test_health_check_returns_200():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "MailRakhwala API" in data["service"]


def test_upload_no_file_rejected():
    response = client.post("/analysis/upload")
    assert response.status_code == 422


def test_upload_unsupported_extension_rejected():
    payload = io.BytesIO(b"dummy binary contents")
    response = client.post(
        "/analysis/upload",
        files={"file": ("malicious.exe", payload, "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Unsupported file extension" in response.json()["detail"]


def test_upload_valid_pcap():
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"\x00" * 32)
    response = client.post(
        "/analysis/upload",
        files={"file": ("session.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    assert response.status_code == 202
    data = response.json()
    assert "analysis_id" in data
    assert data["status"] == "queued"
    assert data["filename"] == "session.pcap"

    job = job_store.get_job(data["analysis_id"])
    path = Path(job.storage_path)
    assert path.exists()
    path.unlink(missing_ok=True)


def test_upload_valid_pcapng():
    payload = io.BytesIO(SYNTHETIC_PCAPNG_SHB_HEADER + b"\x00" * 32)
    response = client.post(
        "/analysis/upload",
        files={"file": ("session.pcapng", payload, "application/octet-stream")}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert data["filename"] == "session.pcapng"

    job = job_store.get_job(data["analysis_id"])
    path = Path(job.storage_path)
    assert path.exists()
    path.unlink(missing_ok=True)


def test_get_analysis_status_lifecycle():
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"\x00" * 32)
    upload_resp = client.post(
        "/analysis/upload",
        files={"file": ("capture.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    analysis_id = upload_resp.json()["analysis_id"]

    get_resp = client.get(f"/analysis/{analysis_id}")
    assert get_resp.status_code == 200
    job_data = get_resp.json()
    assert job_data["analysis_id"] == analysis_id
    assert job_data["status"] == "queued"
    assert job_data["filename"] == "capture.pcap"
    assert job_data["file_size_bytes"] > 0

    job = job_store.get_job(analysis_id)
    Path(job.storage_path).unlink(missing_ok=True)


def test_get_unknown_analysis_id_returns_404():
    response = client.get("/analysis/non-existent-uuid-1234")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_upload_oversized_file_rejected(monkeypatch):
    monkeypatch.setattr(settings, "MAX_PCAP_SIZE_MB", 1)

    chunk_size = 512 * 1024
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"0" * (chunk_size * 3))

    response = client.post(
        "/analysis/upload",
        files={"file": ("oversized.pcap", payload, "application/vnd.tcpdump.pcap")}
    )
    assert response.status_code == 413
    assert "exceeds maximum allowed size" in response.json()["detail"]


def test_path_traversal_filename_sanitization_and_containment():
    payload = io.BytesIO(SYNTHETIC_PCAP_LE_HEADER + b"\x00" * 32)
    traversal_filename = "../../../../../etc/shadow.pcap"

    response = client.post(
        "/analysis/upload",
        files={"file": (traversal_filename, payload, "application/vnd.tcpdump.pcap")}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert data["filename"] == "shadow.pcap"

    job = job_store.get_job(data["analysis_id"])
    assert job is not None
    stored_path = Path(job.storage_path)
    assert stored_path.exists()
    assert stored_path.resolve().parent == settings.UPLOAD_DIR.resolve()
    stored_path.unlink(missing_ok=True)


def test_empty_pcap_rejected():
    empty_payload = io.BytesIO(b"")
    response = client.post(
        "/analysis/upload",
        files={"file": ("empty.pcap", empty_payload, "application/vnd.tcpdump.pcap")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()