"""
Integration tests for Step 29 background analysis lifecycle and status transitions.
Validates the QUEUED -> PROCESSING -> COMPLETED/FAILED sequence via job_store.
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.api import JobStatus
from app.services.job_store import job_store

client = TestClient(app)

SYNTHETIC_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"
    + (2).to_bytes(2, "little")
    + (4).to_bytes(2, "little")
    + (0).to_bytes(4, "little")
    + (0).to_bytes(4, "little")
    + (65535).to_bytes(4, "little")
    + (1).to_bytes(4, "little")
)


@pytest.fixture(autouse=True)
def clean_job_store():
    job_store.clear()
    yield
    job_store.clear()


def test_upload_creates_queued_job(monkeypatch):
    """Verifies that uploading a PCAP creates a session in queued state."""
    monkeypatch.setattr("fastapi.BackgroundTasks.add_task", lambda self, func, *a, **kw: None)

    payload = io.BytesIO(SYNTHETIC_PCAP_HEADER + b"\x00" * 32)
    response = client.post(
        "/analysis/upload",
        files={"file": ("test.pcap", payload, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    analysis_id = data["analysis_id"]

    status_resp = client.get(f"/analysis/{analysis_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "queued"


def test_status_endpoint_returns_404_for_unknown():
    """Verifies unknown analysis ID returns 404."""
    response = client.get("/analysis/non-existent-uuid-1234")
    assert response.status_code == 404


def test_background_worker_lifecycle_completion(monkeypatch):
    """Verifies background worker updates status to completed."""
    def mock_pipeline(analysis_id: str, pcap_path: str, filename: str):
        job_store.set_report(analysis_id, {"session": {"session_id": analysis_id, "status": "COMPLETED"}})

    monkeypatch.setattr("app.api.routes.analysis.run_pipeline_task", mock_pipeline)

    payload = io.BytesIO(SYNTHETIC_PCAP_HEADER + b"\x00" * 32)
    response = client.post(
        "/analysis/upload",
        files={"file": ("sample.pcap", payload, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 202
    analysis_id = response.json()["analysis_id"]

    status_resp = client.get(f"/analysis/{analysis_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "completed"


def test_background_worker_failure_transition(monkeypatch):
    """Verifies background worker failure sets status to failed."""
    def mock_failing_task(analysis_id: str, pcap_path: str, filename: str):
        job_store.update_status(analysis_id, JobStatus.FAILED, "Corrupted packet capture")

    monkeypatch.setattr("app.api.routes.analysis.run_pipeline_task", mock_failing_task)

    payload = io.BytesIO(SYNTHETIC_PCAP_HEADER + b"\x00" * 32)
    response = client.post(
        "/analysis/upload",
        files={"file": ("corrupt.pcap", payload, "application/vnd.tcpdump.pcap")},
    )
    analysis_id = response.json()["analysis_id"]

    status_resp = client.get(f"/analysis/{analysis_id}")
    assert status_resp.status_code == 200
    res = status_resp.json()
    assert res["status"] == "failed"
    assert "Corrupted packet capture" in res["message"]