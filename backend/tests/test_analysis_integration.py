from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.api import JobStatus
from app.schemas.packet import DissectedPacket
from app.services.job_store import job_store

client = TestClient(app)

MOCK_PCAP_GLOBAL_HEADER = (
    b"\xd4\xc3\xb2\xa1"  # Magic Number (PCAP Little-Endian)
    b"\x02\x00\x04\x00"  # Version 2.4
    b"\x00\x00\x00\x00"  # Thiszone
    b"\x00\x00\x00\x00"  # Sigfigs
    b"\xff\xff\x00\x00"  # Snaplen (65535)
    b"\x01\x00\x00\x00"  # LinkType (Ethernet)
)


@pytest.fixture(autouse=True)
def clean_job_store():
    job_store.clear()
    yield
    job_store.clear()


def test_analysis_pipeline_successful_execution():
    """Verify the end-to-end upload and background task completion."""
    mock_packets = [
        DissectedPacket(
            frame_number=1,
            timestamp_epoch=1710000000.0,
            frame_len=60,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=25,
            transport_protocol="TCP",
            tcp_stream=0,
            highest_layer="SMTP",
        )
    ]

    with patch("app.api.routes.analysis.TSharkService") as mock_tshark_cls:
        mock_tshark = MagicMock()
        mock_tshark.dissect_packets_stream.return_value = iter(mock_packets)
        mock_tshark_cls.return_value = mock_tshark

        response = client.post(
            "/analysis/upload",
            files={"file": ("test_capture.pcap", MOCK_PCAP_GLOBAL_HEADER, "application/vnd.tcpdump.pcap")},
        )

        assert response.status_code == 202
        data = response.json()
        analysis_id = data["analysis_id"]

        # In TestClient, BackgroundTasks execute synchronously
        job = job_store.get_job(analysis_id)
        assert job is not None
        assert job.status == JobStatus.COMPLETED

        report_resp = client.get(f"/analysis/{analysis_id}/report")
        assert report_resp.status_code == 200
        report_data = report_resp.json()
        assert report_data["session"]["session_id"] == analysis_id
        assert report_data["session"]["status"] == "COMPLETED"