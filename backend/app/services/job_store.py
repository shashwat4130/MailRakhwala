"""
In-memory job management service for MailRakhwala.
Tracks analysis metadata and state transitions.
"""

from datetime import datetime, timezone
from typing import Dict, Optional
from app.schemas.api import JobStatus, AnalysisJobResponse


class JobRecord:
    def __init__(self, analysis_id: str, filename: str, storage_path: str, file_size_bytes: int):
        self.analysis_id = analysis_id
        self.filename = filename
        self.storage_path = storage_path
        self.file_size_bytes = file_size_bytes
        self.status = JobStatus.QUEUED
        self.message = "Analysis queued"
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at

    def to_response(self) -> AnalysisJobResponse:
        return AnalysisJobResponse(
            analysis_id=self.analysis_id,
            status=self.status,
            filename=self.filename,
            file_size_bytes=self.file_size_bytes,
            created_at=self.created_at,
            updated_at=self.updated_at,
            message=self.message,
        )


class JobStore:
    def __init__(self):
        self._jobs: Dict[str, JobRecord] = {}

    def create_job(self, analysis_id: str, filename: str, storage_path: str, file_size_bytes: int) -> JobRecord:
        record = JobRecord(analysis_id, filename, storage_path, file_size_bytes)
        self._jobs[analysis_id] = record
        return record

    def get_job(self, analysis_id: str) -> Optional[JobRecord]:
        return self._jobs.get(analysis_id)

    def update_status(self, analysis_id: str, status: JobStatus, message: Optional[str] = None) -> Optional[JobRecord]:
        job = self._jobs.get(analysis_id)
        if job:
            job.status = status
            job.updated_at = datetime.now(timezone.utc)
            if message:
                job.message = message
        return job

    def clear(self):
        """Utility for test suites."""
        self._jobs.clear()


job_store = JobStore()