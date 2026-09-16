"""
MailRakhwala Capture Ingestion & Analysis Routes (Step 06)
Handles secure bounded file upload, path containment, low-footprint magic-byte inspection, and job tracking.
"""

import uuid
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.core.config import settings
from app.schemas.api import AnalysisJobResponse, AnalysisUploadResponse, JobStatus
from app.services.job_store import job_store
from app.services.pcap_validator import (
    MAGIC_PCAPNG_SHB,
    MAX_PCAPNG_SHB_LEN,
    MIN_PCAP_GLOBAL_HEADER_LEN,
    MIN_PCAPNG_SHB_LEN,
    PCAPNG_BOM_BE,
    PCAPNG_BOM_LE,
    PCAPValidationError,
    inspect_capture_header,
    validate_file_extension,
)

router = APIRouter(prefix="/analysis", tags=["Analysis"])


def sanitize_filename(filename: Optional[str]) -> str:
    """Strips directory traversal sequences, Windows drive letters, and isolates base name."""
    if not filename:
        return "unnamed_capture.pcap"
    clean = filename.replace("\x00", "").replace("\\", "/")
    base_name = Path(clean).name
    return base_name if base_name else "unnamed_capture.pcap"


@router.post(
    "/upload",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload PCAP/PCAPNG capture for forensic assessment"
)
async def upload_capture(file: UploadFile = File(...)):
    original_name = file.filename or ""
    clean_name = sanitize_filename(original_name)

    try:
        suffix = validate_file_extension(clean_name)
    except PCAPValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err.message
        )

    analysis_id = str(uuid.uuid4())
    safe_disk_filename = f"{analysis_id}{suffix}"

    upload_root = settings.UPLOAD_DIR.resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    destination = (upload_root / safe_disk_filename).resolve()

    if upload_root not in destination.parents and destination.parent != upload_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal storage destination path."
        )

    total_bytes = 0
    chunk_size = 1024 * 1024  # 1MB stream buffer
    header_buffer = bytearray()
    header_inspected = False

    try:
        with open(destination, "wb") as buffer:
            while chunk := await file.read(chunk_size):
                total_bytes += len(chunk)

                if total_bytes > settings.max_upload_bytes:
                    buffer.close()
                    destination.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Capture exceeds maximum allowed size of {settings.MAX_PCAP_SIZE_MB}MB"
                    )

                if not header_inspected:
                    can_take = MAX_PCAPNG_SHB_LEN - len(header_buffer)
                    if can_take > 0:
                        header_buffer.extend(chunk[:can_take])

                    if suffix == ".pcap" and len(header_buffer) >= MIN_PCAP_GLOBAL_HEADER_LEN:
                        inspect_capture_header(bytes(header_buffer[:MIN_PCAP_GLOBAL_HEADER_LEN]), suffix)
                        header_inspected = True
                        header_buffer.clear()
                    elif suffix == ".pcapng" and len(header_buffer) >= MIN_PCAPNG_SHB_LEN:
                        if header_buffer[:4] == MAGIC_PCAPNG_SHB:
                            bom = header_buffer[8:12]
                            order = "little" if bom == PCAPNG_BOM_LE else ("big" if bom == PCAPNG_BOM_BE else None)
                            if order:
                                declared_len = int.from_bytes(header_buffer[4:8], byteorder=order)
                                if len(header_buffer) >= declared_len:
                                    inspect_capture_header(bytes(header_buffer[:declared_len]), suffix)
                                    header_inspected = True
                                    header_buffer.clear()

                buffer.write(chunk)

        if not header_inspected:
            inspect_capture_header(bytes(header_buffer), suffix)
            header_buffer.clear()

    except PCAPValidationError as val_err:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=val_err.message
        )
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist uploaded capture safely."
        ) from exc

    if total_bytes == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded capture file is empty."
        )

    job_store.create_job(
        analysis_id=analysis_id,
        filename=clean_name,
        storage_path=str(destination),
        file_size_bytes=total_bytes
    )

    return AnalysisUploadResponse(
        analysis_id=analysis_id,
        status=JobStatus.QUEUED,
        filename=clean_name,
        message="Capture validated and queued for analysis."
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisJobResponse,
    summary="Query status of an analysis job"
)
async def get_analysis_job(analysis_id: str):
    job = job_store.get_job(analysis_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID '{analysis_id}' not found."
        )
    return job.to_response()