"""
MailRakhwala Application Configuration
Loads and validates settings from environment variables with safe defaults.
"""

import os
from pathlib import Path
from typing import List
from pydantic import BaseModel, Field


class Settings(BaseModel):
    APP_ENV: str = Field(default="development", description="Application environment")
    MAX_PCAP_SIZE_MB: int = Field(default=100, ge=1, le=1000, description="Max capture size limit in MB")
    UPLOAD_DIR: Path = Field(
        default=Path(__file__).resolve().parent.parent.parent / "data" / "uploads",
        description="Controlled directory for temporary capture storage"
    )
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        description="Allowed frontend origins for CORS"
    )

    # Step 08: TCP Stream Reconstruction Configuration
    TCP_STREAM_MAX_ACTIVE_STREAMS: int = 1000
    TCP_STREAM_MAX_BYTES_PER_DIR: int = 512 * 1024  # 512 KB per direction
    TCP_STREAM_MAX_SEGMENTS_BUFFERED: int = 500      # Out-of-order segment window
    TCP_STREAM_INACTIVITY_TIMEOUT_SEC: float = 300.0  # 5 minutes

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_PCAP_SIZE_MB * 1024 * 1024

    @classmethod
    def load_from_env(cls) -> "Settings":
        env = os.getenv("APP_ENV", "development")
        max_size = int(os.getenv("MAX_PCAP_SIZE_MB", "100"))

        custom_upload = os.getenv("UPLOAD_DIR")
        upload_path = Path(custom_upload) if custom_upload else cls.model_fields["UPLOAD_DIR"].default

        cors_raw = os.getenv("CORS_ORIGINS")
        cors_origins = [origin.strip() for origin in cors_raw.split(",")] if cors_raw else cls.model_fields["CORS_ORIGINS"].default

        return cls(
            APP_ENV=env,
            MAX_PCAP_SIZE_MB=max_size,
            UPLOAD_DIR=upload_path,
            CORS_ORIGINS=cors_origins,
        )


settings = Settings.load_from_env()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)