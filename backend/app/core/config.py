"""
MailRakhwala Application Configuration
Loads and validates settings from environment variables with safe defaults.
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


def _resolve_rules_dir() -> Path:
    env_path = os.getenv("RULES_DIR")
    if env_path:
        return Path(env_path)
    # Check repository root: <root>/rules
    repo_root_rules = Path(__file__).resolve().parents[3] / "rules"
    if repo_root_rules.is_dir():
        return repo_root_rules
    # Check backend parent: <backend>/rules
    backend_rules = Path(__file__).resolve().parents[2] / "rules"
    if backend_rules.is_dir():
        return backend_rules
    return repo_root_rules


def _resolve_models_dir() -> Path:
    env_path = os.getenv("MODELS_DIR")
    if env_path:
        return Path(env_path)
    repo_models = Path(__file__).resolve().parents[3] / "data" / "models"
    if repo_models.is_dir():
        return repo_models
    backend_models = Path(__file__).resolve().parents[2] / "data" / "models"
    return backend_models


def _resolve_static_dir() -> Optional[Path]:
    env_path = os.getenv("STATIC_DIR")
    if env_path:
        p = Path(env_path)
        return p if p.is_dir() else None
    # Check repository root: <root>/frontend/dist
    repo_root_dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if repo_root_dist.is_dir():
        return repo_root_dist
    # Check backend parent: <backend>/frontend/dist
    backend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if backend_dist.is_dir():
        return backend_dist
    return None


class Settings(BaseModel):
    APP_ENV: str = Field(default="development", description="Application environment")
    MAX_PCAP_SIZE_MB: int = Field(default=100, ge=1, le=1000, description="Max capture size limit in MB")
    UPLOAD_DIR: Path = Field(
        default=Path(__file__).resolve().parent.parent.parent / "data" / "uploads",
        description="Controlled directory for temporary capture storage"
    )
    MODELS_DIR: Path = Field(
        default_factory=_resolve_models_dir,
        description="Controlled directory for ML model artifacts"
    )
    RULES_DIR: Path = Field(
        default_factory=_resolve_rules_dir,
        description="Path to canonical security rules catalog directory"
    )
    STATIC_DIR: Optional[Path] = Field(
        default_factory=_resolve_static_dir,
        description="Path to pre-built frontend static distribution assets"
    )
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        description="Allowed frontend origins for CORS"
    )

    # TCP Stream Reconstruction Configuration
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

        models_dir = _resolve_models_dir()
        rules_dir = _resolve_rules_dir()
        static_dir = _resolve_static_dir()

        cors_raw = os.getenv("CORS_ORIGINS")
        if cors_raw:
            cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
        else:
            cors_origins = cls.model_fields["CORS_ORIGINS"].default

        return cls(
            APP_ENV=env,
            MAX_PCAP_SIZE_MB=max_size,
            UPLOAD_DIR=upload_path,
            MODELS_DIR=models_dir,
            RULES_DIR=rules_dir,
            STATIC_DIR=static_dir,
            CORS_ORIGINS=cors_origins,
        )


settings = Settings.load_from_env()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)