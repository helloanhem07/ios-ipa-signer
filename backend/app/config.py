"""
Application Configuration and Settings Management.
"""
from pathlib import Path
from typing import Optional
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIGNING_",
        case_sensitive=False,
        extra="ignore",
    )

    # Server network settings
    HOST: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("SIGNING_SERVER_HOST", "SIGNING_HOST", "HOST"),
    )
    PORT: int = Field(
        default=8000,
        validation_alias=AliasChoices("SIGNING_SERVER_PORT", "SIGNING_PORT", "PORT"),
    )
    BASE_URL: str = Field(
        default="http://localhost:8000",
        validation_alias=AliasChoices("SIGNING_BASE_URL", "BASE_URL"),
    )

    # Filesystem directories
    BACKEND_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    STORAGE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "storage")
    JOBS_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "storage" / "jobs")

    # Concurrency and timeouts
    MAX_CONCURRENT_JOBS: int = Field(
        default=3,
        validation_alias=AliasChoices("SIGNING_MAX_CONCURRENT_JOBS", "MAX_CONCURRENT_JOBS"),
    )
    SIGNING_TIMEOUT_SECONDS: int = Field(
        default=300,
        validation_alias=AliasChoices("SIGNING_TIMEOUT_SECONDS", "SIGNING_TIMEOUT"),
    )
    JOB_TTL_HOURS: int = Field(
        default=24,
        validation_alias=AliasChoices("SIGNING_JOB_TTL_HOURS", "JOB_TTL_HOURS"),
    )
    MAX_UPLOAD_SIZE_BYTES: int = Field(
        default=4 * 1024 * 1024 * 1024,  # 4 GB
        validation_alias=AliasChoices("SIGNING_MAX_UPLOAD_SIZE_BYTES", "MAX_UPLOAD_SIZE_BYTES"),
    )

    # Engine configurations
    ZSIGN_BIN_PATH: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("SIGNING_ZSIGN_BIN_PATH", "ZSIGN_BIN_PATH"),
    )
    DEFAULT_COMPRESSION_LEVEL: int = Field(
        default=1,
        validation_alias=AliasChoices(
            "SIGNING_DEFAULT_COMPRESSION_LEVEL", "DEFAULT_COMPRESSION_LEVEL", "DEFAULT_COMPRESSION"
        ),
    )
    PREFERRED_ENGINE: str = Field(
        default="auto",
        validation_alias=AliasChoices("SIGNING_ENGINE", "PREFERRED_ENGINE"),
    )


settings = Settings()
