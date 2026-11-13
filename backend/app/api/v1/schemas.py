"""
Pydantic schemas for request validation and response serialization.
Strictly conforms to PROJECT.md § Interface Contracts.
"""
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class EnginesStatus(BaseModel):
    zsign: bool = Field(..., description="Whether native zsign binary engine is available")
    fallback: bool = Field(..., description="Whether pure-Python fallback signing engine is active")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Overall system health status")
    version: str = Field(default="1.0.0", description="Backend service version")
    engines: EnginesStatus = Field(..., description="Availability status of signing engines")


class JobCreateResponse(BaseModel):
    job_id: str = Field(..., description="Unique UUID identifier for the signing job")
    status: JobStatus = Field(default=JobStatus.QUEUED, description="Initial status of the submitted job")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp of creation")
    poll_url: Optional[str] = Field(None, description="URL endpoint to poll for job progress and results")


class JobDetailResponse(BaseModel):
    job_id: str = Field(..., description="Unique UUID identifier for the job")
    status: JobStatus = Field(..., description="Current status: queued | processing | completed | failed")
    download_url: Optional[str] = Field(None, description="Direct download URL for the signed IPA package")
    manifest_url: Optional[str] = Field(None, description="URL for the Apple OTA manifest.plist")
    install_url: Optional[str] = Field(None, description="Web landing page URL for iOS Safari 1-tap install")
    itms_url: Optional[str] = Field(None, description="Apple itms-services:// wireless install protocol URI")
    error: Optional[str] = Field(None, description="Error message if status is failed")
    bundle_id: Optional[str] = Field(None, description="Final bundle identifier of the signed application")
    bundle_version: Optional[str] = Field(None, description="Final short version string (CFBundleShortVersionString)")
    app_name: Optional[str] = Field(None, description="Application display name (CFBundleDisplayName)")
    created_at: Optional[str] = Field(None, description="ISO 8601 timestamp when job was queued")
    completed_at: Optional[str] = Field(None, description="ISO 8601 timestamp when signing concluded")


class ErrorResponse(BaseModel):
    error: str = Field("Error", description="Summary error description or error code")
    error_code: Optional[str] = Field(None, description="Optional standardized machine error code")
    detail: Optional[Any] = Field(None, description="Detailed diagnostic or error information")
    status_code: Optional[int] = Field(None, description="HTTP status code")
