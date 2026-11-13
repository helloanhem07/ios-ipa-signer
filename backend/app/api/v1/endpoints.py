"""
REST API Endpoints for iOS Signing and OTA Distribution.
Strictly conforms to PROJECT.md § Interface Contracts.
"""
import re
from typing import Optional
from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse

from app.api.v1.schemas import (
    HealthResponse,
    EnginesStatus,
    JobCreateResponse,
    JobDetailResponse,
    JobStatus,
)
from app.services.signing_manager import signing_manager
from app.services.manifest_service import ManifestService
from app.config import settings

api_router = APIRouter()

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def get_request_base_url(request: Request) -> str:
    """Returns the effective base URL, preferring settings.BASE_URL if configured."""
    if settings.BASE_URL and settings.BASE_URL != "http://localhost:8000":
        return settings.BASE_URL.rstrip("/")
    return str(request.base_url).rstrip("/")


@api_router.get("/health", response_model=HealthResponse)
async def get_health():
    """Returns system health and availability of signing engines."""
    engines_status = signing_manager.get_engines_status()
    return HealthResponse(
        status="ok",
        version="1.0.0",
        engines=EnginesStatus(
            zsign=engines_status["zsign"],
            fallback=engines_status["fallback"],
        ),
    )


@api_router.post(
    "/jobs",
    response_model=JobCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit iOS IPA package for re-signing",
)
async def create_signing_job(
    request: Request,
    ipa: UploadFile = File(..., description="Unsigned or ad-hoc iOS IPA archive"),
    p12: UploadFile = File(..., description="PKCS#12 (.p12/.pfx) code signing certificate"),
    password: str = Form("", description="Password for the .p12 certificate (empty string if none)"),
    mobileprovision: UploadFile = File(..., description="Apple .mobileprovision profile"),
    bundle_id: Optional[str] = Form(None, description="Override CFBundleIdentifier"),
    bundle_name: Optional[str] = Form(None, description="Override CFBundleDisplayName"),
    bundle_version: Optional[str] = Form(None, description="Override CFBundleShortVersionString"),
    entitlements: Optional[UploadFile] = File(None, description="Custom entitlements XML plist"),
    compression_level: Optional[int] = Form(1, description="ZIP compression level (0-9)"),
):
    """
    Submits an iOS signing job.
    Accepts unsigned IPA, certificate, password, and provisioning profile.
    Returns HTTP 202 with job UUID and polling URL.
    """
    # Filename validations
    if not (ipa.filename or "").lower().endswith((".ipa", ".zip")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IPA file. Expected .ipa or .zip archive.",
        )
    if not (p12.filename or "").lower().endswith((".p12", ".pfx")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid certificate file. Expected .p12 or .pfx archive.",
        )
    if not (mobileprovision.filename or "").lower().endswith(".mobileprovision"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid profile file. Expected .mobileprovision file.",
        )

    base_url = get_request_base_url(request)

    job_record = await signing_manager.create_job(
        ipa=ipa,
        p12=p12,
        password=password,
        mobileprovision=mobileprovision,
        bundle_id=bundle_id,
        bundle_name=bundle_name,
        bundle_version=bundle_version,
        entitlements=entitlements,
        compression_level=compression_level if compression_level is not None else settings.DEFAULT_COMPRESSION_LEVEL,
        base_url=base_url,
    )

    return JobCreateResponse(
        job_id=job_record.job_id,
        status=job_record.status,
        created_at=job_record.created_at,
        poll_url=f"{base_url}/api/v1/jobs/{job_record.job_id}",
    )


@api_router.get(
    "/jobs/{job_id}",
    response_model=JobDetailResponse,
    summary="Query status and artifact URLs of a signing job",
)
async def get_job_status(job_id: str, request: Request):
    """
    Returns current status and download links for the specified job ID.
    """
    if not UUID_REGEX.match(job_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job UUID format.",
        )

    job = signing_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found.",
        )

    base_url = get_request_base_url(request)
    return job.to_detail_response(base_url=base_url)


@api_router.get(
    "/downloads/{job_id}/{filename}",
    summary="Download signed IPA artifact with HTTP Range support",
)
async def download_signed_ipa(job_id: str, filename: str):
    """
    Streams the signed IPA package directly from disk.
    Supports HTTP 206 byte-range requests for iOS installation daemons.
    """
    if not UUID_REGEX.match(job_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job ID format.",
        )
    if not SAFE_FILENAME_REGEX.match(filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename format.",
        )

    outputs_dir = (settings.JOBS_DIR / job_id / "outputs").resolve()
    file_path = (outputs_dir / filename).resolve()

    # Path traversal protection
    try:
        if not file_path.is_relative_to(outputs_dir) or not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Requested artifact not found.",
            )
    except AttributeError:
        # Fallback for Python versions where is_relative_to might behave differently
        if not str(file_path).startswith(str(outputs_dir)) or not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Requested artifact not found.",
            )

    media_type = (
        "application/x-itunes-ipa"
        if filename.endswith(".ipa")
        else "application/octet-stream"
    )

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename,
        headers={"Accept-Ranges": "bytes"},
    )


@api_router.get(
    "/ota/{job_id}/manifest.plist",
    summary="Fetch Apple Enterprise DTD Over-The-Air manifest.plist",
)
async def get_ota_manifest(job_id: str, request: Request):
    """
    Returns the XML property list manifest conforming to Apple's Wireless App Distribution specification.
    """
    if not UUID_REGEX.match(job_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job UUID format.",
        )

    job = signing_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found.",
        )

    if job.status == JobStatus.QUEUED or job.status == JobStatus.PROCESSING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Job is still processing. Manifest will be available upon completion.",
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job failed: {job.error}",
        )

    manifest_path = (settings.JOBS_DIR / job_id / "outputs" / "manifest.plist").resolve()
    if not manifest_path.is_file():
        # Dynamically generate if missing
        base_url = get_request_base_url(request)
        ipa_url = f"{base_url}/api/v1/downloads/{job_id}/{job.output_filename}"
        manifest_bytes = ManifestService.generate_manifest_xml(
            ipa_url=ipa_url,
            bundle_id=job.bundle_id or "com.apple.application",
            bundle_version=job.bundle_version or "1.0.0",
            title=job.app_name or "SignedApp",
        )
        return Response(content=manifest_bytes, media_type="application/xml")

    with open(manifest_path, "rb") as f:
        content = f.read()

    return Response(content=content, media_type="application/xml")


@api_router.get(
    "/ota/{job_id}/install",
    response_class=HTMLResponse,
    summary="Mobile Safari 1-tap OTA installation web landing page",
)
async def get_ota_install_page(job_id: str, request: Request):
    """
    Serves a responsive mobile Safari landing page with a 1-tap itms-services:// trigger.
    """
    if not UUID_REGEX.match(job_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job UUID format.",
        )

    job = signing_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found.",
        )

    if job.status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Job status is '{job.status.value}'. Install page is only available once signing completes.",
        )

    base_url = get_request_base_url(request)
    manifest_url = f"{base_url}/api/v1/ota/{job_id}/manifest.plist"
    itms_url = ManifestService.build_itms_url(manifest_url)
    download_url = f"{base_url}/api/v1/downloads/{job_id}/{job.output_filename}"

    html_content = ManifestService.generate_install_html(
        app_name=job.app_name or "Signed Application",
        bundle_id=job.bundle_id or "com.apple.application",
        bundle_version=job.bundle_version or "1.0.0",
        itms_url=itms_url,
        download_url=download_url,
        file_size_bytes=job.file_size_bytes,
    )

    return HTMLResponse(content=html_content)
