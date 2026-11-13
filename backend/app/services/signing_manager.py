"""
Asynchronous Job Management, Concurrency Control, and Workspace Scratchpad Isolation.
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import shutil
from typing import Any, Dict, Optional
import uuid

from fastapi import HTTPException, UploadFile, status

from app.config import settings
from app.api.v1.schemas import JobStatus, JobDetailResponse
from app.services.signing_engine import SigningEngine, SigningResult
from app.services.zsign_engine import ZsignBinaryEngine
from app.services.fallback_engine import FallbackSigningEngine
from app.services.manifest_service import ManifestService
from app.services.plist_utils import extract_ipa_metadata

logger = logging.getLogger("signing_backend.signing_manager")
UUID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}$")


@dataclass
class JobRecord:
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    bundle_id: Optional[str] = None
    bundle_version: Optional[str] = None
    app_name: Optional[str] = None
    error: Optional[str] = None
    output_filename: str = "signed.ipa"
    file_size_bytes: Optional[int] = None
    engine_used: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "app_name": self.app_name,
            "error": self.error,
            "output_filename": self.output_filename,
            "file_size_bytes": self.file_size_bytes,
            "engine_used": self.engine_used,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobRecord":
        return cls(
            job_id=data["job_id"],
            status=JobStatus(data.get("status", JobStatus.QUEUED)),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            completed_at=data.get("completed_at"),
            bundle_id=data.get("bundle_id"),
            bundle_version=data.get("bundle_version"),
            app_name=data.get("app_name"),
            error=data.get("error"),
            output_filename=data.get("output_filename", "signed.ipa"),
            file_size_bytes=data.get("file_size_bytes"),
            engine_used=data.get("engine_used"),
        )

    def to_detail_response(self, base_url: str) -> JobDetailResponse:
        download_url = None
        manifest_url = None
        install_url = None
        itms_url = None

        if self.status == JobStatus.COMPLETED:
            download_url = f"{base_url}/api/v1/downloads/{self.job_id}/{self.output_filename}"
            manifest_url = f"{base_url}/api/v1/ota/{self.job_id}/manifest.plist"
            install_url = f"{base_url}/api/v1/ota/{self.job_id}/install"
            itms_url = ManifestService.build_itms_url(manifest_url)

        return JobDetailResponse(
            job_id=self.job_id,
            status=self.status,
            download_url=download_url,
            manifest_url=manifest_url,
            install_url=install_url,
            itms_url=itms_url,
            error=self.error,
            bundle_id=self.bundle_id,
            bundle_version=self.bundle_version,
            app_name=self.app_name,
            created_at=self.created_at,
            completed_at=self.completed_at,
        )


class SigningManager:
    """
    Coordinates asynchronous job queuing, concurrency limiting via asyncio.Semaphore,
    isolated scratchpad directory management, and signing engine selection.
    """

    def __init__(self):
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._jobs: Dict[str, JobRecord] = {}
        self._zsign_engine = ZsignBinaryEngine()
        self._fallback_engine = FallbackSigningEngine()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    async def startup(self):
        """Initializes storage directories, semaphore, and starts background tasks."""
        settings.JOBS_DIR.mkdir(parents=True, exist_ok=True)
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_JOBS)

        # Recover existing completed jobs from storage
        self._recover_jobs_from_disk()

        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(
            f"SigningManager initialized. Max concurrent jobs: {settings.MAX_CONCURRENT_JOBS}"
        )

    async def shutdown(self):
        """Cancels background tasks gracefully."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                if self._cleanup_task.get_loop() is asyncio.get_running_loop():
                    await self._cleanup_task
            except (asyncio.CancelledError, RuntimeError):
                pass
        logger.info("SigningManager shutdown successfully.")

    def get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_JOBS)
        return self._semaphore

    def get_engines_status(self) -> Dict[str, bool]:
        return {
            "zsign": self._zsign_engine.is_available(),
            "fallback": self._fallback_engine.is_available(),
        }

    def select_engine(self, preference: Optional[str] = None) -> SigningEngine:
        pref = (preference or settings.PREFERRED_ENGINE).lower()
        if pref == "zsign":
            if self._zsign_engine.is_available():
                return self._zsign_engine
            logger.warning("Preferred engine 'zsign' unavailable; selecting fallback engine.")
            return self._fallback_engine
        elif pref == "fallback":
            return self._fallback_engine
        else:  # auto
            if self._zsign_engine.is_available():
                return self._zsign_engine
            return self._fallback_engine

    def _recover_jobs_from_disk(self):
        """Scans storage directory for metadata.json files to repopulate state across server restarts."""
        try:
            if not settings.JOBS_DIR.is_dir():
                return
            for job_dir in settings.JOBS_DIR.iterdir():
                if job_dir.is_dir() and UUID_PATTERN.match(job_dir.name):
                    meta_path = job_dir / "outputs" / "metadata.json"
                    if meta_path.is_file():
                        try:
                            with open(meta_path, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                job_record = JobRecord.from_dict(data)
                                self._jobs[job_record.job_id] = job_record
                        except Exception as e:
                            logger.warning(f"Failed to load job metadata from {meta_path}: {e}")
        except Exception as e:
            logger.error(f"Error during job recovery from disk: {e}")

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        """Retrieves job state from memory or disk cache."""
        if job_id in self._jobs:
            return self._jobs[job_id]

        # Check disk
        meta_file = settings.JOBS_DIR / job_id / "outputs" / "metadata.json"
        if meta_file.is_file():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    job_record = JobRecord.from_dict(data)
                    self._jobs[job_id] = job_record
                    return job_record
            except Exception as e:
                logger.warning(f"Error reading job metadata for {job_id}: {e}")
        return None

    def _save_job_metadata(self, job_record: JobRecord):
        """Persists job metadata to outputs/metadata.json for crash recovery."""
        try:
            out_dir = settings.JOBS_DIR / job_record.job_id / "outputs"
            out_dir.mkdir(parents=True, exist_ok=True)
            meta_file = out_dir / "metadata.json"
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(job_record.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to persist job metadata for {job_record.job_id}: {e}")

    async def _stream_upload(
        self, upload_file: UploadFile, dest_path: Path, max_bytes: int
    ) -> int:
        """
        Streams uploaded file directly to disk in 1MB chunks without holding the entire
        file in system RAM, preventing Out-Of-Memory errors on large IPAs.
        """
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        total_written = 0
        chunk_size = 1024 * 1024  # 1MB buffer

        with dest_path.open("wb") as out_file:
            while True:
                chunk = await upload_file.read(chunk_size)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > max_bytes:
                    out_file.close()
                    dest_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed upload size of {max_bytes} bytes.",
                    )
                out_file.write(chunk)
        return total_written

    async def create_job(
        self,
        ipa: UploadFile,
        p12: UploadFile,
        password: str,
        mobileprovision: UploadFile,
        bundle_id: Optional[str] = None,
        bundle_name: Optional[str] = None,
        bundle_version: Optional[str] = None,
        entitlements: Optional[UploadFile] = None,
        compression_level: int = 1,
        base_url: str = "http://localhost:8000",
    ) -> JobRecord:
        """
        Allocates isolated scratchpad directory, streams upload files to disk,
        registers job in memory, and triggers asynchronous execution.
        """
        job_id = str(uuid.uuid4())
        job_dir = settings.JOBS_DIR / job_id
        inputs_dir = job_dir / "inputs"
        work_dir = job_dir / "work"
        outputs_dir = job_dir / "outputs"

        inputs_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        outputs_dir.mkdir(parents=True, exist_ok=True)

        ipa_path = inputs_dir / "input.ipa"
        p12_path = inputs_dir / "certificate.p12"
        prov_path = inputs_dir / "profile.mobileprovision"
        entitlements_path = inputs_dir / "entitlements.plist" if entitlements else None

        # Stream uploads directly to scratchpad disk
        try:
            await self._stream_upload(ipa, ipa_path, settings.MAX_UPLOAD_SIZE_BYTES)
            await self._stream_upload(p12, p12_path, 50 * 1024 * 1024)
            await self._stream_upload(mobileprovision, prov_path, 10 * 1024 * 1024)
            if entitlements and entitlements_path:
                await self._stream_upload(entitlements, entitlements_path, 5 * 1024 * 1024)
        except Exception as e:
            shutil.rmtree(job_dir, ignore_errors=True)
            raise e

        # Extract initial metadata if possible
        initial_meta = {}
        try:
            initial_meta = extract_ipa_metadata(ipa_path)
        except Exception:
            pass

        final_bundle_id = bundle_id or initial_meta.get("bundle_id")
        final_app_name = bundle_name or initial_meta.get("bundle_name")
        final_bundle_version = bundle_version or initial_meta.get("bundle_version")

        record = JobRecord(
            job_id=job_id,
            status=JobStatus.QUEUED,
            bundle_id=final_bundle_id,
            bundle_version=final_bundle_version,
            app_name=final_app_name,
        )

        self._jobs[job_id] = record
        self._save_job_metadata(record)

        # Launch background task
        asyncio.create_task(
            self._process_job(
                job_id=job_id,
                ipa_path=ipa_path,
                p12_path=p12_path,
                password=password,
                prov_path=prov_path,
                entitlements_path=entitlements_path,
                bundle_id=bundle_id,
                bundle_name=bundle_name,
                bundle_version=bundle_version,
                compression_level=compression_level,
                base_url=base_url,
            )
        )

        return record

    async def _process_job(
        self,
        job_id: str,
        ipa_path: Path,
        p12_path: Path,
        password: str,
        prov_path: Path,
        entitlements_path: Optional[Path],
        bundle_id: Optional[str],
        bundle_name: Optional[str],
        bundle_version: Optional[str],
        compression_level: int,
        base_url: str,
    ):
        """Background execution worker throttled by semaphore."""
        sem = self.get_semaphore()
        async with sem:
            job = self._jobs.get(job_id)
            if not job:
                return

            job.status = JobStatus.PROCESSING
            self._save_job_metadata(job)

            job_dir = settings.JOBS_DIR / job_id
            work_dir = job_dir / "work"
            outputs_dir = job_dir / "outputs"
            output_ipa_path = outputs_dir / "signed.ipa"

            engine = self.select_engine()
            job.engine_used = engine.name

            logger.info(f"Job {job_id}: Processing started using engine '{engine.name}'")

            try:
                result: SigningResult = await engine.sign(
                    ipa_path=ipa_path,
                    p12_path=p12_path,
                    p12_password=password,
                    provisioning_path=prov_path,
                    output_path=output_ipa_path,
                    bundle_id=bundle_id,
                    bundle_name=bundle_name,
                    bundle_version=bundle_version,
                    entitlements_path=entitlements_path,
                    compression_level=compression_level,
                    temp_dir=work_dir,
                    timeout_seconds=settings.SIGNING_TIMEOUT_SECONDS,
                )

                if result.success and output_ipa_path.is_file():
                    job.status = JobStatus.COMPLETED
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.bundle_id = result.bundle_id or job.bundle_id
                    job.bundle_version = result.bundle_version or job.bundle_version
                    job.app_name = result.bundle_name or job.app_name
                    job.file_size_bytes = output_ipa_path.stat().st_size

                    # Generate and write manifest.plist into outputs
                    ipa_url = f"{base_url}/api/v1/downloads/{job_id}/signed.ipa"
                    manifest_bytes = ManifestService.generate_manifest_xml(
                        ipa_url=ipa_url,
                        bundle_id=job.bundle_id or "com.apple.application",
                        bundle_version=job.bundle_version or "1.0.0",
                        title=job.app_name or "SignedApp",
                    )
                    manifest_path = outputs_dir / "manifest.plist"
                    with open(manifest_path, "wb") as mf:
                        mf.write(manifest_bytes)

                    # Clean work scratchpad
                    shutil.rmtree(work_dir, ignore_errors=True)
                    logger.info(f"Job {job_id}: Completed successfully.")
                else:
                    job.status = JobStatus.FAILED
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.error = result.error_message or "Signing execution failed."
                    shutil.rmtree(work_dir, ignore_errors=True)
                    logger.error(f"Job {job_id}: Failed with error: {job.error}")

            except Exception as e:
                logger.exception(f"Job {job_id}: Unhandled exception during signing: {e}")
                job.status = JobStatus.FAILED
                job.completed_at = datetime.now(timezone.utc).isoformat()
                job.error = f"Internal signing failure: {str(e)}"
                shutil.rmtree(work_dir, ignore_errors=True)

            finally:
                self._save_job_metadata(job)

    async def _cleanup_loop(self):
        """Periodic background garbage collection purging scratchpads older than JOB_TTL_HOURS."""
        while True:
            try:
                await asyncio.sleep(3600)  # Hourly check
                cutoff = datetime.now(timezone.utc).timestamp() - (settings.JOB_TTL_HOURS * 3600)
                if settings.JOBS_DIR.is_dir():
                    for job_dir in settings.JOBS_DIR.iterdir():
                        if job_dir.is_dir() and UUID_PATTERN.match(job_dir.name):
                            if job_dir.stat().st_mtime < cutoff:
                                shutil.rmtree(job_dir, ignore_errors=True)
                                self._jobs.pop(job_dir.name, None)
                                logger.info(f"Purged expired job workspace: {job_dir.name}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in job cleanup loop: {e}")


signing_manager = SigningManager()
