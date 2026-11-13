"""
Subprocess wrapper for the native compiled C++ zsign executable.
"""
import asyncio
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Optional, Tuple

from app.services.signing_engine import SigningEngine, SigningResult
from app.services.plist_utils import extract_ipa_metadata
from app.config import settings

logger = logging.getLogger("signing_backend.zsign_engine")

ERROR_PATTERNS = [
    (
        re.compile(r"password incorrect|can't parse pkcs12|pkcs12_parse failed|mac verify failure", re.I),
        "INVALID_CERT_PASSWORD",
        "Invalid certificate password or damaged PKCS#12 file.",
    ),
    (
        re.compile(r"parse mobileprovision failed|can't parse provision|invalid mobileprovision", re.I),
        "INVALID_PROVISIONING_PROFILE",
        "Invalid or malformed mobileprovision profile.",
    ),
    (
        re.compile(r"can't find app folder|no app bundle found|can't find payload|not a valid ipa", re.I),
        "INVALID_IPA_ARCHIVE",
        "Invalid IPA archive structure: missing Payload/<App>.app.",
    ),
    (
        re.compile(r"parse entitlements failed|invalid entitlements", re.I),
        "INVALID_ENTITLEMENTS",
        "Invalid custom entitlements plist structure.",
    ),
    (
        re.compile(r"bundle id mismatch", re.I),
        "BUNDLE_ID_MISMATCH",
        "Provisioning profile does not permit the requested bundle identifier.",
    ),
]


def resolve_zsign_binary() -> Optional[Path]:
    """
    Discovers the native zsign binary across configured paths and system PATH.
    """
    # 1. Configured path from settings
    if settings.ZSIGN_BIN_PATH:
        p = Path(settings.ZSIGN_BIN_PATH)
        if p.is_file():
            return p.resolve()

    # 2. Environment variable
    env_path = os.environ.get("ZSIGN_BIN_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p.resolve()

    # 3. System PATH
    which_name = "zsign.exe" if os.name == "nt" else "zsign"
    found = shutil.which(which_name) or shutil.which("zsign")
    if found:
        return Path(found).resolve()

    # 4. Project bin directory
    bin_name = "zsign.exe" if os.name == "nt" else "zsign"
    candidate = settings.BACKEND_DIR / "bin" / bin_name
    if candidate.is_file():
        return candidate.resolve()

    return None


def parse_zsign_error(stdout_str: str, stderr_str: str, returncode: int) -> Tuple[str, str]:
    """
    Parses zsign output and maps failures to standardized error codes and actionable messages.
    """
    combined = f"{stdout_str}\n{stderr_str}"
    for pattern, code, msg in ERROR_PATTERNS:
        if pattern.search(combined):
            return code, msg

    lines = [ln.strip() for ln in combined.splitlines() if ln.strip()]
    detail = lines[-1] if lines else f"Process exited with code {returncode}"
    return "PROCESS_FAILED", f"zsign signing failed: {detail}"


class ZsignBinaryEngine(SigningEngine):
    """
    High-performance signing engine executing native zsign CLI subprocess.
    """

    def __init__(self, binary_path: Optional[Path] = None):
        self._binary_path = binary_path or resolve_zsign_binary()

    @property
    def name(self) -> str:
        return "zsign"

    def is_available(self) -> bool:
        """
        Returns True if zsign binary exists on host.
        """
        if not self._binary_path or not self._binary_path.is_file():
            # Refresh lookup in case it was placed dynamically
            self._binary_path = resolve_zsign_binary()
        return bool(
            self._binary_path
            and self._binary_path.is_file()
            and (os.name == "nt" or os.access(self._binary_path, os.X_OK))
        )

    def build_command(
        self,
        ipa_path: Path,
        p12_path: Path,
        p12_password: str,
        provisioning_path: Path,
        output_path: Path,
        bundle_id: Optional[str] = None,
        bundle_name: Optional[str] = None,
        bundle_version: Optional[str] = None,
        entitlements_path: Optional[Path] = None,
        compression_level: int = 1,
        temp_dir: Optional[Path] = None,
    ) -> list[str]:
        """
        Constructs the exact CLI argument vector for zsign.
        """
        bin_str = str(self._binary_path) if self._binary_path else "zsign"
        cmd = [
            bin_str,
            "-k", str(p12_path.resolve()),
            "-p", p12_password,
            "-m", str(provisioning_path.resolve()),
            "-o", str(output_path.resolve()),
            "-z", str(max(0, min(9, compression_level))),
            "-f",  # force re-sign
        ]

        if temp_dir:
            cmd.extend(["-t", str(temp_dir.resolve())])

        if bundle_id and re.match(r"^[a-zA-Z0-9.\-_]+$", bundle_id.strip()):
            cmd.extend(["-b", bundle_id.strip()])

        if bundle_name and bundle_name.strip():
            cmd.extend(["-n", bundle_name.strip()])

        if bundle_version and bundle_version.strip():
            cmd.extend(["-r", bundle_version.strip()])

        if entitlements_path and entitlements_path.is_file():
            cmd.extend(["-e", str(entitlements_path.resolve())])

        cmd.append(str(ipa_path.resolve()))
        return cmd

    async def sign(
        self,
        ipa_path: Path,
        p12_path: Path,
        p12_password: str,
        provisioning_path: Path,
        output_path: Path,
        bundle_id: Optional[str] = None,
        bundle_name: Optional[str] = None,
        bundle_version: Optional[str] = None,
        entitlements_path: Optional[Path] = None,
        compression_level: int = 1,
        temp_dir: Optional[Path] = None,
        timeout_seconds: float = 300.0,
    ) -> SigningResult:
        if not self.is_available():
            return SigningResult(
                success=False,
                error_code="ENGINE_UNAVAILABLE",
                error_message=f"Native zsign binary not found or not executable: {self._binary_path}",
                engine_used=self.name,
            )

        start_time = time.monotonic()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if temp_dir:
            temp_dir.mkdir(parents=True, exist_ok=True)

        cmd = self.build_command(
            ipa_path=ipa_path,
            p12_path=p12_path,
            p12_password=p12_password,
            provisioning_path=provisioning_path,
            output_path=output_path,
            bundle_id=bundle_id,
            bundle_name=bundle_name,
            bundle_version=bundle_version,
            entitlements_path=entitlements_path,
            compression_level=compression_level,
            temp_dir=temp_dir,
        )

        logger.info(f"Executing zsign command: {' '.join(cmd[:4])} [REDACTED_PASSWORD] {' '.join(cmd[6:])}")

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout_seconds,
            )
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            duration = time.monotonic() - start_time

            if proc.returncode != 0:
                err_code, err_msg = parse_zsign_error(stdout_str, stderr_str, proc.returncode)
                logger.error(f"zsign exited with {proc.returncode}: {err_msg}")
                return SigningResult(
                    success=False,
                    error_code=err_code,
                    error_message=err_msg,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    execution_time_seconds=duration,
                    engine_used=self.name,
                )

            if not output_path.is_file() or output_path.stat().st_size == 0:
                return SigningResult(
                    success=False,
                    error_code="PROCESS_FAILED",
                    error_message="zsign succeeded with code 0 but output IPA was not created.",
                    stdout=stdout_str,
                    stderr=stderr_str,
                    execution_time_seconds=duration,
                    engine_used=self.name,
                )

            meta = extract_ipa_metadata(output_path)
            return SigningResult(
                success=True,
                output_path=output_path,
                bundle_id=meta.get("bundle_id", bundle_id),
                bundle_name=meta.get("bundle_name", bundle_name),
                bundle_version=meta.get("bundle_version", bundle_version),
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time_seconds=duration,
                engine_used=self.name,
                metadata=meta,
            )

        except asyncio.TimeoutError:
            if proc:
                try:
                    proc.terminate()
                    await asyncio.sleep(0.5)
                    if proc.returncode is None:
                        proc.kill()
                except ProcessLookupError:
                    pass
            return SigningResult(
                success=False,
                error_code="SIGNING_TIMEOUT",
                error_message=f"Signing process timed out after {timeout_seconds} seconds.",
                execution_time_seconds=time.monotonic() - start_time,
                engine_used=self.name,
            )
        except Exception as e:
            return SigningResult(
                success=False,
                error_code="PROCESS_FAILED",
                error_message=f"Subprocess execution exception: {str(e)}",
                execution_time_seconds=time.monotonic() - start_time,
                engine_used=self.name,
            )
