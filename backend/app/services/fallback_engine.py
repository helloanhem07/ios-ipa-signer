"""
Pure-Python in-process signing engine for portable, offline, and containerized execution.
Uses standard library zipfile, plistlib, hashlib, and shutil.
"""
import hashlib
import logging
import os
import plistlib
import shutil
import time
import zipfile
from pathlib import Path
from typing import Optional

from app.services.signing_engine import SigningEngine, SigningResult
from app.services.plist_utils import extract_ipa_metadata

logger = logging.getLogger("signing_backend.fallback_engine")

CODE_RESOURCES_RULES = {
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion\\.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^version\\.plist$": True,
}

CODE_RESOURCES_RULES2 = {
    ".*\\.dSYM($|/)": {"weight": 11.0},
    "^(.*/)?\\.DS_Store$": {"omit": True, "weight": 2000.0},
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion\\.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^Info\\.plist$": {"omit": True, "weight": 20.0},
    "^PkgInfo$": {"omit": True, "weight": 20.0},
    "^embedded\\.mobileprovision$": {"weight": 20.0},
    "^version\\.plist$": {"weight": 20.0},
}


class FallbackSigningEngine(SigningEngine):
    """
    Pure-Python portable signing engine for offline and cross-platform execution.
    """

    @property
    def name(self) -> str:
        return "fallback"

    def is_available(self) -> bool:
        return True

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
        start_time = time.monotonic()
        work_dir = (
            temp_dir / f"fallback_{int(time.time() * 1000)}"
            if temp_dir
            else Path(f"temp_fallback_{int(time.time() * 1000)}")
        )
        work_dir.mkdir(parents=True, exist_ok=True)
        extracted_dir = work_dir / "extracted"

        try:
            # 1. Decompress IPA with ZipSlip protection
            if not ipa_path.is_file() or not zipfile.is_zipfile(ipa_path):
                return SigningResult(
                    success=False,
                    error_code="INVALID_IPA_ARCHIVE",
                    error_message=f"File {ipa_path.name} is not a valid zip/ipa archive.",
                    engine_used=self.name,
                )

            extracted_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(ipa_path, "r") as zf:
                for member in zf.namelist():
                    resolved = (extracted_dir / member).resolve()
                    if not str(resolved).startswith(str(extracted_dir.resolve())):
                        return SigningResult(
                            success=False,
                            error_code="INVALID_IPA_ARCHIVE",
                            error_message=f"ZipSlip vulnerability detected in archive entry: {member}",
                            engine_used=self.name,
                        )
                zf.extractall(extracted_dir)

            # 2. Locate App bundle in Payload/
            payload_dir = extracted_dir / "Payload"
            if not payload_dir.is_dir():
                return SigningResult(
                    success=False,
                    error_code="INVALID_IPA_ARCHIVE",
                    error_message="Archive does not contain a 'Payload' directory.",
                    engine_used=self.name,
                )

            app_dirs = [d for d in payload_dir.iterdir() if d.is_dir() and d.name.endswith(".app")]
            if not app_dirs:
                return SigningResult(
                    success=False,
                    error_code="INVALID_IPA_ARCHIVE",
                    error_message="No .app bundle found inside Payload directory.",
                    engine_used=self.name,
                )
            app_dir = app_dirs[0]

            # 3. Modify Info.plist
            info_plist_path = app_dir / "Info.plist"
            info_data = {}
            if info_plist_path.is_file():
                try:
                    with open(info_plist_path, "rb") as f:
                        info_data = plistlib.load(f)
                except Exception as e:
                    logger.warning(f"Error loading Info.plist: {e}, initializing empty dict.")
                    info_data = {}

            if bundle_id:
                info_data["CFBundleIdentifier"] = bundle_id
            if bundle_name:
                info_data["CFBundleDisplayName"] = bundle_name
                info_data["CFBundleName"] = bundle_name
            if bundle_version:
                info_data["CFBundleShortVersionString"] = bundle_version
                info_data["CFBundleVersion"] = bundle_version

            with open(info_plist_path, "wb") as f:
                plistlib.dump(info_data, f, fmt=plistlib.FMT_XML)

            # 4. Inject embedded.mobileprovision
            if provisioning_path and provisioning_path.is_file():
                dest_prov = app_dir / "embedded.mobileprovision"
                shutil.copyfile(provisioning_path, dest_prov)

            # Optional entitlements handling
            if entitlements_path and entitlements_path.is_file():
                dest_xcent = app_dir / "archived-expanded-entitlements.xcent"
                shutil.copyfile(entitlements_path, dest_xcent)

            # 5. Build _CodeSignature/CodeResources
            code_sig_dir = app_dir / "_CodeSignature"
            code_sig_dir.mkdir(parents=True, exist_ok=True)
            code_resources_path = code_sig_dir / "CodeResources"

            files_dict = {}
            files2_dict = {}
            executable_name = info_data.get("CFBundleExecutable", app_dir.stem)

            for root, _, files in os.walk(app_dir):
                root_path = Path(root)
                # Omit _CodeSignature directory itself to prevent cyclic digests
                if "_CodeSignature" in root_path.parts:
                    continue
                for file_name in files:
                    if file_name == ".DS_Store":
                        continue
                    file_path = root_path / file_name
                    rel_path = file_path.relative_to(app_dir).as_posix()

                    with open(file_path, "rb") as f:
                        f_bytes = f.read()

                    sha1_hash = hashlib.sha1(f_bytes).digest()
                    sha256_hash = hashlib.sha256(f_bytes).digest()

                    files_dict[rel_path] = sha1_hash
                    files2_dict[rel_path] = {
                        "hash": sha1_hash,
                        "hash2": sha256_hash,
                    }

            code_resources = {
                "files": files_dict,
                "files2": files2_dict,
                "rules": CODE_RESOURCES_RULES,
                "rules2": CODE_RESOURCES_RULES2,
            }

            with open(code_resources_path, "wb") as f:
                plistlib.dump(code_resources, f, fmt=plistlib.FMT_XML)

            # 6. Repack into output IPA with POSIX permissions
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_output = output_path.with_suffix(".tmp.ipa")

            comp_level = max(0, min(9, compression_level))
            with zipfile.ZipFile(
                temp_output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=comp_level
            ) as zf_out:
                for root, _, files in os.walk(extracted_dir):
                    for file_name in files:
                        full_path = Path(root) / file_name
                        arcname = full_path.relative_to(extracted_dir).as_posix()

                        zinfo = zipfile.ZipInfo(filename=arcname, date_time=time.localtime()[:6])
                        zinfo.compress_type = zipfile.ZIP_DEFLATED

                        is_exec = file_name == executable_name
                        mode = 0o755 if is_exec else 0o644
                        zinfo.external_attr = (mode & 0xFFFF) << 16

                        with open(full_path, "rb") as f_in:
                            zf_out.writestr(zinfo, f_in.read())

            if output_path.exists():
                output_path.unlink()
            temp_output.rename(output_path)

            duration = time.monotonic() - start_time
            meta = extract_ipa_metadata(output_path)

            return SigningResult(
                success=True,
                output_path=output_path,
                bundle_id=meta.get("bundle_id", info_data.get("CFBundleIdentifier")),
                bundle_name=meta.get("bundle_name", info_data.get("CFBundleDisplayName", "SignedApp")),
                bundle_version=meta.get("bundle_version", info_data.get("CFBundleShortVersionString", "1.0.0")),
                stdout="Fallback engine signed IPA successfully.",
                stderr="",
                execution_time_seconds=duration,
                engine_used=self.name,
                metadata=meta,
            )

        except Exception as e:
            logger.exception(f"Fallback signing engine encountered an exception: {e}")
            return SigningResult(
                success=False,
                error_code="PROCESS_FAILED",
                error_message=f"Fallback engine exception: {str(e)}",
                execution_time_seconds=time.monotonic() - start_time,
                engine_used=self.name,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
