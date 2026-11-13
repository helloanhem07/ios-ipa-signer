"""
IPA PKZIP Structure & CodeResources Validator.
Validates the internal directory hierarchy and integrity of iOS application archives (.ipa).
"""

import plistlib
import zipfile
from typing import Dict, Any, List, Optional


def validate_ipa_zip_structure(ipa_path: str) -> Dict[str, Any]:
    """
    Validates basic PKZIP format and presence of Payload/<AppName>.app hierarchy.
    """
    if not zipfile.is_zipfile(ipa_path):
        return {"valid": False, "error": "File is not a valid PKZIP archive"}

    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            names = z.namelist()
            app_prefixes = set()

            for n in names:
                parts = n.split("/")
                if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
                    app_prefixes.add(f"Payload/{parts[1]}")

            if not app_prefixes:
                return {
                    "valid": False,
                    "error": "Missing 'Payload/<AppName>.app' directory in IPA archive",
                    "file_count": len(names),
                    "names": names
                }

            app_dir = sorted(list(app_prefixes))[0]
            info_plist_path = f"{app_dir}/Info.plist"
            has_info_plist = info_plist_path in names or any(n.endswith("/Info.plist") for n in names)

            return {
                "valid": True,
                "app_dir": app_dir,
                "has_info_plist": has_info_plist,
                "file_count": len(names),
                "names": names,
                "error": None
            }
    except Exception as e:
        return {"valid": False, "error": f"Failed to inspect zip file: {e}"}


def validate_signed_ipa_archive(ipa_path: str) -> Dict[str, Any]:
    """
    Validates that an IPA has been signed, inspecting Info.plist,
    _CodeSignature/CodeResources, and embedded.mobileprovision.
    """
    base_check = validate_ipa_zip_structure(ipa_path)
    if not base_check["valid"]:
        return base_check

    names = base_check["names"]
    app_dir = base_check["app_dir"]

    has_code_resources = any(n == f"{app_dir}/_CodeSignature/CodeResources" or "_CodeSignature/CodeResources" in n for n in names)
    has_embedded_profile = any(n == f"{app_dir}/embedded.mobileprovision" or "embedded.mobileprovision" in n for n in names)

    # Read Info.plist if available
    info_dict = {}
    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            info_target = f"{app_dir}/Info.plist"
            if info_target in names:
                info_bytes = z.read(info_target)
                info_dict = plistlib.loads(info_bytes)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to read/parse Info.plist: {e}",
            "has_code_resources": has_code_resources,
            "has_embedded_profile": has_embedded_profile
        }

    return {
        "valid": True,
        "app_dir": app_dir,
        "has_info_plist": base_check["has_info_plist"],
        "has_code_resources": has_code_resources,
        "has_embedded_profile": has_embedded_profile,
        "bundle_id": info_dict.get("CFBundleIdentifier"),
        "bundle_name": info_dict.get("CFBundleDisplayName") or info_dict.get("CFBundleName"),
        "bundle_version": info_dict.get("CFBundleShortVersionString") or info_dict.get("CFBundleVersion"),
        "executable": info_dict.get("CFBundleExecutable"),
        "total_files": base_check["file_count"],
        "error": None
    }
