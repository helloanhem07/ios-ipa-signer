"""
Utilities for parsing iOS Plist metadata, CMS Mobileprovision profiles,
and inspecting PKCS#12 signing certificates.
"""
import datetime
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import plistlib
import zipfile

logger = logging.getLogger("signing_backend.plist_utils")


def extract_ipa_metadata(ipa_path: Path) -> Dict[str, Any]:
    """
    Directly inspects an .ipa archive to locate Payload/<App>.app/Info.plist
    and extract standard iOS metadata fields without extracting the whole archive.
    """
    if not ipa_path.is_file():
        raise FileNotFoundError(f"IPA file not found: {ipa_path}")

    if not zipfile.is_zipfile(ipa_path):
        raise ValueError(f"File is not a valid zip archive: {ipa_path}")

    with zipfile.ZipFile(ipa_path, "r") as zf:
        plist_entries = [
            name
            for name in zf.namelist()
            if name.startswith("Payload/") and name.endswith(".app/Info.plist")
        ]
        if not plist_entries:
            return {}

        # Use the first matched primary Info.plist (shallowest bundle)
        plist_entries.sort(key=lambda s: s.count("/"))
        plist_data = zf.read(plist_entries[0])
        try:
            info = plistlib.loads(plist_data)
        except Exception as e:
            logger.warning(f"Failed to parse Info.plist in {ipa_path}: {e}")
            return {}

        bundle_name = (
            info.get("CFBundleDisplayName")
            or info.get("CFBundleName")
            or Path(plist_entries[0]).parent.stem
        )
        bundle_id = info.get("CFBundleIdentifier")
        bundle_version = (
            info.get("CFBundleShortVersionString")
            or info.get("CFBundleVersion")
            or "1.0.0"
        )
        executable_name = info.get("CFBundleExecutable")

        return {
            "bundle_id": bundle_id,
            "bundle_name": str(bundle_name),
            "bundle_version": str(bundle_version),
            "min_os_version": info.get("MinimumOSVersion", "12.0"),
            "executable_name": executable_name,
            "package_type": info.get("CFBundlePackageType", "APPL"),
            "raw_info": info,
        }


def extract_plist_from_mobileprovision(content: bytes) -> bytes:
    """
    Extracts the encapsulated XML plist from a DER-encoded CMS/PKCS#7 .mobileprovision file.
    Operates without external OpenSSL or cryptography toolchain dependencies.
    """
    xml_start = content.find(b"<?xml")
    if xml_start == -1:
        raise ValueError("No XML plist header found in mobileprovision payload")

    xml_end = content.find(b"</plist>")
    if xml_end == -1:
        raise ValueError("No XML plist closing tag found in mobileprovision payload")

    xml_end += len(b"</plist>")
    return content[xml_start:xml_end]


def parse_provisioning_profile(provisioning_path: Path) -> Dict[str, Any]:
    """
    Parses a .mobileprovision file and returns structured profile information.
    """
    if not provisioning_path.is_file():
        raise FileNotFoundError(f"Provisioning profile not found: {provisioning_path}")

    with open(provisioning_path, "rb") as f:
        raw_bytes = f.read()

    plist_bytes = extract_plist_from_mobileprovision(raw_bytes)
    profile_dict = plistlib.loads(plist_bytes)

    creation_date = profile_dict.get("CreationDate")
    expiration_date = profile_dict.get("ExpirationDate")

    is_expired = False
    if isinstance(expiration_date, datetime.datetime):
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = expiration_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        is_expired = exp < now

    return {
        "name": profile_dict.get("Name"),
        "app_id_name": profile_dict.get("AppIDName"),
        "team_identifier": profile_dict.get("TeamIdentifier", []),
        "team_name": profile_dict.get("TeamName"),
        "creation_date": creation_date.isoformat() if isinstance(creation_date, datetime.datetime) else None,
        "expiration_date": expiration_date.isoformat() if isinstance(expiration_date, datetime.datetime) else None,
        "is_expired": is_expired,
        "uuid": profile_dict.get("UUID"),
        "entitlements": profile_dict.get("Entitlements", {}),
        "is_enterprise": profile_dict.get("ProvisionsAllDevices", False),
        "provisioned_devices": profile_dict.get("ProvisionedDevices", []),
        "raw_profile": profile_dict,
    }


def validate_p12_certificate(p12_path: Path, password: str) -> Dict[str, Any]:
    """
    Pre-validates a PKCS#12 file and extracts certificate metadata using cryptography.
    Falls back gracefully if the cryptography library is unavailable.
    """
    if not p12_path.is_file():
        return {"valid": False, "error": f"Certificate file not found: {p12_path}"}

    try:
        import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12

        with open(p12_path, "rb") as f:
            p12_data = f.read()

        pass_bytes = password.encode("utf-8") if password else None
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(p12_data, pass_bytes)

        if not cert:
            return {"valid": False, "error": "No certificate found in PKCS#12 archive"}

        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        expired = not_after < now

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        return {
            "valid": True,
            "expired": expired,
            "subject": subject,
            "issuer": issuer,
            "not_valid_before": not_before.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "has_private_key": private_key is not None,
        }
    except ImportError:
        return {
            "valid": p12_path.is_file() and p12_path.stat().st_size > 0,
            "warning": "cryptography package not available for deep P12 inspection",
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}
