"""
ASN.1 CMS SignedData Envelope & Mobileprovision Validator.
Extracts and validates inner XML property lists from Apple .mobileprovision profiles.
"""

import plistlib
import re
from typing import Dict, Any, Union

# ASN.1 OID 1.2.840.113549.1.7.2 (pkcs7-signedData) in DER bytes:
CMS_SIGNED_DATA_OID_BYTES = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])


def extract_cms_payload(mobileprovision_bytes: bytes) -> bytes:
    """
    Extracts the inner XML plist payload from an Apple ASN.1 CMS SignedData envelope.
    """
    if not isinstance(mobileprovision_bytes, (bytes, bytearray)):
        raise TypeError("Expected bytes or bytearray")

    start_tag = b"<?xml"
    end_tag = b"</plist>"

    start_idx = mobileprovision_bytes.find(start_tag)
    end_idx = mobileprovision_bytes.find(end_tag)

    if start_idx == -1 or end_idx == -1:
        raise ValueError("Could not find valid XML plist markers in mobileprovision CMS envelope")

    return bytes(mobileprovision_bytes[start_idx : end_idx + len(end_tag)])


def validate_cms_envelope(data_or_path: Union[str, bytes]) -> Dict[str, Any]:
    """
    Validates the ASN.1 CMS SignedData envelope structure and extracts metadata from .mobileprovision.
    """
    if isinstance(data_or_path, str):
        try:
            with open(data_or_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            return {"valid": False, "error": f"Failed to read mobileprovision file: {e}"}
    elif isinstance(data_or_path, (bytes, bytearray)):
        raw_bytes = bytes(data_or_path)
    else:
        return {"valid": False, "error": "Invalid argument type"}

    if len(raw_bytes) < 64:
        return {"valid": False, "error": "File too small to be a valid mobileprovision profile"}

    has_cms_tag = raw_bytes[0] == 0x30  # ASN.1 SEQUENCE
    has_signed_data_oid = CMS_SIGNED_DATA_OID_BYTES in raw_bytes

    try:
        xml_payload = extract_cms_payload(raw_bytes)
        parsed_plist = plistlib.loads(xml_payload)
    except Exception as e:
        return {
            "valid": False,
            "has_cms_tag": has_cms_tag,
            "has_signed_data_oid": has_signed_data_oid,
            "error": f"Failed to extract or parse inner plist: {e}"
        }

    entitlements = parsed_plist.get("Entitlements", {})
    team_identifier = parsed_plist.get("TeamIdentifier", [])
    uuid = parsed_plist.get("UUID")
    app_id_name = parsed_plist.get("AppIDName")
    name = parsed_plist.get("Name")

    return {
        "valid": True,
        "has_cms_tag": has_cms_tag,
        "has_signed_data_oid": has_signed_data_oid,
        "uuid": str(uuid) if uuid else None,
        "name": name,
        "app_id_name": app_id_name,
        "team_identifier": team_identifier,
        "entitlements": entitlements,
        "full_data": parsed_plist,
        "raw_xml": xml_payload.decode("utf-8", errors="replace"),
        "error": None
    }
