"""
Apple Property List & OTA Manifest Validator.
Validates XML declaration, Apple Enterprise DTD compliance,
and required OTA manifest dictionary keys.
"""

import plistlib
from typing import Dict, Any, Union

APPLE_DTD_SUBSTRING = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>'


def validate_apple_plist_xml(xml_content: Union[str, bytes]) -> Dict[str, Any]:
    """
    Validates XML declaration, Apple DTD DOCTYPE, and plistlib deserialization.
    """
    if isinstance(xml_content, bytes):
        raw_bytes = xml_content
        try:
            xml_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            return {"valid": False, "error": f"Failed to decode XML as UTF-8: {e}"}
    elif isinstance(xml_content, str):
        xml_str = xml_content
        raw_bytes = xml_content.encode("utf-8")
    else:
        return {"valid": False, "error": "Invalid input type; expected str or bytes"}

    trimmed = xml_str.strip()
    has_xml_decl = trimmed.startswith("<?xml")
    has_apple_dtd = APPLE_DTD_SUBSTRING in trimmed

    try:
        parsed_dict = plistlib.loads(raw_bytes)
    except Exception as e:
        return {
            "valid": False,
            "has_xml_decl": has_xml_decl,
            "has_apple_dtd": has_apple_dtd,
            "error": f"plistlib parsing failed: {e}",
            "data": None
        }

    return {
        "valid": True,
        "has_xml_decl": has_xml_decl,
        "has_apple_dtd": has_apple_dtd,
        "data": parsed_dict,
        "error": None
    }


def validate_ota_manifest_structure(manifest_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates the exact dict hierarchy required by iOS for itms-services OTA installation:
    items -> assets (kind="software-package", url) & metadata (kind="software", bundle-identifier, bundle-version, title).
    """
    if not isinstance(manifest_dict, dict):
        return {"valid": False, "error": "Root plist element must be a dictionary"}

    items = manifest_dict.get("items")
    if not isinstance(items, list):
        return {"valid": False, "error": "Root dict must contain 'items' array"}
    if len(items) == 0:
        return {"valid": False, "error": "'items' array must contain at least one item"}

    item = items[0]
    if not isinstance(item, dict):
        return {"valid": False, "error": "Item in 'items' array must be a dictionary"}

    assets = item.get("assets")
    metadata = item.get("metadata")

    if not isinstance(assets, list) or len(assets) == 0:
        return {"valid": False, "error": "Item must contain non-empty 'assets' array"}
    if not isinstance(metadata, dict):
        return {"valid": False, "error": "Item must contain 'metadata' dictionary"}

    sw_pkg = next((a for a in assets if isinstance(a, dict) and a.get("kind") == "software-package"), None)
    if not sw_pkg:
        return {"valid": False, "error": "Assets array must contain an entry with kind='software-package'"}

    pkg_url = sw_pkg.get("url")
    if not pkg_url or not isinstance(pkg_url, str):
        return {"valid": False, "error": "Software-package asset missing valid 'url'"}

    required_meta = ["bundle-identifier", "bundle-version", "kind", "title"]
    for k in required_meta:
        if k not in metadata:
            return {"valid": False, "error": f"Metadata missing required key: '{k}'"}

    if metadata.get("kind") != "software":
        return {"valid": False, "error": f"Metadata 'kind' must be 'software', got '{metadata.get('kind')}'"}

    return {
        "valid": True,
        "package_url": pkg_url,
        "bundle_id": metadata["bundle-identifier"],
        "bundle_version": metadata["bundle-version"],
        "title": metadata["title"],
        "error": None
    }
