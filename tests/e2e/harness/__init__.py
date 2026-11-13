"""
Test Harness Utilities for iOS IPA Signing E2E Test Suite.
Provides bit-level validators, HTTP clients, and fixture generators.
"""

import zipfile

# ZipInfo backwards-compatibility wrapper for arcname parameter
_orig_zipinfo_init = zipfile.ZipInfo.__init__


def _patched_zipinfo_init(self, filename="", date_time=(1980, 1, 1, 0, 0, 0), *args, **kwargs):
    if "arcname" in kwargs:
        filename = kwargs.pop("arcname")
    return _orig_zipinfo_init(self, filename, date_time, *args, **kwargs)


zipfile.ZipInfo.__init__ = _patched_zipinfo_init

from .macho_validator import validate_macho_binary, MH_MAGIC_64, CPU_TYPE_ARM64
from .plist_validator import validate_apple_plist_xml, validate_ota_manifest_structure, APPLE_DTD_SUBSTRING
from .cms_validator import extract_cms_payload, validate_cms_envelope
from .zip_validator import validate_signed_ipa_archive, validate_ipa_zip_structure
from .http_client import TestHTTPClient, APIResponse
from .fixture_manager import FixtureManager

__all__ = [
    "validate_macho_binary",
    "MH_MAGIC_64",
    "CPU_TYPE_ARM64",
    "validate_apple_plist_xml",
    "validate_ota_manifest_structure",
    "APPLE_DTD_SUBSTRING",
    "extract_cms_payload",
    "validate_cms_envelope",
    "validate_signed_ipa_archive",
    "validate_ipa_zip_structure",
    "TestHTTPClient",
    "APIResponse",
    "FixtureManager",
]

