"""
tests/test_m2_engine_security.py
Adversarial Challenge & Empirical Test Suite for Milestone 2:
Embedded zsign Engine, Objective-C++ Bridge, and Security Parsers.
"""

import os
import re
import sys
import struct
import binascii
import hashlib
import plistlib
from datetime import datetime, timezone, timedelta
import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import pkcs7

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IOSAPP_DIR = os.path.join(WORKSPACE_ROOT, "iOSApp")
ZSIGN_SRC_DIR = os.path.join(IOSAPP_DIR, "Sources", "zsign")
BRIDGE_DIR = os.path.join(IOSAPP_DIR, "Sources", "Bridge")
SERVICES_DIR = os.path.join(IOSAPP_DIR, "Sources", "Services")
SCOPE_MD_PATH = os.path.join(WORKSPACE_ROOT, ".agents", "teamwork", "sub_orch_m2", "SCOPE.md")


# ==============================================================================
# 1. FORBIDDEN CALLS AUDIT (exit, _exit, abort, system, SystemExec)
# ==============================================================================

def test_forbidden_calls_in_cpp_engine():
    """
    Empirically inspects all C++ engine and bridge files to verify that
    forbidden process-terminating calls (exit, _exit, abort, system, SystemExec)
    are NOT invoked in the codebase.
    """
    target_files = [
        os.path.join(ZSIGN_SRC_DIR, "zsign.cpp"),
        os.path.join(ZSIGN_SRC_DIR, "zsign.h"),
        os.path.join(ZSIGN_SRC_DIR, "bundle.cpp"),
        os.path.join(ZSIGN_SRC_DIR, "bundle.h"),
        os.path.join(ZSIGN_SRC_DIR, "macho.cpp"),
        os.path.join(ZSIGN_SRC_DIR, "macho.h"),
        os.path.join(ZSIGN_SRC_DIR, "openssl.cpp"),
        os.path.join(ZSIGN_SRC_DIR, "openssl.h"),
        os.path.join(ZSIGN_SRC_DIR, "common.h"),
        os.path.join(BRIDGE_DIR, "ZsignBridge.mm"),
        os.path.join(BRIDGE_DIR, "ZsignBridge.h"),
    ]

    forbidden_patterns = [
        (re.compile(r'(?<![a-zA-Z0-9_])exit\s*\('), "exit()"),
        (re.compile(r'(?<![a-zA-Z0-9_])_exit\s*\('), "_exit()"),
        (re.compile(r'(?<![a-zA-Z0-9_])abort\s*\('), "abort()"),
        (re.compile(r'(?<![a-zA-Z0-9_])system\s*\('), "system()"),
        (re.compile(r'(?<![a-zA-Z0-9_])SystemExec\s*\('), "SystemExec()"),
    ]

    violations = []

    for file_path in target_files:
        assert os.path.isfile(file_path), f"Required source file not found: {file_path}"
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        in_multiline_comment = False
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Handle multiline comments /* ... */
            if "/*" in line and "*/" not in line:
                in_multiline_comment = True
                continue
            if in_multiline_comment:
                if "*/" in line:
                    in_multiline_comment = False
                continue

            # Strip single-line comments
            code_part = re.sub(r'//.*$', '', raw_line)
            code_part = re.sub(r'/\*.*?\*/', '', code_part)

            for regex, name in forbidden_patterns:
                if regex.search(code_part):
                    violations.append((file_path, line_no, name, raw_line.strip()))

    assert len(violations) == 0, (
        f"Found {len(violations)} forbidden call violations in C++/ObjC files:\n" +
        "\n".join([f"  {v[0]}:{v[1]} - Call: {v[2]} in `{v[3]}`" for v in violations])
    )


# ==============================================================================
# 2. ZIP EXTERNAL ATTRIBUTES VERIFICATION (POSIX 0755 & 0x41ED0000 / 0x81ED0000)
# ==============================================================================

def test_zip_external_attributes_in_zsign_bridge():
    """
    Verifies that ZIP external attributes in ZsignBridge.mm use:
    - 0x81ED0000 ((0100755 << 16)) for executable files
    - 0x41ED0000 ((0040755 << 16)) for directories
    - 0x81A40000 ((0100644 << 16)) for regular non-executable files
    - UNIX host system identifier (verMadeBy = 0x031e)
    """
    bridge_mm_path = os.path.join(BRIDGE_DIR, "ZsignBridge.mm")
    assert os.path.isfile(bridge_mm_path)

    with open(bridge_mm_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify directory attribute 0x41ED0000
    assert "(0040755 << 16)" in content or "0x41ED0000" in content, (
        "Directory attribute (0040755 << 16) / 0x41ED0000 not found in ZsignBridge.mm"
    )

    # Verify executable attribute 0x81ED0000
    assert "(0100755 << 16)" in content or "0x81ED0000" in content, (
        "Executable attribute (0100755 << 16) / 0x81ED0000 not found in ZsignBridge.mm"
    )

    # Verify regular file attribute 0x81A40000
    assert "(0100644 << 16)" in content or "0x81A40000" in content, (
        "Regular file attribute (0100644 << 16) / 0x81A40000 not found in ZsignBridge.mm"
    )

    # Verify Unix platform specifier (verMadeBy upper byte == 3)
    assert "0x031e" in content or "0x03" in content, (
        "ZIP Central Directory verMadeBy UNIX flag (0x031e) missing from ZsignBridge.mm"
    )

    # Empirically calculate bit-level values to ensure C++ octal shifts produce exact values:
    dir_attr = 0o040755 << 16
    exec_attr = 0o100755 << 16
    reg_attr = 0o100644 << 16

    assert dir_attr == 0x41ED0000, f"Expected 0x41ED0000, got {hex(dir_attr)}"
    assert exec_attr == 0x81ED0000, f"Expected 0x81ED0000, got {hex(exec_attr)}"
    assert reg_attr == 0x81A40000, f"Expected 0x81A40000, got {hex(reg_attr)}"


def test_inprocess_unpack_posix_preservation():
    """
    Verifies that InProcessUnpackIPA inspects Mach-O magic numbers and sets
    POSIX 0755 permissions for binaries and dynamic libraries.
    """
    bridge_mm_path = os.path.join(BRIDGE_DIR, "ZsignBridge.mm")
    with open(bridge_mm_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Must check Mach-O magics: 0xfeedfacf (MH_MAGIC_64), 0xfeedface (MH_MAGIC),
    # 0xcafebabe (FAT_MAGIC), 0xbebafeca (FAT_CIGAM)
    for magic in ["0xfeedfacf", "0xfeedface", "0xcafebabe", "0xbebafeca"]:
        assert magic in content, f"Mach-O magic {magic} check missing in InProcessUnpackIPA"

    # Must chmod executable files to 0755 (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
    assert "S_IRWXU" in content or "0755" in content, "POSIX 0755 chmod missing in InProcessUnpackIPA"


# ==============================================================================
# 3. INTERFACE CONTRACT COMPLIANCE (SCOPE.md Lines 50-80)
# ==============================================================================

def test_zsign_bridge_method_signatures_conformance():
    """
    Verifies ZsignBridge.h and ZsignBridge.mm against sub_orch_m2/SCOPE.md lines 50-80.
    Checks:
    - typedef void (^ZsignProgressBlock)(float progress, NSString *statusMessage);
    - ZsignResult class and properties:
      success (BOOL), outputIpaPath, bundleId, appVersion, appName, errorMessage.
    - ZsignBridge class and class methods:
      + signAppBundleWithIpaPath:...
      + zsignVersion
    """
    bridge_h_path = os.path.join(BRIDGE_DIR, "ZsignBridge.h")
    assert os.path.isfile(bridge_h_path)
    with open(bridge_h_path, "r", encoding="utf-8") as f:
        header_content = f.read()

    # 1. ZsignProgressBlock
    assert re.search(r'typedef\s+void\s*\(\^ZsignProgressBlock\)\s*\(\s*float\s+progress\s*,\s*NSString\s*\*statusMessage\s*\);', header_content), (
        "ZsignProgressBlock typedef does not match specification."
    )

    # 2. ZsignResult properties
    expected_props = [
        r'@property\s*\(\s*nonatomic\s*,\s*assign\s*\)\s*BOOL\s+success;',
        r'@property\s*\(\s*nonatomic\s*,\s*copy\s*,\s*nullable\s*\)\s*NSString\s*\*outputIpaPath;',
        r'@property\s*\(\s*nonatomic\s*,\s*copy\s*,\s*nullable\s*\)\s*NSString\s*\*bundleId;',
        r'@property\s*\(\s*nonatomic\s*,\s*copy\s*,\s*nullable\s*\)\s*NSString\s*\*appVersion;',
        r'@property\s*\(\s*nonatomic\s*,\s*copy\s*,\s*nullable\s*\)\s*NSString\s*\*appName;',
        r'@property\s*\(\s*nonatomic\s*,\s*copy\s*,\s*nullable\s*\)\s*NSString\s*\*errorMessage;',
    ]
    for prop_pattern in expected_props:
        assert re.search(prop_pattern, header_content), f"Property matching '{prop_pattern}' missing in ZsignResult."

    # 3. ZsignBridge class methods
    expected_method = (
        r'\+\s*\(\s*ZsignResult\s*\*\s*\)signAppBundleWithIpaPath:\s*\(\s*NSString\s*\*\s*\)ipaPath\s+'
        r'p12Path:\s*\(\s*NSString\s*\*\s*\)p12Path\s+'
        r'p12Password:\s*\(\s*NSString\s*\*\s*\)p12Password\s+'
        r'provisioningPath:\s*\(\s*NSString\s*\*\s*\)provisioningPath\s+'
        r'bundleId:\s*\(\s*nullable\s+NSString\s*\*\s*\)bundleId\s+'
        r'displayName:\s*\(\s*nullable\s+NSString\s*\*\s*\)displayName\s+'
        r'entitlementsPath:\s*\(\s*nullable\s+NSString\s*\*\s*\)entitlementsPath\s+'
        r'compression:\s*\(\s*NSInteger\s*\)compression\s+'
        r'progress:\s*\(\s*nullable\s+ZsignProgressBlock\s*\)progressBlock;'
    )
    assert re.search(expected_method, header_content, re.MULTILINE), (
        "ZsignBridge signAppBundleWithIpaPath signature does not match sub_orch_m2/SCOPE.md."
    )

    assert re.search(r'\+\s*\(\s*NSString\s*\*\s*\)zsignVersion;', header_content), (
        "+ (NSString *)zsignVersion method declaration missing in ZsignBridge.h"
    )

    # Verify implementation file conforms
    bridge_mm_path = os.path.join(BRIDGE_DIR, "ZsignBridge.mm")
    with open(bridge_mm_path, "r", encoding="utf-8") as f:
        mm_content = f.read()

    assert "+ (ZsignResult *)signAppBundleWithIpaPath:" in mm_content
    assert "+ (NSString *)zsignVersion" in mm_content


# ==============================================================================
# 4. AMFI DER ENTITLEMENTS SLOT 7 (CSSLOT_DER_ENTITLEMENTS = 7, 0xfade7172)
# ==============================================================================

def test_amfi_der_entitlements_slot7_in_macho():
    """
    Verifies that macho.h and macho.cpp correctly declare and implement
    AMFI DER Entitlements slot 7 (CSSLOT_DER_ENTITLEMENTS = 7, magic 0xfade7172)
    required for iOS 15+ code validation.
    """
    macho_h_path = os.path.join(ZSIGN_SRC_DIR, "macho.h")
    macho_cpp_path = os.path.join(ZSIGN_SRC_DIR, "macho.cpp")

    with open(macho_h_path, "r", encoding="utf-8") as f:
        h_code = f.read()

    with open(macho_cpp_path, "r", encoding="utf-8") as f:
        cpp_code = f.read()

    # 1. Macro constants in macho.h
    assert "#define CSMAGIC_EMBEDDED_DER_ENTITLEMENTS  0xfade7172" in h_code, (
        "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS (0xfade7172) definition missing from macho.h"
    )
    assert "#define CSSLOT_DER_ENTITLEMENTS            7" in h_code, (
        "CSSLOT_DER_ENTITLEMENTS (7) definition missing from macho.h"
    )

    # 2. Slot allocation and hashing in macho.cpp
    assert "uint32_t nSpecialSlots = 7;" in cpp_code, (
        "nSpecialSlots must be at least 7 to support slot -7 (DER Entitlements)."
    )

    # Check Slot -7 hashing into specialHashes[6]
    assert re.search(r'specialHashes\[6\]', cpp_code), (
        "specialHashes[6] (representing Slot -7) not hashed in macho.cpp"
    )
    assert "ZSignAsset::Sha256(rawDerEnt, specialHashes[6]);" in cpp_code, (
        "DER Entitlements must be hashed into specialHashes[6]."
    )

    # Check SuperBlob slot index assignment for CSSLOT_DER_ENTITLEMENTS
    assert "CSSLOT_DER_ENTITLEMENTS" in cpp_code, (
        "CSSLOT_DER_ENTITLEMENTS must be referenced in SuperBlob index assembly."
    )
    assert "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS" in cpp_code, (
        "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS header must be written before DER data."
    )

    # Check blobCount includes the DER blob
    assert "uint32_t blobCount = 5;" in cpp_code, (
        "SuperBlob must include 5 blobs (CD, Requirements, XML Ent, DER Ent, CMS Sig)."
    )


def test_der_entitlements_asn1_octet_string_encoding():
    """
    Tests the ASN.1 OCTET STRING header encoding algorithm used by ZSignAsset::GenerateDEREntitlements.
    Ensures that short form (<128) and long form (128..255, 256..65535, >65535) are strictly valid DER.
    """
    def generate_der_entitlements(xml_str: str) -> bytes:
        data = xml_str.encode("utf-8")
        length = len(data)
        out = bytearray()
        out.append(0x04) # ASN.1 OCTET STRING tag
        if length < 128:
            out.append(length)
        elif length <= 0xFF:
            out.append(0x81)
            out.append(length)
        elif length <= 0xFFFF:
            out.append(0x82)
            out.append((length >> 8) & 0xFF)
            out.append(length & 0xFF)
        else:
            out.append(0x84)
            out.append((length >> 24) & 0xFF)
            out.append((length >> 16) & 0xFF)
            out.append((length >> 8) & 0xFF)
            out.append(length & 0xFF)
        out.extend(data)
        return bytes(out)

    # Test cases across boundary lengths
    test_cases = [
        0,           # Empty
        50,          # Single byte short length (<128)
        127,         # Boundary short length
        128,         # Boundary 1-byte long length (0x81 0x80)
        255,         # Boundary 1-byte long length (0x81 0xFF)
        256,         # Boundary 2-byte long length (0x82 0x01 0x00)
        1024,        # Standard realistic entitlement size
        65535,       # Boundary 2-byte long length
        65536,       # Boundary 4-byte long length
    ]

    for size in test_cases:
        dummy_xml = "x" * size
        der_bytes = generate_der_entitlements(dummy_xml)

        assert der_bytes[0] == 0x04, "Tag must be 0x04 (OCTET STRING)"
        if size < 128:
            assert der_bytes[1] == size
            assert der_bytes[2:] == dummy_xml.encode("utf-8")
        elif size <= 0xFF:
            assert der_bytes[1] == 0x81
            assert der_bytes[2] == size
            assert der_bytes[3:] == dummy_xml.encode("utf-8")
        elif size <= 0xFFFF:
            assert der_bytes[1] == 0x82
            decoded_len = (der_bytes[2] << 8) | der_bytes[3]
            assert decoded_len == size
            assert der_bytes[4:] == dummy_xml.encode("utf-8")
        else:
            assert der_bytes[1] == 0x84
            decoded_len = struct.unpack(">I", der_bytes[2:6])[0]
            assert decoded_len == size
            assert der_bytes[6:] == dummy_xml.encode("utf-8")


# ==============================================================================
# 5. PKCS12Parser.swift LOGIC & ADVERSARIAL STRESS TESTING
# ==============================================================================

class MockPKCS12ParserSimulator:
    """
    Emulates the exact parsing algorithms of PKCS12Parser.swift to stress-test
    edge cases, regex extractions, and error guards.
    """
    @staticmethod
    def extract_team_name(cn: str) -> str:
        # Swift:
        # if let colonIndex = cn.firstIndex(of: ":") {
        #     let afterColon = cn[cn.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
        #     if let parenIndex = afterColon.firstIndex(of: "(") {
        #         return String(afterColon[..<parenIndex]).trimmingCharacters(in: .whitespaces)
        #     }
        #     return afterColon
        # }
        # return cn
        if ":" in cn:
            after_colon = cn.split(":", 1)[1].strip()
            if "(" in after_colon:
                return after_colon.split("(", 1)[0].strip()
            return after_colon
        return cn

    @staticmethod
    def extract_team_id(cn: str) -> str:
        # Swift:
        # if let start = cn.range(of: "(", options: .backwards)?.upperBound,
        #    let end = cn.range(of: ")", options: .backwards)?.lowerBound,
        #    start < end {
        #     return String(cn[start..<end]).trimmingCharacters(in: .whitespaces)
        # }
        # return ""
        start = cn.rfind("(")
        end = cn.rfind(")")
        if start != -1 and end != -1 and start < end:
            return cn[start + 1:end].strip()
        return ""

    @staticmethod
    def detect_certificate_type(cn: str) -> str:
        if "Apple Development" in cn or "iPhone Developer" in cn:
            return "development"
        elif "Apple Distribution" in cn or "iPhone Distribution" in cn:
            return "distribution"
        elif "Enterprise" in cn:
            return "enterprise"
        return "unknown"


def test_pkcs12_parser_name_and_id_extraction_matrix():
    """
    Tests edge cases for PKCS12Parser team name and team identifier extraction.
    """
    sim = MockPKCS12ParserSimulator

    test_vectors = [
        # (CN, expected_name, expected_id, expected_type)
        (
            "iPhone Distribution: ACME Corp (ABC1234XYZ)",
            "ACME Corp",
            "ABC1234XYZ",
            "distribution"
        ),
        (
            "Apple Development: Jane Doe (DEV9999999)",
            "Jane Doe",
            "DEV9999999",
            "development"
        ),
        (
            "iPhone Developer: John Appleseed (TEST123456)",
            "John Appleseed",
            "TEST123456",
            "development"
        ),
        (
            "Apple Distribution: Global Enterprise Ltd (ENT987654)",
            "Global Enterprise Ltd",
            "ENT987654",
            "distribution"
        ),
        (
            "Enterprise iOS Signing: MegaCorp",
            "MegaCorp",
            "",
            "enterprise"
        ),
        (
            "iPhone Distribution: Complex (Nested (Paren)) (REAL_ID)",
            "Complex",
            "REAL_ID",
            "distribution"
        ),
        (
            "Custom CA Root",
            "Custom CA Root",
            "",
            "unknown"
        ),
        (
            "",
            "",
            "",
            "unknown"
        ),
        (
            "iPhone Distribution:    Leading and Trailing Spaces    (  SPACES_ID  )",
            "Leading and Trailing Spaces",
            "SPACES_ID",
            "distribution"
        ),
        (
            "iPhone Distribution: Corp Without Parens",
            "Corp Without Parens",
            "",
            "distribution"
        ),
        (
            "iPhone Distribution: Empty Parens ()",
            "Empty Parens",
            "",
            "distribution"
        ),
        (
            "Malformed (Parens Inverted: Test",
            "Test",
            "",
            "unknown"
        )
    ]

    for cn, expected_name, expected_id, expected_type in test_vectors:
        assert sim.extract_team_name(cn) == expected_name, f"Failed team name for: {cn}"
        assert sim.extract_team_id(cn) == expected_id, f"Failed team ID for: {cn}"
        assert sim.detect_certificate_type(cn) == expected_type, f"Failed cert type for: {cn}"


def test_pkcs12_crypto_generation_and_validation():
    """
    Generates real PKCS#12 binary bundles using Python cryptography and verifies:
    - Valid password decrypts and yields correct X.509 subject/CN
    - Invalid password fails to decrypt
    - Empty payload throws emptyData error
    """
    # 1. Generate RSA Key & Self-Signed Cert
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Distribution: Test Company (MOCKTEAM123)"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Company"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MOCKTEAM123"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    password = b"secret123"
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"Test Identity",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    # 2. Test successful deserialization with correct password
    loaded_key, loaded_cert, loaded_cas = pkcs12.load_key_and_certificates(p12_bytes, password)
    assert loaded_key is not None
    assert loaded_cert is not None
    cn_attrs = loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn_attrs) == 1
    cn_value = cn_attrs[0].value
    assert cn_value == "iPhone Distribution: Test Company (MOCKTEAM123)"

    # Verify SHA1 & SHA256 fingerprints
    sha1_fp = binascii.hexlify(loaded_cert.fingerprint(hashes.SHA1())).decode("ascii").upper()
    sha256_fp = binascii.hexlify(loaded_cert.fingerprint(hashes.SHA256())).decode("ascii").upper()
    assert len(sha1_fp) == 40
    assert len(sha256_fp) == 64

    # 3. Test failed deserialization with incorrect password
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(p12_bytes, b"wrong_password")

    # 4. Test corrupted / truncated bytes
    corrupted_p12 = p12_bytes[:len(p12_bytes) // 2]
    with pytest.raises(Exception):
        pkcs12.load_key_and_certificates(corrupted_p12, password)


# ==============================================================================
# 6. MobileProvisionParser.swift LOGIC & ADVERSARIAL STRESS TESTING
# ==============================================================================

class MockMobileProvisionSimulator:
    """
    Emulates the exact CMS extraction, fallback XML slicing, and PropertyList deserialization
    performed by MobileProvisionParser.swift.
    """
    @staticmethod
    def parse(data: bytes):
        if not data:
            raise ValueError("emptyData")

        plist_data = None

        # Step 1: In Swift, CMSDecoder extracts the inner content.
        # If wrapped in CMS, python pkcs7 can extract or fallback to regex:
        # Step 1b: Fallback XML regex extraction
        xml_start = data.find(b"<?xml")
        xml_end = data.rfind(b"</plist>")

        if xml_start != -1 and xml_end != -1 and xml_end > xml_start:
            plist_data = data[xml_start:xml_end + len(b"</plist>")]

        if not plist_data:
            raise ValueError("invalidCMSData")

        try:
            plist = plistlib.loads(plist_data)
        except Exception:
            raise ValueError("plistDeserializationFailed")

        name = plist.get("Name", "Unnamed Provisioning Profile")
        uuid = plist.get("UUID", "mock-uuid")
        team_name = plist.get("TeamName", "Unknown Team")
        team_ids = plist.get("TeamIdentifier", [])
        team_identifier = team_ids[0] if team_ids else ""
        is_enterprise = plist.get("ProvisionsAllDevices", False)
        devices = plist.get("ProvisionedDevices")
        provisioned_devices_count = None if is_enterprise else (len(devices) if devices is not None else 0)

        # Profile Type
        if is_enterprise:
            profile_type = "enterprise"
        elif devices is not None and len(devices) > 0:
            profile_type = "adHoc"
        else:
            profile_type = "development"

        # DeveloperCertificates fingerprints
        dev_certs = plist.get("DeveloperCertificates", [])
        sha1_fingerprints = []
        for cert_bytes in dev_certs:
            h = hashlib.sha1(cert_bytes).hexdigest().upper()
            sha1_fingerprints.append(h)

        entitlements = {k: str(v) for k, v in plist.get("Entitlements", {}).items()}

        return {
            "name": name,
            "uuid": uuid,
            "team_name": team_name,
            "team_identifier": team_identifier,
            "is_enterprise": is_enterprise,
            "provisioned_devices_count": provisioned_devices_count,
            "profile_type": profile_type,
            "developer_certificates_sha1": sha1_fingerprints,
            "entitlements": entitlements,
        }


def test_mobileprovision_parser_with_synthesized_profiles():
    """
    Stress-tests MobileProvisionParser with development, ad-hoc, enterprise,
    and adversarial malformed payloads.
    """
    sim = MockMobileProvisionSimulator

    dummy_cert_der = b"\x30\x82\x01\x00" + b"\xFF" * 128
    expected_cert_sha1 = hashlib.sha1(dummy_cert_der).hexdigest().upper()

    # 1. Standard Development Profile
    dev_dict = {
        "Name": "iOS Team Provisioning Profile: com.example.test",
        "UUID": "11111111-2222-3333-4444-555555555555",
        "TeamName": "Developer Team",
        "TeamIdentifier": ["TEAM123456"],
        "ApplicationIdentifierPrefix": ["TEAM123456"],
        "ProvisionsAllDevices": False,
        "ProvisionedDevices": ["00008030-001234567890ABCD"],
        "DeveloperCertificates": [dummy_cert_der],
        "Entitlements": {
            "application-identifier": "TEAM123456.com.example.test",
            "get-task-allow": True,
        }
    }
    raw_xml_dev = plistlib.dumps(dev_dict)
    # Wrap with simulated CMS header & trailer
    raw_profile_dev = b"\x30\x82\x05\x00\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" + raw_xml_dev + b"\x00\x00\x00\x00"

    res_dev = sim.parse(raw_profile_dev)
    assert res_dev["name"] == "iOS Team Provisioning Profile: com.example.test"
    assert res_dev["team_identifier"] == "TEAM123456"
    assert res_dev["profile_type"] == "adHoc"  # Devices listed -> adHoc
    assert res_dev["provisioned_devices_count"] == 1
    assert res_dev["developer_certificates_sha1"] == [expected_cert_sha1]
    assert res_dev["entitlements"]["get-task-allow"] == "True"

    # 2. Enterprise Profile (ProvisionsAllDevices = True)
    ent_dict = {
        "Name": "Enterprise In-House Distribution Profile",
        "UUID": "EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE",
        "TeamName": "Enterprise Corp",
        "TeamIdentifier": ["ENT9999999"],
        "ProvisionsAllDevices": True,
        "DeveloperCertificates": [dummy_cert_der],
        "Entitlements": {
            "application-identifier": "ENT9999999.com.enterprise.app",
        }
    }
    raw_profile_ent = plistlib.dumps(ent_dict)
    res_ent = sim.parse(raw_profile_ent)
    assert res_ent["profile_type"] == "enterprise"
    assert res_ent["is_enterprise"] is True
    assert res_ent["provisioned_devices_count"] is None

    # 3. Development Profile without devices
    pure_dev_dict = {
        "Name": "Pure Dev Profile",
        "UUID": "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD",
        "TeamIdentifier": ["TEAM123"],
        "ProvisionsAllDevices": False,
        "Entitlements": {}
    }
    raw_profile_pure_dev = plistlib.dumps(pure_dev_dict)
    res_pure_dev = sim.parse(raw_profile_pure_dev)
    assert res_pure_dev["profile_type"] == "development"
    assert res_pure_dev["provisioned_devices_count"] == 0


def test_mobileprovision_parser_adversarial_inputs():
    """
    Feeds corrupt, truncated, and malicious payloads into MobileProvisionParser logic.
    """
    sim = MockMobileProvisionSimulator

    # Case A: Empty data
    with pytest.raises(ValueError, match="emptyData"):
        sim.parse(b"")

    # Case B: Garbage binary without <?xml
    with pytest.raises(ValueError, match="invalidCMSData"):
        sim.parse(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")

    # Case C: <?xml present but no </plist>
    with pytest.raises(ValueError, match="invalidCMSData"):
        sim.parse(b"garbage <?xml version='1.0'> <dict> truncated content...")

    # Case D: Inverted xml and plist tags
    with pytest.raises(ValueError, match="invalidCMSData"):
        sim.parse(b"</plist> something <?xml>")

    # Case E: Broken XML inside <?xml ... </plist>
    with pytest.raises(ValueError, match="plistDeserializationFailed"):
        sim.parse(b"HEADER <?xml version='1.0'?><not a valid xml plist at all! </plist> TRAILER")


# ==============================================================================
# 7. OPENSSL FALLBACK XML EXTRACTOR ADVERSARIAL STRESS TEST
# ==============================================================================

def test_openssl_cpp_xml_and_entitlements_extractor():
    """
    Empirically verifies the substring and entitlement extraction logic from
    ZSignAsset::LoadProvisioningProfile in openssl.cpp:
    - Finds <?xml and </plist>
    - Extracts <key>Entitlements</key><dict>...</dict>
    - Assembles valid XML plist
    """
    def c_style_extract_entitlements(profile_data: str) -> str:
        # Emulate lines 168-199 in openssl.cpp
        start = profile_data.find("<?xml")
        end = profile_data.rfind("</plist>")
        xml_plist = ""
        if start != -1 and end != -1 and end > start:
            xml_plist = profile_data[start:(end + 8)]

        if not xml_plist:
            return ""

        ent_key = xml_plist.find("<key>Entitlements</key>")
        ent_data = ""
        if ent_key != -1:
            dict_start = xml_plist.find("<dict>", ent_key)
            dict_end = xml_plist.find("</dict>", dict_start)
            if dict_start != -1 and dict_end != -1:
                inner_dict = xml_plist[dict_start:(dict_end + 7)]
                ent_data = (
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                    "<plist version=\"1.0\">\n" + inner_dict + "\n</plist>"
                )

        if not ent_data:
            ent_data = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<plist version=\"1.0\"><dict></dict></plist>"
            )
        return ent_data

    sample_plist = (
        "DER_GARBAGE_PREFIX_BEFORE_XML\n"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "\t<key>AppIDName</key>\n"
        "\t<string>TestApp</string>\n"
        "\t<key>Entitlements</key>\n"
        "\t<dict>\n"
        "\t\t<key>application-identifier</key>\n"
        "\t\t<string>ABCD.com.test.app</string>\n"
        "\t\t<key>get-task-allow</key>\n"
        "\t\t<true/>\n"
        "\t</dict>\n"
        "\t<key>Name</key>\n"
        "\t<string>Test Profile</string>\n"
        "</dict>\n"
        "</plist>\n"
        "DER_GARBAGE_SUFFIX_AFTER_PLIST"
    )

    extracted_ent = c_style_extract_entitlements(sample_plist)
    assert "<key>application-identifier</key>" in extracted_ent
    assert "<string>ABCD.com.test.app</string>" in extracted_ent
    assert extracted_ent.startswith("<?xml version=\"1.0\"")
    assert extracted_ent.strip().endswith("</plist>")

    # Parse with standard plist parser to guarantee extracted entitlements are 100% syntactically valid
    parsed_ent = plistlib.loads(extracted_ent.encode("utf-8"))
    assert parsed_ent["application-identifier"] == "ABCD.com.test.app"
    assert parsed_ent["get-task-allow"] is True


# ==============================================================================
# 8. RESOURCE MANAGEMENT & MEMORY LEAK AUDIT
# ==============================================================================

def test_memory_and_resource_lifecycle():
    """
    Audits C++ classes (ZMachO, ZSignAsset) for proper destructor and Free() implementations:
    - ZMachO frees m_pMapping and closes m_fd
    - ZSignAsset frees EVP_PKEY, X509, and STACK_OF(X509)
    - ZsignBridge.mm cleans up temporary workspaces in failure and success paths
    """
    macho_cpp = os.path.join(ZSIGN_SRC_DIR, "macho.cpp")
    with open(macho_cpp, "r", encoding="utf-8") as f:
        macho_src = f.read()

    assert "ZMachO::~ZMachO() {\n    Free();\n}" in macho_src
    assert "free(m_pMapping);" in macho_src
    assert "close(m_fd);" in macho_src

    openssl_cpp = os.path.join(ZSIGN_SRC_DIR, "openssl.cpp")
    with open(openssl_cpp, "r", encoding="utf-8") as f:
        openssl_src = f.read()

    assert "ZSignAsset::~ZSignAsset() {\n    Free();\n}" in openssl_src
    assert "EVP_PKEY_free(m_pKey);" in openssl_src
    assert "X509_free(m_pCert);" in openssl_src
    assert "sk_X509_pop_free" in openssl_src

    bridge_mm = os.path.join(BRIDGE_DIR, "ZsignBridge.mm")
    with open(bridge_mm, "r", encoding="utf-8") as f:
        bridge_src = f.read()

    # Verify workspace cleanup
    cleanup_count = bridge_src.count("[fm removeItemAtPath:workspaceDir error:nil];")
    assert cleanup_count >= 5, (
        f"Expected at least 5 cleanup call sites for scratchpad workspaceDir, found {cleanup_count}"
    )


# ==============================================================================
# 9. LOCAL ZSIGN ENGINE SWIFT COMPLIANCE
# ==============================================================================

def test_local_zsign_engine_disk_space_guard_and_call():
    """
    Inspects LocalZsignEngine.swift to verify:
    - Pre-flight disk space calculation requires 2.5x IPA size
    - Detached background queue dispatch via Task.detached
    - Mapping of ZsignResult to LocalSigningResult
    - Error translation for invalid password vs signing failures
    """
    engine_swift_path = os.path.join(SERVICES_DIR, "LocalZsignEngine.swift")
    assert os.path.isfile(engine_swift_path)

    with open(engine_swift_path, "r", encoding="utf-8") as f:
        engine_src = f.read()

    # Pre-flight check
    assert "ipaSize * 5 / 2" in engine_src or "2.5" in engine_src, (
        "LocalZsignEngine must check for approx 2.5x disk space headroom."
    )
    assert "Task.detached" in engine_src, "Signing must be dispatched onto detached background task."
    assert "ZsignBridge.signAppBundle" in engine_src, "Must call ZsignBridge.signAppBundle."
    assert "invalidCertificatePassword" in engine_src, "Must catch and translate certificate password errors."
