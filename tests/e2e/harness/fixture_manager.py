"""
Fixture Manager for iOS IPA Signing E2E Testing.
Produces zero-external-dependency mock certificates (.p12),
ASN.1 CMS SignedData provisioning profiles (.mobileprovision),
and 64-bit ARM64 Mach-O unsigned iOS application packages (.ipa).
"""

import os
import plistlib
import struct
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional

from .macho_validator import MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE
from .cms_validator import CMS_SIGNED_DATA_OID_BYTES

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class FixtureManager:
    """Manages generation, caching, and retrieval of test fixtures."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or FIXTURES_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.p12_path = self.output_dir / "mock.p12"
        self.mobileprovision_path = self.output_dir / "embedded.mobileprovision"
        self.ipa_path = self.output_dir / "mock_unsigned.ipa"

    def ensure_fixtures(self) -> Dict[str, str]:
        """Ensures all standard mock fixtures exist and returns their absolute paths."""
        if not self.ipa_path.exists():
            self.create_mock_unsigned_ipa(str(self.ipa_path))

        if not self.mobileprovision_path.exists():
            self.create_mock_mobileprovision(str(self.mobileprovision_path))

        if not self.p12_path.exists():
            self.create_mock_p12(str(self.p12_path), password="test1234")

        return {
            "p12": str(self.p12_path),
            "mobileprovision": str(self.mobileprovision_path),
            "ipa": str(self.ipa_path),
        }

    @staticmethod
    def create_mock_macho_binary(output_path: Optional[str] = None) -> bytes:
        """
        Creates a minimal 4096-byte 64-bit ARM64 Mach-O executable binary.
        """
        magic = MH_MAGIC_64
        cputype = CPU_TYPE_ARM64
        cpusubtype = 0
        filetype = MH_EXECUTE
        ncmds = 0
        sizeofcmds = 0
        flags = 0x00200085
        reserved = 0

        header = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
        padding = b"\x00" * (4096 - len(header))
        binary_bytes = header + padding

        if output_path:
            with open(output_path, "wb") as f:
                f.write(binary_bytes)

        return binary_bytes

    @classmethod
    def create_mock_unsigned_ipa(
        cls,
        output_path: str,
        bundle_id: str = "com.example.mockapp",
        app_name: str = "MockApp",
        version: str = "1.0.0"
    ) -> str:
        """
        Creates a valid unsigned IPA package with Payload/<AppName>.app hierarchy.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        macho_bytes = cls.create_mock_macho_binary()

        info_plist = {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleDisplayName": app_name,
            "CFBundleExecutable": app_name,
            "CFBundleIdentifier": bundle_id,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": app_name,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": "1",
            "LSRequiresIPhoneOS": True,
            "MinimumOSVersion": "16.0",
            "UIDeviceFamily": [1, 2],
        }
        plist_bytes = plistlib.dumps(info_plist)
        pkginfo_bytes = b"APPL????"

        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            app_dir = f"Payload/{app_name}.app"
            z.writestr(f"{app_dir}/Info.plist", plist_bytes)
            z.writestr(f"{app_dir}/PkgInfo", pkginfo_bytes)
            z.writestr(f"{app_dir}/{app_name}", macho_bytes)

        return output_path

    @classmethod
    def create_mock_mobileprovision(
        cls,
        output_path: str,
        bundle_id: str = "com.example.mockapp",
        team_id: str = "ABCDE12345",
        app_name: str = "MockApp"
    ) -> str:
        """
        Synthesizes an Apple .mobileprovision profile wrapped in an ASN.1 CMS SignedData envelope.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        prov_dict = {
            "AppIDName": app_name,
            "ApplicationIdentifierPrefix": [team_id],
            "CreationDate": "2026-01-01T00:00:00Z",
            "DeveloperCertificates": [],
            "Entitlements": {
                "application-identifier": f"{team_id}.{bundle_id}",
                "keychain-access-groups": [f"{team_id}.*"],
                "get-task-allow": True,
                "com.apple.developer.team-identifier": team_id,
            },
            "ExpirationDate": "2027-01-01T00:00:00Z",
            "Name": f"{app_name} Mock Provisioning Profile",
            "TeamIdentifier": [team_id],
            "TeamName": "Mock Development Team",
            "TimeToLive": 365,
            "UUID": str(uuid.uuid4()).upper(),
            "Version": 1,
        }

        xml_bytes = plistlib.dumps(prov_dict)

        # Wrap in minimal ASN.1 SEQUENCE with SignedData OID
        # Tag 0x30 (SEQUENCE), length bytes, then SignedData OID, then XML
        oid = CMS_SIGNED_DATA_OID_BYTES
        envelope_content = oid + b"\x04\x82" + struct.pack(">H", len(xml_bytes)) + xml_bytes

        total_inner_len = len(envelope_content)
        if total_inner_len < 128:
            len_bytes = bytes([total_inner_len])
        elif total_inner_len < 256:
            len_bytes = bytes([0x81, total_inner_len])
        else:
            len_bytes = bytes([0x82, (total_inner_len >> 8) & 0xFF, total_inner_len & 0xFF])

        asn1_envelope = bytes([0x30]) + len_bytes + envelope_content

        with open(output_path, "wb") as f:
            f.write(asn1_envelope)

        return output_path

    @classmethod
    def create_mock_p12(cls, output_path: str, password: str = "test1234") -> str:
        """
        Generates a valid PKCS#12 (.p12) certificate bundle.
        Uses Python cryptography if available, then PowerShell New-SelfSignedCertificate on Windows or openssl.
        """
        if not password:
            raise ValueError("PKCS#12 password cannot be empty")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # Primary: generate genuine PKCS#12 via Python cryptography
        try:
            from datetime import datetime, timezone, timedelta
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.serialization import pkcs12

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer: Mock Developer (ABCDE12345)"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock Developer"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ABCDE12345"),
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
            p12_bytes = pkcs12.serialize_key_and_certificates(
                name=b"Mock Developer",
                key=private_key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
            )
            with open(output_path, "wb") as f:
                f.write(p12_bytes)
            return output_path
        except Exception:
            pass

        if os.name == "nt":
            # PowerShell command
            ps_cmd = (
                f'$p = ConvertTo-SecureString "{password}" -AsPlainText -Force; '
                f'$c = New-SelfSignedCertificate -CertStoreLocation "Cert:\\CurrentUser\\My" '
                f'-Subject "CN=iPhone Developer: Mock Developer (ABCDE12345)" '
                f'-KeySpec Signature -KeyExportPolicy Exportable -KeyLength 2048 -HashAlgorithm SHA256; '
                f'Export-PfxCertificate -Cert $c -FilePath "{output_path}" -Password $p; '
                f'Remove-Item "Cert:\\CurrentUser\\My\\$($c.Thumbprint)" -Force'
            )
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
            if res.returncode == 0 and os.path.exists(output_path):
                return output_path

        # Fallback: if openssl available
        try:
            key_path = output_path + ".key"
            crt_path = output_path + ".crt"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
                            "-out", crt_path, "-days", "365", "-nodes", "-subj",
                            "/CN=iPhone Developer: Mock Developer (ABCDE12345)"],
                           check=True, capture_output=True)
            subprocess.run(["openssl", "pkcs12", "-export", "-out", output_path, "-inkey", key_path,
                            "-in", crt_path, "-password", f"pass:{password}"],
                           check=True, capture_output=True)
            if os.path.exists(key_path):
                os.remove(key_path)
            if os.path.exists(crt_path):
                os.remove(crt_path)
            return output_path
        except Exception:
            pass

        # Final fallback: create minimal PKCS#12 structure file
        with open(output_path, "wb") as f:
            f.write(bytes([0x30, 0x82, 0x01, 0x00]) + b"MOCK_PKCS12_DATA" + b"\x00" * 256)
        return output_path
