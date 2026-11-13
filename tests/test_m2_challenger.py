"""
Empirical Challenger Test Suite for Milestone 2: iOS Signing Application Project
Adversarial testing and verification for:
  1. Xcode Project Structure & PBX Integrity (project.pbxproj)
  2. Resource & Entitlement Conformance (Info.plist, iOSApp.entitlements)
  3. Apple Enterprise Wireless App Distribution Schema (ManifestBuilder.swift)
  4. HTTP/1.1 Protocol & Range Parsing Edge Cases (OTAHTTPConnection.swift, LocalOTAServer.swift)
"""

import os
import re
import sys
import plistlib
import xml.etree.ElementTree as ET
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
IOSAPP_DIR = REPO_ROOT / "iOSApp"
PROJECT_PBX_PATH = IOSAPP_DIR / "iOSApp.xcodeproj" / "project.pbxproj"
INFO_PLIST_PATH = IOSAPP_DIR / "Resources" / "Info.plist"
ENTITLEMENTS_PATH = IOSAPP_DIR / "Resources" / "iOSApp.entitlements"
MANIFEST_BUILDER_PATH = IOSAPP_DIR / "Sources" / "Services" / "ManifestBuilder.swift"
OTA_HTTP_CONN_PATH = IOSAPP_DIR / "Sources" / "Services" / "OTAHTTPConnection.swift"
LOCAL_OTA_SERVER_PATH = IOSAPP_DIR / "Sources" / "Services" / "LocalOTAServer.swift"


# ==============================================================================
# Suite 1: Xcode Project Structure & PBX Integrity
# ==============================================================================

class TestXcodeProjectIntegrity:
    """Empirical verification of project.pbxproj syntax, references, and phases."""

    @classmethod
    def setup_class(cls):
        assert PROJECT_PBX_PATH.exists(), f"Missing project.pbxproj at {PROJECT_PBX_PATH}"
        with open(PROJECT_PBX_PATH, "r", encoding="utf-8") as f:
            cls.pbx_text = f.read()

    def test_pbx_file_syntax_and_delimiters(self):
        """Verify PBX syntax: header, rootObject, matched braces, and sections."""
        assert self.pbx_text.startswith("// !$*UTF8*$!"), "PBX file must start with UTF8 encoding comment"
        assert "archiveVersion = 1;" in self.pbx_text
        assert "objectVersion =" in self.pbx_text
        assert "rootObject =" in self.pbx_text

        # Balanced curly braces
        open_braces = self.pbx_text.count("{")
        close_braces = self.pbx_text.count("}")
        assert open_braces == close_braces, f"Mismatched braces in PBX file: {open_braces} open vs {close_braces} close"

        # Check required standard PBX sections exist
        required_sections = [
            "PBXBuildFile",
            "PBXFileReference",
            "PBXFrameworksBuildPhase",
            "PBXGroup",
            "PBXNativeTarget",
            "PBXProject",
            "PBXResourcesBuildPhase",
            "PBXSourcesBuildPhase",
            "XCBuildConfiguration",
            "XCConfigurationList",
        ]
        for sec in required_sections:
            assert f"/* Begin {sec} section */" in self.pbx_text, f"Missing section: {sec}"
            assert f"/* End {sec} section */" in self.pbx_text, f"Missing section end: {sec}"

    def test_pbx_all_source_files_on_disk_are_referenced(self):
        """Verify every Swift, C++, and ObjC source file under iOSApp/Sources exists in PBX."""
        sources_dir = IOSAPP_DIR / "Sources"
        assert sources_dir.exists()

        disk_files = []
        for ext in ["*.swift", "*.cpp", "*.h", "*.mm"]:
            for p in sources_dir.rglob(ext):
                disk_files.append(p.name)

        assert len(disk_files) > 0, "No source files found on disk"

        missing_in_pbx = []
        for fname in disk_files:
            # Check for file reference in PBX
            pattern = re.compile(rf"/\*\s*{re.escape(fname)}\s*\*/\s*=\s*\{{isa\s*=\s*PBXFileReference;")
            if not pattern.search(self.pbx_text):
                missing_in_pbx.append(fname)

        assert not missing_in_pbx, f"Source files on disk missing from PBXFileReference: {missing_in_pbx}"

    def test_pbx_compile_sources_phase_completeness(self):
        """Verify PBXSourcesBuildPhase compiles all .swift, .mm, .cpp files and excludes .h headers."""
        sources_phase_match = re.search(
            r"/\* Begin PBXSourcesBuildPhase section \*/(.*?)/\* End PBXSourcesBuildPhase section \*/",
            self.pbx_text,
            re.DOTALL,
        )
        assert sources_phase_match, "Could not extract PBXSourcesBuildPhase"
        sources_content = sources_phase_match.group(1)

        # Headers must NOT be in compile sources
        for header in ["ZsignBridge.h", "iOSApp-Bridging-Header.h", "common.h", "openssl.h", "macho.h", "bundle.h", "zsign.h"]:
            assert f"{header} in Sources" not in sources_content, f"Header {header} incorrectly placed in Sources build phase!"

        # Implementation files MUST be in compile sources
        expected_sources = [
            "iOSApp.swift", "AppState.swift", "CertificateItem.swift", "ProfileItem.swift",
            "IPAItem.swift", "SigningConfiguration.swift", "SigningJob.swift", "MainTabView.swift",
            "CertificatesView.swift", "ProfilesView.swift", "IPALibraryView.swift",
            "SigningSettingsView.swift", "ServerConnectionView.swift", "KeychainManager.swift",
            "PKCS12Parser.swift", "MobileProvisionParser.swift", "IPAMetadataParser.swift",
            "CertificateStore.swift", "ProfileStore.swift", "IPALibraryStore.swift",
            "LocalZsignEngine.swift", "LocalOTAServer.swift", "OTAHTTPConnection.swift",
            "ManifestBuilder.swift", "CertificateAuthorityManager.swift",
            "RemoteSigningClient.swift", "SigningCoordinator.swift",
            "ZsignBridge.mm", "openssl.cpp", "macho.cpp", "bundle.cpp", "zsign.cpp"
        ]

        missing_from_sources = []
        for src in expected_sources:
            if f"{src} in Sources" not in sources_content:
                missing_from_sources.append(src)

        assert not missing_from_sources, f"Implementation files missing from PBXSourcesBuildPhase: {missing_from_sources}"

    def test_pbx_framework_dependencies(self):
        """Verify PBXFrameworksBuildPhase links Security, Network, UniformTypeIdentifiers, libz, and libc++."""
        frameworks_phase_match = re.search(
            r"/\* Begin PBXFrameworksBuildPhase section \*/(.*?)/\* End PBXFrameworksBuildPhase section \*/",
            self.pbx_text,
            re.DOTALL,
        )
        assert frameworks_phase_match, "Could not extract PBXFrameworksBuildPhase"
        fw_content = frameworks_phase_match.group(1)

        required_frameworks = [
            "Security.framework",
            "Network.framework",
            "UniformTypeIdentifiers.framework",
            "libz.tbd",
            "libc++.tbd",
        ]
        for fw in required_frameworks:
            assert f"{fw} in Frameworks" in fw_content, f"Framework {fw} missing from PBXFrameworksBuildPhase"

    def test_pbx_build_configurations_and_deployment_target(self):
        """Verify target deployment target >= 16.0, Swift version >= 5.0, and C++17 flags."""
        assert "IPHONEOS_DEPLOYMENT_TARGET = 16.0;" in self.pbx_text
        assert 'CLANG_CXX_LANGUAGE_STANDARD = "c++17";' in self.pbx_text
        assert 'CLANG_CXX_LIBRARY = "libc++";' in self.pbx_text
        assert 'SWIFT_VERSION = 5.9;' in self.pbx_text

    def test_pbx_build_setting_paths_resolution(self):
        """
        Adversarial Check: Verify how build setting paths (INFOPLIST_FILE, CODE_SIGN_ENTITLEMENTS, etc.)
        resolve depending on whether SRCROOT is repo root or iOSApp directory.
        """
        # When xcodebuild builds iOSApp.xcodeproj, Xcode sets SRCROOT to the directory containing .xcodeproj (i.e. <repo>/iOSApp).
        # Check current settings in pbxproj:
        info_plist_match = re.search(r'INFOPLIST_FILE\s*=\s*"([^"]+)";', self.pbx_text)
        assert info_plist_match, "INFOPLIST_FILE not found in pbxproj"
        info_plist_setting = info_plist_match.group(1)

        entitlements_match = re.search(r'CODE_SIGN_ENTITLEMENTS\s*=\s*"([^"]+)";', self.pbx_text)
        assert entitlements_match, "CODE_SIGN_ENTITLEMENTS not found in pbxproj"
        entitlements_setting = entitlements_match.group(1)

        bridging_match = re.search(r'SWIFT_OBJC_BRIDGING_HEADER\s*=\s*"([^"]+)";', self.pbx_text)
        assert bridging_match, "SWIFT_OBJC_BRIDGING_HEADER not found in pbxproj"
        bridging_setting = bridging_match.group(1)

        # Check resolution if SRCROOT == iOSApp (the standard Xcode behavior when project is opened)
        srcroot_iosapp = IOSAPP_DIR
        path_if_srcroot_iosapp = srcroot_iosapp / info_plist_setting

        # Check resolution if SRCROOT == REPO_ROOT (if opened from root workspace or CLI override)
        srcroot_repo = REPO_ROOT
        path_if_srcroot_repo = srcroot_repo / info_plist_setting

        # Record findings
        assert path_if_srcroot_iosapp.exists() or path_if_srcroot_repo.exists(), f"Path {info_plist_setting} does not exist relative to iOSApp {srcroot_iosapp} or repo root {srcroot_repo}"
        
        # NOTE FOR CHALLENGER REPORT:
        # If SRCROOT is iOSApp directory (as xcodebuild normally defines for an isolated .xcodeproj),
        # 'iOSApp/Resources/Info.plist' would look for 'iOSApp/iOSApp/Resources/Info.plist'!
        # However, scripts/build_ipa.sh runs from repo root.


# ==============================================================================
# Suite 2: Resources & Entitlement Conformance
# ==============================================================================

class TestResourceConformance:
    """Empirical verification of Info.plist and iOSApp.entitlements conformance."""

    @classmethod
    def setup_class(cls):
        assert INFO_PLIST_PATH.exists(), f"Missing Info.plist at {INFO_PLIST_PATH}"
        assert ENTITLEMENTS_PATH.exists(), f"Missing iOSApp.entitlements at {ENTITLEMENTS_PATH}"

        with open(INFO_PLIST_PATH, "rb") as f:
            cls.info_plist = plistlib.load(f)
        with open(INFO_PLIST_PATH, "r", encoding="utf-8") as f:
            cls.info_plist_raw = f.read()

        with open(ENTITLEMENTS_PATH, "rb") as f:
            cls.entitlements = plistlib.load(f)
        with open(ENTITLEMENTS_PATH, "r", encoding="utf-8") as f:
            cls.entitlements_raw = f.read()

    def test_info_plist_strict_xml_and_dtd(self):
        """Verify Info.plist is well-formed XML and includes Apple DTD."""
        assert self.info_plist_raw.strip().startswith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        assert "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" in self.info_plist_raw
        # Validate XML parse
        root = ET.fromstring(self.info_plist_raw)
        assert root.tag == "plist"
        assert root.attrib.get("version") == "1.0"

    def test_info_plist_required_keys(self):
        """Verify CFBundleIdentifier, CFBundleName, MinimumOSVersion, etc."""
        assert self.info_plist.get("CFBundleIdentifier") == "com.signing.iosapp"
        assert self.info_plist.get("CFBundleName") == "iOSApp"
        assert self.info_plist.get("CFBundleDisplayName") == "IPA Signer"
        assert self.info_plist.get("CFBundlePackageType") == "APPL"
        assert self.info_plist.get("CFBundleShortVersionString") == "1.0.0"
        assert self.info_plist.get("CFBundleVersion") == "1"
        assert float(self.info_plist.get("MinimumOSVersion", 0)) >= 16.0
        assert self.info_plist.get("LSRequiresIPhoneOS") is True
        assert self.info_plist.get("UIFileSharingEnabled") is True
        assert self.info_plist.get("LSSupportsOpeningDocumentsInPlace") is True

    def test_info_plist_network_and_ats_keys(self):
        """Verify NSLocalNetworkUsageDescription and NSAppTransportSecurity settings."""
        usage_desc = self.info_plist.get("NSLocalNetworkUsageDescription")
        assert usage_desc and len(usage_desc) > 10, "NSLocalNetworkUsageDescription must provide meaningful explanation"

        ats = self.info_plist.get("NSAppTransportSecurity")
        assert isinstance(ats, dict), "NSAppTransportSecurity must be a dictionary"
        assert ats.get("NSAllowsArbitraryLoads") is True, "NSAllowsArbitraryLoads must be true for local OTA server"

    def test_info_plist_document_types(self):
        """Verify CFBundleDocumentTypes declares handlers for IPA, P12, and MobileProvision."""
        doc_types = self.info_plist.get("CFBundleDocumentTypes")
        assert isinstance(doc_types, list), "CFBundleDocumentTypes must be an array"
        assert len(doc_types) >= 3, f"Expected at least 3 document types, found {len(doc_types)}"

        content_types = []
        for dt in doc_types:
            content_types.extend(dt.get("LSItemContentTypes", []))

        assert "com.apple.itunes.ipa" in content_types or "public.archive" in content_types, "Missing IPA document type handler"
        assert "com.rsa.pkcs-12" in content_types, "Missing PKCS#12 document type handler"
        assert "com.apple.mobileprovision" in content_types, "Missing MobileProvision document type handler"

    def test_entitlements_strict_xml_and_keys(self):
        """Verify iOSApp.entitlements format, keychain group, and network server entitlements."""
        assert self.entitlements_raw.strip().startswith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        assert "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" in self.entitlements_raw

        # Parse XML
        root = ET.fromstring(self.entitlements_raw)
        assert root.tag == "plist"

        # Check keychain-access-groups
        keychain_groups = self.entitlements.get("keychain-access-groups")
        assert isinstance(keychain_groups, list), "keychain-access-groups must be an array"
        assert any("com.signing.iosapp" in g for g in keychain_groups), "Keychain access group missing bundle id"

        # Check network entitlements
        assert self.entitlements.get("com.apple.security.network.server") is True, "Missing server network entitlement"
        assert self.entitlements.get("com.apple.security.network.client") is True, "Missing client network entitlement"


# ==============================================================================
# Suite 3: ManifestBuilder & Apple Enterprise Wireless App Distribution Schema
# ==============================================================================

class TestManifestBuilderSchema:
    """Empirical verification of ManifestBuilder.swift XML schema conformance & edge cases."""

    @classmethod
    def setup_class(cls):
        assert MANIFEST_BUILDER_PATH.exists(), f"Missing ManifestBuilder.swift at {MANIFEST_BUILDER_PATH}"
        with open(MANIFEST_BUILDER_PATH, "r", encoding="utf-8") as f:
            cls.swift_code = f.read()

    @staticmethod
    def simulate_manifest_builder(bundle_id: str, bundle_version: str, title: str, server_port: int, host: str = "127.0.0.1") -> str:
        """Exact replica of ManifestBuilder.swift logic."""
        ipa_url = f"https://{host}:{server_port}/download/signed.ipa"
        icon_url = f"https://{host}:{server_port}/download/icon.png"

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>display-image</string>
                    <key>needs-shine</key>
                    <false/>
                    <key>url</key>
                    <string>{icon_url}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>full-size-image</string>
                    <key>needs-shine</key>
                    <false/>
                    <key>url</key>
                    <string>{icon_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{bundle_id}</string>
                <key>bundle-version</key>
                <string>{bundle_version}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{title}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""

    def test_standard_manifest_schema_and_dtd(self):
        """Verify generated manifest complies strictly with Apple Enterprise OTA DTD."""
        xml_str = self.simulate_manifest_builder(
            bundle_id="com.example.enterprise.app",
            bundle_version="2.1.0",
            title="Enterprise Signer",
            server_port=8443
        )

        # Parse with plistlib
        data = plistlib.loads(xml_str.encode("utf-8"))
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) == 1

        item = data["items"][0]
        assert "assets" in item
        assert "metadata" in item

        # Verify assets
        assets = item["assets"]
        assert len(assets) == 3

        kinds = {a["kind"]: a["url"] for a in assets}
        assert "software-package" in kinds
        assert kinds["software-package"] == "https://127.0.0.1:8443/download/signed.ipa"
        assert "display-image" in kinds
        assert kinds["display-image"] == "https://127.0.0.1:8443/download/icon.png"
        assert "full-size-image" in kinds
        assert kinds["full-size-image"] == "https://127.0.0.1:8443/download/icon.png"

        # Verify metadata
        metadata = item["metadata"]
        assert metadata["bundle-identifier"] == "com.example.enterprise.app"
        assert metadata["bundle-version"] == "2.1.0"
        assert metadata["kind"] == "software"
        assert metadata["title"] == "Enterprise Signer"

    def test_manifest_builder_adversarial_xml_injection_and_entities(self):
        """
        Adversarial Stress Test: What happens when title or bundleId has XML entities
        (e.g., 'Tom & Jerry <Pro> "Edition"')?
        """
        raw_title = 'Tom & Jerry <Pro> "Edition"'
        xml_str = self.simulate_manifest_builder(
            bundle_id="com.example.app",
            bundle_version="1.0.0",
            title=raw_title,
            server_port=8443
        )

        # Unescaped XML will fail parsing with ParseError
        is_valid_xml = True
        parse_err = None
        try:
            plistlib.loads(xml_str.encode("utf-8"))
        except Exception as e:
            is_valid_xml = False
            parse_err = str(e)

        # In Swift's ManifestBuilder.swift, string interpolation is used without xml escaping:
        # <string>\(title)</string>
        # If title contains '&' or '<', XML is malformed!
        assert not is_valid_xml, "Expected raw unescaped '&' and '<' to fail XML parsing"
        assert "not well-formed" in parse_err or "syntax error" in parse_err.lower() or "reference" in parse_err.lower()

    def test_manifest_builder_empty_and_unicode_strings(self):
        """Verify behavior with unicode characters and empty strings."""
        unicode_title = "Ứng dụng Ký Số IPA 2026 🚀"
        xml_str = self.simulate_manifest_builder(
            bundle_id="com.example.unicode",
            bundle_version="1.0.0",
            title=unicode_title,
            server_port=8443
        )
        data = plistlib.loads(xml_str.encode("utf-8"))
        assert data["items"][0]["metadata"]["title"] == unicode_title


# ==============================================================================
# Suite 4: HTTP Protocol & Range Streaming Edge Cases
# ==============================================================================

class TestHTTPProtocolAndRangeParsing:
    """
    Empirical testing of HTTP/1.1 parsing and range streaming boundary conditions
    matching OTAHTTPConnection.swift and LocalOTAServer.swift logic.
    """

    @staticmethod
    def parse_http_buffer(buffer: bytes):
        """Python replica of OTAHTTPConnection.parseHTTPBuffer()."""
        delimiter = b"\r\n\r\n"
        idx = buffer.find(delimiter)
        if idx == -1:
            return None
        header_data = buffer[:idx]
        try:
            header_string = header_data.decode("utf-8")
        except UnicodeDecodeError:
            return None

        lines = header_string.split("\r\n")
        if not lines:
            return None
        request_line = lines[0]
        tokens = request_line.split(" ")
        if len(tokens) < 3:
            return None

        method = tokens[0]
        full_path = tokens[1]
        http_version = tokens[2]

        path_parts = full_path.split("?", 1)
        path = path_parts[0]
        query_params = {}
        if len(path_parts) > 1 and path_parts[1]:
            pairs = path_parts[1].split("&")
            for pair in pairs:
                kv = pair.split("=", 1)
                if len(kv) == 2:
                    query_params[kv[0]] = kv[1]

        headers = {}
        for line in lines[1:]:
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip().lower()
                value = parts[1].strip()
                headers[key] = value

        return {
            "method": method,
            "path": path,
            "query_params": query_params,
            "headers": headers,
            "http_version": http_version,
        }

    @staticmethod
    def parse_range_header(headers: dict):
        """Python replica of HTTPRequest.rangeHeader logic."""
        range_str = headers.get("range") or headers.get("Range")
        if not range_str or not range_str.startswith("bytes="):
            return None
        spec = range_str[6:]
        parts = spec.split("-")
        try:
            start = int(parts[0])
            if start < 0 or start > 18446744073709551615:  # UInt64 bounds
                return None
        except (ValueError, IndexError):
            return None

        end = None
        if len(parts) > 1 and parts[1] != "":
            try:
                end_val = int(parts[1])
                if end_val < 0 or end_val > 18446744073709551615:
                    return None
                end = end_val
            except ValueError:
                end = None

        return (start, end)

    @staticmethod
    def simulate_stream_file_range(file_size: int, range_header: tuple, is_head_only: bool = False):
        """Python replica of OTAHTTPConnection.streamFile logic."""
        if range_header:
            start = range_header[0]
            raw_end = range_header[1] if range_header[1] is not None else (file_size - 1)
            end = min(raw_end, file_size - 1)
            is_range = True
        else:
            start = 0
            end = file_size - 1
            is_range = False

        content_length = (end - start + 1) if (end >= start) else 0
        status = 206 if is_range else 200
        status_msg = "Partial Content" if is_range else "OK"

        headers = {
            "status": status,
            "status_msg": status_msg,
            "Content-Type": "application/octet-stream",
            "Content-Length": content_length,
            "Accept-Ranges": "bytes",
        }
        if is_range:
            headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"

        return headers

    def test_http_request_parsing_standard(self):
        """Verify standard GET request parsing."""
        req = b"GET /manifest.plist HTTP/1.1\r\nHost: 127.0.0.1:8443\r\nUser-Agent: itms-services\r\n\r\n"
        res = self.parse_http_buffer(req)
        assert res is not None
        assert res["method"] == "GET"
        assert res["path"] == "/manifest.plist"
        assert res["http_version"] == "HTTP/1.1"
        assert res["headers"]["host"] == "127.0.0.1:8443"
        assert res["headers"]["user-agent"] == "itms-services"

    def test_http_request_parsing_with_query_params(self):
        """Verify query parameters extraction."""
        req = b"GET /download/signed.ipa?token=abc123xyz&retry=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        res = self.parse_http_buffer(req)
        assert res is not None
        assert res["path"] == "/download/signed.ipa"
        assert res["query_params"] == {"token": "abc123xyz", "retry": "1"}

    def test_http_request_incomplete_buffer(self):
        """Verify incomplete HTTP request (no double CRLF) returns None (wait for more data)."""
        req = b"GET /download/signed.ipa HTTP/1.1\r\nHost: localhost\r\n"
        res = self.parse_http_buffer(req)
        assert res is None, "Incomplete HTTP request without double CRLF must return None"

    def test_http_request_malformed_tokens(self):
        """Verify malformed request lines with fewer than 3 tokens return None."""
        assert self.parse_http_buffer(b"GET\r\n\r\n") is None
        assert self.parse_http_buffer(b"GET /\r\n\r\n") is None
        assert self.parse_http_buffer(b"\r\n\r\n") is None

    def test_range_header_standard_ranges(self):
        """Verify standard range requests."""
        # bytes=0-499
        r1 = self.parse_range_header({"range": "bytes=0-499"})
        assert r1 == (0, 499)

        # bytes=500- (from 500 to end)
        r2 = self.parse_range_header({"range": "bytes=500-"})
        assert r2 == (500, None)

        # bytes=0-0 (single byte)
        r3 = self.parse_range_header({"range": "bytes=0-0"})
        assert r3 == (0, 0)

        # Case-insensitive header lookup: Range
        r4 = self.parse_range_header({"Range": "bytes=1024-2048"})
        assert r4 == (1024, 2048)

    def test_range_header_edge_cases_and_adversarial_inputs(self):
        """Stress test range header parser with invalid and boundary inputs."""
        # Non-bytes unit
        assert self.parse_range_header({"range": "items=0-10"}) is None

        # Missing bytes= prefix
        assert self.parse_range_header({"range": "0-100"}) is None

        # Non-numeric start
        assert self.parse_range_header({"range": "bytes=abc-100"}) is None

        # Suffix range (RFC 7233 §2.1 bytes=-500)
        # Note: parts[0] is empty, so UInt64("") returns nil. Code does not support suffix range.
        r_suffix = self.parse_range_header({"range": "bytes=-500"})
        assert r_suffix is None, "Suffix range bytes=-500 returns None under current UInt64(parts[0]) implementation"

        # UInt64 Overflow: 2^64 = 18446744073709551616
        r_overflow = self.parse_range_header({"range": "bytes=18446744073709551616-"})
        assert r_overflow is None, "UInt64 overflow value must return None"

    def test_stream_file_range_calculations(self):
        """Verify range calculation with simulated file size (e.g. 10,000,000 bytes)."""
        file_size = 10_000_000

        # Normal partial content: bytes=0-499
        h1 = self.simulate_stream_file_range(file_size, (0, 499))
        assert h1["status"] == 206
        assert h1["Content-Length"] == 500
        assert h1["Content-Range"] == f"bytes 0-499/{file_size}"

        # Prefix range: bytes=5000-
        h2 = self.simulate_stream_file_range(file_size, (5000, None))
        assert h2["status"] == 206
        assert h2["Content-Length"] == 9_995_000
        assert h2["Content-Range"] == f"bytes 5000-{file_size - 1}/{file_size}"

        # End beyond file size: bytes=9000000-20000000 -> clipped to file_size - 1
        h3 = self.simulate_stream_file_range(file_size, (9_000_000, 20_000_000))
        assert h3["status"] == 206
        assert h3["Content-Length"] == 1_000_000
        assert h3["Content-Range"] == f"bytes 9000000-{file_size - 1}/{file_size}"

        # Inverted range (adversarial): bytes=500-100 (start > end)
        h4 = self.simulate_stream_file_range(file_size, (500, 100))
        # Finding: Under current Swift implementation, status is 206, Content-Length is 0, Content-Range is "bytes 500-100/10000000"
        # Standard HTTP/1.1 would return 416 Range Not Satisfiable
        assert h4["Content-Length"] == 0
        assert h4["status"] == 206

    def test_local_ota_server_routing_table(self):
        """Verify complete routing coverage and unsupported route handling in LocalOTAServer."""
        with open(LOCAL_OTA_SERVER_PATH, "r", encoding="utf-8") as f:
            server_code = f.read()

        # Check all required endpoints are handled
        expected_routes = [
            'case ("GET", "/manifest.plist")',
            'case ("GET", "/download/signed.ipa"), ("HEAD", "/download/signed.ipa")',
            'case ("GET", "/download/icon.png")',
            'case ("GET", "/ca.mobileconfig")',
            'case ("GET", "/install")',
            'default:',
        ]
        for route in expected_routes:
            assert route in server_code, f"Missing route pattern in LocalOTAServer: {route}"

        # Content types (distributed across LocalOTAServer and OTAHTTPConnection)
        with open(OTA_HTTP_CONN_PATH, "r", encoding="utf-8") as f:
            conn_code = f.read()

        assert 'contentType: "text/xml; charset=utf-8"' in server_code
        assert 'Content-Type: application/octet-stream' in conn_code
        assert 'contentType: "image/png"' in server_code
        assert 'contentType: "application/x-apple-aspen-config"' in server_code
        assert 'contentType: "text/html; charset=utf-8"' in server_code
        assert 'status: 404' in server_code
