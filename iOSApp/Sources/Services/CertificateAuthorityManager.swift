//
//  CertificateAuthorityManager.swift
//  iOSApp
//
//  Manages root CA certificates and Apple .mobileconfig configuration profiles for TLS trust.
//

import Foundation
import Security

public final class CertificateAuthorityManager {
    public static let shared = CertificateAuthorityManager()

    private init() {}

    /// Loads or returns the PKCS#12 server identity used by NWListener
    public func loadServerIdentity() -> SecIdentity? {
        // Look in App Bundle resources for bundled server.p12
        if let p12URL = Bundle.main.url(forResource: "server", withExtension: "p12"),
           let p12Data = try? Data(contentsOf: p12URL) {
            let options: [String: Any] = [kSecImportExportPassphrase as String: "signingapp"]
            var items: CFArray?
            let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
            if status == errSecSuccess, let array = items as? [[String: Any]], let first = array.first {
                return first[kSecImportItemIdentity as String] as? SecIdentity
            }
        }
        return nil
    }

    /// Generates Apple Configuration Profile (.mobileconfig) embedding the local Root CA
    public func generateRootCAProfileData() -> Data? {
        // Attempt to load ca.crt from app bundle or resources
        let caCertData: Data
        if let caURL = Bundle.main.url(forResource: "ca", withExtension: "crt"),
           let data = try? Data(contentsOf: caURL) {
            caCertData = data
        } else {
            // Default placeholder root CA certificate payload
            caCertData = "LOCAL_OTA_ROOT_CA_CERTIFICATE".data(using: .utf8)!
        }

        let profileDict: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": "com.signingapp.localca",
            "PayloadUUID": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
            "PayloadDisplayName": "Local OTA Root CA",
            "PayloadDescription": "Enables local over-the-air installation for signed apps on iOS",
            "PayloadOrganization": "iOS Signing Application",
            "PayloadContent": [
                [
                    "PayloadType": "com.apple.security.root",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": "com.signingapp.localca.root",
                    "PayloadUUID": "B2C3D4E5-F6A7-8901-BCDE-F12345678901",
                    "PayloadDisplayName": "Local OTA Signing Root CA",
                    "PayloadCertificateData": caCertData
                ]
            ]
        ]

        return try? PropertyListSerialization.data(fromPropertyList: profileDict, format: .xml, options: 0)
    }
}
