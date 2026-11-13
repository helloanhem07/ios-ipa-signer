//
//  KeychainManager.swift
//  iOSApp
//
//  Secure, hardware-backed iOS Keychain manager for certificate passwords and API tokens.
//

import Foundation
import Security

public final class KeychainManager {
    public static let shared = KeychainManager()
    
    private let certPasswordService = "com.signing.iosapp.certpasswords"
    private let serverTokenService = "com.signing.iosapp.tokens"

    private init() {}

    // MARK: - Certificate Password Storage

    @discardableResult
    public func savePassword(_ password: String, forCertificateFingerprint fingerprint: String) -> Bool {
        guard let data = password.data(using: .utf8) else { return false }
        
        // Remove existing item if present
        deletePassword(forCertificateFingerprint: fingerprint)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: certPasswordService,
            kSecAttrAccount as String: fingerprint.uppercased(),
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public func getPassword(forCertificateFingerprint fingerprint: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: certPasswordService,
            kSecAttrAccount as String: fingerprint.uppercased(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    public func deletePassword(forCertificateFingerprint fingerprint: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: certPasswordService,
            kSecAttrAccount as String: fingerprint.uppercased()
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - Remote Server API Token Storage

    @discardableResult
    public func saveToken(_ token: String, forServerURL serverURL: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        deleteToken(forServerURL: serverURL)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serverTokenService,
            kSecAttrAccount as String: serverURL.lowercased(),
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public func getToken(forServerURL serverURL: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serverTokenService,
            kSecAttrAccount as String: serverURL.lowercased(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    public func deleteToken(forServerURL serverURL: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serverTokenService,
            kSecAttrAccount as String: serverURL.lowercased()
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
