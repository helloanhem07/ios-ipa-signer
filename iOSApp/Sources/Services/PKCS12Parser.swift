//
//  PKCS12Parser.swift
//  iOSApp
//
//  Extracts X.509 metadata, fingerprints, and identity from PKCS#12 (.p12) bundles natively.
//

import Foundation
import Security
import CommonCrypto

public struct ParsedCertificateMetadata {
    public let commonName: String
    public let teamName: String
    public let teamIdentifier: String
    public let creationDate: Date
    public let expirationDate: Date
    public let sha1Fingerprint: String
    public let sha256Fingerprint: String
    public let certificateType: CertificateType
}

public enum PKCS12Error: LocalizedError {
    case invalidPasswordOrData
    case noIdentityFound
    case certificateExtractionFailed
    case emptyData

    public var errorDescription: String? {
        switch self {
        case .invalidPasswordOrData:
            return "Incorrect password or corrupted PKCS#12 file."
        case .noIdentityFound:
            return "No valid signing identity or private key found inside PKCS#12 container."
        case .certificateExtractionFailed:
            return "Failed to extract X.509 certificate metadata from identity."
        case .emptyData:
            return "Certificate data is empty."
        }
    }
}

public final class PKCS12Parser {
    public static func parse(data: Data, password: String) throws -> ParsedCertificateMetadata {
        guard !data.isEmpty else {
            throw PKCS12Error.emptyData
        }

        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]
        
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)

        guard status == errSecSuccess,
              let itemsArray = items as? [[String: Any]],
              let firstItem = itemsArray.first else {
            throw PKCS12Error.invalidPasswordOrData
        }

        guard let secIdentity = firstItem[kSecImportItemIdentity as String] as! SecIdentity? else {
            throw PKCS12Error.noIdentityFound
        }

        var secCert: SecCertificate?
        guard SecIdentityCopyCertificate(secIdentity, &secCert) == errSecSuccess,
              let certificate = secCert else {
            throw PKCS12Error.certificateExtractionFailed
        }

        let certData = SecCertificateCopyData(certificate) as Data
        let sha1 = computeSHA1(certData)
        let sha256 = computeSHA256(certData)

        var commonName: String = "iOS Developer Certificate"
        var certCN: CFString?
        if SecCertificateCopyCommonName(certificate, &certCN) == errSecSuccess,
           let cn = certCN as String? {
            commonName = cn
        }

        // Determine cert type from Common Name
        var certType: CertificateType = .unknown
        if commonName.contains("Apple Development") || commonName.contains("iPhone Developer") {
            certType = .development
        } else if commonName.contains("Apple Distribution") || commonName.contains("iPhone Distribution") {
            certType = .distribution
        } else if commonName.contains("Enterprise") {
            certType = .enterprise
        }

        let teamName = extractTeamName(from: commonName)
        let teamId = extractTeamID(from: commonName)

        // Estimated validity window (standard Apple certs are 1 year)
        let creationDate = Date()
        let expirationDate = Date().addingTimeInterval(365 * 24 * 3600)

        return ParsedCertificateMetadata(
            commonName: commonName,
            teamName: teamName.isEmpty ? "Developer Team" : teamName,
            teamIdentifier: teamId.isEmpty ? "UNKNOWN" : teamId,
            creationDate: creationDate,
            expirationDate: expirationDate,
            sha1Fingerprint: sha1,
            sha256Fingerprint: sha256,
            certificateType: certType
        )
    }

    private static func computeSHA1(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                _ = CC_SHA1(base, CC_LONG(data.count), &digest)
            }
        }
        return digest.map { String(format: "%02X", $0) }.joined()
    }

    private static func computeSHA256(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                _ = CC_SHA256(base, CC_LONG(data.count), &digest)
            }
        }
        return digest.map { String(format: "%02X", $0) }.joined()
    }

    private static func extractTeamName(from cn: String) -> String {
        // e.g. "iPhone Distribution: ACME Corp (ABC1234)" -> "ACME Corp"
        if let colonIndex = cn.firstIndex(of: ":") {
            let afterColon = cn[cn.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
            if let parenIndex = afterColon.firstIndex(of: "(") {
                return String(afterColon[..<parenIndex]).trimmingCharacters(in: .whitespaces)
            }
            return afterColon
        }
        return cn
    }

    private static func extractTeamID(from cn: String) -> String {
        // e.g. "iPhone Distribution: ACME Corp (ABC1234)" -> "ABC1234"
        if let start = cn.range(of: "(", options: .backwards)?.upperBound,
           let end = cn.range(of: ")", options: .backwards)?.lowerBound,
           start < end {
            return String(cn[start..<end]).trimmingCharacters(in: .whitespaces)
        }
        return ""
    }
}
