//
//  MobileProvisionParser.swift
//  iOSApp
//
//  Extracts and parses Apple Provisioning Profiles (.mobileprovision) and their embedded CMS plists.
//

import Foundation
import Security
import CommonCrypto

public struct ParsedProvisioningProfile {
    public let name: String
    public let uuid: String
    public let teamName: String
    public let teamIdentifier: String
    public let appIdentifierPrefix: String
    public let bundleIdentifierPattern: String
    public let creationDate: Date
    public let expirationDate: Date
    public let profileType: ProfileType
    public let isEnterprise: Bool
    public let provisionedDevicesCount: Int?
    public let developerCertificatesSHA1: [String]
    public let entitlements: [String: String]
}

public enum MobileProvisionError: LocalizedError {
    case invalidCMSData
    case plistDeserializationFailed
    case emptyData

    public var errorDescription: String? {
        switch self {
        case .invalidCMSData:
            return "Unable to decode CMS envelope from mobileprovision file."
        case .plistDeserializationFailed:
            return "Failed to deserialize inner XML property list from provisioning profile."
        case .emptyData:
            return "Provisioning profile data is empty."
        }
    }
}

public final class MobileProvisionParser {
    public static func parse(data: Data) throws -> ParsedProvisioningProfile {
        guard !data.isEmpty else {
            throw MobileProvisionError.emptyData
        }

        // Step 1: Extract XML plist Data from CMS payload
        var plistData: Data? = nil

        #if os(macOS)
        var decoder: CMSDecoder?
        CMSDecoderCreate(&decoder)
        if let cms = decoder {
            data.withUnsafeBytes { ptr in
                if let base = ptr.baseAddress {
                    CMSDecoderUpdateMessage(cms, base, data.count)
                }
            }
            CMSDecoderFinalizeMessage(cms)

            var contentData: CFData?
            let status = CMSDecoderCopyContent(cms, &contentData)
            if status == errSecSuccess, let cf = contentData {
                plistData = cf as Data
            }
        }
        #endif

        // Extract XML plist directly from profile bytes
        if plistData == nil {
            if let xmlStart = data.range(of: Data("<?xml".utf8)),
               let xmlEnd = data.range(of: Data("</plist>".utf8), options: .backwards) {
                plistData = data.subdata(in: xmlStart.lowerBound..<xmlEnd.upperBound)
            }
        }

        guard let validPlistData = plistData else {
            throw MobileProvisionError.invalidCMSData
        }

        // Step 2: Parse XML Property List
        guard let plist = try? PropertyListSerialization.propertyList(from: validPlistData, format: nil) as? [String: Any] else {
            throw MobileProvisionError.plistDeserializationFailed
        }

        let name = plist["Name"] as? String ?? "Unnamed Provisioning Profile"
        let uuid = plist["UUID"] as? String ?? UUID().uuidString
        let teamName = plist["TeamName"] as? String ?? "Unknown Team"
        let teamIDs = plist["TeamIdentifier"] as? [String] ?? []
        let teamIdentifier = teamIDs.first ?? ""
        let appIDPrefixes = plist["ApplicationIdentifierPrefix"] as? [String] ?? []
        let appIdentifierPrefix = appIDPrefixes.first ?? ""
        let creationDate = plist["CreationDate"] as? Date ?? Date()
        let expirationDate = plist["ExpirationDate"] as? Date ?? Date().addingTimeInterval(365 * 24 * 3600)
        let isEnterprise = plist["ProvisionsAllDevices"] as? Bool ?? false
        let devices = plist["ProvisionedDevices"] as? [String]
        let provisionedDevicesCount = isEnterprise ? nil : (devices?.count ?? 0)

        // Parse Entitlements
        var parsedEntitlements: [String: String] = [:]
        var bundleIdPattern: String = ""
        if let entDict = plist["Entitlements"] as? [String: Any] {
            for (key, val) in entDict {
                parsedEntitlements[key] = "\(val)"
            }
            if let appID = entDict["application-identifier"] as? String {
                bundleIdPattern = appID
            }
        }

        // Determine profile type
        let profileType: ProfileType
        if isEnterprise {
            profileType = .enterprise
        } else if let devs = devices, !devs.isEmpty {
            profileType = .adHoc
        } else {
            profileType = .development
        }

        // Extract DeveloperCertificates DER data and compute SHA-1 fingerprints
        var devCertSHA1s: [String] = []
        if let devCerts = plist["DeveloperCertificates"] as? [Data] {
            for certData in devCerts {
                var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                certData.withUnsafeBytes { ptr in
                    if let base = ptr.baseAddress {
                        _ = CC_SHA1(base, CC_LONG(certData.count), &digest)
                    }
                }
                let hex = digest.map { String(format: "%02X", $0) }.joined()
                devCertSHA1s.append(hex)
            }
        }

        return ParsedProvisioningProfile(
            name: name,
            uuid: uuid,
            teamName: teamName,
            teamIdentifier: teamIdentifier,
            appIdentifierPrefix: appIdentifierPrefix,
            bundleIdentifierPattern: bundleIdPattern,
            creationDate: creationDate,
            expirationDate: expirationDate,
            profileType: profileType,
            isEnterprise: isEnterprise,
            provisionedDevicesCount: provisionedDevicesCount,
            developerCertificatesSHA1: devCertSHA1s,
            entitlements: parsedEntitlements
        )
    }
}
