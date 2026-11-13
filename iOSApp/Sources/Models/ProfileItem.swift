//
//  ProfileItem.swift
//  iOSApp
//
//  Data model representing an imported Apple Provisioning Profile (.mobileprovision).
//

import Foundation

public enum ProfileType: String, Codable, CaseIterable {
    case development = "Development"
    case adHoc = "Ad-Hoc"
    case enterprise = "Enterprise"
    case appStore = "App Store"
}

public struct ProfileItem: Identifiable, Codable, Hashable, Equatable {
    public let id: UUID
    public let fileName: String                // e.g. "abcd-1234.mobileprovision"
    public let name: String                    // Profile Name, e.g. "ACME Wildcard Profile"
    public let uuid: String                    // Profile UUID string
    public let teamName: String                // Team name string
    public let teamIdentifier: String          // Primary team ID
    public let appIdentifierPrefix: String     // e.g. "ABCDE12345"
    public let bundleIdentifierPattern: String // e.g. "ABCDE12345.*"
    public let creationDate: Date
    public let expirationDate: Date
    public let profileType: ProfileType
    public let isEnterprise: Bool
    public let provisionedDevicesCount: Int?   // nil if Enterprise (no device limit)
    public let developerCertificatesSHA1: [String] // Array of SHA-1 fingerprints of embedded certs
    public let entitlements: [String: String]  // Key-value representation for UI display

    public var isExpired: Bool {
        Date() > expirationDate
    }

    public var daysUntilExpiration: Int {
        Calendar.current.dateComponents([.day], from: Date(), to: expirationDate).day ?? 0
    }

    public var isExpiringSoon: Bool {
        !isExpired && daysUntilExpiration <= 30
    }

    public init(
        id: UUID = UUID(),
        fileName: String,
        name: String,
        uuid: String,
        teamName: String,
        teamIdentifier: String,
        appIdentifierPrefix: String,
        bundleIdentifierPattern: String,
        creationDate: Date,
        expirationDate: Date,
        profileType: ProfileType,
        isEnterprise: Bool,
        provisionedDevicesCount: Int?,
        developerCertificatesSHA1: [String],
        entitlements: [String: String]
    ) {
        self.id = id
        self.fileName = fileName
        self.name = name
        self.uuid = uuid
        self.teamName = teamName
        self.teamIdentifier = teamIdentifier
        self.appIdentifierPrefix = appIdentifierPrefix
        self.bundleIdentifierPattern = bundleIdentifierPattern
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.profileType = profileType
        self.isEnterprise = isEnterprise
        self.provisionedDevicesCount = provisionedDevicesCount
        self.developerCertificatesSHA1 = developerCertificatesSHA1.map { $0.uppercased() }
        self.entitlements = entitlements
    }
}
