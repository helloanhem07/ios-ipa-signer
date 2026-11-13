//
//  CertificateItem.swift
//  iOSApp
//
//  Data model representing an imported PKCS#12 (.p12) code-signing certificate.
//

import Foundation

public enum CertificateType: String, Codable, CaseIterable {
    case development = "Development"
    case distribution = "Distribution"
    case enterprise = "Enterprise"
    case unknown = "Unknown"
}

public struct CertificateItem: Identifiable, Codable, Hashable, Equatable {
    public let id: UUID
    public let fileName: String           // e.g. "a1b2c3d4e5.p12"
    public let commonName: String         // e.g. "Apple Development: Jane Doe (XYZ123)"
    public let teamName: String           // e.g. "ACME Corp"
    public let teamIdentifier: String     // OU attribute, e.g. "ABCDE12345"
    public let creationDate: Date
    public let expirationDate: Date
    public let sha1Fingerprint: String    // 40 hex characters, uppercase
    public let sha256Fingerprint: String  // 64 hex characters, uppercase
    public var isDefault: Bool
    public let certificateType: CertificateType

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
        commonName: String,
        teamName: String,
        teamIdentifier: String,
        creationDate: Date,
        expirationDate: Date,
        sha1Fingerprint: String,
        sha256Fingerprint: String,
        isDefault: Bool = false,
        certificateType: CertificateType = .unknown
    ) {
        self.id = id
        self.fileName = fileName
        self.commonName = commonName
        self.teamName = teamName
        self.teamIdentifier = teamIdentifier
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.sha1Fingerprint = sha1Fingerprint.uppercased()
        self.sha256Fingerprint = sha256Fingerprint.uppercased()
        self.isDefault = isDefault
        self.certificateType = certificateType
    }
}
