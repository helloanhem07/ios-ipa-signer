//
//  IPAItem.swift
//  iOSApp
//
//  Data model representing an imported, unsigned, or signed iOS Application Package (.ipa).
//

import Foundation

public enum IPASigningStatus: String, Codable {
    case unsigned = "Unsigned"
    case signedLocal = "Signed (Local)"
    case signedRemote = "Signed (Remote)"
}

public struct IPAItem: Identifiable, Codable, Hashable, Equatable {
    public let id: UUID
    public let fileName: String               // e.g. "PayloadApp.ipa"
    public let bundleDisplayName: String      // CFBundleDisplayName or CFBundleName
    public let bundleIdentifier: String       // CFBundleIdentifier
    public let bundleShortVersion: String     // CFBundleShortVersionString
    public let bundleVersion: String          // CFBundleVersion
    public let minimumOSVersion: String       // MinimumOSVersion, e.g. "16.0"
    public let fileSize: Int64                // File size in bytes
    public let importDate: Date
    public var signingStatus: IPASigningStatus
    public let iconFileName: String?          // Relative path to cached PNG icon
    public let supportedArchitectures: [String] // e.g. ["arm64"]

    public var formattedFileSize: String {
        ByteCountFormatter.string(fromByteCount: fileSize, countStyle: .file)
    }

    public var isSigned: Bool {
        signingStatus != .unsigned
    }

    public init(
        id: UUID = UUID(),
        fileName: String,
        bundleDisplayName: String,
        bundleIdentifier: String,
        bundleShortVersion: String,
        bundleVersion: String,
        minimumOSVersion: String,
        fileSize: Int64,
        importDate: Date = Date(),
        signingStatus: IPASigningStatus = .unsigned,
        iconFileName: String? = nil,
        supportedArchitectures: [String] = ["arm64"]
    ) {
        self.id = id
        self.fileName = fileName
        self.bundleDisplayName = bundleDisplayName
        self.bundleIdentifier = bundleIdentifier
        self.bundleShortVersion = bundleShortVersion
        self.bundleVersion = bundleVersion
        self.minimumOSVersion = minimumOSVersion
        self.fileSize = fileSize
        self.importDate = importDate
        self.signingStatus = signingStatus
        self.iconFileName = iconFileName
        self.supportedArchitectures = supportedArchitectures
    }
}
