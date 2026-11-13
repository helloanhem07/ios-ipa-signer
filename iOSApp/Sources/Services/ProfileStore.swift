//
//  ProfileStore.swift
//  iOSApp
//
//  Manages persistence, metadata indexing, and automatic certificate pairing for provisioning profiles.
//

import Foundation
import Combine

@MainActor
public final class ProfileStore: ObservableObject {
    @Published public private(set) var profiles: [ProfileItem] = []

    private let fileManager = FileManager.default
    private let baseDirectory: URL
    private let metadataURL: URL

    public init() {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.baseDirectory = appSupport.appendingPathComponent("Profiles", isDirectory: true)
        self.metadataURL = self.baseDirectory.appendingPathComponent("profiles.json")

        try? fileManager.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
        loadFromDisk()
    }

    public func loadFromDisk() {
        guard let data = try? Data(contentsOf: metadataURL),
              let decoded = try? JSONDecoder().decode([ProfileItem].self, from: data) else {
            self.profiles = []
            return
        }
        self.profiles = decoded
    }

    private func saveToDisk() {
        if let data = try? JSONEncoder().encode(profiles) {
            try? data.write(to: metadataURL, options: .atomic)
        }
    }

    public func importProfile(from sourceURL: URL) async throws -> ProfileItem {
        let fileData: Data
        if sourceURL.startAccessingSecurityScopedResource() {
            defer { sourceURL.stopAccessingSecurityScopedResource() }
            fileData = try Data(contentsOf: sourceURL)
        } else {
            fileData = try Data(contentsOf: sourceURL)
        }

        let parsed = try MobileProvisionParser.parse(data: fileData)

        let targetFileName = "\(parsed.uuid).mobileprovision"
        let targetURL = baseDirectory.appendingPathComponent(targetFileName)
        try fileData.write(to: targetURL, options: .atomic)

        let item = ProfileItem(
            fileName: targetFileName,
            name: parsed.name,
            uuid: parsed.uuid,
            teamName: parsed.teamName,
            teamIdentifier: parsed.teamIdentifier,
            appIdentifierPrefix: parsed.appIdentifierPrefix,
            bundleIdentifierPattern: parsed.bundleIdentifierPattern,
            creationDate: parsed.creationDate,
            expirationDate: parsed.expirationDate,
            profileType: parsed.profileType,
            isEnterprise: parsed.isEnterprise,
            provisionedDevicesCount: parsed.provisionedDevicesCount,
            developerCertificatesSHA1: parsed.developerCertificatesSHA1,
            entitlements: parsed.entitlements
        )

        profiles.removeAll(where: { $0.uuid == item.uuid })
        profiles.append(item)
        saveToDisk()
        return item
    }

    public func delete(_ item: ProfileItem) {
        let fileURL = baseDirectory.appendingPathComponent(item.fileName)
        try? fileManager.removeItem(at: fileURL)
        profiles.removeAll(where: { $0.id == item.id })
        saveToDisk()
    }

    public func getProfileFileURL(for item: ProfileItem) -> URL {
        baseDirectory.appendingPathComponent(item.fileName)
    }

    // MARK: - Automatic Pairing Engine

    /// Finds matching CertificateItems whose SHA-1 fingerprints are embedded inside this profile
    public func findPairedCertificates(for profile: ProfileItem, in certStore: CertificateStore) -> [CertificateItem] {
        return certStore.certificates.filter { cert in
            profile.developerCertificatesSHA1.contains(cert.sha1Fingerprint.uppercased())
        }
    }

    /// Finds matching ProfileItems that embed this certificate's SHA-1 fingerprint
    public func findPairedProfiles(for certificate: CertificateItem) -> [ProfileItem] {
        return profiles.filter { profile in
            profile.developerCertificatesSHA1.contains(certificate.sha1Fingerprint.uppercased())
        }
    }
}
