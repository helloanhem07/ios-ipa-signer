//
//  CertificateStore.swift
//  iOSApp
//
//  Manages persistence, metadata indexing, and lifecycle for PKCS#12 certificates.
//

import Foundation
import Combine

@MainActor
public final class CertificateStore: ObservableObject {
    @Published public private(set) var certificates: [CertificateItem] = []
    @Published public private(set) var defaultCertificate: CertificateItem?

    private let fileManager = FileManager.default
    private let baseDirectory: URL
    private let metadataURL: URL

    public var expiredCount: Int {
        certificates.filter { $0.isExpired }.count
    }

    public var validCount: Int {
        certificates.filter { !$0.isExpired }.count
    }

    public init() {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.baseDirectory = appSupport.appendingPathComponent("Certificates", isDirectory: true)
        self.metadataURL = self.baseDirectory.appendingPathComponent("certificates.json")

        try? fileManager.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
        loadFromDisk()
    }

    public func loadFromDisk() {
        guard let data = try? Data(contentsOf: metadataURL),
              let decoded = try? JSONDecoder().decode([CertificateItem].self, from: data) else {
            self.certificates = []
            return
        }
        self.certificates = decoded
        self.defaultCertificate = decoded.first(where: { $0.isDefault }) ?? decoded.first
    }

    private func saveToDisk() {
        if let data = try? JSONEncoder().encode(certificates) {
            try? data.write(to: metadataURL, options: .atomic)
        }
    }

    public func importCertificate(from sourceURL: URL, password: String) async throws -> CertificateItem {
        let fileData: Data
        if sourceURL.startAccessingSecurityScopedResource() {
            defer { sourceURL.stopAccessingSecurityScopedResource() }
            fileData = try Data(contentsOf: sourceURL)
        } else {
            fileData = try Data(contentsOf: sourceURL)
        }

        // Validate and extract X.509 metadata via PKCS12Parser
        let metadata = try PKCS12Parser.parse(data: fileData, password: password)

        let targetFileName = "\(metadata.sha1Fingerprint).p12"
        let targetURL = baseDirectory.appendingPathComponent(targetFileName)
        try fileData.write(to: targetURL, options: .atomic)

        // Save password securely in Hardware Keychain
        KeychainManager.shared.savePassword(password, forCertificateFingerprint: metadata.sha1Fingerprint)

        let isFirst = certificates.isEmpty
        let item = CertificateItem(
            fileName: targetFileName,
            commonName: metadata.commonName,
            teamName: metadata.teamName,
            teamIdentifier: metadata.teamIdentifier,
            creationDate: metadata.creationDate,
            expirationDate: metadata.expirationDate,
            sha1Fingerprint: metadata.sha1Fingerprint,
            sha256Fingerprint: metadata.sha256Fingerprint,
            isDefault: isFirst,
            certificateType: metadata.certificateType
        )

        // Remove duplicate if re-imported
        certificates.removeAll(where: { $0.sha1Fingerprint == item.sha1Fingerprint })
        certificates.append(item)
        if isFirst {
            defaultCertificate = item
        }
        saveToDisk()
        return item
    }

    public func setDefault(_ item: CertificateItem) {
        for i in 0..<certificates.count {
            certificates[i].isDefault = (certificates[i].id == item.id)
        }
        defaultCertificate = item
        saveToDisk()
    }

    public func delete(_ item: CertificateItem) {
        let fileURL = baseDirectory.appendingPathComponent(item.fileName)
        try? fileManager.removeItem(at: fileURL)
        KeychainManager.shared.deletePassword(forCertificateFingerprint: item.sha1Fingerprint)
        certificates.removeAll(where: { $0.id == item.id })
        if defaultCertificate?.id == item.id {
            defaultCertificate = certificates.first
            if let def = defaultCertificate {
                setDefault(def)
            }
        }
        saveToDisk()
    }

    public func getP12FileURL(for item: CertificateItem) -> URL {
        baseDirectory.appendingPathComponent(item.fileName)
    }
}
