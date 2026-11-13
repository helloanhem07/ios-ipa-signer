//
//  IPALibraryStore.swift
//  iOSApp
//
//  Manages the repository of imported, unsigned, and signed IPA packages and their cached icons.
//

import Foundation
import Combine

@MainActor
public final class IPALibraryStore: ObservableObject {
    @Published public private(set) var items: [IPAItem] = []

    private let fileManager = FileManager.default
    private let baseDirectory: URL
    private let iconsDirectory: URL
    private let metadataURL: URL

    public init() {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.baseDirectory = appSupport.appendingPathComponent("IPAs", isDirectory: true)
        self.iconsDirectory = self.baseDirectory.appendingPathComponent("Icons", isDirectory: true)
        self.metadataURL = self.baseDirectory.appendingPathComponent("ipas.json")

        try? fileManager.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
        try? fileManager.createDirectory(at: iconsDirectory, withIntermediateDirectories: true)
        loadFromDisk()
    }

    public func loadFromDisk() {
        guard let data = try? Data(contentsOf: metadataURL),
              let decoded = try? JSONDecoder().decode([IPAItem].self, from: data) else {
            self.items = []
            return
        }
        self.items = decoded
    }

    private func saveToDisk() {
        if let data = try? JSONEncoder().encode(items) {
            try? data.write(to: metadataURL, options: .atomic)
        }
    }

    public func importIPA(from sourceURL: URL) async throws -> IPAItem {
        let hasSecurityScope = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if hasSecurityScope {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }

        let fileSize = (try? fileManager.attributesOfItem(atPath: sourceURL.path)[.size] as? Int64) ?? 0

        // Extract Info.plist and Icon using parser
        let extracted = try IPAMetadataParser.extract(from: sourceURL)
        let itemId = UUID()

        // Cache icon if extracted
        var iconPathName: String? = nil
        if let iconData = extracted.iconData {
            let iconFile = "\(itemId.uuidString).png"
            let iconURL = iconsDirectory.appendingPathComponent(iconFile)
            try? iconData.write(to: iconURL)
            iconPathName = iconFile
        }

        let originalName = sourceURL.lastPathComponent
        let sanitizedName = originalName.replacingOccurrences(of: " ", with: "_")
        let targetFileName = "\(itemId.uuidString)_\(sanitizedName)"
        let targetURL = baseDirectory.appendingPathComponent(targetFileName)
        
        try fileManager.copyItem(at: sourceURL, to: targetURL)

        let item = IPAItem(
            id: itemId,
            fileName: targetFileName,
            bundleDisplayName: extracted.displayName,
            bundleIdentifier: extracted.bundleIdentifier,
            bundleShortVersion: extracted.shortVersion,
            bundleVersion: extracted.version,
            minimumOSVersion: extracted.minimumOSVersion,
            fileSize: fileSize,
            iconFileName: iconPathName,
            supportedArchitectures: extracted.architectures
        )

        items.insert(item, at: 0)
        saveToDisk()
        return item
    }

    public func addSignedIPA(from fileURL: URL, originalIPA: IPAItem, newBundleId: String, newVersion: String, newAppName: String) -> IPAItem {
        let itemId = UUID()
        let fileSize = (try? fileManager.attributesOfItem(atPath: fileURL.path)[.size] as? Int64) ?? 0
        let targetFileName = "\(itemId.uuidString)_signed_\(originalIPA.fileName)"
        let targetURL = baseDirectory.appendingPathComponent(targetFileName)

        try? fileManager.copyItem(at: fileURL, to: targetURL)

        let signedItem = IPAItem(
            id: itemId,
            fileName: targetFileName,
            bundleDisplayName: newAppName.isEmpty ? originalIPA.bundleDisplayName : newAppName,
            bundleIdentifier: newBundleId.isEmpty ? originalIPA.bundleIdentifier : newBundleId,
            bundleShortVersion: newVersion.isEmpty ? originalIPA.bundleShortVersion : newVersion,
            bundleVersion: originalIPA.bundleVersion,
            minimumOSVersion: originalIPA.minimumOSVersion,
            fileSize: fileSize,
            signingStatus: .signedLocal,
            iconFileName: originalIPA.iconFileName,
            supportedArchitectures: originalIPA.supportedArchitectures
        )

        items.insert(signedItem, at: 0)
        saveToDisk()
        return signedItem
    }

    public func updateSigningStatus(itemId: UUID, status: IPASigningStatus) {
        if let idx = items.firstIndex(where: { $0.id == itemId }) {
            items[idx].signingStatus = status
            saveToDisk()
        }
    }

    public func delete(_ item: IPAItem) {
        let fileURL = baseDirectory.appendingPathComponent(item.fileName)
        try? fileManager.removeItem(at: fileURL)
        if let iconFile = item.iconFileName {
            let iconURL = iconsDirectory.appendingPathComponent(iconFile)
            try? fileManager.removeItem(at: iconURL)
        }
        items.removeAll(where: { $0.id == item.id })
        saveToDisk()
    }

    public func getIPAFileURL(for item: IPAItem) -> URL {
        baseDirectory.appendingPathComponent(item.fileName)
    }

    public func getIconURL(for item: IPAItem) -> URL? {
        guard let iconFile = item.iconFileName else { return nil }
        return iconsDirectory.appendingPathComponent(iconFile)
    }
}
