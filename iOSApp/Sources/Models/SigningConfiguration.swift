//
//  SigningConfiguration.swift
//  iOSApp
//
//  Configuration parameters for on-device and remote re-signing jobs.
//

import Foundation

public enum BundleIdOption: String, Codable, CaseIterable {
    case keepOriginal = "Keep Original"
    case useProfile = "Use Profile App ID"
    case custom = "Custom Bundle ID"
    case appendSuffix = "Append Suffix"
}

public enum SigningEngineChoice: String, Codable, CaseIterable {
    case onDevice = "On-Device (zsign)"
    case remoteServer = "Remote Server"
}

public struct SigningConfiguration: Codable, Equatable {
    public var engineChoice: SigningEngineChoice
    public var bundleIdOption: BundleIdOption
    public var customBundleId: String
    public var bundleIdSuffix: String
    public var displayNameOverride: String
    public var versionOverride: String
    public var buildOverride: String
    public var enableFileSharing: Bool
    public var enableDebugging: Bool
    public var customEntitlementsXML: String
    public var compressionLevel: Int // 1 (fastest) to 9 (maximum)

    public init(
        engineChoice: SigningEngineChoice = .onDevice,
        bundleIdOption: BundleIdOption = .keepOriginal,
        customBundleId: String = "",
        bundleIdSuffix: String = ".signed",
        displayNameOverride: String = "",
        versionOverride: String = "",
        buildOverride: String = "",
        enableFileSharing: Bool = false,
        enableDebugging: Bool = false,
        customEntitlementsXML: String = "",
        compressionLevel: Int = 1
    ) {
        self.engineChoice = engineChoice
        self.bundleIdOption = bundleIdOption
        self.customBundleId = customBundleId
        self.bundleIdSuffix = bundleIdSuffix
        self.displayNameOverride = displayNameOverride
        self.versionOverride = versionOverride
        self.buildOverride = buildOverride
        self.enableFileSharing = enableFileSharing
        self.enableDebugging = enableDebugging
        self.customEntitlementsXML = customEntitlementsXML
        self.compressionLevel = compressionLevel
    }
}
