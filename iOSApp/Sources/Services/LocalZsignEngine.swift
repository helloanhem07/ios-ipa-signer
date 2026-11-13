//
//  LocalZsignEngine.swift
//  iOSApp
//
//  Swift service wrapping embedded C++ zsign engine via ZsignBridge.
//

import Foundation

/// Unified result from local signing.
public struct LocalSigningResult {
    public let outputIPAURL: URL
    public let bundleId: String
    public let appVersion: String
    public let appName: String
    public let durationSeconds: TimeInterval
}

/// Strongly typed errors produced by the local signing pipeline.
public enum LocalSigningError: LocalizedError {
    case fileNotFound(String)
    case insufficientDiskSpace(requiredMB: Int, availableMB: Int)
    case invalidCertificatePassword
    case signingFailed(String)
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let path):
            return "Required file not found: \(path)"
        case .insufficientDiskSpace(let req, let avail):
            return "Insufficient disk space: Need at least \(req) MB, but only \(avail) MB available."
        case .invalidCertificatePassword:
            return "Incorrect .p12 certificate password or unsupported encryption algorithm."
        case .signingFailed(let msg):
            return "Signing engine error: \(msg)"
        case .cancelled:
            return "Signing operation was cancelled by the user."
        }
    }
}

/// Actor or service providing asynchronous local IPA signing.
public final class LocalZsignEngine {
    public static let shared = LocalZsignEngine()

    private init() {}

    /**
     Executes on-device signing asynchronously using embedded C++ zsign.
     
     - Parameters:
       - ipaURL: URL to the unsigned .ipa file.
       - certificateURL: URL to the .p12 certificate file.
       - certificatePassword: Password for unlocking the .p12 file.
       - profileURL: URL to the .mobileprovision file.
       - bundleIdOverride: Optional bundle ID override.
       - displayNameOverride: Optional display name override.
       - entitlementsURL: Optional custom entitlements file URL.
       - compressionLevel: Compression level (1 fastest, 9 maximum).
       - progressHandler: Closure receiving progress (0.0 to 1.0) and status string.
     - Returns: LocalSigningResult on success.
     */
    public func sign(
        ipaURL: URL,
        certificateURL: URL,
        certificatePassword: String,
        profileURL: URL,
        bundleIdOverride: String? = nil,
        displayNameOverride: String? = nil,
        entitlementsURL: URL? = nil,
        compressionLevel: Int = 6,
        progressHandler: @escaping (Float, String) -> Void
    ) async throws -> LocalSigningResult {

        let startTime = Date()

        // 1. Verify file paths exist
        guard FileManager.default.fileExists(atPath: ipaURL.path) else {
            throw LocalSigningError.fileNotFound(ipaURL.lastPathComponent)
        }
        guard FileManager.default.fileExists(atPath: certificateURL.path) else {
            throw LocalSigningError.fileNotFound(certificateURL.lastPathComponent)
        }
        guard FileManager.default.fileExists(atPath: profileURL.path) else {
            throw LocalSigningError.fileNotFound(profileURL.lastPathComponent)
        }

        // 2. Pre-flight Disk Space Check
        // Signing requires approx. 2.5x the IPA size (unpacked payload + repacked output)
        if let ipaAttributes = try? FileManager.default.attributesOfItem(atPath: ipaURL.path),
           let ipaSize = ipaAttributes[.size] as? Int64 {
            let requiredBytes = ipaSize * 5 / 2 // 2.5x
            if let freeBytes = try? Self.availableDiskSpace(), freeBytes > 0 && freeBytes < requiredBytes {
                let reqMB = Int(requiredBytes / (1024 * 1024))
                let availMB = Int(freeBytes / (1024 * 1024))
                throw LocalSigningError.insufficientDiskSpace(requiredMB: reqMB, availableMB: availMB)
            }
        }

        // 3. Dispatch to Detached Background Queue
        let result: ZsignResult = try await Task.detached(priority: .userInitiated) {
            let rawResult = ZsignBridge.signAppBundle(
                withIpaPath: ipaURL.path,
                p12Path: certificateURL.path,
                p12Password: certificatePassword,
                provisioningPath: profileURL.path,
                bundleId: (bundleIdOverride?.isEmpty ?? true) ? nil : bundleIdOverride,
                displayName: (displayNameOverride?.isEmpty ?? true) ? nil : displayNameOverride,
                entitlementsPath: entitlementsURL?.path,
                compression: compressionLevel
            ) { progress, statusMessage in
                DispatchQueue.main.async {
                    progressHandler(progress, statusMessage)
                }
            }
            return rawResult
        }.value

        // 4. Handle Result
        guard result.success, let outputPath = result.outputIpaPath else {
            let err = result.errorMessage ?? "Unknown native signing failure."
            if err.localizedCaseInsensitiveContains("password") || err.localizedCaseInsensitiveContains("PKCS12") {
                throw LocalSigningError.invalidCertificatePassword
            }
            throw LocalSigningError.signingFailed(err)
        }

        let duration = Date().timeIntervalSince(startTime)
        let outputURL = URL(fileURLWithPath: outputPath)

        return LocalSigningResult(
            outputIPAURL: outputURL,
            bundleId: result.bundleId ?? "unknown",
            appVersion: result.appVersion ?? "1.0",
            appName: result.appName ?? "SignedApp",
            durationSeconds: duration
        )
    }

    /// Queries the iOS volume available capacity for important usage.
    private static func availableDiskSpace() throws -> Int64 {
        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory())
        let values = try tempURL.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values.volumeAvailableCapacityForImportantUsage ?? 0
    }
}
