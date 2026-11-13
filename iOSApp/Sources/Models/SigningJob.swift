//
//  SigningJob.swift
//  iOSApp
//
//  Observable signing execution state, real-time progress, and live log buffer.
//

import Foundation
import Combine

public enum SigningJobState: String, Codable {
    case idle = "Idle"
    case preparing = "Preparing Workspace"
    case signing = "Signing Binaries"
    case repacking = "Repacking IPA"
    case completed = "Completed"
    case failed = "Failed"
}

public class SigningJob: ObservableObject, Identifiable {
    public let id: UUID
    public let targetIPA: IPAItem
    public let certificate: CertificateItem
    public let profile: ProfileItem
    public let configuration: SigningConfiguration
    
    @Published public var state: SigningJobState = .idle
    @Published public var progress: Double = 0.0 // 0.0 to 1.0
    @Published public var currentStep: String = "Ready to start"
    @Published public var logLines: [String] = []
    @Published public var signedIPAURL: URL?
    @Published public var otaManifestURL: URL?
    @Published public var errorMessage: String?
    
    public let createdAt: Date
    public var completedAt: Date?

    public init(
        id: UUID = UUID(),
        targetIPA: IPAItem,
        certificate: CertificateItem,
        profile: ProfileItem,
        configuration: SigningConfiguration
    ) {
        self.id = id
        self.targetIPA = targetIPA
        self.certificate = certificate
        self.profile = profile
        self.configuration = configuration
        self.createdAt = Date()
    }

    public func appendLog(_ message: String) {
        DispatchQueue.main.async {
            let formatter = DateFormatter()
            formatter.dateFormat = "HH:mm:ss"
            let timestamp = formatter.string(from: Date())
            self.logLines.append("[\(timestamp)] \(message)")
        }
    }
}
