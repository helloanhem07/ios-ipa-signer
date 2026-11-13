//
//  AppState.swift
//  iOSApp
//
//  Centralized application state container coordinating stores, services, and navigation.
//

import Foundation
import Combine
import SwiftUI

@MainActor
public final class AppState: ObservableObject {
    @Published public var selectedTab: Int = 2 // Defaults to IPA Library tab

    // Stores
    @Published public var certificateStore = CertificateStore()
    @Published public var profileStore = ProfileStore()
    @Published public var ipaLibraryStore = IPALibraryStore()

    // Active Signing Selection
    @Published public var selectedSigningIPA: IPAItem?
    @Published public var selectedCertificate: CertificateItem?
    @Published public var selectedProfile: ProfileItem?
    @Published public var signingConfiguration = SigningConfiguration()

    // Active Signing Job
    @Published public var currentSigningJob: SigningJob?
    @Published public var isSigningHUDPresented: Bool = false

    // Server State
    @Published public var serverBaseURL: String = "http://127.0.0.1:8000"
    @Published public var serverConnected: Bool = false
    @Published public var serverLatencyMs: Double = 0.0
    @Published public var serverVersion: String = ""
    @Published public var serverEngines: [String: Bool] = [:]

    // Services
    public let signingCoordinator = SigningCoordinator.shared
    public let localOTAServer = LocalOTAServer.shared
    public let remoteSigningClient = RemoteSigningClient.shared

    public init() {
        // Automatically select default certificate if present
        if let defaultCert = certificateStore.defaultCertificate {
            self.selectedCertificate = defaultCert
            autoSelectPairedProfile(for: defaultCert)
        }
    }

    public func autoSelectPairedProfile(for certificate: CertificateItem) {
        let paired = profileStore.findPairedProfiles(for: certificate)
        if let first = paired.first {
            self.selectedProfile = first
        }
    }

    /// Handles AirDrop, Document Picker, or Safari incoming file URLs
    public func handleIncomingURL(_ url: URL) {
        let ext = url.pathExtension.lowercased()
        Task {
            do {
                if ext == "ipa" {
                    let imported = try await ipaLibraryStore.importIPA(from: url)
                    self.selectedSigningIPA = imported
                    self.selectedTab = 2 // Go to IPA Library
                } else if ext == "p12" || ext == "pfx" {
                    self.selectedTab = 0 // Go to Certificates
                } else if ext == "mobileprovision" {
                    _ = try await profileStore.importProfile(from: url)
                    self.selectedTab = 1 // Go to Profiles
                }
            } catch {
                print("Failed to import incoming file: \(error.localizedDescription)")
            }
        }
    }
}
