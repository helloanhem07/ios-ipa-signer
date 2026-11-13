//
//  SigningCoordinator.swift
//  iOSApp
//
//  Unified pipeline coordinator routing to local zsign vs remote server offloading.
//

import Foundation
import Combine
import UIKit

@MainActor
public final class SigningCoordinator: ObservableObject {
    public static let shared = SigningCoordinator()

    @Published public private(set) var activeJob: SigningJob?
    @Published public private(set) var isBusy: Bool = false

    private init() {}

    public func executeSigning(
        ipa: IPAItem,
        certificate: CertificateItem,
        profile: ProfileItem,
        configuration: SigningConfiguration,
        certStore: CertificateStore,
        profileStore: ProfileStore,
        ipaStore: IPALibraryStore
    ) async -> SigningJob {

        let job = SigningJob(
            targetIPA: ipa,
            certificate: certificate,
            profile: profile,
            configuration: configuration
        )
        self.activeJob = job
        self.isBusy = true

        job.appendLog("Starting signing pipeline for \(ipa.bundleDisplayName)...")
        job.state = .preparing

        if configuration.engineChoice == .onDevice {
            await executeLocalSigning(job: job, certStore: certStore, profileStore: profileStore, ipaStore: ipaStore)
        } else {
            await executeRemoteSigning(job: job, certStore: certStore, profileStore: profileStore, ipaStore: ipaStore)
        }

        self.isBusy = false
        return job
    }

    // MARK: - Local On-Device Signing Pipeline

    private func executeLocalSigning(
        job: SigningJob,
        certStore: CertificateStore,
        profileStore: ProfileStore,
        ipaStore: IPALibraryStore
    ) async {
        let ipaURL = ipaStore.getIPAFileURL(for: job.targetIPA)
        let certURL = certStore.getP12FileURL(for: job.certificate)
        let profileURL = profileStore.getProfileFileURL(for: job.profile)

        guard let password = KeychainManager.shared.getPassword(forCertificateFingerprint: job.certificate.sha1Fingerprint) else {
            job.state = .failed
            job.errorMessage = "Certificate password not found in Keychain. Please re-import certificate."
            job.appendLog("Error: Missing certificate password in hardware keychain.")
            return
        }

        job.appendLog("Resolved local file assets. Preparing workspace...")
        job.state = .signing

        // Compute bundle ID override
        var bundleIdOverride: String? = nil
        switch job.configuration.bundleIdOption {
        case .keepOriginal:
            bundleIdOverride = nil
        case .useProfile:
            bundleIdOverride = job.profile.bundleIdentifierPattern.replacingOccurrences(of: "*", with: "app")
        case .custom:
            bundleIdOverride = job.configuration.customBundleId.isEmpty ? nil : job.configuration.customBundleId
        case .appendSuffix:
            bundleIdOverride = "\(job.targetIPA.bundleIdentifier)\(job.configuration.bundleIdSuffix)"
        }

        let displayNameOverride = job.configuration.displayNameOverride.isEmpty ? nil : job.configuration.displayNameOverride

        do {
            let result = try await LocalZsignEngine.shared.sign(
                ipaURL: ipaURL,
                certificateURL: certURL,
                certificatePassword: password,
                profileURL: profileURL,
                bundleIdOverride: bundleIdOverride,
                displayNameOverride: displayNameOverride,
                entitlementsURL: nil,
                compressionLevel: job.configuration.compressionLevel
            ) { progress, statusMessage in
                DispatchQueue.main.async {
                    job.progress = Double(progress)
                    job.currentStep = statusMessage
                    job.appendLog(statusMessage)
                    if progress >= 0.85 {
                        job.state = .repacking
                    }
                }
            }

            job.signedIPAURL = result.outputIPAURL
            job.appendLog("Signed package produced at: \(result.outputIPAURL.lastPathComponent)")

            // Register with Local OTA Server
            LocalOTAServer.shared.setServeContext(
                ipaURL: result.outputIPAURL,
                bundleId: result.bundleId,
                version: result.appVersion,
                appName: result.appName,
                iconData: nil
            )

            if !LocalOTAServer.shared.isRunning {
                try? LocalOTAServer.shared.start()
            }

            job.otaManifestURL = LocalOTAServer.shared.itmsInstallURL

            // Add signed IPA into IPA Library Store
            _ = ipaStore.addSignedIPA(
                from: result.outputIPAURL,
                originalIPA: job.targetIPA,
                newBundleId: result.bundleId,
                newVersion: result.appVersion,
                newAppName: result.appName
            )

            job.state = .completed
            job.progress = 1.0
            job.currentStep = "Signing complete"
            job.completedAt = Date()
            job.appendLog("Signing pipeline finished successfully in \(String(format: "%.2f", result.durationSeconds))s.")

        } catch {
            job.state = .failed
            job.errorMessage = error.localizedDescription
            job.appendLog("Signing failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Remote Backend Signing Pipeline

    private func executeRemoteSigning(
        job: SigningJob,
        certStore: CertificateStore,
        profileStore: ProfileStore,
        ipaStore: IPALibraryStore
    ) async {
        let ipaURL = ipaStore.getIPAFileURL(for: job.targetIPA)
        let certURL = certStore.getP12FileURL(for: job.certificate)
        let profileURL = profileStore.getProfileFileURL(for: job.profile)

        guard let password = KeychainManager.shared.getPassword(forCertificateFingerprint: job.certificate.sha1Fingerprint) else {
            job.state = .failed
            job.errorMessage = "Certificate password missing from Keychain."
            job.appendLog("Error: Missing certificate password.")
            return
        }

        job.appendLog("Initiating remote signing offload to backend...")
        job.state = .signing

        var bundleIdOverride: String? = nil
        switch job.configuration.bundleIdOption {
        case .keepOriginal:
            bundleIdOverride = nil
        case .useProfile:
            bundleIdOverride = job.profile.bundleIdentifierPattern.replacingOccurrences(of: "*", with: "app")
        case .custom:
            bundleIdOverride = job.configuration.customBundleId.isEmpty ? nil : job.configuration.customBundleId
        case .appendSuffix:
            bundleIdOverride = "\(job.targetIPA.bundleIdentifier)\(job.configuration.bundleIdSuffix)"
        }

        do {
            let submission = try await RemoteSigningClient.shared.submitJob(
                ipaURL: ipaURL,
                p12URL: certURL,
                password: password,
                profileURL: profileURL,
                bundleId: bundleIdOverride,
                displayName: job.configuration.displayNameOverride.isEmpty ? nil : job.configuration.displayNameOverride,
                compressionLevel: job.configuration.compressionLevel
            ) { uploadFraction in
                DispatchQueue.main.async {
                    job.progress = uploadFraction * 0.5 // Scale upload to 50%
                    job.currentStep = String(format: "Uploading to server: %.0f%%", uploadFraction * 100)
                }
            }

            job.appendLog("Job submitted to remote server. Job ID: \(submission.job_id)")
            job.currentStep = "Server processing..."

            let completedStatus = try await RemoteSigningClient.shared.pollJobStatus(jobId: submission.job_id) { statusUpdate in
                DispatchQueue.main.async {
                    job.currentStep = "Remote status: \(statusUpdate.status)"
                    job.appendLog("Server: \(statusUpdate.status)")
                    if statusUpdate.status.lowercased() == "processing" {
                        job.progress = 0.75
                    }
                }
            }

            if let itmsStr = completedStatus.itms_url, let itmsURL = URL(string: itmsStr) {
                job.otaManifestURL = itmsURL
            }

            // Download signed IPA to local storage if download URL is available
            if let downloadPath = completedStatus.download_url {
                job.currentStep = "Downloading signed IPA..."
                let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
                let tempOutput = tempDir.appendingPathComponent("remote_signed_\(submission.job_id).ipa")

                try await RemoteSigningClient.shared.downloadSignedIPA(from: downloadPath, destinationURL: tempOutput)
                job.signedIPAURL = tempOutput

                _ = ipaStore.addSignedIPA(
                    from: tempOutput,
                    originalIPA: job.targetIPA,
                    newBundleId: completedStatus.bundle_id ?? job.targetIPA.bundleIdentifier,
                    newVersion: completedStatus.bundle_version ?? job.targetIPA.bundleShortVersion,
                    newAppName: completedStatus.app_name ?? job.targetIPA.bundleDisplayName
                )
            }

            job.state = .completed
            job.progress = 1.0
            job.currentStep = "Remote signing completed"
            job.completedAt = Date()
            job.appendLog("Remote signing and delivery finished successfully.")

        } catch {
            job.state = .failed
            job.errorMessage = error.localizedDescription
            job.appendLog("Remote signing failed: \(error.localizedDescription)")
        }
    }
}
