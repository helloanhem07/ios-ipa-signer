//
//  SigningSettingsView.swift
//  iOSApp
//
//  Signing customization controls, parameter overrides, and live execution HUD.
//

import SwiftUI

public struct SigningSettingsView: View {
    @EnvironmentObject var appState: AppState

    @State private var showingCustomEntitlementsEditor = false
    @State private var isExecuting = false
    @State private var errorMessage: String?
    @State private var sharingURL: URL?

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                // Section 1: Signing Assets
                Section("Signing Assets") {
                    ipaPicker
                    certificatePicker
                    profilePicker
                }

                // Section 2: Engine Selection
                Section("Signing Engine") {
                    Picker("Engine", selection: $appState.signingConfiguration.engineChoice) {
                        ForEach(SigningEngineChoice.allCases, id: \.self) { choice in
                            Text(choice.rawValue).tag(choice)
                        }
                    }
                    .pickerStyle(.segmented)

                    if appState.signingConfiguration.engineChoice == .remoteServer && !appState.serverConnected {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Remote server is currently offline. Connect in Server tab.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                // Section 3: Bundle Identifier Override
                Section("Bundle Identifier") {
                    Picker("Bundle ID Mode", selection: $appState.signingConfiguration.bundleIdOption) {
                        ForEach(BundleIdOption.allCases, id: \.self) { opt in
                            Text(opt.rawValue).tag(opt)
                        }
                    }

                    if appState.signingConfiguration.bundleIdOption == .custom {
                        TextField("e.g. com.example.customapp", text: $appState.signingConfiguration.customBundleId)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                            .font(.system(.body, design: .monospaced))
                    } else if appState.signingConfiguration.bundleIdOption == .appendSuffix {
                        TextField("Suffix (e.g. .signed)", text: $appState.signingConfiguration.bundleIdSuffix)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                            .font(.system(.body, design: .monospaced))
                    }
                }

                // Section 4: Display & Version Overrides
                Section("Application Metadata") {
                    TextField("Display Name Override", text: $appState.signingConfiguration.displayNameOverride)
                    TextField("Version Override (e.g. 1.2.0)", text: $appState.signingConfiguration.versionOverride)
                    TextField("Build Override (e.g. 42)", text: $appState.signingConfiguration.buildOverride)
                }

                // Section 5: Dynamic Entitlements Injection
                Section("Dynamic Entitlements") {
                    Toggle("Enable File Sharing (iTunes / Files)", isOn: $appState.signingConfiguration.enableFileSharing)
                    Toggle("Enable Debugging (get-task-allow)", isOn: $appState.signingConfiguration.enableDebugging)

                    DisclosureGroup("Custom XML Entitlements", isExpanded: $showingCustomEntitlementsEditor) {
                        TextEditor(text: $appState.signingConfiguration.customEntitlementsXML)
                            .frame(height: 120)
                            .font(.system(.caption, design: .monospaced))
                    }
                }

                // Section 6: Compression Level
                Section("Compression Level: \(appState.signingConfiguration.compressionLevel)") {
                    HStack {
                        Text("Fast (1)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Slider(
                            value: Binding(
                                get: { Double(appState.signingConfiguration.compressionLevel) },
                                set: { appState.signingConfiguration.compressionLevel = Int($0) }
                            ),
                            in: 1...9,
                            step: 1
                        )
                        Text("Max (9)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                // Section 7: Action Button
                Section {
                    Button {
                        startSigningAction()
                    } label: {
                        HStack {
                            Spacer()
                            Label("Start Signing Package", systemImage: "signature")
                                .font(.headline)
                            Spacer()
                        }
                    }
                    .disabled(!canSign || isExecuting)
                    .buttonStyle(.borderedProminent)
                }
            }
            .navigationTitle("Sign Package")
            .sheet(isPresented: $appState.isSigningHUDPresented) {
                if let job = appState.currentSigningJob {
                    SigningProgressHUD(job: job)
                }
            }
            .alert("Signing Error", isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }

    // MARK: - Subpickers

    private var ipaPicker: some View {
        Picker("Target IPA", selection: $appState.selectedSigningIPA) {
            Text("Select an IPA").tag(Optional<IPAItem>.none)
            ForEach(appState.ipaLibraryStore.items) { ipa in
                Text(ipa.bundleDisplayName).tag(Optional(ipa))
            }
        }
    }

    private var certificatePicker: some View {
        Picker("Certificate (.p12)", selection: $appState.selectedCertificate) {
            Text("Select Certificate").tag(Optional<CertificateItem>.none)
            ForEach(appState.certificateStore.certificates) { cert in
                HStack {
                    Text(cert.commonName)
                    if cert.isDefault { Text("★") }
                }
                .tag(Optional(cert))
            }
        }
        .onChange(of: appState.selectedCertificate) { newCert in
            if let cert = newCert {
                appState.autoSelectPairedProfile(for: cert)
            }
        }
    }

    private var profilePicker: some View {
        Picker("Provisioning Profile", selection: $appState.selectedProfile) {
            Text("Select Profile").tag(Optional<ProfileItem>.none)
            ForEach(appState.profileStore.profiles) { profile in
                Text(profile.name).tag(Optional(profile))
            }
        }
    }

    private var canSign: Bool {
        appState.selectedSigningIPA != nil &&
        appState.selectedCertificate != nil &&
        appState.selectedProfile != nil
    }

    private func startSigningAction() {
        guard let ipa = appState.selectedSigningIPA,
              let cert = appState.selectedCertificate,
              let profile = appState.selectedProfile else {
            return
        }

        isExecuting = true
        appState.isSigningHUDPresented = true

        Task {
            let job = await appState.signingCoordinator.executeSigning(
                ipa: ipa,
                certificate: cert,
                profile: profile,
                configuration: appState.signingConfiguration,
                certStore: appState.certificateStore,
                profileStore: appState.profileStore,
                ipaStore: appState.ipaLibraryStore
            )
            appState.currentSigningJob = job
            isExecuting = false
        }
    }
}

// MARK: - Live Signing Progress HUD

struct SigningProgressHUD: View {
    @ObservedObject var job: SigningJob
    @Environment(\.dismiss) var dismiss
    @State private var sharingURL: URL?

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // Status Header
                VStack(spacing: 8) {
                    if job.state == .completed {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.green)
                    } else if job.state == .failed {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.red)
                    } else {
                        ProgressView(value: job.progress, total: 1.0)
                            .progressViewStyle(LinearProgressViewStyle(tint: .blue))
                            .padding(.horizontal)
                    }

                    Text(job.state.rawValue)
                        .font(.title2.bold())

                    Text(job.currentStep)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                .padding(.top, 24)

                // Live Console Logs
                VStack(alignment: .leading, spacing: 6) {
                    Text("Execution Log")
                        .font(.caption.bold())
                        .foregroundColor(.secondary)
                        .padding(.horizontal)

                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 4) {
                                ForEach(Array(job.logLines.enumerated()), id: \.offset) { idx, line in
                                    Text(line)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundColor(.primary)
                                        .id(idx)
                                }
                            }
                            .padding(12)
                        }
                        .background(Color(UIColor.secondarySystemBackground))
                        .cornerRadius(8)
                        .padding(.horizontal)
                        .frame(maxHeight: 220)
                        .onChange(of: job.logLines.count) { count in
                            if count > 0 {
                                proxy.scrollTo(count - 1, anchor: .bottom)
                            }
                        }
                    }
                }

                // Post-Signing Actions
                if job.state == .completed {
                    VStack(spacing: 12) {
                        if let otaURL = job.otaManifestURL {
                            Button {
                                UIApplication.shared.open(otaURL)
                            } label: {
                                Label("Install via Wireless OTA", systemImage: "arrow.down.circle.fill")
                                    .font(.headline)
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                        }

                        if let signedURL = job.signedIPAURL {
                            Button {
                                sharingURL = signedURL
                            } label: {
                                Label("Share Signed IPA", systemImage: "square.and.arrow.up")
                                    .font(.subheadline)
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .padding(.horizontal)
                } else if job.state == .failed {
                    if let err = job.errorMessage {
                        Text(err)
                            .font(.caption)
                            .foregroundColor(.red)
                            .padding(.horizontal)
                    }
                }

                Spacer()
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(job.state == .completed || job.state == .failed ? "Done" : "Dismiss") {
                        dismiss()
                    }
                }
            }
            .sheet(item: $sharingURL) { url in
                ActivityView(activityItems: [url])
            }
        }
    }
}
