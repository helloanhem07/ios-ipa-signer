//
//  CertificatesView.swift
//  iOSApp
//
//  PKCS#12 certificate manager view: import, password challenge, metadata inspection, and Keychain storage.
//

import SwiftUI
import UniformTypeIdentifiers

public struct CertificatesView: View {
    @EnvironmentObject var appState: AppState

    @State private var isFileImporterPresented = false
    @State private var selectedP12URL: URL?
    @State private var isPasswordSheetPresented = false
    @State private var passwordInput = ""
    @State private var isImporting = false
    @State private var importErrorMessage: String?
    @State private var inspectingCertificate: CertificateItem?

    public init() {}

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Header Summary Stats
                statsHeader
                    .padding()
                    .background(Color(UIColor.secondarySystemBackground))

                if appState.certificateStore.certificates.isEmpty {
                    emptyStateView
                } else {
                    certificateList
                }
            }
            .navigationTitle("Certificates")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        isFileImporterPresented = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .fileImporter(
                isPresented: $isFileImporterPresented,
                allowedContentTypes: [.pkcs12, UTType(filenameExtension: "p12") ?? .data],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first {
                        self.selectedP12URL = url
                        self.passwordInput = ""
                        self.importErrorMessage = nil
                        self.isPasswordSheetPresented = true
                    }
                case .failure(let error):
                    self.importErrorMessage = error.localizedDescription
                }
            }
            .sheet(isPresented: $isPasswordSheetPresented) {
                passwordChallengeSheet
            }
            .sheet(item: $inspectingCertificate) { cert in
                certificateDetailSheet(cert)
            }
        }
    }

    // MARK: - Subviews

    private var statsHeader: some View {
        HStack(spacing: 12) {
            statChip(title: "Total", count: appState.certificateStore.certificates.count, color: .blue)
            statChip(title: "Valid", count: appState.certificateStore.validCount, color: .green)
            statChip(title: "Expired", count: appState.certificateStore.expiredCount, color: .red)
        }
    }

    private func statChip(title: String, count: Int, color: Color) -> some View {
        VStack {
            Text("\(count)")
                .font(.title3.bold())
                .foregroundColor(color)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color(UIColor.systemBackground))
        .cornerRadius(8)
    }

    private var emptyStateView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "rosette")
                .font(.system(size: 54))
                .foregroundColor(.secondary)
            Text("No Certificates Installed")
                .font(.headline)
            Text("Import a PKCS#12 (.p12) developer certificate to begin on-device signing.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button {
                isFileImporterPresented = true
            } label: {
                Label("Import .p12 Certificate", systemImage: "plus.circle.fill")
                    .font(.headline)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 8)
            Spacer()
        }
    }

    private var certificateList: some View {
        List {
            ForEach(appState.certificateStore.certificates) { cert in
                certificateRow(cert)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        inspectingCertificate = cert
                    }
                    .swipeActions(edge: .leading) {
                        Button {
                            appState.certificateStore.setDefault(cert)
                            appState.selectedCertificate = cert
                            appState.autoSelectPairedProfile(for: cert)
                        } label: {
                            Label("Default", systemImage: "star.fill")
                        }
                        .tint(.orange)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            appState.certificateStore.delete(cert)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func certificateRow(_ cert: CertificateItem) -> some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: cert.isExpired ? "exclamationmark.octagon.fill" : (cert.isExpiringSoon ? "clock.fill" : "checkmark.seal.fill"))
                .font(.title2)
                .foregroundColor(cert.isExpired ? .red : (cert.isExpiringSoon ? .orange : .green))

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(cert.commonName)
                        .font(.body.bold())
                        .lineLimit(1)
                    if cert.isDefault {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }

                Text("\(cert.teamName) (\(cert.teamIdentifier))")
                    .font(.caption)
                    .foregroundColor(.secondary)

                HStack {
                    Text(cert.certificateType.rawValue)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.1))
                        .foregroundColor(.blue)
                        .cornerRadius(4)

                    if cert.isExpired {
                        Text("Expired")
                            .font(.caption2.bold())
                            .foregroundColor(.red)
                    } else {
                        Text("Expires in \(cert.daysUntilExpiration)d")
                            .font(.caption2)
                            .foregroundColor(cert.isExpiringSoon ? .orange : .secondary)
                    }
                }
            }

            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundColor(.tertiaryLabel)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Password Challenge Modal

    private var passwordChallengeSheet: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.blue)
                    .padding(.top, 24)

                Text("Enter Certificate Password")
                    .font(.title3.bold())

                if let url = selectedP12URL {
                    Text(url.lastPathComponent)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                SecureField("PKCS#12 Password", text: $passwordInput)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)

                if let err = importErrorMessage {
                    Text(err)
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.horizontal)
                }

                Button {
                    Task {
                        await importCertificateWithPassword()
                    }
                } label: {
                    if isImporting {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Text("Unlock & Store in Keychain")
                            .font(.headline)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isImporting)
                .padding(.horizontal)

                Spacer()
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        isPasswordSheetPresented = false
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }

    private func importCertificateWithPassword() async {
        guard let url = selectedP12URL else { return }
        isImporting = true
        importErrorMessage = nil

        do {
            let cert = try await appState.certificateStore.importCertificate(from: url, password: passwordInput)
            appState.selectedCertificate = cert
            appState.autoSelectPairedProfile(for: cert)
            isImporting = false
            isPasswordSheetPresented = false
        } catch {
            isImporting = false
            importErrorMessage = error.localizedDescription
        }
    }

    // MARK: - Certificate Detail Sheet

    private func certificateDetailSheet(_ cert: CertificateItem) -> some View {
        NavigationStack {
            List {
                Section("Identity") {
                    labeledRow(label: "Common Name", value: cert.commonName)
                    labeledRow(label: "Team Name", value: cert.teamName)
                    labeledRow(label: "Team Identifier", value: cert.teamIdentifier)
                    labeledRow(label: "Type", value: cert.certificateType.rawValue)
                }

                Section("Validity") {
                    labeledRow(label: "Expiration Date", value: cert.expirationDate.formatted(date: .long, time: .shortened))
                    labeledRow(label: "Days Remaining", value: "\(cert.daysUntilExpiration) days")
                    labeledRow(label: "Status", value: cert.isExpired ? "Expired" : "Valid")
                }

                Section("Fingerprints") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("SHA-1 Fingerprint")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(cert.sha1Fingerprint)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("SHA-256 Fingerprint")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(cert.sha256Fingerprint)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                Section {
                    Button(role: .destructive) {
                        appState.certificateStore.delete(cert)
                        inspectingCertificate = nil
                    } label: {
                        Label("Delete Certificate", systemImage: "trash")
                            .foregroundColor(.red)
                    }
                }
            }
            .navigationTitle("Certificate Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        inspectingCertificate = nil
                    }
                }
            }
        }
    }

    private func labeledRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline)
                .multilineTextAlignment(.trailing)
        }
    }
}
