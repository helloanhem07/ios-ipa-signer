//
//  ProfilesView.swift
//  iOSApp
//
//  Provisioning profile manager view: CMS extraction, entitlements viewer, and automatic pairing engine.
//

import SwiftUI
import UniformTypeIdentifiers

public struct ProfilesView: View {
    @EnvironmentObject var appState: AppState

    @State private var isFileImporterPresented = false
    @State private var importErrorMessage: String?
    @State private var inspectingProfile: ProfileItem?

    public init() {}

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Header Summary Stats
                statsHeader
                    .padding()
                    .background(Color(UIColor.secondarySystemBackground))

                if appState.profileStore.profiles.isEmpty {
                    emptyStateView
                } else {
                    profileList
                }
            }
            .navigationTitle("Profiles")
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
                allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first {
                        Task {
                            do {
                                let profile = try await appState.profileStore.importProfile(from: url)
                                appState.selectedProfile = profile
                            } catch {
                                self.importErrorMessage = error.localizedDescription
                            }
                        }
                    }
                case .failure(let error):
                    self.importErrorMessage = error.localizedDescription
                }
            }
            .sheet(item: $inspectingProfile) { profile in
                profileDetailSheet(profile)
            }
            .alert("Import Error", isPresented: Binding(
                get: { importErrorMessage != nil },
                set: { if !$0 { importErrorMessage = nil } }
            )) {
                Button("OK") { importErrorMessage = nil }
            } message: {
                Text(importErrorMessage ?? "")
            }
        }
    }

    // MARK: - Subviews

    private var statsHeader: some View {
        HStack(spacing: 12) {
            statChip(title: "Profiles", count: appState.profileStore.profiles.count, color: .blue)
            statChip(title: "Paired", count: pairedCount, color: .green)
            statChip(title: "Unpaired", count: appState.profileStore.profiles.count - pairedCount, color: .orange)
        }
    }

    private var pairedCount: Int {
        appState.profileStore.profiles.filter {
            !appState.profileStore.findPairedCertificates(for: $0, in: appState.certificateStore).isEmpty
        }.count
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
            Image(systemName: "doc.text.badge.plus")
                .font(.system(size: 54))
                .foregroundColor(.secondary)
            Text("No Provisioning Profiles")
                .font(.headline)
            Text("Import a .mobileprovision file to pair with your signing certificates.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button {
                isFileImporterPresented = true
            } label: {
                Label("Import .mobileprovision", systemImage: "plus.circle.fill")
                    .font(.headline)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 8)
            Spacer()
        }
    }

    private var profileList: some View {
        List {
            ForEach(appState.profileStore.profiles) { profile in
                let pairedCerts = appState.profileStore.findPairedCertificates(for: profile, in: appState.certificateStore)
                profileRow(profile, pairedWith: pairedCerts.first)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        inspectingProfile = profile
                    }
                    .swipeActions(edge: .leading) {
                        Button {
                            appState.selectedProfile = profile
                        } label: {
                            Label("Select", systemImage: "checkmark.circle")
                        }
                        .tint(.blue)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            appState.profileStore.delete(profile)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func profileRow(_ profile: ProfileItem, pairedWith cert: CertificateItem?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(profile.name)
                    .font(.body.bold())
                    .lineLimit(1)
                Spacer()
                Text(profile.profileType.rawValue)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(4)
            }

            Text(profile.bundleIdentifierPattern)
                .font(.caption.monospaced())
                .foregroundColor(.secondary)

            HStack {
                // Automatic Pairing Engine Badge
                if let pairedCert = cert {
                    Label("Paired: \(pairedCert.teamName)", systemImage: "link.circle.fill")
                        .font(.caption2.bold())
                        .foregroundColor(.green)
                } else {
                    Label("No Matching Certificate", systemImage: "link.circle")
                        .font(.caption2)
                        .foregroundColor(.orange)
                }

                Spacer()

                if profile.isExpired {
                    Text("Expired")
                        .font(.caption2.bold())
                        .foregroundColor(.red)
                } else {
                    Text("Expires in \(profile.daysUntilExpiration)d")
                        .font(.caption2)
                        .foregroundColor(profile.isExpiringSoon ? .orange : .secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - Profile Detail Sheet

    private func profileDetailSheet(_ profile: ProfileItem) -> some View {
        NavigationStack {
            List {
                Section("Profile Metadata") {
                    labeledRow(label: "Name", value: profile.name)
                    labeledRow(label: "UUID", value: profile.uuid)
                    labeledRow(label: "Team Name", value: profile.teamName)
                    labeledRow(label: "Team Identifier", value: profile.teamIdentifier)
                    labeledRow(label: "App ID Prefix", value: profile.appIdentifierPrefix)
                    labeledRow(label: "App ID Pattern", value: profile.bundleIdentifierPattern)
                    labeledRow(label: "Type", value: profile.profileType.rawValue)
                    labeledRow(label: "Distribution", value: profile.isEnterprise ? "Enterprise All Devices" : "\(profile.provisionedDevicesCount ?? 0) Devices")
                }

                Section("Validity") {
                    labeledRow(label: "Expiration Date", value: profile.expirationDate.formatted(date: .long, time: .shortened))
                    labeledRow(label: "Days Remaining", value: "\(profile.daysUntilExpiration) days")
                    labeledRow(label: "Status", value: profile.isExpired ? "Expired" : "Valid")
                }

                Section("Entitlements (\(profile.entitlements.count))") {
                    ForEach(profile.entitlements.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key)
                                .font(.caption.bold())
                                .foregroundColor(.primary)
                            Text(value)
                                .font(.caption.monospaced())
                                .foregroundColor(.secondary)
                        }
                    }
                }

                Section {
                    Button(role: .destructive) {
                        appState.profileStore.delete(profile)
                        inspectingProfile = nil
                    } label: {
                        Label("Delete Profile", systemImage: "trash")
                            .foregroundColor(.red)
                    }
                }
            }
            .navigationTitle("Profile Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        inspectingProfile = nil
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
