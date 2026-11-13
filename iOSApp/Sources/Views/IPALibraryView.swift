//
//  IPALibraryView.swift
//  iOSApp
//
//  IPA Library browser: metadata inspection, app icons, search/filter, and AirDrop ingestion.
//

import SwiftUI
import UniformTypeIdentifiers

public struct IPALibraryView: View {
    @EnvironmentObject var appState: AppState

    @State private var isFileImporterPresented = false
    @State private var searchText = ""
    @State private var selectedFilter: FilterOption = .all
    @State private var isGridView = false
    @State private var importErrorMessage: String?
    @State private var sharingURL: URL?

    enum FilterOption: String, CaseIterable {
        case all = "All"
        case unsigned = "Unsigned"
        case signed = "Signed"
    }

    public init() {}

    private var filteredItems: [IPAItem] {
        appState.ipaLibraryStore.items.filter { item in
            let matchesSearch = searchText.isEmpty ||
                item.bundleDisplayName.localizedCaseInsensitiveContains(searchText) ||
                item.bundleIdentifier.localizedCaseInsensitiveContains(searchText)

            let matchesFilter: Bool
            switch selectedFilter {
            case .all:
                matchesFilter = true
            case .unsigned:
                matchesFilter = !item.isSigned
            case .signed:
                matchesFilter = item.isSigned
            }

            return matchesSearch && matchesFilter
        }
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filter Picker
                Picker("Filter", selection: $selectedFilter) {
                    ForEach(FilterOption.allCases, id: \.self) { opt in
                        Text(opt.rawValue).tag(opt)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(UIColor.secondarySystemBackground))

                if appState.ipaLibraryStore.items.isEmpty {
                    emptyStateView
                } else if filteredItems.isEmpty {
                    noResultsView
                } else {
                    if isGridView {
                        gridView
                    } else {
                        listView
                    }
                }
            }
            .navigationTitle("IPA Library")
            .searchable(text: $searchText, prompt: "Search by name or bundle ID")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        isGridView.toggle()
                    } label: {
                        Image(systemName: isGridView ? "list.bullet" : "square.grid.2x2")
                    }
                }
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
                allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data, .archive],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first {
                        Task {
                            do {
                                let imported = try await appState.ipaLibraryStore.importIPA(from: url)
                                appState.selectedSigningIPA = imported
                            } catch {
                                self.importErrorMessage = error.localizedDescription
                            }
                        }
                    }
                case .failure(let error):
                    self.importErrorMessage = error.localizedDescription
                }
            }
            .sheet(item: $sharingURL) { url in
                ActivityView(activityItems: [url])
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

    // MARK: - Views

    private var emptyStateView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "square.stack.3d.up.fill")
                .font(.system(size: 54))
                .foregroundColor(.secondary)
            Text("No IPAs in Library")
                .font(.headline)
            Text("Import an iOS application package (.ipa) via Document Picker or AirDrop.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button {
                isFileImporterPresented = true
            } label: {
                Label("Import .ipa Package", systemImage: "plus.circle.fill")
                    .font(.headline)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 8)
            Spacer()
        }
    }

    private var noResultsView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "magnifyingglass")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text("No Matching Packages")
                .font(.headline)
            Spacer()
        }
    }

    private var listView: some View {
        List {
            ForEach(filteredItems) { item in
                ipaListRow(item)
                    .swipeActions(edge: .leading) {
                        Button {
                            appState.selectedSigningIPA = item
                            appState.selectedTab = 3 // Switch to Sign tab
                        } label: {
                            Label("Sign", systemImage: "signature")
                        }
                        .tint(.blue)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            appState.ipaLibraryStore.delete(item)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }

                        Button {
                            sharingURL = appState.ipaLibraryStore.getIPAFileURL(for: item)
                        } label: {
                            Label("Share", systemImage: "square.and.arrow.up")
                        }
                        .tint(.gray)
                    }
            }
        }
        .listStyle(.plain)
    }

    private func ipaListRow(_ item: IPAItem) -> some View {
        HStack(spacing: 12) {
            iconThumbnail(for: item, size: 52)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(item.bundleDisplayName)
                        .font(.body.bold())
                        .lineLimit(1)
                    Spacer()
                    signingStatusBadge(item.signingStatus)
                }

                Text(item.bundleIdentifier)
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text("v\(item.bundleShortVersion) (\(item.bundleVersion))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text("•")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(item.formattedFileSize)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text("•")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text("iOS \(item.minimumOSVersion)+")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            // Quick Action Button
            if item.isSigned {
                Button {
                    triggerOTAInstall(for: item)
                } label: {
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.title2)
                        .foregroundColor(.green)
                }
                .buttonStyle(.borderless)
            } else {
                Button {
                    appState.selectedSigningIPA = item
                    appState.selectedTab = 3
                } label: {
                    Image(systemName: "signature")
                        .font(.title3)
                        .foregroundColor(.blue)
                }
                .buttonStyle(.borderless)
            }
        }
        .padding(.vertical, 4)
    }

    private var gridView: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 16)], spacing: 16) {
                ForEach(filteredItems) { item in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            iconThumbnail(for: item, size: 60)
                            Spacer()
                            signingStatusBadge(item.signingStatus)
                        }

                        Text(item.bundleDisplayName)
                            .font(.subheadline.bold())
                            .lineLimit(1)

                        Text(item.bundleIdentifier)
                            .font(.caption2.monospaced())
                            .foregroundColor(.secondary)
                            .lineLimit(1)

                        HStack {
                            Text("v\(item.bundleShortVersion)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(item.formattedFileSize)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }

                        Button {
                            appState.selectedSigningIPA = item
                            appState.selectedTab = 3
                        } label: {
                            Text(item.isSigned ? "Re-Sign" : "Sign Package")
                                .font(.caption.bold())
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                    .padding(12)
                    .background(Color(UIColor.secondarySystemGroupedBackground))
                    .cornerRadius(12)
                }
            }
            .padding()
        }
    }

    private func iconThumbnail(for item: IPAItem, size: CGFloat) -> some View {
        Group {
            if let iconURL = appState.ipaLibraryStore.getIconURL(for: item),
               let uiImage = UIImage(contentsOfFile: iconURL.path) {
                Image(uiImage: uiImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            } else {
                ZStack {
                    RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                        .fill(LinearGradient(colors: [.blue, .indigo], startPoint: .topLeading, endPoint: .bottomTrailing))
                    Image(systemName: "app.fill")
                        .foregroundColor(.white)
                        .font(.system(size: size * 0.45))
                }
            }
        }
        .frame(width: size, height: size)
        .cornerRadius(size * 0.22)
    }

    private func signingStatusBadge(_ status: IPASigningStatus) -> some View {
        Text(status.rawValue)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(status == .unsigned ? Color.secondary.opacity(0.1) : Color.green.opacity(0.15))
            .foregroundColor(status == .unsigned ? .secondary : .green)
            .cornerRadius(4)
    }

    private func triggerOTAInstall(for item: IPAItem) {
        let fileURL = appState.ipaLibraryStore.getIPAFileURL(for: item)
        appState.localOTAServer.setServeContext(
            ipaURL: fileURL,
            bundleId: item.bundleIdentifier,
            version: item.bundleShortVersion,
            appName: item.bundleDisplayName
        )
        if !appState.localOTAServer.isRunning {
            try? appState.localOTAServer.start()
        }
        if let itmsURL = appState.localOTAServer.itmsInstallURL {
            UIApplication.shared.open(itmsURL)
        }
    }
}

// Activity View wrapper for UIActivityViewController
struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]
    let applicationActivities: [UIActivity]? = nil

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: applicationActivities)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}
