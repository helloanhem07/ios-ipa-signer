//
//  MainTabView.swift
//  iOSApp
//
//  5-Tab root navigation interface with SF Symbols and dynamic badges.
//

import SwiftUI

public struct MainTabView: View {
    @EnvironmentObject var appState: AppState

    public init() {}

    public var body: some View {
        TabView(selection: $appState.selectedTab) {
            CertificatesView()
                .tabItem {
                    Label("Certificates", systemImage: "rosette")
                }
                .tag(0)
                .badge(appState.certificateStore.expiredCount > 0 ? "!" : nil)

            ProfilesView()
                .tabItem {
                    Label("Profiles", systemImage: "doc.text.badge.plus")
                }
                .tag(1)

            IPALibraryView()
                .tabItem {
                    Label("IPA Library", systemImage: "square.stack.3d.up.fill")
                }
                .tag(2)
                .badge(appState.ipaLibraryStore.items.count > 0 ? "\(appState.ipaLibraryStore.items.count)" : nil)

            SigningSettingsView()
                .tabItem {
                    Label("Sign", systemImage: "signature")
                }
                .tag(3)

            ServerConnectionView()
                .tabItem {
                    Label("Server", systemImage: "network")
                }
                .tag(4)
                .badge(appState.serverConnected ? nil : "offline")
        }
    }
}
