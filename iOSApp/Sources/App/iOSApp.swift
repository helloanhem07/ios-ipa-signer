//
//  iOSApp.swift
//  iOSApp
//
//  SwiftUI @main application entry point with shared AppState.
//

import SwiftUI

@main
struct iOSApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            MainTabView()
                .environmentObject(appState)
                .onOpenURL { url in
                    appState.handleIncomingURL(url)
                }
        }
    }
}
