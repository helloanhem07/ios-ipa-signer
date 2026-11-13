//
//  ServerConnectionView.swift
//  iOSApp
//
//  Remote backend server connection configuration, live health test, and remote job dashboard.
//

import SwiftUI

public struct ServerConnectionView: View {
    @EnvironmentObject var appState: AppState

    @State private var serverURLInput = ""
    @State private var apiKeyInput = ""
    @State private var isTesting = false
    @State private var testResultText: String?
    @State private var testFailed = false

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                // Section 1: Server URL & Credentials
                Section("Backend Endpoint") {
                    TextField("Server Base URL", text: $serverURLInput)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .font(.system(.body, design: .monospaced))

                    SecureField("API Token (stored in Keychain)", text: $apiKeyInput)
                        .textFieldStyle(.plain)

                    Button {
                        testConnection()
                    } label: {
                        HStack {
                            if isTesting {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text("Test Server Connection")
                                .bold()
                        }
                    }
                    .disabled(isTesting || serverURLInput.isEmpty)
                }

                // Section 2: Live Connection Status Card
                Section("Connection Status") {
                    HStack {
                        Text("Status")
                        Spacer()
                        HStack(spacing: 6) {
                            Circle()
                                .fill(appState.serverConnected ? Color.green : Color.red)
                                .frame(width: 10, height: 10)
                            Text(appState.serverConnected ? "Online" : "Offline")
                                .font(.subheadline.bold())
                                .foregroundColor(appState.serverConnected ? .green : .red)
                        }
                    }

                    if appState.serverConnected {
                        HStack {
                            Text("Latency")
                            Spacer()
                            Text(String(format: "%.0f ms", appState.serverLatencyMs))
                                .font(.subheadline.monospaced())
                                .foregroundColor(.secondary)
                        }

                        if !appState.serverVersion.isEmpty {
                            HStack {
                                Text("Backend Version")
                                Spacer()
                                Text(appState.serverVersion)
                                    .font(.subheadline.monospaced())
                                    .foregroundColor(.secondary)
                            }
                        }

                        if !appState.serverEngines.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Supported Engines")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                HStack(spacing: 8) {
                                    ForEach(Array(appState.serverEngines.keys.sorted()), id: \.self) { engine in
                                        let active = appState.serverEngines[engine] ?? false
                                        Text("\(engine): \(active ? "✓" : "✗")")
                                            .font(.caption2.bold())
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(active ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
                                            .foregroundColor(active ? .green : .red)
                                            .cornerRadius(4)
                                    }
                                }
                            }
                        }
                    }

                    if let result = testResultText {
                        Text(result)
                            .font(.caption)
                            .foregroundColor(testFailed ? .red : .secondary)
                    }
                }

                // Section 3: Architecture Info
                Section("Remote Offload Architecture") {
                    Text("The remote backend service executes signing in isolated UUID scratchpads using native zsign or pure-Python fallback engines, generating dynamic manifest.plist and one-tap wireless installation.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Remote Server")
            .onAppear {
                serverURLInput = appState.serverBaseURL
                if let savedToken = KeychainManager.shared.getToken(forServerURL: appState.serverBaseURL) {
                    apiKeyInput = savedToken
                }
            }
        }
    }

    private func testConnection() {
        guard let url = URL(string: serverURLInput) else {
            testResultText = "Invalid URL format."
            testFailed = true
            return
        }

        isTesting = true
        testResultText = nil
        testFailed = false

        appState.serverBaseURL = serverURLInput
        appState.remoteSigningClient.serverBaseURL = serverURLInput

        if !apiKeyInput.isEmpty {
            KeychainManager.shared.saveToken(apiKeyInput, forServerURL: serverURLInput)
        }

        Task {
            do {
                let (health, latency) = try await appState.remoteSigningClient.checkHealth(baseURL: serverURLInput)
                appState.serverConnected = (health.status == "ok")
                appState.serverLatencyMs = latency * 1000.0
                appState.serverVersion = health.version
                appState.serverEngines = health.engines

                isTesting = false
                testResultText = "Connection successful (round-trip: \(String(format: "%.0f ms", appState.serverLatencyMs)))."
                testFailed = false
            } catch {
                appState.serverConnected = false
                isTesting = false
                testResultText = "Connection failed: \(error.localizedDescription)"
                testFailed = true
            }
        }
    }
}
