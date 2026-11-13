//
//  LocalOTAServer.swift
//  iOSApp
//
//  Embedded in-process HTTP/TLS server serving signed IPAs and manifest.plist using Network.framework.
//

import Foundation
import Network
import UIKit

/// Error domain for Local OTA Server operations
public enum OTAServerError: LocalizedError {
    case alreadyRunning
    case failedToBindPort(Int)
    case tlsIdentityCreationFailed
    case missingIPAPath
    case fileNotFound(String)

    public var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            return "Local OTA Server is already running."
        case .failedToBindPort(let port):
            return "Failed to bind to local port \(port)."
        case .tlsIdentityCreationFailed:
            return "Failed to create TLS identity for secure local server."
        case .missingIPAPath:
            return "No IPA package is configured to serve."
        case .fileNotFound(let path):
            return "File not found at path: \(path)"
        }
    }
}

/// In-process HTTP/TLS server serving OTA installation packages using Network.framework
public final class LocalOTAServer: ObservableObject {
    public static let shared = LocalOTAServer()

    @Published public private(set) var isRunning: Bool = false
    @Published public private(set) var boundPort: UInt16 = 8443
    @Published public private(set) var activeConnectionCount: Int = 0
    @Published public private(set) var serverError: String?

    private var listener: NWListener?
    private let serverQueue = DispatchQueue(label: "com.signingapp.otaserver", qos: .userInitiated)
    private var activeConnections: [NWConnection] = []
    private var backgroundTaskId: UIBackgroundTaskIdentifier = .invalid

    // Serving context
    private var currentIPAURL: URL?
    private var currentBundleId: String = "com.example.app"
    private var currentVersion: String = "1.0.0"
    private var currentAppName: String = "App"
    private var currentIconData: Data?

    private init() {}

    /// Configures the current application assets to serve
    public func setServeContext(ipaURL: URL, bundleId: String, version: String, appName: String, iconData: Data? = nil) {
        self.currentIPAURL = ipaURL
        self.currentBundleId = bundleId
        self.currentVersion = version
        self.currentAppName = appName
        self.currentIconData = iconData
    }

    /// Starts the server on the specified port (default: 8443)
    public func start(port: UInt16 = 8443, identity: SecIdentity? = nil) throws {
        guard !isRunning else { throw OTAServerError.alreadyRunning }

        let parameters: NWParameters
        if let identity = identity {
            parameters = try createTLSParameters(identity: identity)
        } else {
            // TCP mode with local reuse
            parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = true
        }

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw OTAServerError.failedToBindPort(Int(port))
        }

        let nwListener = try NWListener(using: parameters, on: nwPort)
        self.listener = nwListener

        nwListener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    self.isRunning = true
                    if let p = nwListener.port?.rawValue {
                        self.boundPort = p
                    }
                    self.serverError = nil
                case .failed(let error):
                    self.isRunning = false
                    self.serverError = error.localizedDescription
                case .cancelled:
                    self.isRunning = false
                default:
                    break
                }
            }
        }

        nwListener.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }

        nwListener.start(queue: serverQueue)
    }

    /// Stops the server and closes all active sockets
    public func stop() {
        serverQueue.async { [weak self] in
            guard let self = self else { return }
            for connection in self.activeConnections {
                connection.cancel()
            }
            self.activeConnections.removeAll()
            self.listener?.cancel()
            self.listener = nil
            self.endBackgroundTask()

            DispatchQueue.main.async {
                self.isRunning = false
                self.activeConnectionCount = 0
            }
        }
    }

    /// Generates the full `itms-services://` URL for wireless installation
    public var itmsInstallURL: URL? {
        let manifestURLString = "https://127.0.0.1:\(boundPort)/manifest.plist"
        guard let encodedManifest = manifestURLString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
            return nil
        }
        return URL(string: "itms-services://?action=download-manifest&url=\(encodedManifest)")
    }

    // MARK: - Internal Connection Handling

    private func handleNewConnection(_ connection: NWConnection) {
        serverQueue.async {
            self.activeConnections.append(connection)
            DispatchQueue.main.async {
                self.activeConnectionCount = self.activeConnections.count
            }

            self.beginBackgroundTask()

            let otaConn = OTAHTTPConnection(connection: connection, serverQueue: self.serverQueue) { [weak self] in
                self?.removeConnection(connection)
            }
            otaConn.onRequestReceived = { [weak self] request in
                self?.routeRequest(request, connection: otaConn)
            }
            otaConn.start()
        }
    }

    private func removeConnection(_ connection: NWConnection) {
        serverQueue.async {
            if let index = self.activeConnections.firstIndex(where: { $0 === connection }) {
                self.activeConnections.remove(at: index)
            }
            DispatchQueue.main.async {
                self.activeConnectionCount = self.activeConnections.count
            }
            if self.activeConnections.isEmpty {
                self.endBackgroundTask()
            }
        }
    }

    private func routeRequest(_ request: HTTPRequest, connection: OTAHTTPConnection) {
        switch (request.method.uppercased(), request.path) {
        case ("GET", "/manifest.plist"):
            let manifest = ManifestBuilder.build(bundleId: currentBundleId,
                                                bundleVersion: currentVersion,
                                                title: currentAppName,
                                                serverPort: boundPort)
            connection.sendResponse(status: 200, contentType: "text/xml; charset=utf-8", body: manifest.data(using: .utf8) ?? Data())

        case ("GET", "/download/signed.ipa"), ("HEAD", "/download/signed.ipa"):
            guard let ipaURL = currentIPAURL, FileManager.default.fileExists(atPath: ipaURL.path) else {
                connection.sendResponse(status: 404, contentType: "text/plain", body: "IPA not found".data(using: .utf8)!)
                return
            }
            connection.streamFile(url: ipaURL, rangeHeader: request.rangeHeader, isHeadOnly: request.method == "HEAD")

        case ("GET", "/download/icon.png"):
            if let iconData = currentIconData {
                connection.sendResponse(status: 200, contentType: "image/png", body: iconData)
            } else {
                connection.sendResponse(status: 404, contentType: "text/plain", body: "Icon not found".data(using: .utf8)!)
            }

        case ("GET", "/ca.mobileconfig"):
            if let profileData = CertificateAuthorityManager.shared.generateRootCAProfileData() {
                connection.sendResponse(status: 200, contentType: "application/x-apple-aspen-config", body: profileData)
            } else {
                connection.sendResponse(status: 404, contentType: "text/plain", body: "CA Profile unavailable".data(using: .utf8)!)
            }

        case ("GET", "/install"):
            let html = """
            <!DOCTYPE html>
            <html>
            <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Install \(currentAppName)</title></head>
            <body style="font-family: -apple-system; text-align: center; padding-top: 50px;">
                <h2>Install \(currentAppName)</h2>
                <p>Version \(currentVersion)</p>
                <p><a href="\(itmsInstallURL?.absoluteString ?? "#")" style="background: #007AFF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold;">Install Now</a></p>
            </body>
            </html>
            """
            connection.sendResponse(status: 200, contentType: "text/html; charset=utf-8", body: html.data(using: .utf8)!)

        default:
            connection.sendResponse(status: 404, contentType: "text/plain", body: "404 Not Found".data(using: .utf8)!)
        }
    }

    // MARK: - TLS Setup

    private func createTLSParameters(identity: SecIdentity) throws -> NWParameters {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 2

        let tlsOptions = NWProtocolTLS.Options()
        guard let secIdentity = sec_identity_create(identity) else {
            throw OTAServerError.tlsIdentityCreationFailed
        }

        let securityOptions = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_local_identity(securityOptions, secIdentity)
        sec_protocol_options_set_min_tls_protocol_version(securityOptions, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(securityOptions, .TLSv13)
        sec_protocol_options_append_tls_ciphersuite_group(securityOptions, .default)

        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        parameters.allowLocalEndpointReuse = true
        return parameters
    }

    // MARK: - Background Task Retention

    private func beginBackgroundTask() {
        guard backgroundTaskId == .invalid else { return }
        backgroundTaskId = UIApplication.shared.beginBackgroundTask(withName: "LocalOTAServerStream") { [weak self] in
            self?.endBackgroundTask()
        }
    }

    private func endBackgroundTask() {
        guard backgroundTaskId != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTaskId)
        backgroundTaskId = .invalid
    }
}
