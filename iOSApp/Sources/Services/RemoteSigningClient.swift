//
//  RemoteSigningClient.swift
//  iOSApp
//
//  Asynchronous REST client communicating with Milestone 1 Backend signing service.
//

import Foundation

// MARK: - API Response Models

public struct HealthResponse: Codable {
    public let status: String
    public let version: String
    public let engines: [String: Bool]
}

public struct JobSubmissionResponse: Codable {
    public let job_id: String
    public let status: String
    public let created_at: String
    public let poll_url: String?
}

public struct JobStatusResponse: Codable {
    public let job_id: String
    public let status: String
    public let download_url: String?
    public let manifest_url: String?
    public let install_url: String?
    public let itms_url: String?
    public let error: String?
    public let bundle_id: String?
    public let bundle_version: String?
    public let app_name: String?
}

public enum RemoteSigningError: LocalizedError {
    case invalidServerURL
    case invalidResponse
    case httpError(statusCode: Int, message: String)
    case serverError(String)
    case jobFailed(String)
    case timeout
    case fileError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidServerURL:
            return "Invalid remote signing server URL."
        case .invalidResponse:
            return "Unexpected response received from server."
        case .httpError(let code, let msg):
            return "HTTP Error \(code): \(msg)"
        case .serverError(let msg):
            return "Remote Server Error: \(msg)"
        case .jobFailed(let msg):
            return "Remote Signing Failed: \(msg)"
        case .timeout:
            return "Remote operation timed out."
        case .fileError(let msg):
            return "File processing error: \(msg)"
        }
    }
}

// MARK: - Remote Signing REST Client

public final class RemoteSigningClient: NSObject, ObservableObject {
    public static let shared = RemoteSigningClient()

    @Published public var serverBaseURL: String = "http://127.0.0.1:8000"
    @Published public var isUploading: Bool = false
    @Published public var uploadProgress: Double = 0.0
    @Published public var currentStatusMessage: String = "Idle"

    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
        super.init()
    }

    // MARK: - Health Check

    public func checkHealth(baseURL: String? = nil) async throws -> (HealthResponse, TimeInterval) {
        let base = baseURL ?? serverBaseURL
        guard let url = URL(string: "\(base)/api/v1/health") else {
            throw RemoteSigningError.invalidServerURL
        }

        let start = CFAbsoluteTimeGetCurrent()
        let (data, response) = try await session.data(from: url)
        let latency = CFAbsoluteTimeGetCurrent() - start

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw RemoteSigningError.httpError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? 500, message: "Health check failed")
        }

        let health = try JSONDecoder().decode(HealthResponse.self, from: data)
        return (health, latency)
    }

    // MARK: - Submit Signing Job (Disk-Backed Multipart Streaming)

    public func submitJob(ipaURL: URL,
                          p12URL: URL,
                          password: String,
                          profileURL: URL,
                          bundleId: String? = nil,
                          displayName: String? = nil,
                          compressionLevel: Int = 1,
                          progressHandler: @escaping (Double) -> Void) async throws -> JobSubmissionResponse {

        guard let url = URL(string: "\(serverBaseURL)/api/v1/jobs") else {
            throw RemoteSigningError.invalidServerURL
        }

        let boundary = "Boundary-\(UUID().uuidString)"
        let tempSpoolURL = FileManager.default.temporaryDirectory.appendingPathComponent("upload_\(UUID().uuidString).tmp")

        defer {
            try? FileManager.default.removeItem(at: tempSpoolURL)
        }

        // Build multipart file on disk to prevent RAM exhaustion
        try createMultipartSpoolFile(at: tempSpoolURL,
                                    boundary: boundary,
                                    ipaURL: ipaURL,
                                    p12URL: p12URL,
                                    password: password,
                                    profileURL: profileURL,
                                    bundleId: bundleId,
                                    displayName: displayName,
                                    compressionLevel: compressionLevel)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 300

        let progressDelegate = UploadProgressDelegate { progress, _, _ in
            DispatchQueue.main.async {
                self.uploadProgress = progress
                self.currentStatusMessage = String(format: "Uploading: %.1f%%", progress * 100)
                progressHandler(progress)
            }
        }

        DispatchQueue.main.async {
            self.isUploading = true
            self.uploadProgress = 0.0
            self.currentStatusMessage = "Starting upload..."
        }

        let (data, response) = try await session.upload(for: request, fromFile: tempSpoolURL, delegate: progressDelegate)

        DispatchQueue.main.async {
            self.isUploading = false
            self.currentStatusMessage = "Upload complete. Server processing..."
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw RemoteSigningError.invalidResponse
        }

        guard httpResponse.statusCode == 202 || httpResponse.statusCode == 200 else {
            let errorText = String(data: data, encoding: .utf8) ?? "Unknown server rejection"
            throw RemoteSigningError.httpError(statusCode: httpResponse.statusCode, message: errorText)
        }

        return try JSONDecoder().decode(JobSubmissionResponse.self, from: data)
    }

    // MARK: - Poll Job Status

    public func pollJobStatus(jobId: String,
                              pollInterval: TimeInterval = 1.5,
                              maxTimeout: TimeInterval = 300,
                              onUpdate: ((JobStatusResponse) -> Void)? = nil) async throws -> JobStatusResponse {

        guard let url = URL(string: "\(serverBaseURL)/api/v1/jobs/\(jobId)") else {
            throw RemoteSigningError.invalidServerURL
        }

        let deadline = Date().addingTimeInterval(maxTimeout)
        var currentInterval = pollInterval
        var failureCount = 0

        while Date() < deadline {
            do {
                let (data, response) = try await session.data(from: url)
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    throw RemoteSigningError.httpError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? 500, message: "Polling failed")
                }

                let jobStatus = try JSONDecoder().decode(JobStatusResponse.self, from: data)
                failureCount = 0

                DispatchQueue.main.async {
                    self.currentStatusMessage = "Status: \(jobStatus.status.capitalized)"
                    onUpdate?(jobStatus)
                }

                switch jobStatus.status.lowercased() {
                case "completed":
                    return jobStatus
                case "failed":
                    throw RemoteSigningError.jobFailed(jobStatus.error ?? "Remote signing failed.")
                case "queued", "processing":
                    try await Task.sleep(nanoseconds: UInt64(currentInterval * 1_000_000_000))
                    currentInterval = min(currentInterval * 1.2, 3.0)
                default:
                    try await Task.sleep(nanoseconds: UInt64(currentInterval * 1_000_000_000))
                }
            } catch let error as RemoteSigningError {
                throw error
            } catch {
                failureCount += 1
                if failureCount > 3 {
                    throw RemoteSigningError.serverError("Network lost while polling remote job.")
                }
                try await Task.sleep(nanoseconds: UInt64(2.0 * 1_000_000_000))
            }
        }

        throw RemoteSigningError.timeout
    }

    // MARK: - Download Signed IPA

    public func downloadSignedIPA(from downloadPath: String, destinationURL: URL) async throws {
        let fullURLString = downloadPath.hasPrefix("http") ? downloadPath : "\(serverBaseURL)\(downloadPath)"
        guard let url = URL(string: fullURLString) else {
            throw RemoteSigningError.invalidServerURL
        }

        DispatchQueue.main.async {
            self.currentStatusMessage = "Downloading signed IPA..."
        }

        let (tempDownloadedURL, response) = try await session.download(from: url)

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw RemoteSigningError.httpError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? 500, message: "Download failed")
        }

        if FileManager.default.fileExists(atPath: destinationURL.path) {
            try FileManager.default.removeItem(at: destinationURL)
        }

        try FileManager.default.moveItem(at: tempDownloadedURL, to: destinationURL)

        DispatchQueue.main.async {
            self.currentStatusMessage = "Download completed."
        }
    }

    // MARK: - Private Disk Multipart Assembler

    private func createMultipartSpoolFile(at destination: URL,
                                          boundary: String,
                                          ipaURL: URL,
                                          p12URL: URL,
                                          password: String,
                                          profileURL: URL,
                                          bundleId: String?,
                                          displayName: String?,
                                          compressionLevel: Int) throws {

        FileManager.default.createFile(atPath: destination.path, contents: nil)
        guard let fileHandle = try? FileHandle(forWritingTo: destination) else {
            throw RemoteSigningError.fileError("Cannot open spool file for writing.")
        }
        defer { try? fileHandle.close() }

        func appendString(_ str: String) {
            if let data = str.data(using: .utf8) {
                fileHandle.write(data)
            }
        }

        func appendFile(name: String, filename: String, fileURL: URL, mimeType: String) throws {
            appendString("--\(boundary)\r\n")
            appendString("Content-Disposition: form-data; name=\"\(name)\"; filename=\"\(filename)\"\r\n")
            appendString("Content-Type: \(mimeType)\r\n\r\n")

            guard let readHandle = try? FileHandle(forReadingFrom: fileURL) else {
                throw RemoteSigningError.fileError("Cannot read file: \(fileURL.lastPathComponent)")
            }
            defer { try? readHandle.close() }

            while true {
                let chunk = readHandle.readData(ofLength: 65536)
                if chunk.isEmpty { break }
                fileHandle.write(chunk)
            }
            appendString("\r\n")
        }

        func appendField(name: String, value: String) {
            appendString("--\(boundary)\r\n")
            appendString("Content-Disposition: form-data; name=\"\(name)\"\r\n\r\n")
            appendString("\(value)\r\n")
        }

        // Append text parameters
        appendField(name: "password", value: password)
        if let bundleId = bundleId, !bundleId.isEmpty {
            appendField(name: "bundle_id", value: bundleId)
        }
        if let displayName = displayName, !displayName.isEmpty {
            appendField(name: "bundle_name", value: displayName)
        }
        appendField(name: "compression_level", value: "\(compressionLevel)")

        // Append binary files
        try appendFile(name: "ipa", filename: ipaURL.lastPathComponent, fileURL: ipaURL, mimeType: "application/octet-stream")
        try appendFile(name: "p12", filename: p12URL.lastPathComponent, fileURL: p12URL, mimeType: "application/x-pkcs12")
        try appendFile(name: "mobileprovision", filename: profileURL.lastPathComponent, fileURL: profileURL, mimeType: "application/octet-stream")

        // Closing boundary
        appendString("--\(boundary)--\r\n")
    }
}

// MARK: - Upload Progress Delegate

final class UploadProgressDelegate: NSObject, URLSessionTaskDelegate {
    private let onProgress: (Double, Int64, Int64) -> Void

    init(onProgress: @escaping (Double, Int64, Int64) -> Void) {
        self.onProgress = onProgress
    }

    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    didSendBodyData bytesSent: Int64,
                    totalBytesSent: Int64,
                    totalBytesExpectedToSend: Int64) {
        let fraction = totalBytesExpectedToSend > 0
            ? Double(totalBytesSent) / Double(totalBytesExpectedToSend)
            : 0.0
        onProgress(fraction, totalBytesSent, totalBytesExpectedToSend)
    }
}
