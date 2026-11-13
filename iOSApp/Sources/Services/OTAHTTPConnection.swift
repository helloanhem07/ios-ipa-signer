//
//  OTAHTTPConnection.swift
//  iOSApp
//
//  Single client HTTP connection handler supporting HTTP 206 Partial Content Range streaming.
//

import Foundation
import Network

/// Represents a parsed HTTP/1.1 Request
public struct HTTPRequest {
    public let method: String
    public let path: String
    public let queryParams: [String: String]
    public let headers: [String: String]
    public let httpVersion: String

    public var rangeHeader: (start: UInt64, end: UInt64?)? {
        guard let rangeStr = headers["range"] ?? headers["Range"],
              rangeStr.hasPrefix("bytes=") else { return nil }
        let spec = String(rangeStr.dropFirst(6))
        let parts = spec.split(separator: "-", omittingEmptySubsequences: false)
        guard let start = UInt64(parts[0]) else { return nil }
        let end = parts.count > 1 && !parts[1].isEmpty ? UInt64(parts[1]) : nil
        return (start, end)
    }
}

/// Manages a single client socket connection over Network.framework NWConnection
public final class OTAHTTPConnection {
    private let connection: NWConnection
    private let serverQueue: DispatchQueue
    private let onClose: () -> Void
    private var buffer = Data()

    public var onRequestReceived: ((HTTPRequest) -> Void)?

    public init(connection: NWConnection, serverQueue: DispatchQueue, onClose: @escaping () -> Void) {
        self.connection = connection
        self.serverQueue = serverQueue
        self.onClose = onClose
    }

    public func start() {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                self?.onClose()
            default:
                break
            }
        }
        connection.start(queue: serverQueue)
        readNext()
    }

    private func readNext() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }
            if let data = content, !data.isEmpty {
                self.buffer.append(data)
                if let request = self.parseHTTPBuffer() {
                    self.onRequestReceived?(request)
                    return
                }
            }
            if isComplete || error != nil {
                self.connection.cancel()
                self.onClose()
            } else {
                self.readNext()
            }
        }
    }

    private func parseHTTPBuffer() -> HTTPRequest? {
        guard let headerEndRange = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let headerData = buffer.subdata(in: 0..<headerEndRange.lowerBound)
        guard let headerString = String(data: headerData, encoding: .utf8) else { return nil }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let tokens = requestLine.split(separator: " ")
        guard tokens.count >= 3 else { return nil }

        let method = String(tokens[0])
        let fullPath = String(tokens[1])
        let httpVersion = String(tokens[2])

        let pathParts = fullPath.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: true)
        let path = String(pathParts[0])
        var queryParams: [String: String] = [:]
        if pathParts.count > 1 {
            let pairs = pathParts[1].split(separator: "&")
            for pair in pairs {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 {
                    queryParams[String(kv[0])] = String(kv[1])
                }
            }
        }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            let headerParts = line.split(separator: ":", maxSplits: 1)
            if headerParts.count == 2 {
                let key = headerParts[0].trimmingCharacters(in: .whitespaces).lowercased()
                let value = headerParts[1].trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
        }

        return HTTPRequest(method: method, path: path, queryParams: queryParams, headers: headers, httpVersion: httpVersion)
    }

    public func sendResponse(status: Int, contentType: String, body: Data) {
        let statusText = status == 200 ? "OK" : (status == 404 ? "Not Found" : "Internal Server Error")
        let header = "HTTP/1.1 \(status) \(statusText)\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var responseData = header.data(using: .utf8) ?? Data()
        responseData.append(body)

        connection.send(content: responseData, completion: .contentProcessed { [weak self] _ in
            self?.connection.cancel()
            self?.onClose()
        })
    }

    public func streamFile(url: URL, rangeHeader: (start: UInt64, end: UInt64?)?, isHeadOnly: Bool) {
        guard let fileAttributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let fileSize = fileAttributes[.size] as? UInt64 else {
            sendResponse(status: 404, contentType: "text/plain", body: "File unreadable".data(using: .utf8)!)
            return
        }

        guard let fileHandle = try? FileHandle(forReadingFrom: url) else {
            sendResponse(status: 500, contentType: "text/plain", body: "Could not open file".data(using: .utf8)!)
            return
        }

        let start: UInt64
        let end: UInt64
        let isRange: Bool

        if let range = rangeHeader {
            start = range.start
            end = min(range.end ?? (fileSize - 1), fileSize - 1)
            isRange = true
        } else {
            start = 0
            end = fileSize - 1
            isRange = false
        }

        let contentLength = end >= start ? (end - start + 1) : 0
        let status = isRange ? 206 : 200
        let statusMsg = isRange ? "Partial Content" : "OK"

        var headers = "HTTP/1.1 \(status) \(statusMsg)\r\n"
        headers += "Content-Type: application/octet-stream\r\n"
        headers += "Content-Length: \(contentLength)\r\n"
        headers += "Accept-Ranges: bytes\r\n"
        if isRange {
            headers += "Content-Range: bytes \(start)-\(end)/\(fileSize)\r\n"
        }
        headers += "Connection: keep-alive\r\n\r\n"

        let headerData = headers.data(using: .utf8) ?? Data()

        connection.send(content: headerData, isComplete: false, completion: .contentProcessed { [weak self] error in
            guard let self = self, error == nil else {
                try? fileHandle.close()
                self?.onClose()
                return
            }
            if isHeadOnly {
                try? fileHandle.close()
                self.connection.cancel()
                self.onClose()
                return
            }
            self.streamFileChunks(fileHandle: fileHandle, currentOffset: start, endOffset: end)
        })
    }

    private func streamFileChunks(fileHandle: FileHandle, currentOffset: UInt64, endOffset: UInt64, chunkSize: Int = 65536) {
        guard currentOffset <= endOffset else {
            try? fileHandle.close()
            return
        }

        let bytesToRead = min(UInt64(chunkSize), endOffset - currentOffset + 1)
        fileHandle.seek(toFileOffset: currentOffset)
        let chunk = fileHandle.readData(ofLength: Int(bytesToRead))

        guard !chunk.isEmpty else {
            try? fileHandle.close()
            return
        }

        let nextOffset = currentOffset + UInt64(chunk.count)
        let isLast = nextOffset > endOffset

        connection.send(content: chunk, isComplete: false, completion: .contentProcessed { [weak self] error in
            guard let self = self, error == nil else {
                try? fileHandle.close()
                self?.onClose()
                return
            }
            if !isLast {
                self.streamFileChunks(fileHandle: fileHandle, currentOffset: nextOffset, endOffset: endOffset, chunkSize: chunkSize)
            } else {
                try? fileHandle.close()
            }
        })
    }
}
