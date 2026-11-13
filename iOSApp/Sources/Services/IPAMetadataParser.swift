//
//  IPAMetadataParser.swift
//  iOSApp
//
//  Extracts bundle metadata, Info.plist entries, and app icons from iOS Application Packages (.ipa).
//

import Foundation
import UIKit
import zlib

public struct ExtractedIPAMetadata {
    public let displayName: String
    public let bundleIdentifier: String
    public let shortVersion: String
    public let version: String
    public let minimumOSVersion: String
    public let iconData: Data?
    public let architectures: [String]
}

public final class IPAMetadataParser {
    public static func extract(from ipaURL: URL) throws -> ExtractedIPAMetadata {
        let baseName = ipaURL.deletingPathExtension().lastPathComponent
        
        // Scan the IPA zip package for Info.plist bytes
        var plistData: Data? = nil
        var iconData: Data? = nil
        
        if let fileData = try? Data(contentsOf: ipaURL, options: .mappedIfSafe) {
            // Find Info.plist inside the zip stream
            // In a ZIP, local file header starts with PK\x03\x04
            // We search for "Info.plist" entry
            if let plistRange = findZipEntry(named: "Info.plist", in: fileData) {
                plistData = plistRange
            }
            
            // Search for icon PNG
            if let iconRange = findZipEntry(named: "AppIcon60x60@2x.png", in: fileData) ??
                               findZipEntry(named: "AppIcon76x76@2x~ipad.png", in: fileData) ??
                               findZipEntry(named: "AppIcon.png", in: fileData) {
                iconData = iconRange
            }
        }

        var bundleId = "com.example.\(baseName.lowercased())"
        var displayName = baseName
        var shortVersion = "1.0.0"
        var version = "1"
        var minOS = "16.0"

        if let data = plistData,
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty {
                bundleId = id
            }
            if let name = plist["CFBundleDisplayName"] as? String, !name.isEmpty {
                displayName = name
            } else if let name = plist["CFBundleName"] as? String, !name.isEmpty {
                displayName = name
            }
            if let v = plist["CFBundleShortVersionString"] as? String, !v.isEmpty {
                shortVersion = v
            }
            if let b = plist["CFBundleVersion"] as? String, !b.isEmpty {
                version = b
            }
            if let os = plist["MinimumOSVersion"] as? String, !os.isEmpty {
                minOS = os
            }
        }

        return ExtractedIPAMetadata(
            displayName: displayName,
            bundleIdentifier: bundleId,
            shortVersion: shortVersion,
            version: version,
            minimumOSVersion: minOS,
            iconData: iconData,
            architectures: ["arm64"]
        )
    }

    /// Helper to locate uncompressed or deflate-stored zip entry data in raw zip bytes
    private static func findZipEntry(named targetName: String, in zipData: Data) -> Data? {
        guard let nameData = targetName.data(using: .utf8) else { return nil }
        
        var searchIndex = 0
        while searchIndex < zipData.count - 30 {
            // Look for Local File Header Signature: 0x04034b50 (PK\x03\x04)
            guard let headerRange = zipData.range(of: Data([0x50, 0x4b, 0x03, 0x04]), in: searchIndex..<zipData.count) else {
                break
            }
            
            let headerOffset = headerRange.lowerBound
            if headerOffset + 30 > zipData.count { break }
            
            let compressionMethod = UInt16(zipData[headerOffset + 8]) | (UInt16(zipData[headerOffset + 9]) << 8)
            let compressedSize = UInt32(zipData[headerOffset + 18]) |
                                 (UInt32(zipData[headerOffset + 19]) << 8) |
                                 (UInt32(zipData[headerOffset + 20]) << 16) |
                                 (UInt32(zipData[headerOffset + 21]) << 24)
            let uncompressedSize = UInt32(zipData[headerOffset + 22]) |
                                   (UInt32(zipData[headerOffset + 23]) << 8) |
                                   (UInt32(zipData[headerOffset + 24]) << 16) |
                                   (UInt32(zipData[headerOffset + 25]) << 24)
            let fileNameLength = Int(UInt16(zipData[headerOffset + 26]) | (UInt16(zipData[headerOffset + 27]) << 8))
            let extraFieldLength = Int(UInt16(zipData[headerOffset + 28]) | (UInt16(zipData[headerOffset + 29]) << 8))
            
            let fileDataStart = headerOffset + 30 + fileNameLength + extraFieldLength
            let nameStart = headerOffset + 30
            
            if nameStart + fileNameLength <= zipData.count {
                let fileNameData = zipData.subdata(in: nameStart..<(nameStart + fileNameLength))
                if let fileName = String(data: fileNameData, encoding: .utf8),
                   fileName.hasSuffix(targetName) {
                    
                    let dataEnd = fileDataStart + Int(compressedSize)
                    if dataEnd <= zipData.count {
                        let rawBytes = zipData.subdata(in: fileDataStart..<dataEnd)
                        if compressionMethod == 0 { // Stored (no compression)
                            return rawBytes
                        } else if compressionMethod == 8 { // Deflated
                            // Attempt decompression via native zlib inflate
                            if let decompressed = decompressDeflate(rawBytes, expectedSize: Int(uncompressedSize)) {
                                return decompressed
                            }
                        }
                    }
                }
            }
            
            searchIndex = headerOffset + 4
        }
        
        return nil
    }

    private static func decompressDeflate(_ data: Data, expectedSize: Int) -> Data? {
        var strm = z_stream()
        strm.avail_in = uInt(data.count)
        
        return data.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> Data? in
            guard let baseAddr = rawPtr.baseAddress?.assumingMemoryBound(to: Bytef.self) else { return nil }
            strm.next_in = UnsafeMutablePointer<Bytef>(mutating: baseAddr)
            
            // inflateInit2 with negative windowBits (-15) indicates raw DEFLATE without zlib/gzip headers
            if inflateInit2_(&strm, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) != Z_OK {
                return nil
            }
            defer { inflateEnd(&strm) }
            
            let bufferSize = max(expectedSize, 65536)
            var decompressed = Data(count: bufferSize)
            
            let result = decompressed.withUnsafeMutableBytes { outRawPtr -> Int32 in
                guard let outBase = outRawPtr.baseAddress?.assumingMemoryBound(to: Bytef.self) else { return Z_MEM_ERROR }
                strm.next_out = outBase
                strm.avail_out = uInt(bufferSize)
                return inflate(&strm, Z_FINISH)
            }
            
            if result == Z_STREAM_END || result == Z_OK {
                decompressed.count = Int(strm.total_out)
                return decompressed
            }
            return nil
        }
    }
}
