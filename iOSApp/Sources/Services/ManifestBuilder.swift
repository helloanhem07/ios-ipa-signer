//
//  ManifestBuilder.swift
//  iOSApp
//
//  Generates Apple Enterprise DTD-compliant manifest.plist for itms-services:// OTA installation.
//

import Foundation

public struct ManifestBuilder {
    public static func build(bundleId: String,
                             bundleVersion: String,
                             title: String,
                             serverPort: UInt16,
                             host: String = "127.0.0.1") -> String {
        let ipaURL = "https://\(host):\(serverPort)/download/signed.ipa"
        let iconURL = "https://\(host):\(serverPort)/download/icon.png"

        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>items</key>
            <array>
                <dict>
                    <key>assets</key>
                    <array>
                        <dict>
                            <key>kind</key>
                            <string>software-package</string>
                            <key>url</key>
                            <string>\(ipaURL)</string>
                        </dict>
                        <dict>
                            <key>kind</key>
                            <string>display-image</string>
                            <key>needs-shine</key>
                            <false/>
                            <key>url</key>
                            <string>\(iconURL)</string>
                        </dict>
                        <dict>
                            <key>kind</key>
                            <string>full-size-image</string>
                            <key>needs-shine</key>
                            <false/>
                            <key>url</key>
                            <string>\(iconURL)</string>
                        </dict>
                    </array>
                    <key>metadata</key>
                    <dict>
                        <key>bundle-identifier</key>
                        <string>\(bundleId)</string>
                        <key>bundle-version</key>
                        <string>\(bundleVersion)</string>
                        <key>kind</key>
                        <string>software</string>
                        <key>title</key>
                        <string>\(title)</string>
                    </dict>
                </dict>
            </array>
        </dict>
        </plist>
        """
    }
}
