"""
Apple Over-The-Air (OTA) Manifest and Installation Landing Page Service.
"""
import html
import plistlib
import urllib.parse
from typing import Any, Dict, Optional


class ManifestService:
    """
    Service for generating Apple Enterprise / Ad-Hoc OTA manifest.plist XML,
    properly percent-encoded itms-services:// URLs, and responsive mobile Safari landing pages.
    """

    @staticmethod
    def generate_manifest_dict(
        ipa_url: str,
        bundle_id: str,
        bundle_version: str,
        title: str,
        display_image_url: Optional[str] = None,
        full_size_image_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Constructs the dictionary adhering to Apple's Wireless App Distribution specification.
        """
        assets = [
            {
                "kind": "software-package",
                "url": ipa_url,
            }
        ]

        if display_image_url:
            assets.append(
                {
                    "kind": "display-image",
                    "needs-shine": False,
                    "url": display_image_url,
                }
            )

        if full_size_image_url:
            assets.append(
                {
                    "kind": "full-size-image",
                    "needs-shine": False,
                    "url": full_size_image_url,
                }
            )

        metadata = {
            "bundle-identifier": bundle_id,
            "bundle-version": bundle_version,
            "kind": "software",
            "title": title,
        }

        return {
            "items": [
                {
                    "assets": assets,
                    "metadata": metadata,
                }
            ]
        }

    @classmethod
    def generate_manifest_xml(
        cls,
        ipa_url: str,
        bundle_id: str,
        bundle_version: str,
        title: str,
        display_image_url: Optional[str] = None,
        full_size_image_url: Optional[str] = None,
    ) -> bytes:
        """
        Serializes the manifest dictionary into XML conforming to Apple Enterprise DTD.
        """
        manifest_data = cls.generate_manifest_dict(
            ipa_url=ipa_url,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            title=title,
            display_image_url=display_image_url,
            full_size_image_url=full_size_image_url,
        )
        return plistlib.dumps(manifest_data, fmt=plistlib.FMT_XML)

    @staticmethod
    def build_itms_url(manifest_url: str) -> str:
        """
        Generates a properly percent-encoded itms-services:// URL.
        """
        encoded_url = urllib.parse.quote(manifest_url, safe="")
        return f"itms-services://?action=download-manifest&url={encoded_url}"

    @classmethod
    def generate_install_html(
        cls,
        app_name: str,
        bundle_id: str,
        bundle_version: str,
        itms_url: str,
        download_url: str,
        file_size_bytes: Optional[int] = None,
    ) -> str:
        """
        Renders a clean, responsive mobile Safari installation HTML landing page.
        """
        safe_app_name = html.escape(app_name or "iOS Application")
        safe_bundle_id = html.escape(bundle_id or "com.apple.application")
        safe_bundle_version = html.escape(bundle_version or "1.0.0")
        safe_itms_url = html.escape(itms_url)
        safe_download_url = html.escape(download_url)

        if file_size_bytes and file_size_bytes > 0:
            mb = file_size_bytes / (1024 * 1024)
            size_str = f"{mb:.1f} MB"
        else:
            size_str = "Signed Package"

        app_initial = html.escape((safe_app_name[0] if safe_app_name else "A").upper())

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Install {safe_app_name}</title>
  <style>
    :root {{
      --bg: #F2F2F7;
      --card-bg: #FFFFFF;
      --text: #1C1C1E;
      --text-secondary: #8E8E93;
      --accent: #007AFF;
      --accent-hover: #0056B3;
      --border: #E5E5EA;
      --badge-bg: #EFEFF4;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #000000;
        --card-bg: #1C1C1E;
        --text: #FFFFFF;
        --text-secondary: #8E8E93;
        --accent: #0A84FF;
        --accent-hover: #409CFF;
        --border: #38383A;
        --badge-bg: #2C2C2E;
      }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      padding: 24px 16px;
      min-height: 100vh;
    }}
    .container {{
      width: 100%;
      max-width: 440px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }}
    .card {{
      background: var(--card-bg);
      border-radius: 20px;
      padding: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
      border: 1px solid var(--border);
      text-align: center;
    }}
    .app-icon {{
      width: 88px;
      height: 88px;
      border-radius: 20px;
      margin: 0 auto 16px;
      background: linear-gradient(135deg, #007AFF, #5856D6);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 36px;
      font-weight: 700;
      box-shadow: 0 4px 12px rgba(0, 122, 255, 0.3);
      overflow: hidden;
    }}
    .app-title {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
    .app-meta {{ font-size: 14px; color: var(--text-secondary); margin-bottom: 16px; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      background: var(--badge-bg);
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      font-family: monospace;
      margin-bottom: 20px;
      word-break: break-all;
    }}
    .btn {{
      display: block;
      width: 100%;
      padding: 14px 20px;
      border-radius: 14px;
      font-size: 16px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      text-align: center;
      transition: background-color 0.15s ease;
    }}
    .btn-primary {{
      background-color: var(--accent);
      color: #FFFFFF;
      margin-bottom: 10px;
    }}
    .btn-primary:active {{ background-color: var(--accent-hover); }}
    .btn-secondary {{
      background-color: transparent;
      color: var(--accent);
      border: 1px solid var(--border);
    }}
    .notice-card {{
      background: var(--card-bg);
      border-radius: 16px;
      padding: 20px;
      border: 1px solid var(--border);
      font-size: 14px;
      line-height: 1.5;
    }}
    .notice-title {{
      font-weight: 600;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .step-list {{
      padding-left: 20px;
      color: var(--text);
    }}
    .step-list li {{ margin-bottom: 8px; }}
    .subtext {{ font-size: 12px; color: var(--text-secondary); margin-top: 12px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="app-icon">
        <span>{app_initial}</span>
      </div>
      <h1 class="app-title">{safe_app_name}</h1>
      <p class="app-meta">Version {safe_bundle_version} • {size_str}</p>
      <div class="badge">{safe_bundle_id}</div>

      <a href="{safe_itms_url}" class="btn btn-primary" id="installBtn">
        Install Application (OTA)
      </a>
      <a href="{safe_download_url}" class="btn btn-secondary">
        Download .IPA Directly
      </a>
    </div>

    <div class="notice-card">
      <div class="notice-title">
        <span>🛡️ First-Time Installation Setup</span>
      </div>
      <ol class="step-list">
        <li>Tap <strong>Install Application (OTA)</strong> above and confirm the prompt in Safari.</li>
        <li>Return to your Home Screen to view the download and installation progress.</li>
        <li>If prompted with <em>"Untrusted Enterprise Developer"</em>:
          <ol style="padding-left: 16px; margin-top: 6px;">
            <li>Go to <strong>Settings</strong> &gt; <strong>General</strong> &gt; <strong>VPN &amp; Device Management</strong>.</li>
            <li>Select the developer enterprise profile.</li>
            <li>Tap <strong>Trust</strong> (or <strong>Allow &amp; Restart</strong> on iOS 18).</li>
          </ol>
        </li>
      </ol>
      <p class="subtext">Developer Certificate note: If signed with a standard developer certificate on iOS 16+, enable Developer Mode under Settings &gt; Privacy &amp; Security.</p>
    </div>
  </div>
</body>
</html>
"""
