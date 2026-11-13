"""
Resilient HTTP Client for Opaque-Box E2E REST API Testing.
Zero-external-dependency HTTP client using urllib.request with multipart/form-data support,
custom header propagation, byte-range requests, and timeout resilience.
"""

import json
import mimetypes
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Dict, Any, Optional, Tuple, Union


class APIResponse:
    """Represents an HTTP API response with status, headers, and parsed payload."""
    def __init__(self, status_code: int, headers: Dict[str, str], body: bytes):
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


class TestHTTPClient:
    """Client for testing backend endpoints."""
    __test__ = False

    def __init__(self, base_url: str = "http://127.0.0.1:8000", default_timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.default_timeout = default_timeout

    def _full_url(self, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        clean_ep = endpoint.lstrip("/")
        return f"{self.base_url}/{clean_ep}"

    def get(self, endpoint: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[float] = None) -> APIResponse:
        url = self._full_url(endpoint)
        req = urllib.request.Request(url, method="GET")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        tout = timeout or self.default_timeout
        try:
            with urllib.request.urlopen(req, timeout=tout) as resp:
                body = resp.read()
                return APIResponse(resp.status, dict(resp.headers), body)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            return APIResponse(e.code, dict(e.headers), err_body)
        except Exception as e:
            return APIResponse(599, {}, f"Connection error: {e}".encode("utf-8"))

    def post_multipart(
        self,
        endpoint: str,
        fields: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Union[str, bytes, Tuple[str, bytes]]]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> APIResponse:
        """
        Submits multipart/form-data upload.
        files dict maps field_name -> file_path OR raw_bytes OR (filename, raw_bytes).
        """
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
        body_lines = []

        fields = fields or {}
        for name, value in fields.items():
            body_lines.append(f"--{boundary}\r\n".encode("utf-8"))
            body_lines.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
            body_lines.append(f"{value}\r\n".encode("utf-8"))

        files = files or {}
        for field_name, file_info in files.items():
            if isinstance(file_info, str):
                # file path
                filename = os.path.basename(file_info)
                with open(file_info, "rb") as f:
                    file_bytes = f.read()
            elif isinstance(file_info, tuple) and len(file_info) == 2:
                filename, file_bytes = file_info
            elif isinstance(file_info, (bytes, bytearray)):
                filename = f"{field_name}.dat"
                file_bytes = bytes(file_info)
            else:
                continue

            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            body_lines.append(f"--{boundary}\r\n".encode("utf-8"))
            body_lines.append(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8")
            )
            body_lines.append(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
            body_lines.append(file_bytes)
            body_lines.append(b"\r\n")

        body_lines.append(f"--{boundary}--\r\n".encode("utf-8"))
        payload = b"".join(body_lines)

        url = self._full_url(endpoint)
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(payload)))

        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        tout = timeout or self.default_timeout
        try:
            with urllib.request.urlopen(req, timeout=tout) as resp:
                body = resp.read()
                return APIResponse(resp.status, dict(resp.headers), body)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            return APIResponse(e.code, dict(e.headers), err_body)
        except Exception as e:
            return APIResponse(599, {}, f"Connection error: {e}".encode("utf-8"))
