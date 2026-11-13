"""
Backend Server Lifecycle Manager.
Spawns, monitors health, and terminates the backend service during test execution.
"""

import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


class ServerManager:
    """Manages the backend FastAPI server subprocess lifecycle."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.process: Optional[subprocess.Popen] = None
        self.spawned_by_us = False

    def is_server_running(self) -> bool:
        """Checks if GET /api/v1/health returns HTTP 200."""
        health_url = f"{self.base_url}/api/v1/health"
        try:
            req = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def ensure_server_running(self) -> bool:
        """
        Verifies if server is already running, or spawns backend/run_server.py.
        Returns True if server is ready, False otherwise.
        """
        if self.is_server_running():
            return True

        # Find backend runner script
        workspace_root = Path(__file__).resolve().parent.parent.parent.parent
        backend_script = workspace_root / "backend" / "run_server.py"

        if not backend_script.exists():
            # Server script does not exist yet (backend not yet implemented or running offline)
            return False

        reports_dir = Path(__file__).resolve().parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = reports_dir / "server.log"

        log_file = open(log_file_path, "w", encoding="utf-8")

        python_exe = sys.executable or "python"
        try:
            self.process = subprocess.Popen(
                [python_exe, str(backend_script)],
                cwd=str(workspace_root),
                stdout=log_file,
                stderr=subprocess.STDOUT
            )
            self.spawned_by_us = True
        except Exception as e:
            log_file.write(f"Failed to spawn backend server: {e}\n")
            log_file.close()
            return False

        # Poll until healthy or timeout
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            if self.process.poll() is not None:
                # Process exited prematurely
                log_file.close()
                return False

            if self.is_server_running():
                return True

            time.sleep(0.5)

        return False

    def teardown(self):
        """Terminates spawned server process cleanly."""
        if not self.spawned_by_us or not self.process:
            return

        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                               capture_output=True)
            else:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        except Exception:
            pass
        finally:
            self.process = None
            self.spawned_by_us = False
