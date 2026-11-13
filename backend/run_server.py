#!/usr/bin/env python3
"""
Standalone CLI Runner for the iOS IPA Signing Server Backend.
"""
import argparse
import os
from pathlib import Path
import sys

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

if sys.platform == "win32":
    import asyncio
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="Launch the iOS IPA Signing Server Backend."
    )
    default_host = os.environ.get(
        "SIGNING_SERVER_HOST", os.environ.get("HOST", "0.0.0.0")
    )
    default_port = int(
        os.environ.get("SIGNING_SERVER_PORT", os.environ.get("PORT", "8000"))
    )
    parser.add_argument(
        "--host",
        type=str,
        default=default_host,
        help=f"Host interface to bind to (default: {default_host})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Port number to listen on (default: {default_port})",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=os.environ.get("SIGNING_SERVER_RELOAD", "false").lower()
        in ("true", "1", "yes"),
        help="Enable uvicorn auto-reload for local development",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print(f"Starting Signing Server Backend on http://{args.host}:{args.port}")
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
