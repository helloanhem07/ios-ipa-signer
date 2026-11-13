"""
FastAPI Application Entry Point, Lifespan Management, Middleware, and Global Routing.
"""
from contextlib import asynccontextmanager
import logging
import sys
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.api.v1.endpoints import api_router
from app.services.signing_manager import signing_manager

# Ensure Windows Proactor event loop is used for async subprocesses if on Windows
if sys.platform == "win32":
    import asyncio
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("signing_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager for startup and graceful shutdown.
    """
    logger.info("Initializing iOS IPA Signing Server Backend...")
    settings.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    await signing_manager.startup()

    engines = signing_manager.get_engines_status()
    logger.info(
        f"Signing Engines Available -> Native zsign: {engines['zsign']}, Fallback: {engines['fallback']}"
    )
    yield
    logger.info("Shutting down iOS IPA Signing Server Backend...")
    await signing_manager.shutdown()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="iOS IPA Signing & Over-The-Air (OTA) Server",
    description="Asynchronous REST backend for re-signing iOS IPAs and wireless distribution via Apple itms-services:// OTA",
    version="1.0.0",
    lifespan=lifespan,
)

# Permissive CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": exc.errors(),
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception during request {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
    )


# Attach v1 API Router
app.include_router(api_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "iOS IPA Signing & Over-The-Air (OTA) Backend",
        "version": "1.0.0",
        "docs_url": "/docs",
        "api_v1_prefix": "/api/v1",
        "health_check": "/api/v1/health",
    }
