from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.api.routes.health import router as health_router
from app.api.routes.analysis import router as analysis_router

app = FastAPI(
    title="MailRakhwala API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Email Communications (SIH26159)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Robust CORS middleware configuration
cors_origins = settings.CORS_ORIGINS
allow_all = "*" in cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else cors_origins,
    allow_credentials=not allow_all,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Centralized API Routers
app.include_router(health_router)
app.include_router(analysis_router)


# Static Distribution and Single Page Application (SPA) Routing
static_dir = settings.STATIC_DIR
if static_dir and static_dir.is_dir():
    assets_dir = static_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/")
    async def serve_root():
        index_file = static_dir / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return {"status": "ok", "service": "MailRakhwala API", "docs": "/docs"}

    @app.get("/{full_path:path}")
    async def serve_spa_fallback(full_path: str):
        # Do not capture API, health, or documentation paths
        if full_path.startswith(("analysis", "health", "docs", "redoc", "openapi.json")):
            return JSONResponse(status_code=404, content={"detail": "Not found"})

        # Exact file match (e.g. favicon.svg, mailrakhwala-demo.pcap, icons.svg)
        target = static_dir / full_path
        if target.is_file():
            return FileResponse(str(target))

        # Client-side SPA routing fallback (e.g. /dashboard, /findings, /analysis)
        index_file = static_dir / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))

        return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Fallback handler to prevent internal trace leakage."""
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred while processing the request."}
    )