"""
MailRakhwala FastAPI Core Application Entrypoint
Mounts CORS middleware, centralized routers, and global error handling.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(analysis_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Fallback handler to prevent internal trace leakage."""
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred while processing the request."}
    )