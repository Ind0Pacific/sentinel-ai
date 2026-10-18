"""
SENTINEL AI — Platform Backend Entrypoint
Integrates dataset management, model registry, inference engines, and pipeline monitoring.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import sys
from pathlib import Path

# Setup paths
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

for p in [str(BACKEND_DIR), str(SCRIPTS_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from app.core.config import settings
from app.api.v1.datasets import router as datasets_router
from app.api.v1.models import router as models_router
from app.api.v1.analyze import router as analyze_router
from app.api.v1.jobs import router as jobs_router

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="SENTINEL AI: AI-powered cybersecurity threat detection, dataset engineering, and response platform.",
    docs_url=settings.docs_url,
    redoc_url=settings.redoc_url
)

# Enable CORS for Next.js / React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Register routers
app.include_router(datasets_router, prefix=settings.api_prefix)
app.include_router(models_router, prefix=settings.api_prefix)
app.include_router(analyze_router, prefix=settings.api_prefix)
app.include_router(jobs_router, prefix=settings.api_prefix)

FRONTEND_DIR = PROJECT_ROOT / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="dashboard")


@app.get("/ui")
def get_ui():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Dashboard index.html not found"}


@app.get("/")
def root():
    return {
        "platform": settings.app_name,
        "version": settings.app_version,
        "status": "OPERATIONAL",
        "documentation": settings.docs_url,
        "dashboard_ui": "/dashboard",
        "endpoints": {
            "datasets": f"{settings.api_prefix}/datasets",
            "models": f"{settings.api_prefix}/models",
            "analyze_url": f"{settings.api_prefix}/analyze/url",
            "analyze_network": f"{settings.api_prefix}/analyze/network",
            "analyze_authentication": f"{settings.api_prefix}/analyze/authentication",
            "training_jobs": f"{settings.api_prefix}/training/jobs"
        }
    }


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": sys.platform
    }
