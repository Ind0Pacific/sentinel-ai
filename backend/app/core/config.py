"""
SENTINEL AI — Backend Configuration
Resolves application paths, registry locations, and environment settings.
"""

from pathlib import Path
from pydantic import BaseModel

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
DATA_DIR = PROJECT_ROOT / "data"
MANIFESTS_DIR = DATA_DIR / "manifests"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
REGISTRY_PATH = MODELS_DIR / "model_registry.json"


class Settings(BaseModel):
    app_name: str = "SENTINEL AI Platform"
    app_version: str = "2.0.0"
    api_prefix: str = "/api/v1"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"
    environment: str = "production"
    debug: bool = False


settings = Settings()
