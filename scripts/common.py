"""
SENTINEL AI — Common Utilities & Configuration
Provides directory paths, hashing utilities, and manifest helpers.
"""

from pathlib import Path
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Project root resolution
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
INTERIM_DATA_DIR = DATA_DIR / "interim"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MANIFESTS_DIR = DATA_DIR / "manifests"
QUARANTINE_DIR = DATA_DIR / "quarantine"

MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
QUALITY_REPORTS_DIR = REPORTS_DIR / "data_quality"
TRAINING_REPORTS_DIR = REPORTS_DIR / "training"
EVALUATION_REPORTS_DIR = REPORTS_DIR / "evaluation"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sentinel")


def compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hash of a file safely in 64KB chunks."""
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"Target file does not exist: {file_path}")
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def compute_string_sha256(content: str) -> str:
    """Compute the SHA-256 hash of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def save_manifest(manifest_data: Dict[str, Any], output_path: Path) -> None:
    """Save a standardized dataset manifest JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_data["manifest_saved_at"] = datetime.now(timezone.utc).isoformat()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, default=str)
    logger.info(f"Manifest written to {output_path}")


def load_manifest(manifest_path: Path) -> Optional[Dict[str, Any]]:
    """Load a dataset manifest JSON."""
    if not manifest_path.exists():
        return None
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_disk_free_gb(target_path: Path) -> float:
    """Return free disk space in Gigabytes for the specified path."""
    stat = os.statvfs(target_path) if hasattr(os, "statvfs") else None
    if stat:
        return (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
    
    # Windows fallback
    import shutil
    total, used, free = shutil.disk_usage(target_path)
    return free / (1024 ** 3)
