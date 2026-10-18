"""
SENTINEL AI — Model Registry
Catalogs trained model artifacts, schemas, checksums, evaluation benchmarks, and deployment status.
Maintains models/model_registry.json as the single source of truth for the API inference layer.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from common import MODELS_DIR, compute_sha256, logger

REGISTRY_PATH = MODELS_DIR / "model_registry.json"


def scan_and_register_all_models() -> Dict[str, Any]:
    """Scan all model metadata files in models/*/*_meta.json and compile the registry."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    registry: Dict[str, Any] = {
        "registry_version": "v1.0",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "models": {}
    }

    meta_files = list(MODELS_DIR.rglob("*_meta.json"))
    logger.info(f"Scanning for model metadata files: found {len(meta_files)}")

    for meta_file in meta_files:
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            task_dir = meta_file.parent.name
            model_file = meta_file.parent / data.get("model_file", "")

            # Verify physical existence and recalculate integrity checksum
            if model_file.exists():
                data["sha256_checksum"] = compute_sha256(model_file)
                data["file_path"] = str(model_file.resolve())
                data["supported_task"] = task_dir
                registry["models"][task_dir] = data
                logger.info(f"Registered model for task '{task_dir}': {data.get('model_name')} ({data.get('model_version')})")
        except Exception as e:
            logger.error(f"Failed to register model from {meta_file}: {e}")

    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)

    logger.info(f"Model registry updated at {REGISTRY_PATH} ({len(registry['models'])} active models)")
    return registry


def get_registered_model(task: str) -> Optional[Dict[str, Any]]:
    if not REGISTRY_PATH.exists():
        scan_and_register_all_models()
    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            reg = json.load(f)
            return reg.get("models", {}).get(task)
    except Exception:
        return None


if __name__ == "__main__":
    scan_and_register_all_models()
