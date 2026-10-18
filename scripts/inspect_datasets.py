"""
SENTINEL AI — Dataset Inspector
Scans raw and processed datasets, outputs summary tables, class distributions, and memory usage.
"""

from pathlib import Path
from typing import Any, Dict
import pandas as pd

from common import RAW_DATA_DIR, PROCESSED_DATA_DIR, MANIFESTS_DIR, logger


def inspect_dataset_file(file_path: Path) -> Dict[str, Any]:
    """Inspect an individual CSV or JSONL dataset file."""
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    if file_path.suffix == ".csv":
        df = pd.read_csv(file_path)
    elif file_path.suffix in (".jsonl", ".json"):
        df = pd.read_json(file_path, lines=(file_path.suffix == ".jsonl"))
    else:
        return {"file": file_path.name, "type": "unsupported"}

    mem_usage = df.memory_usage(deep=True).sum() / (1024 * 1024)
    missing = df.isnull().sum()
    missing_dict = {col: int(cnt) for col, cnt in missing.items() if cnt > 0}

    class_dist = {}
    for candidate in ["label", "is_anomaly", "status", "threat_type"]:
        if candidate in df.columns:
            class_dist[candidate] = {str(k): int(v) for k, v in df[candidate].value_counts().items()}

    return {
        "filename": file_path.name,
        "rows": len(df),
        "columns": len(df.columns),
        "column_names": list(df.columns),
        "memory_mb": round(mem_usage, 2),
        "missing_values": missing_dict,
        "class_distributions": class_dist
    }


def inspect_all_datasets() -> Dict[str, Any]:
    logger.info("Inspecting all datasets in data/...")
    report = {"raw": {}, "processed": {}}

    for p in RAW_DATA_DIR.rglob("*.*"):
        if p.suffix in (".csv", ".jsonl"):
            report["raw"][p.stem] = inspect_dataset_file(p)

    for p in PROCESSED_DATA_DIR.rglob("*.*"):
        if p.suffix in (".csv", ".jsonl"):
            report["processed"][p.stem] = inspect_dataset_file(p)

    logger.info(f"Inspected {len(report['raw'])} raw files and {len(report['processed'])} processed files.")
    return report


if __name__ == "__main__":
    res = inspect_all_datasets()
    for cat, items in res.items():
        print(f"\n=== {cat.upper()} DATASETS ===")
        for name, info in items.items():
            print(f"- {name}: {info.get('rows', 0)} rows, {info.get('columns', 0)} cols, {info.get('memory_mb', 0)} MB")
