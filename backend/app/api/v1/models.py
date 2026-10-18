"""
SENTINEL AI — Models API Endpoints
Serves registered models, metadata, feature schemas, thresholds, and evaluation metrics.
"""

import json
from typing import List
from fastapi import APIRouter, HTTPException

from app.core.config import REGISTRY_PATH, REPORTS_DIR
from app.schemas.model import ModelSummary, ModelDetail, ModelMetrics

router = APIRouter(prefix="/models", tags=["Models"])


def load_registry():
    if not REGISTRY_PATH.exists():
        return {}
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        return data.get("models", {})
    except Exception:
        return {}


@router.get("", response_model=List[ModelSummary])
def list_models():
    """List all models registered in the SENTINEL AI model registry."""
    models_dict = load_registry()
    summaries = []
    for task, info in models_dict.items():
        summaries.append(ModelSummary(
            id=task,
            model_name=info.get("model_name", task),
            model_version=info.get("model_version", "v1.0.0"),
            algorithm=info.get("algorithm", "unknown"),
            supported_task=info.get("supported_task", task),
            decision_threshold=info.get("decision_threshold", 0.50),
            status=info.get("status", "production"),
            sha256_checksum=info.get("sha256_checksum", ""),
            training_timestamp=info.get("training_timestamp", "")
        ))
    return summaries


@router.get("/{model_id}", response_model=ModelDetail)
def get_model_detail(model_id: str):
    """Retrieve full configuration and feature list for a specific model."""
    models_dict = load_registry()
    if model_id not in models_dict:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found in registry.")

    info = models_dict[model_id]
    m_data = info.get("metrics", {})
    metrics_obj = ModelMetrics(
        test_precision=m_data.get("test_precision", 0.0),
        test_recall=m_data.get("test_recall", 0.0),
        test_f1=m_data.get("test_f1", 0.0),
        false_positive_rate=m_data.get("false_positive_rate", 0.0),
        test_roc_auc=m_data.get("test_roc_auc"),
        test_pr_auc=m_data.get("test_pr_auc"),
        confusion_matrix=m_data.get("confusion_matrix")
    ) if m_data else None

    return ModelDetail(
        id=model_id,
        model_name=info.get("model_name", model_id),
        model_version=info.get("model_version", "v1.0.0"),
        algorithm=info.get("algorithm", "unknown"),
        supported_task=info.get("supported_task", model_id),
        decision_threshold=info.get("decision_threshold", 0.50),
        status=info.get("status", "production"),
        sha256_checksum=info.get("sha256_checksum", ""),
        training_timestamp=info.get("training_timestamp", ""),
        features=info.get("features", []),
        top_features=info.get("top_features"),
        metrics=metrics_obj,
        training_dataset=info.get("training_dataset"),
        manifest_reference=info.get("manifest_reference"),
        file_path=info.get("file_path")
    )


@router.get("/{model_id}/metrics", response_model=ModelMetrics)
def get_model_metrics(model_id: str):
    """Retrieve verified evaluation metrics and confusion matrix for a specific model."""
    models_dict = load_registry()
    if model_id not in models_dict:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found in registry.")

    info = models_dict[model_id]
    m_data = info.get("metrics")
    if not m_data:
        raise HTTPException(status_code=404, detail=f"Metrics for model '{model_id}' unavailable.")

    # Also load measured inference latency if present in evaluation_summary.json
    eval_file = REPORTS_DIR / "evaluation" / "evaluation_summary.json"
    latency = None
    if eval_file.exists():
        try:
            eval_data = json.loads(eval_file.read_text(encoding="utf-8"))
            latency = eval_data.get(model_id, {}).get("inference_latency_ms")
        except Exception:
            pass

    return ModelMetrics(
        test_precision=m_data.get("test_precision", 0.0),
        test_recall=m_data.get("test_recall", 0.0),
        test_f1=m_data.get("test_f1", 0.0),
        false_positive_rate=m_data.get("false_positive_rate", 0.0),
        test_roc_auc=m_data.get("test_roc_auc"),
        test_pr_auc=m_data.get("test_pr_auc"),
        confusion_matrix=m_data.get("confusion_matrix"),
        inference_latency_ms=latency
    )
