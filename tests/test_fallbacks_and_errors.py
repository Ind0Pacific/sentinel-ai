"""
SENTINEL AI — Test Suite: Fallbacks & Error Handling
Tests deterministic rule fallback behavior when models are absent and error handling on invalid requests.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

for p in [str(BACKEND_DIR), str(SCRIPTS_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from app.main import app
from app.services.inference import InferenceService
from train_auth_anomaly_model import FallbackRuleEngine

client = TestClient(app)


def test_fallback_rule_engine_clean():
    """Clean normal event produces no triggered rules."""
    event = {
        "is_failure": 0,
        "window_fail_count_ip": 0,
        "distinct_users_targeted_ip": 1,
        "is_known_threat_ip": 0,
        "burst_rate_per_min": 1.0
    }
    is_anom, score, rules = FallbackRuleEngine.evaluate(event)
    assert is_anom is False
    assert score == 0.0
    assert len(rules) == 0


def test_fallback_rule_engine_password_spray():
    """Multiple accounts targeted from one IP triggers password spray rule."""
    event = {
        "distinct_users_targeted_ip": 5,
        "window_fail_count_ip": 5
    }
    is_anom, score, rules = FallbackRuleEngine.evaluate(event)
    assert is_anom is True
    assert "RULE_PASSWORD_SPRAY_SUSPECTED" in rules
    assert score >= 0.88


def test_inference_service_without_models():
    """Inference service runs successfully in fallback mode even if pipeline is not loaded."""
    mock_service = InferenceService()
    mock_service._phishing_pipeline = None

    res = mock_service.analyze_url("http://192.168.10.50:8080/admin/login.php")
    assert "risk_score" in res
    assert "fallback" in res["model_version"].lower()


def test_api_invalid_url_error():
    """Empty URL payload returns 400 or 422 Bad Request."""
    res = client.post("/api/v1/analyze/url", json={"url": ""})
    assert res.status_code == 400


def test_api_nonexistent_dataset_404():
    res = client.get("/api/v1/datasets/non_existent_dataset_123")
    assert res.status_code == 404


def test_api_nonexistent_model_404():
    res = client.get("/api/v1/models/non_existent_model_123")
    assert res.status_code == 404
