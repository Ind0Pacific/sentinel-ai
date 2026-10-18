"""
SENTINEL AI — Test Suite: FastAPI Endpoints
Tests REST APIs for datasets, models, metrics, real-time analysis, and pipeline monitoring.
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

client = TestClient(app)


def test_health_check_endpoint():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"


def test_list_datasets_endpoint():
    res = client.get("/api/v1/datasets")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 3


def test_get_dataset_detail_endpoint():
    res = client.get("/api/v1/datasets/phishing_urls")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "phishing_urls"
    assert "sha256_checksum" in data


def test_list_models_endpoint():
    res = client.get("/api/v1/models")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 3


def test_get_model_metrics_endpoint():
    res = client.get("/api/v1/models/phishing/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "test_precision" in data
    assert "test_f1" in data
    assert "confusion_matrix" in data


def test_analyze_url_endpoint():
    payload = {"url": "http://paypal-verification-portal.xyz/login.php"}
    res = client.post("/api/v1/analyze/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert data["verdict"] in ("phishing", "suspicious", "legitimate")


def test_analyze_network_endpoint():
    payload = {
        "dur": 0.1,
        "rate": 500.0,
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 1024,
        "dbytes": 2048,
        "proto": "tcp",
        "service": "http",
        "state": "FIN"
    }
    res = client.post("/api/v1/analyze/network", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "intrusion_probability" in data
    assert "verdict" in data


def test_analyze_authentication_endpoint():
    payload = {
        "user_id": "alice.admin@sentinel.internal",
        "source_ip": "185.220.101.5",
        "status": "failure",
        "window_fail_count_ip": 12,
        "window_attempt_count_ip": 15,
        "distinct_users_targeted_ip": 1,
        "burst_rate_per_min": 10.0
    }
    res = client.post("/api/v1/analyze/authentication", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "is_anomaly" in data
    assert data["is_anomaly"] is True


def test_list_pipeline_jobs_endpoint():
    res = client.get("/api/v1/training/jobs")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
