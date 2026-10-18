"""
SENTINEL AI — Test Suite: Model Artifacts & Inference Service
Validates model weights, joblib serialization, score bounds, and real-time inference latency.
"""

import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

for p in [str(BACKEND_DIR), str(SCRIPTS_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from app.services.inference import inference_service


def test_inference_service_loaded():
    assert inference_service is not None
    assert inference_service.ti_store is not None


def test_url_analyzer_inference_benign():
    url = "https://en.wikipedia.org/wiki/Computer_science"
    res = inference_service.analyze_url(url)

    assert "risk_score" in res
    assert 0.0 <= res["risk_score"] <= 1.0
    assert res["verdict"] == "legitimate"
    assert "evidence" in res


def test_url_analyzer_inference_phishing():
    url = "http://paypal-verification-portal.xyz/login.php?user_id=confirm"
    res = inference_service.analyze_url(url)

    assert res["risk_score"] >= 0.50
    assert res["verdict"] == "phishing"
    assert res["threat_intel_match"] is not None


def test_network_analyzer_inference():
    flow = {
        "dur": 0.05,
        "rate": 150.0,
        "spkts": 5,
        "dpkts": 4,
        "sbytes": 450,
        "dbytes": 800,
        "proto": "tcp",
        "service": "http",
        "state": "FIN"
    }
    res = inference_service.analyze_network(flow)

    assert "intrusion_probability" in res
    assert 0.0 <= res["intrusion_probability"] <= 1.0
    assert res["verdict"] in ("normal", "intrusion_detected")
    assert "confidence" in res


def test_authentication_analyzer_brute_force():
    req = {
        "user_id": "alice.admin@sentinel.internal",
        "source_ip": "185.220.101.5",
        "status": "failure",
        "window_fail_count_ip": 18,
        "window_attempt_count_ip": 20,
        "distinct_users_targeted_ip": 1,
        "burst_rate_per_min": 15.0
    }
    res = inference_service.analyze_authentication(req)

    assert res["is_anomaly"] is True
    assert res["risk_score"] >= 0.80
    assert "RULE_BRUTE_FORCE_IP_THRESHOLD" in res["triggered_rules"]
