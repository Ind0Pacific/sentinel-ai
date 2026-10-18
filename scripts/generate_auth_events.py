"""
SENTINEL AI — Synthetic Authentication Event Generator
Generates realistic, labeled authentication logs covering normal operations and 7 threat scenarios.
Output is stored in data/raw/authentication/ and documented via data/manifests/auth_events_manifest.json.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

from common import (
    RAW_DATA_DIR,
    MANIFESTS_DIR,
    compute_sha256,
    save_manifest,
    logger
)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

USERS = [
    "alice.admin@sentinel.internal",
    "bob.analyst@sentinel.internal",
    "carol.engineer@sentinel.internal",
    "david.hr@sentinel.internal",
    "eve.finance@sentinel.internal",
    "frank.devops@sentinel.internal",
    "grace.ops@sentinel.internal",
    "heidi.intern@sentinel.internal"
]

INTERNAL_IPS = [
    "10.100.1.15", "10.100.1.22", "10.100.2.45", "10.100.2.80",
    "192.168.1.50", "192.168.1.102", "172.16.0.12", "172.16.0.44"
]

EXTERNAL_BENIGN_IPS = [
    "203.0.113.10", "198.51.100.25", "198.51.100.77"
]

MALICIOUS_IPS = [
    "185.220.101.5", "45.154.255.89", "194.26.29.112", "91.240.118.23"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Safari/17.4.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "SentinelAuthAgent/2.4 (Kali-Headless; Python/3.11)"
]

RESOURCES = [
    "/dashboard/overview",
    "/api/v1/reports",
    "/user/profile",
    "/internal/wiki",
    "/admin/credentials_vault",
    "/admin/system_keys",
    "/admin/database_dump"
]


def generate_scenario_events(start_time: datetime, count_normal: int = 2000) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    current_time = start_time

    # Scenario 1: Normal Login Activity (workday hours, expected IPs, SSO/password)
    for _ in range(count_normal):
        user = random.choice(USERS)
        ip = random.choice(INTERNAL_IPS + EXTERNAL_BENIGN_IPS)
        success = random.random() > 0.05
        current_time += timedelta(seconds=random.randint(15, 180))

        events.append({
            "event_id": f"AUTH-{len(events)+1:06d}",
            "timestamp": current_time.isoformat(),
            "user_id": user,
            "source_ip": ip,
            "event_type": "login_attempt",
            "status": "success" if success else "failure",
            "auth_method": random.choice(["sso", "password", "mfa_push"]),
            "user_agent": random.choice(USER_AGENTS[:3]),
            "resource_requested": random.choice(RESOURCES[:4]),
            "risk_score": 0.05 if success else 0.20,
            "failure_reason": None if success else "invalid_credentials",
            "is_anomaly": 0,
            "anomaly_type": "none"
        })

    # Scenario 2: Repeated Failed Logins (Brute Force against single account)
    target_user = "alice.admin@sentinel.internal"
    attacker_ip = "185.220.101.5"
    current_time += timedelta(minutes=10)
    for _ in range(35):
        current_time += timedelta(seconds=random.randint(1, 4))
        events.append({
            "event_id": f"AUTH-{len(events)+1:06d}",
            "timestamp": current_time.isoformat(),
            "user_id": target_user,
            "source_ip": attacker_ip,
            "event_type": "login_attempt",
            "status": "failure",
            "auth_method": "password",
            "user_agent": "Python-requests/2.31.0",
            "resource_requested": "/admin/credentials_vault",
            "risk_score": 0.85,
            "failure_reason": "invalid_credentials",
            "is_anomaly": 1,
            "anomaly_type": "brute_force"
        })

    # Scenario 3: Successful Login After Multiple Failures (Compromised account)
    current_time += timedelta(seconds=5)
    events.append({
        "event_id": f"AUTH-{len(events)+1:06d}",
        "timestamp": current_time.isoformat(),
        "user_id": target_user,
        "source_ip": attacker_ip,
        "event_type": "login_attempt",
        "status": "success",
        "auth_method": "password",
        "user_agent": "Python-requests/2.31.0",
        "resource_requested": "/admin/credentials_vault",
        "risk_score": 0.95,
        "failure_reason": None,
        "is_anomaly": 1,
        "anomaly_type": "success_after_brute_force"
    })

    # Scenario 4: Password Spraying (Single IP attacking multiple distinct users)
    spray_ip = "45.154.255.89"
    current_time += timedelta(minutes=30)
    for user in USERS:
        for _ in range(2):
            current_time += timedelta(seconds=random.randint(2, 6))
            events.append({
                "event_id": f"AUTH-{len(events)+1:06d}",
                "timestamp": current_time.isoformat(),
                "user_id": user,
                "source_ip": spray_ip,
                "event_type": "login_attempt",
                "status": "failure",
                "auth_method": "password",
                "user_agent": "Hydra/9.5 (Kali)",
                "resource_requested": "/dashboard/overview",
                "risk_score": 0.88,
                "failure_reason": "invalid_credentials",
                "is_anomaly": 1,
                "anomaly_type": "password_spray"
            })

    # Scenario 5: Unusual Login Frequency / Burst (High volume in seconds)
    burst_user = "bob.analyst@sentinel.internal"
    burst_ip = "194.26.29.112"
    current_time += timedelta(hours=1)
    for _ in range(40):
        current_time += timedelta(milliseconds=random.randint(100, 300))
        events.append({
            "event_id": f"AUTH-{len(events)+1:06d}",
            "timestamp": current_time.isoformat(),
            "user_id": burst_user,
            "source_ip": burst_ip,
            "event_type": "token_refresh",
            "status": "failure",
            "auth_method": "api_token",
            "user_agent": "Go-http-client/1.1",
            "resource_requested": "/api/v1/reports",
            "risk_score": 0.80,
            "failure_reason": "rate_limit_exceeded",
            "is_anomaly": 1,
            "anomaly_type": "event_burst"
        })

    # Scenario 6: Suspicious Source Changes (Impossible Travel)
    it_user = "carol.engineer@sentinel.internal"
    current_time += timedelta(hours=2)
    # Legitimate login in New York (203.0.113.10)
    events.append({
        "event_id": f"AUTH-{len(events)+1:06d}",
        "timestamp": current_time.isoformat(),
        "user_id": it_user,
        "source_ip": "203.0.113.10",
        "event_type": "login_attempt",
        "status": "success",
        "auth_method": "sso",
        "user_agent": USER_AGENTS[0],
        "resource_requested": "/dashboard/overview",
        "risk_score": 0.05,
        "failure_reason": None,
        "is_anomaly": 0,
        "anomaly_type": "none"
    })
    # 4 minutes later login from Eastern Europe / Tor Exit
    current_time += timedelta(minutes=4)
    events.append({
        "event_id": f"AUTH-{len(events)+1:06d}",
        "timestamp": current_time.isoformat(),
        "user_id": it_user,
        "source_ip": "91.240.118.23",
        "event_type": "login_attempt",
        "status": "success",
        "auth_method": "password",
        "user_agent": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0)",
        "resource_requested": "/admin/system_keys",
        "risk_score": 0.92,
        "failure_reason": None,
        "is_anomaly": 1,
        "anomaly_type": "impossible_travel"
    })

    # Scenario 7: Benign lookalike (User mistyped password twice then succeeded)
    mistype_user = "david.hr@sentinel.internal"
    mistype_ip = "192.168.1.50"
    current_time += timedelta(hours=1)
    for _ in range(2):
        current_time += timedelta(seconds=random.randint(5, 12))
        events.append({
            "event_id": f"AUTH-{len(events)+1:06d}",
            "timestamp": current_time.isoformat(),
            "user_id": mistype_user,
            "source_ip": mistype_ip,
            "event_type": "login_attempt",
            "status": "failure",
            "auth_method": "password",
            "user_agent": USER_AGENTS[1],
            "resource_requested": "/user/profile",
            "risk_score": 0.25,
            "failure_reason": "invalid_credentials",
            "is_anomaly": 0,
            "anomaly_type": "benign_mistype"
        })
    current_time += timedelta(seconds=10)
    events.append({
        "event_id": f"AUTH-{len(events)+1:06d}",
        "timestamp": current_time.isoformat(),
        "user_id": mistype_user,
        "source_ip": mistype_ip,
        "event_type": "login_attempt",
        "status": "success",
        "auth_method": "password",
        "user_agent": USER_AGENTS[1],
        "resource_requested": "/user/profile",
        "risk_score": 0.05,
        "failure_reason": None,
        "is_anomaly": 0,
        "anomaly_type": "benign_mistype"
    })

    # Scenario 8: Unauthorized access to sensitive vault resource
    current_time += timedelta(hours=3)
    events.append({
        "event_id": f"AUTH-{len(events)+1:06d}",
        "timestamp": current_time.isoformat(),
        "user_id": "heidi.intern@sentinel.internal",
        "source_ip": "10.100.2.80",
        "event_type": "privilege_escalation",
        "status": "blocked",
        "auth_method": "password",
        "user_agent": USER_AGENTS[2],
        "resource_requested": "/admin/database_dump",
        "risk_score": 0.89,
        "failure_reason": "insufficient_permissions",
        "is_anomaly": 1,
        "anomaly_type": "sensitive_resource_access"
    })

    return events


def generate_and_save_auth_dataset(count_normal: int = 2500) -> Path:
    raw_auth_dir = RAW_DATA_DIR / "authentication"
    raw_auth_dir.mkdir(parents=True, exist_ok=True)
    
    start_time = datetime(2026, 10, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = generate_scenario_events(start_time, count_normal)

    csv_path = raw_auth_dir / "auth_events_synthetic.csv"
    jsonl_path = raw_auth_dir / "auth_events_synthetic.jsonl"

    df = pd.DataFrame(events)
    df.to_csv(csv_path, index=False)

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    sha256_csv = compute_sha256(csv_path)
    file_size = csv_path.stat().st_size

    anomaly_distribution = df["anomaly_type"].value_counts().to_dict()
    label_distribution = df["is_anomaly"].value_counts().to_dict()

    manifest = {
        "dataset_name": "sentinel_auth_events_synthetic",
        "source_url": "internal://sentinel/synthetic/auth_events_generator_v1",
        "original_filename": csv_path.name,
        "retrieval_timestamp": datetime.now(timezone.utc).isoformat(),
        "file_size_bytes": file_size,
        "sha256_checksum": sha256_csv,
        "is_official_checksum": False,
        "license": "Apache-2.0 (Synthetic Benchmark Dataset)",
        "citation": "SENTINEL AI Synthetic Threat Generation Framework (2026)",
        "original_schema": {
            "event_id": "string",
            "timestamp": "iso8601",
            "user_id": "string (email)",
            "source_ip": "string (ipv4)",
            "event_type": "string",
            "status": "string (success|failure|blocked)",
            "auth_method": "string",
            "user_agent": "string",
            "resource_requested": "string",
            "risk_score": "float",
            "failure_reason": "string|null",
            "is_anomaly": "int (0=normal, 1=anomaly)",
            "anomaly_type": "string"
        },
        "label_definitions": {
            "0": "Normal authentication flow (including benign mistypes)",
            "1": "Security anomaly (brute force, password spray, impossible travel, bursts, sensitive access)"
        },
        "preprocessing_version": "v1.0",
        "record_counts": len(df),
        "missing_value_counts": {k: int(v) for k, v in df.isnull().sum().to_dict().items()},
        "duplicate_counts": int(df.duplicated(subset=["event_id"]).sum()),
        "anomaly_distribution": anomaly_distribution,
        "class_distribution": {"benign_count": int(label_distribution.get(0, 0)), "anomaly_count": int(label_distribution.get(1, 0))},
        "known_limitations": [
            "Synthetic data generated for rule and anomaly baseline calibration.",
            "Does not represent exact production traffic prevalence."
        ]
    }

    manifest_path = MANIFESTS_DIR / "auth_events_manifest.json"
    save_manifest(manifest, manifest_path)
    logger.info(f"Generated {len(df)} synthetic auth events saved to {csv_path}")
    return csv_path


if __name__ == "__main__":
    generate_and_save_auth_dataset()
