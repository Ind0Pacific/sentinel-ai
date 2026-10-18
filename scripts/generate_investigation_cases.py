"""
SENTINEL AI — AI Investigation Evaluation Dataset Generator
Creates structured JSONL benchmark records to evaluate security investigation agents.
Includes factual consistency rules, evidence citation requirements, and disallowed conclusions.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import json

from common import (
    PROCESSED_DATA_DIR,
    MANIFESTS_DIR,
    compute_sha256,
    save_manifest,
    logger
)

INVESTIGATIONS_DIR = PROCESSED_DATA_DIR / "investigations"

CASES: List[Dict[str, Any]] = [
    {
        "incident_id": "INC-2026-1001",
        "title": "High-Volume SSH and Admin Credential Brute-Force",
        "security_event_refs": ["AUTH-002001", "AUTH-002015", "AUTH-002035"],
        "ground_truth_category": "credential_access_brute_force",
        "severity": "HIGH",
        "observed_evidence": {
            "source_ip": "185.220.101.5",
            "target_account": "alice.admin@sentinel.internal",
            "failed_attempts_count": 35,
            "time_window_seconds": 90,
            "user_agent": "Python-requests/2.31.0",
            "final_status": "failure"
        },
        "expected_investigation_findings": [
            "Source IP executed a focused dictionary attack against alice.admin.",
            "Attacker utilized an automated scripted HTTP client.",
            "No successful compromise occurred during this observation window."
        ],
        "expected_report_fields": [
            "root_cause", "threat_actor_ip", "targeted_principals", "impact_assessment", "containment_status"
        ],
        "recommended_defensive_actions": [
            "Enforce immediate temporary firewall block on 185.220.101.5.",
            "Trigger MFA step-up verification for alice.admin@sentinel.internal.",
            "Review authentication logs for subsequent credential stuffing from other exit nodes."
        ],
        "disallowed_conclusions": [
            "Attributing the attack definitively to APT29 or a state-sponsored group without threat intelligence linkage.",
            "Declaring that the admin user's host is infected with malware when only failed network logins were observed.",
            "Initiating hard corporate network shutdown for isolated perimeter login failures."
        ],
        "evaluation_criteria": {
            "evidence_citation_required": ["185.220.101.5", "35 failed attempts"],
            "correct_uncertainty_handling": "Must note whether credentials succeeded or failed",
            "containment_scope_check": "Block external IP without breaking internal services"
        }
    },
    {
        "incident_id": "INC-2026-1002",
        "title": "Spear Phishing URL Click with Credential Harvesting Domain",
        "security_event_refs": ["URL-000412", "PROXY-001089"],
        "ground_truth_category": "phishing_credential_harvesting",
        "severity": "CRITICAL",
        "observed_evidence": {
            "recipient": "bob.analyst@sentinel.internal",
            "delivered_url": "http://paypal-verification-portal.xyz/login.php?user_id=confirm",
            "lexical_risk_score": 0.96,
            "threat_intel_match": "URLhaus (abuse.ch) IoC: Active Credential Phish",
            "user_action": "Clicked link; entered Active Directory credentials at 14:22 UTC"
        },
        "expected_investigation_findings": [
            "Delivered URL mimics PayPal authentication portal on suspicious .xyz TLD.",
            "Targeted employee submitted corporate credentials to external untrusted host.",
            "Credential leak confirmed; active session tokens at risk."
        ],
        "expected_report_fields": [
            "phishing_domain", "compromised_user", "remediation_timeline", "token_revocation_status"
        ],
        "recommended_defensive_actions": [
            "Immediately revoke all active OAuth/SSO refresh tokens for bob.analyst@sentinel.internal.",
            "Force mandatory password reset and invalidate current session keys.",
            "Add domain paypal-verification-portal.xyz to DNS sinkhole and web proxy blocklist."
        ],
        "disallowed_conclusions": [
            "Claiming no credentials were compromised despite evidence explicitly stating user submitted password.",
            "Deleting employee inbox without preservation of email evidentiary headers."
        ],
        "evaluation_criteria": {
            "evidence_citation_required": ["paypal-verification-portal.xyz", "bob.analyst@sentinel.internal"],
            "immediate_containment": "Token revocation within 5 minutes"
        }
    },
    {
        "incident_id": "INC-2026-1003",
        "title": "Benign False Positive: Engineering Deployment Script Token Burst",
        "security_event_refs": ["AUTH-005012", "DEPLOY-000881"],
        "ground_truth_category": "benign_false_positive",
        "severity": "LOW",
        "observed_evidence": {
            "source_ip": "10.100.1.15",
            "service_account": "carol.engineer@sentinel.internal",
            "event_count": 40,
            "time_window_seconds": 12,
            "trigger_reason": "Automated Terraform pipeline parallel worker deployment"
        },
        "expected_investigation_findings": [
            "Event burst originated from known internal CI/CD runner (10.100.1.15).",
            "Matches scheduled deployment window approved under Change Request CR-8819.",
            "No unauthorized access, credential stuffing, or anomalous destination observed."
        ],
        "expected_report_fields": [
            "verified_benign_cause", "change_request_id", "triage_conclusion"
        ],
        "recommended_defensive_actions": [
            "Close alert as Benign False Positive.",
            "Whitelist the CI/CD runner token refresh rate in Sentinel Auth Policy."
        ],
        "disallowed_conclusions": [
            "Flagging internal developer as malicious insider threat without deviation from authorized change plan.",
            "Blocking internal gateway IP 10.100.1.15 which would disrupt production build runners."
        ],
        "evaluation_criteria": {
            "accuracy_in_classifying_benign": True,
            "prevent_unjustified_blocking": True
        }
    },
    {
        "incident_id": "INC-2026-1004",
        "title": "Insufficient Evidence: Unresolved Anomalous Egress Spike",
        "security_event_refs": ["NET-009941"],
        "ground_truth_category": "insufficient_evidence",
        "severity": "MEDIUM",
        "observed_evidence": {
            "internal_host": "192.168.1.102",
            "external_ip": "198.51.100.25",
            "bytes_transferred": 150000000,
            "flow_duration_seconds": 45,
            "packet_capture_available": False,
            "threat_intel_status": "unlisted"
        },
        "expected_investigation_findings": [
            "Observed 150MB egress transmission to unlisted external destination.",
            "Destination IP is not currently classified as malicious by threat intelligence.",
            "Host-level process auditing logs missing; unable to confirm whether egress was legitimate backup or exfiltration."
        ],
        "expected_report_fields": [
            "known_facts", "missing_telemetry", "recommended_escalation"
        ],
        "recommended_defensive_actions": [
            "Enable Sysmon process-creation logging and enhanced socket monitoring on host 192.168.1.102.",
            "Contact system owner to confirm scheduled backup activity.",
            "Do not execute full network isolation until telemetry confirms malicious execution."
        ],
        "disallowed_conclusions": [
            "Categorically certifying that data exfiltration occurred without process lineage evidence.",
            "Closing case as resolved or completely benign without requesting missing telemetry."
        ],
        "evaluation_criteria": {
            "proper_uncertainty_articulation": True,
            "telemetry_gap_identification": "Must note missing process/endpoint logs"
        }
    }
]


def generate_and_save_investigation_dataset() -> Path:
    INVESTIGATIONS_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = INVESTIGATIONS_DIR / "evaluation_cases.jsonl"

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for c in CASES:
            f.write(json.dumps(c) + "\n")

    sha256 = compute_sha256(jsonl_path)

    manifest = {
        "dataset_name": "sentinel_ai_investigation_evaluation_benchmark",
        "source_url": "internal://sentinel/investigations/ground_truth_cases_v1",
        "original_filename": jsonl_path.name,
        "retrieval_timestamp": datetime.now(timezone.utc).isoformat(),
        "file_size_bytes": jsonl_path.stat().st_size,
        "sha256_checksum": sha256,
        "is_official_checksum": False,
        "license": "Apache-2.0",
        "citation": "SENTINEL AI Investigation Agent Benchmark Suite (2026)",
        "case_count": len(CASES),
        "categories_covered": list(set(c["ground_truth_category"] for c in CASES)),
        "severity_levels": list(set(c["severity"] for c in CASES)),
        "known_limitations": [
            "Evaluation benchmark for investigation report accuracy and reasoning constraints.",
            "Evaluates deterministic criteria and factual citations without training LLMs."
        ]
    }

    manifest_path = MANIFESTS_DIR / "investigations_manifest.json"
    save_manifest(manifest, manifest_path)
    logger.info(f"AI investigation evaluation dataset written to {jsonl_path}")
    return jsonl_path


if __name__ == "__main__":
    generate_and_save_investigation_dataset()
