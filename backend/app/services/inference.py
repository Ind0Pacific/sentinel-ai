"""
SENTINEL AI — Production Inference Engine
Loads trained model artifacts, executes real-time feature extraction, applies decision
thresholds, queries threat intelligence caches, and falls back to deterministic rules if needed.
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib
import pandas as pd
import numpy as np

# Ensure scripts directory is on path for shared extractors
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from preprocess_phishing import extract_url_lexical_features
from enrich_threat_intel import ThreatIntelStore
from train_auth_anomaly_model import FallbackRuleEngine, FEATURE_COLS as AUTH_FEAT_COLS
from common import MODELS_DIR, logger


class InferenceService:
    def __init__(self):
        self.ti_store = ThreatIntelStore()
        self._phishing_pipeline = None
        self._phishing_meta = None
        self._network_model = None
        self._network_iforest = None
        self._network_meta = None
        self._auth_model = None
        self._auth_scaler = None
        self._auth_meta = None
        self.load_models()

    def load_models(self):
        """Safely load model artifacts from disk if available."""
        # 1. Phishing model
        phish_path = MODELS_DIR / "phishing" / "phishing_detector_v1.joblib"
        phish_meta_path = MODELS_DIR / "phishing" / "phishing_detector_v1_meta.json"
        if phish_path.exists():
            try:
                self._phishing_pipeline = joblib.load(phish_path)
                if phish_meta_path.exists():
                    import json
                    self._phishing_meta = json.loads(phish_meta_path.read_text(encoding="utf-8"))
                logger.info("Loaded Phishing Detector artifact.")
            except Exception as e:
                logger.error(f"Failed to load phishing model: {e}")

        # 2. Network model
        net_path = MODELS_DIR / "network" / "network_detector_v1.joblib"
        net_if_path = MODELS_DIR / "network" / "network_isolation_forest_v1.joblib"
        net_meta_path = MODELS_DIR / "network" / "network_detector_v1_meta.json"
        if net_path.exists():
            try:
                self._network_model = joblib.load(net_path)
                if net_if_path.exists():
                    self._network_iforest = joblib.load(net_if_path)
                if net_meta_path.exists():
                    import json
                    self._network_meta = json.loads(net_meta_path.read_text(encoding="utf-8"))
                logger.info("Loaded Network Intrusion Detector artifact.")
            except Exception as e:
                logger.error(f"Failed to load network model: {e}")

        # 3. Authentication model
        auth_path = MODELS_DIR / "authentication" / "auth_anomaly_detector_v1.joblib"
        auth_scaler_path = MODELS_DIR / "authentication" / "auth_scaler_v1.joblib"
        auth_meta_path = MODELS_DIR / "authentication" / "auth_anomaly_detector_v1_meta.json"
        if auth_path.exists() and auth_scaler_path.exists():
            try:
                self._auth_model = joblib.load(auth_path)
                self._auth_scaler = joblib.load(auth_scaler_path)
                if auth_meta_path.exists():
                    import json
                    self._auth_meta = json.loads(auth_meta_path.read_text(encoding="utf-8"))
                logger.info("Loaded Authentication Anomaly Detector artifact.")
            except Exception as e:
                logger.error(f"Failed to load auth model: {e}")

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL string using lexical extraction + ML pipeline + Threat Intel cache."""
        lex_features = extract_url_lexical_features(url)
        domain = lex_features.get("domain_group", "")

        # Threat Intel enrichment
        ti_enrichment = self.ti_store.enrich(domain)
        if not ti_enrichment["found"]:
            ti_enrichment = self.ti_store.enrich(url)

        threshold = (self._phishing_meta or {}).get("decision_threshold", 0.50)
        version = (self._phishing_meta or {}).get("model_version", "v1.0.0")

        # Fallback if ML model is missing
        if self._phishing_pipeline is None:
            # Deterministic heuristic fallback
            score = 0.10
            if lex_features.get("is_ip_address", 0) == 1:
                score += 0.45
            if lex_features.get("is_suspicious_tld", 0) == 1:
                score += 0.35
            if lex_features.get("has_security_keyword", 0) == 1:
                score += 0.25
            if ti_enrichment.get("malicious"):
                score = 0.99
            risk_score = min(1.0, score)
            verdict = "phishing" if risk_score >= threshold else ("suspicious" if risk_score >= 0.4 else "legitimate")
            return {
                "url": url,
                "risk_score": round(risk_score, 4),
                "verdict": verdict,
                "model_version": f"{version}-fallback",
                "decision_threshold": threshold,
                "evidence": lex_features,
                "threat_intel_match": ti_enrichment if ti_enrichment["found"] else None,
                "limitations": ["Model artifact was loaded in heuristic fallback mode."]
            }

        # Format input DataFrame matching training feature columns
        expected_features = (self._phishing_meta or {}).get("features", [])
        if not expected_features:
            expected_features = [k for k in lex_features.keys() if k != "domain_group"]

        input_df = pd.DataFrame([{col: lex_features.get(col, 0) for col in expected_features}])
        probs = self._phishing_pipeline.predict_proba(input_df)[0]
        ml_risk_score = float(probs[1])

        # If threat intel has direct verified match, adjust score accordingly
        if ti_enrichment.get("malicious"):
            ml_risk_score = max(ml_risk_score, 0.98)

        verdict = "phishing" if ml_risk_score >= threshold else ("suspicious" if ml_risk_score >= 0.40 else "legitimate")

        return {
            "url": url,
            "risk_score": round(ml_risk_score, 4),
            "verdict": verdict,
            "model_version": version,
            "decision_threshold": threshold,
            "evidence": {
                "url_length": lex_features["url_length"],
                "hostname_length": lex_features["hostname_length"],
                "is_ip_address": lex_features["is_ip_address"],
                "is_suspicious_tld": lex_features["is_suspicious_tld"],
                "has_security_keyword": lex_features["has_security_keyword"],
                "url_entropy": lex_features["url_entropy"],
                "hostname_entropy": lex_features["hostname_entropy"]
            },
            "threat_intel_match": ti_enrichment if ti_enrichment["found"] else None,
            "limitations": [
                "Analysis performed strictly via static lexical features without DNS resolution or content retrieval.",
                "High-reputation compromised domains require additional endpoint and traffic telemetry."
            ]
        }

    def analyze_network(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network flow features against Random Forest classifier and Isolation Forest."""
        version = (self._network_meta or {}).get("model_version", "v1.0.0")
        expected_features = (self._network_meta or {}).get("features", [])

        if self._network_model is None or not expected_features:
            # Deterministic fallback
            dur = flow_dict.get("dur", 0.0)
            rate = flow_dict.get("rate", 0.0)
            is_attack = 1 if (rate > 20000.0 or dur > 2.0) else 0
            prob = 0.85 if is_attack else 0.15
            return {
                "intrusion_probability": prob,
                "verdict": "intrusion_detected" if is_attack else "normal",
                "confidence": 0.80,
                "anomaly_flag": bool(is_attack),
                "model_version": f"{version}-fallback",
                "evidence": {"rate": rate, "dur": dur},
                "limitations": ["Model artifact was evaluated in fallback mode."]
            }

        # Build feature vector matching encoded columns
        row = {f: 0 for f in expected_features}
        for k, v in flow_dict.items():
            if k in row:
                row[k] = v
            # check encoded categorical forms (e.g. proto_tcp, service_http, state_FIN)
            encoded_key = f"{k}_{v}"
            if encoded_key in row:
                row[encoded_key] = 1

        input_df = pd.DataFrame([row])
        probs = self._network_model.predict_proba(input_df)[0]
        intrusion_prob = float(probs[1])

        # Anomaly scoring
        is_anomaly = False
        if self._network_iforest:
            try:
                if_pred = self._network_iforest.predict(input_df)[0]
                is_anomaly = (if_pred == -1)
            except Exception:
                pass

        verdict = "intrusion_detected" if intrusion_prob >= 0.50 else "normal"

        return {
            "intrusion_probability": round(intrusion_prob, 4),
            "verdict": verdict,
            "confidence": round(max(intrusion_prob, 1.0 - intrusion_prob), 4),
            "anomaly_flag": is_anomaly,
            "model_version": version,
            "evidence": {
                "dur": flow_dict.get("dur"),
                "rate": flow_dict.get("rate"),
                "sbytes": flow_dict.get("sbytes"),
                "dbytes": flow_dict.get("dbytes"),
                "spkts": flow_dict.get("spkts"),
                "dpkts": flow_dict.get("dpkts")
            },
            "limitations": [
                "Evaluates tabular flow attributes without full payload inspection.",
                "Volumetric spikes may indicate legitimate backups if not correlated with host logs."
            ]
        }

    def analyze_authentication(self, req_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze authentication event using FallbackRuleEngine + Isolation Forest."""
        user = req_dict.get("user_id", "")
        ip = req_dict.get("source_ip", "")
        status = req_dict.get("status", "failure")
        res = req_dict.get("resource_requested", "")

        ti_match = self.ti_store.enrich(ip)
        is_threat_ip = 1 if ti_match.get("malicious") else 0
        is_sensitive = 1 if any(res.startswith(p) for p in ("/admin", "/api/v1/keys", "/system")) else 0

        # Construct feature dictionary for rule engine and model
        feat_dict = {
            "is_failure": 1 if status == "failure" else 0,
            "is_success": 1 if status == "success" else 0,
            "is_blocked": 1 if status == "blocked" else 0,
            "is_sensitive_resource": is_sensitive,
            "is_off_hours": 0,
            "is_known_threat_ip": is_threat_ip,
            "window_fail_count_ip": req_dict.get("window_fail_count_ip", 0),
            "window_attempt_count_ip": req_dict.get("window_attempt_count_ip", 1),
            "distinct_users_targeted_ip": req_dict.get("distinct_users_targeted_ip", 1),
            "success_after_failure_seq": req_dict.get("success_after_failure_seq", 0),
            "fail_ratio_10m": round(req_dict.get("window_fail_count_ip", 0) / max(1, req_dict.get("window_attempt_count_ip", 1)), 4),
            "burst_rate_per_min": req_dict.get("burst_rate_per_min", 1.0)
        }

        # 1. Rule Engine evaluation
        rule_anom, rule_score, triggered_rules = FallbackRuleEngine.evaluate(feat_dict)

        # 2. Statistical model evaluation
        stat_anom = False
        fallback_used = False
        stat_score = 0.0

        if self._auth_model and self._auth_scaler:
            try:
                row_df = pd.DataFrame([feat_dict])[AUTH_FEAT_COLS].fillna(0)
                scaled_x = self._auth_scaler.transform(row_df)
                raw_score = float(self._auth_model.score_samples(scaled_x)[0])
                stat_score = min(1.0, max(0.0, 1.0 - (raw_score + 0.5)))
                stat_anom = stat_score >= 0.75
            except Exception as e:
                logger.warning(f"Auth model inference error; falling back to rule engine: {e}")
                fallback_used = True
        else:
            fallback_used = True

        combined_score = max(rule_score, stat_score)
        is_anom = rule_anom or stat_anom
        verdict = "anomaly_detected" if is_anom else "normal"

        return {
            "risk_score": round(combined_score, 4),
            "is_anomaly": is_anom,
            "verdict": verdict,
            "triggered_rules": triggered_rules,
            "fallback_used": fallback_used,
            "threat_intel_match": ti_match if ti_match["found"] else None,
            "model_version": (self._auth_meta or {}).get("model_version", "v1.0.0")
        }


inference_service = InferenceService()
