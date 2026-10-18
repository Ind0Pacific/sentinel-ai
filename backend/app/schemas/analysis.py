"""
SENTINEL AI — Analysis & Inference Schemas
Defines request and response models for real-time security analysis endpoints.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# URL Analysis
class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL string to analyze without network requests")


class URLAnalysisResponse(BaseModel):
    url: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    verdict: str = Field(..., description="'phishing', 'legitimate', or 'suspicious'")
    model_version: str
    decision_threshold: float
    evidence: Dict[str, Any]
    threat_intel_match: Optional[Dict[str, Any]] = None
    limitations: List[str]


# Network Flow Analysis
class NetworkAnalysisRequest(BaseModel):
    dur: float = 0.5
    proto: str = "tcp"
    service: str = "-"
    state: str = "FIN"
    spkts: int = 10
    dpkts: int = 8
    sbytes: int = 1024
    dbytes: int = 2048
    rate: float = 100.0
    sttl: int = 64
    dttl: int = 64
    sload: float = 50000.0
    dload: float = 100000.0
    sloss: int = 0
    dloss: int = 0
    sinpkt: float = 10.0
    dinpkt: float = 10.0
    sjit: float = 5.0
    djit: float = 5.0
    swin: int = 255
    stcpb: float = 1000000.0
    dtcpb: float = 1000000.0
    dwin: int = 255
    tcprtt: float = 0.05
    synack: float = 0.02
    ackdat: float = 0.03
    smean: float = 100.0
    dmean: float = 200.0
    trans_depth: int = 0
    response_body_len: int = 0
    ct_srv_src: int = 1
    ct_state_ttl: int = 1
    ct_dst_ltm: int = 1
    ct_src_dport_ltm: int = 1
    ct_dst_sport_ltm: int = 1
    ct_dst_src_ltm: int = 1
    is_ftp_login: int = 0
    ct_ftp_cmd: int = 0
    ct_flw_http_mthd: int = 0
    ct_src_ltm: int = 1
    ct_srv_dst: int = 1
    is_sm_ips_ports: int = 0


class NetworkAnalysisResponse(BaseModel):
    intrusion_probability: float
    verdict: str = Field(..., description="'normal' or 'intrusion_detected'")
    confidence: float
    anomaly_flag: bool
    model_version: str
    evidence: Dict[str, Any]
    limitations: List[str]


# Authentication Analysis
class AuthAnalysisRequest(BaseModel):
    user_id: str
    source_ip: str
    status: str = Field("failure", description="'success', 'failure', or 'blocked'")
    auth_method: str = "password"
    resource_requested: str = "/dashboard/overview"
    window_fail_count_ip: int = 0
    window_attempt_count_ip: int = 1
    distinct_users_targeted_ip: int = 1
    burst_rate_per_min: float = 1.0
    success_after_failure_seq: int = 0


class AuthAnalysisResponse(BaseModel):
    risk_score: float
    is_anomaly: bool
    verdict: str
    triggered_rules: List[str]
    fallback_used: bool
    threat_intel_match: Optional[Dict[str, Any]] = None
    model_version: str
