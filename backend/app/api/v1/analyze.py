"""
SENTINEL AI — Real-Time Security Analysis Endpoints
Provides high-throughput endpoints for URL lexical analysis, network flow intrusion detection,
and authentication anomaly scoring.
"""

from fastapi import APIRouter, HTTPException

from app.schemas.analysis import (
    URLAnalysisRequest, URLAnalysisResponse,
    NetworkAnalysisRequest, NetworkAnalysisResponse,
    AuthAnalysisRequest, AuthAnalysisResponse
)
from app.services.inference import inference_service

router = APIRouter(prefix="/analyze", tags=["Real-Time Threat Analysis"])


@router.post("/url", response_model=URLAnalysisResponse)
def analyze_url(req: URLAnalysisRequest):
    """
    Analyze a URL string using 22 static lexical features.
    Treats input strictly as untrusted text. NEVER performs HTTP requests, DNS lookups, or crawling.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL parameter cannot be empty.")

    try:
        result = inference_service.analyze_url(req.url)
        return URLAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error during URL analysis: {str(e)}")


@router.post("/network", response_model=NetworkAnalysisResponse)
def analyze_network(req: NetworkAnalysisRequest):
    """
    Analyze a network flow feature dictionary (UNSW-NB15 schema).
    Evaluates intrusion probability and flags novel statistical anomalies.
    """
    try:
        flow_dict = req.model_dump()
        result = inference_service.analyze_network(flow_dict)
        return NetworkAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error during network analysis: {str(e)}")


@router.post("/authentication", response_model=AuthAnalysisResponse)
def analyze_authentication(req: AuthAnalysisRequest):
    """
    Analyze an authentication event or sliding-window aggregation.
    Runs rule-based detection engine and statistical Isolation Forest.
    """
    try:
        req_dict = req.model_dump()
        result = inference_service.analyze_authentication(req_dict)
        return AuthAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error during authentication analysis: {str(e)}")
