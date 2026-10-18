"""
SENTINEL AI — Training & Pipeline Jobs API Endpoints
Manages asynchronous pipeline executions and monitoring of ingestion/training jobs.
"""

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.core.config import REPORTS_DIR, SCRIPTS_DIR

router = APIRouter(prefix="/training/jobs", tags=["Training & Pipeline Jobs"])

JOB_STATE: Dict[str, Dict[str, Any]] = {}


class JobRunRequest(BaseModel):
    mode: str = "lightweight"


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    mode: str
    started_at: str
    completed_at: str = None
    duration_seconds: float = None
    stages: List[Dict[str, Any]] = []
    error: str = None


def run_pipeline_worker(job_id: str, mode: str):
    JOB_STATE[job_id]["status"] = "RUNNING"
    st = time.perf_counter()

    try:
        import sys
        if str(SCRIPTS_DIR) not in sys.path:
            sys.path.insert(0, str(SCRIPTS_DIR))
        from run_pipeline import execute_full_pipeline
        summary = execute_full_pipeline(mode=mode)

        JOB_STATE[job_id]["status"] = "SUCCESS"
        JOB_STATE[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        JOB_STATE[job_id]["duration_seconds"] = summary.get("total_duration_seconds")
        JOB_STATE[job_id]["stages"] = summary.get("stages", [])

        from app.services.inference import inference_service
        inference_service.load_models()
    except Exception as e:
        JOB_STATE[job_id]["status"] = "FAILED"
        JOB_STATE[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        JOB_STATE[job_id]["duration_seconds"] = round(time.perf_counter() - st, 2)
        JOB_STATE[job_id]["error"] = str(e)


@router.post("/run", response_model=JobStatusResponse)
def trigger_pipeline_job(req: JobRunRequest, background_tasks: BackgroundTasks):
    """Trigger a dataset engineering and model training pipeline in the background."""
    job_id = f"JOB-{int(time.time())}"
    JOB_STATE[job_id] = {
        "job_id": job_id,
        "status": "QUEUED",
        "mode": req.mode,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "stages": [],
        "error": None
    }
    background_tasks.add_task(run_pipeline_worker, job_id, req.mode)
    return JobStatusResponse(**JOB_STATE[job_id])


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    """Retrieve the real-time status, stage progression, and errors of a pipeline job."""
    if job_id in JOB_STATE:
        return JobStatusResponse(**JOB_STATE[job_id])

    # Check persisted run reports in reports/training/
    training_reports = list((REPORTS_DIR / "training").glob(f"*{job_id}*.json"))
    if training_reports:
        try:
            data = json.loads(training_reports[0].read_text(encoding="utf-8"))
            return JobStatusResponse(
                job_id=job_id,
                status=data.get("status", "SUCCESS"),
                mode=data.get("mode", "lightweight"),
                started_at=data.get("completed_at", ""),
                completed_at=data.get("completed_at"),
                duration_seconds=data.get("total_duration_seconds"),
                stages=data.get("stages", [])
            )
        except Exception:
            pass

    raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")


@router.get("", response_model=List[JobStatusResponse])
def list_jobs():
    """List recent in-memory and persisted pipeline jobs."""
    jobs = [JobStatusResponse(**v) for v in JOB_STATE.values()]
    # Also load latest persisted report
    persisted = sorted((REPORTS_DIR / "training").glob("pipeline_run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in persisted[:5]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            jid = data.get("pipeline_run_id", p.stem)
            if not any(j.job_id == jid for j in jobs):
                jobs.append(JobStatusResponse(
                    job_id=jid,
                    status=data.get("status", "SUCCESS"),
                    mode=data.get("mode", "lightweight"),
                    started_at=data.get("completed_at", ""),
                    completed_at=data.get("completed_at"),
                    duration_seconds=data.get("total_duration_seconds"),
                    stages=data.get("stages", [])
                ))
        except Exception:
            pass
    return jobs
