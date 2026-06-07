"""FastAPI web dashboard for the Offensive Security Agent."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from dashboard import demo_service, job_service, misconfig_service, report_store, scan_service  # noqa: E402
from utils.llm_client import resolve_llm_config  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Aivar Offensive Security Agent Dashboard",
    description="Level 1 AWS infrastructure security scan dashboard",
    version="1.1.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _any_job_running() -> bool:
    return job_service.is_busy() or scan_service.is_running()


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health():
    llm_ok = False
    llm_provider = None
    llm_model = None
    try:
        llm = resolve_llm_config()
        llm_ok = True
        llm_provider = llm.provider
        llm_model = llm.model
    except ValueError:
        pass

    scan_st = scan_service.get_status()
    job_st = job_service.get_status()

    active = "idle"
    if scan_st["state"] == "running":
        active = "scan"
    elif job_st["state"] == "running":
        active = job_st.get("job_type") or "job"

    return {
        "status": "ok",
        "aws_configured": bool(
            os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        ),
        "admin_configured": misconfig_service.admin_configured(),
        "llm_configured": llm_ok,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "scan_state": scan_st["state"],
        "job_state": job_st["state"],
        "active_job": active,
    }


@app.get("/api/reports")
async def list_reports():
    return [r.model_dump() for r in report_store.list_reports()]


@app.get("/api/reports/latest")
async def latest_report():
    report = report_store.load_latest_report()
    if not report:
        raise HTTPException(status_code=404, detail="No reports found. Run a scan first.")
    return report


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    report = report_store.load_report(filename)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {filename}")
    return report


@app.post("/api/scans/run")
async def run_scan_endpoint():
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if not scan_service.start_scan("checklist.yaml"):
        raise HTTPException(status_code=409, detail="A scan is already running.")
    return {"message": "Scan started", "status": scan_service.get_status()}


@app.get("/api/scans/status")
async def scan_status():
    return scan_service.get_status()


@app.get("/api/demo/verify")
async def demo_verify():
    """Quick synchronous verify (scanner creds)."""
    if not os.getenv("AWS_ACCESS_KEY_ID"):
        raise HTTPException(status_code=400, detail="Scanner AWS credentials not in .env")
    return misconfig_service.verify_misconfigs()


@app.post("/api/demo/setup")
async def demo_setup():
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if not misconfig_service.admin_configured():
        raise HTTPException(
            status_code=400,
            detail=".env.admin not configured. Add aivar-admin keys (see README §7).",
        )
    if not misconfig_service.start_setup():
        raise HTTPException(status_code=409, detail="Setup already running.")
    return {"message": "Creating test misconfigs", "status": job_service.get_status()}


@app.post("/api/demo/cleanup")
async def demo_cleanup():
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if not misconfig_service.admin_configured():
        raise HTTPException(status_code=400, detail=".env.admin not configured.")
    if not misconfig_service.start_cleanup():
        raise HTTPException(status_code=409, detail="Cleanup already running.")
    return {"message": "Cleaning up test resources", "status": job_service.get_status()}


@app.post("/api/demo/verify-run")
async def demo_verify_run():
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if not misconfig_service.start_verify():
        raise HTTPException(status_code=409, detail="Verify already running.")
    return {"message": "Verifying test resources", "status": job_service.get_status()}


@app.post("/api/demo/full")
async def demo_full():
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if not misconfig_service.admin_configured():
        raise HTTPException(status_code=400, detail=".env.admin not configured.")
    if not demo_service.start_full_demo():
        raise HTTPException(status_code=409, detail="Demo already running.")
    return {"message": "Full demo started", "status": job_service.get_status()}


@app.get("/api/jobs/status")
async def jobs_status():
    """Unified status for setup/cleanup/verify/full_demo jobs."""
    return job_service.get_status()
