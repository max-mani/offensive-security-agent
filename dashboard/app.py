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

from dashboard import report_store, scan_service  # noqa: E402
from utils.llm_client import resolve_llm_config  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Aivar Offensive Security Agent Dashboard",
    description="Level 1 AWS infrastructure security scan dashboard",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


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

    return {
        "status": "ok",
        "aws_configured": bool(
            os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        ),
        "llm_configured": llm_ok,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "scan_state": scan_service.get_status()["state"],
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
    if not scan_service.start_scan("checklist.yaml"):
        raise HTTPException(status_code=409, detail="A scan is already running.")
    return {"message": "Scan started", "status": scan_service.get_status()}


@app.get("/api/scans/status")
async def scan_status():
    return scan_service.get_status()
