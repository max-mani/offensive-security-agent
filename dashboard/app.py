"""FastAPI web dashboard for the Offensive Security Agent."""

import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Literal, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from dashboard import daemon_service, demo_service, job_service, l3_service, misconfig_service, report_store, scan_service  # noqa: E402
from utils.llm_client import resolve_llm_config  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Aivar Offensive Security Agent Dashboard",
    description="Level 1, 2 & 3 security scan dashboard",
    version="3.0.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class L3DaemonStartBody(BaseModel):
    schedule_mode: Literal["default", "custom"] = "default"
    interval_hours: Optional[float] = Field(None, ge=0.25, le=168)
    interval_minutes: Optional[float] = Field(None, ge=15, le=10080)


def _any_job_running() -> bool:
    return (
        job_service.is_busy()
        or scan_service.is_running()
        or daemon_service.is_busy()
        or daemon_service.is_daemon_running()
    )


def _level3_deps_ok() -> bool:
    try:
        from agent.runner import check_level3_dependencies

        check_level3_dependencies()
        return True
    except RuntimeError:
        return False


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _lookup_isp(ip: str) -> str:
    if ip in ("unknown", "127.0.0.1", "::1", "localhost"):
        return "Local session"
    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        if resp.ok:
            data = resp.json()
            if data.get("success"):
                conn = data.get("connection") or {}
                return conn.get("isp") or conn.get("org") or "Unknown provider"
    except requests.RequestException:
        pass
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if resp.ok:
            data = resp.json()
            return data.get("org") or data.get("asn") or "Unknown provider"
    except requests.RequestException:
        pass
    return "Unknown provider"


@app.get("/api/client-session")
async def client_session(request: Request):
    """Return the dashboard client's public IP and ISP for session display."""
    ip = _client_ip(request)
    isp = _lookup_isp(ip)
    return {
        "ip": ip,
        "isp": isp,
        "label": f"{ip} · {isp}",
    }


def _level2_deps_ok() -> bool:
    try:
        from agent.runner import check_level2_dependencies

        check_level2_dependencies()
        return True
    except RuntimeError:
        return False


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
        "level2_ready": _level2_deps_ok(),
        "level3_ready": _level3_deps_ok(),
        "slack_configured": bool(os.getenv("SLACK_WEBHOOK_URL")),
        "daemon_state": daemon_service.get_status()["daemon_state"],
        "l3_scan_state": daemon_service.get_status()["l3_scan_state"],
        "scan_state": scan_st["state"],
        "job_state": job_st["state"],
        "active_job": active,
    }


@app.get("/api/reports")
async def list_reports():
    return [r.model_dump() for r in report_store.list_reports()]


@app.get("/api/reports/latest")
async def latest_report(level: int | None = Query(None, ge=1, le=3)):
    report = report_store.load_latest_report(level=level)
    if not report:
        label = f"Level {level} " if level else ""
        raise HTTPException(status_code=404, detail=f"No {label}reports found. Run a scan first.")
    return report


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    report = report_store.load_report(filename)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {filename}")
    return report


@app.delete("/api/reports")
async def delete_reports_bulk(level: int | None = Query(None)):
    """Delete all report files. Optional level=1 or level=2 to filter."""
    if level is not None and level not in (1, 2):
        raise HTTPException(status_code=400, detail="level must be 1 or 2")
    deleted = report_store.delete_reports(level=level)
    if not deleted:
        label = f"Level {level} " if level else ""
        raise HTTPException(status_code=404, detail=f"No {label}reports found to delete.")
    return {
        "message": f"Deleted {len(deleted)} report(s)",
        "deleted": deleted,
        "count": len(deleted),
    }


@app.delete("/api/reports/{filename}")
async def delete_report_endpoint(filename: str):
    if not report_store.delete_report(filename):
        raise HTTPException(status_code=404, detail=f"Report not found: {filename}")
    return {"message": f"Deleted {filename}"}


@app.post("/api/scans/run")
async def run_scan_endpoint(
    level: int = Query(1, ge=1, le=2, description="Scan level: 1=AWS, 2=multi-domain"),
    config: str | None = Query(None, description="Config file path"),
):
    if _any_job_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if level >= 2 and not _level2_deps_ok():
        raise HTTPException(
            status_code=400,
            detail="Level 2 packages missing. Run: pip install -r requirements.txt (in your venv).",
        )
    config_path = config or ("checklist_l2.yaml" if level >= 2 else "checklist.yaml")
    if not scan_service.start_scan(config_path, level=level):
        raise HTTPException(status_code=409, detail="A scan is already running.")
    return {
        "message": f"Level {level} scan started",
        "config": config_path,
        "status": scan_service.get_status(),
    }


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
            detail=".env.admin not configured. Add aivar-admin keys (see README Section 7).",
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


@app.post("/api/l3/run")
async def l3_run_once(config: str | None = Query(None)):
    if _any_job_running() and not daemon_service.is_daemon_running():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if daemon_service.is_busy():
        raise HTTPException(status_code=409, detail="L3 scan already running.")
    if not _level3_deps_ok():
        raise HTTPException(
            status_code=400,
            detail="Level 3 packages missing. Run: pip install -r requirements.txt",
        )
    config_path = config or "checklist_l3.yaml"
    if not daemon_service.run_once(config_path):
        raise HTTPException(status_code=409, detail="L3 scan or daemon already active.")
    return {"message": "Level 3 scan started", "status": daemon_service.get_status()}


@app.post("/api/l3/daemon/start")
async def l3_daemon_start(
    body: L3DaemonStartBody | None = None,
    config: str | None = Query(None),
):
    if scan_service.is_running() or job_service.is_busy():
        raise HTTPException(status_code=409, detail="Another operation is already running.")
    if daemon_service.is_daemon_running():
        raise HTTPException(status_code=409, detail="Daemon already running.")
    if not _level3_deps_ok():
        raise HTTPException(status_code=400, detail="Level 3 packages missing.")
    config_path = config or "checklist_l3.yaml"
    opts = body or L3DaemonStartBody()
    if not daemon_service.start_daemon(
        config_path,
        schedule_mode=opts.schedule_mode,
        interval_hours=opts.interval_hours,
        interval_minutes=opts.interval_minutes,
    ):
        raise HTTPException(status_code=409, detail="Failed to start daemon.")
    return {"message": "Daemon started", "status": daemon_service.get_status()}


@app.post("/api/l3/daemon/stop")
async def l3_daemon_stop():
    if not daemon_service.stop_daemon():
        raise HTTPException(status_code=409, detail="Daemon is not running.")
    return {"message": "Daemon stopped", "status": daemon_service.get_status()}


@app.get("/api/l3/daemon/status")
async def l3_daemon_status():
    return daemon_service.get_status()


@app.get("/api/l3/findings")
async def l3_findings(status: str | None = Query(None)):
    return l3_service.get_findings(status=status)


@app.get("/api/l3/audit")
async def l3_audit(limit: int = Query(50, ge=1, le=200)):
    return l3_service.get_audit(limit=limit)


@app.get("/api/l3/scan-health")
async def l3_scan_health(scan_run_id: str | None = Query(None)):
    return l3_service.get_scan_health(scan_run_id)


@app.get("/api/l3/trend")
async def l3_trend():
    return l3_service.get_summary()


@app.get("/api/l3/scan-runs")
async def l3_scan_runs(limit: int = Query(30, ge=1, le=100)):
    return l3_service.get_scan_runs(limit=limit)


@app.delete("/api/l3/scan-runs/{run_id}")
async def l3_delete_scan_run(run_id: str):
    if not l3_service.delete_scan_run(run_id):
        raise HTTPException(status_code=404, detail=f"Scan run not found: {run_id}")
    return {"message": f"Deleted scan run {run_id}"}


@app.delete("/api/l3/reset")
async def l3_reset():
    """Clear L3 SQLite data and posture history for a fresh first-run demo."""
    if daemon_service.is_busy():
        raise HTTPException(status_code=409, detail="Cannot reset while an L3 scan is running.")
    if scan_service.is_running() or job_service.is_busy():
        raise HTTPException(status_code=409, detail="Cannot reset while another operation is running.")
    return l3_service.reset_all()


@app.post("/api/l3/trend/generate")
async def l3_trend_generate():
    from config.loader import load_config
    from reporter.trend_reporter import TrendReporter

    config = load_config(PROJECT_ROOT / "checklist_l3.yaml")
    keep_n = 30
    if config.level3:
        keep_n = config.level3.trend_report.keep_last_n_scans
    report = TrendReporter(config.scan.output_dir, keep_last_n=keep_n).generate()
    return report

