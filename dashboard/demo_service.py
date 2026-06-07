"""Full demo pipeline: setup → verify → scan."""

import time

from dashboard import job_service, misconfig_service, scan_service

FULL_DEMO_STEPS = [
    {"id": "demo_setup", "label": "Step 1: Create 5 test misconfigs (admin)", "status": "pending", "detail": ""},
    {"id": "demo_verify", "label": "Step 2: Verify scanner sees all resources", "status": "pending", "detail": ""},
    {"id": "demo_scan", "label": "Step 3: Run security scan", "status": "pending", "detail": ""},
    {"id": "demo_done", "label": "Step 4: Load findings report", "status": "pending", "detail": ""},
]


def _full_demo_worker() -> None:
    # Step 1: Setup (synchronous — avoids nested job_service)
    job_service.update_step("demo_setup", "running")
    misconfig_service.create_misconfigs_sync()
    job_service.update_step("demo_setup", "completed", "5 resources created")

    # Step 2: Verify
    job_service.update_step("demo_verify", "running")
    data = misconfig_service.verify_misconfigs()
    if not data["all_pass"]:
        job_service.update_step(
            "demo_verify", "failed", f"{data['passed']}/{data['total']} visible"
        )
        raise RuntimeError(f"Verify failed: {data['passed']}/{data['total']} resources visible")
    job_service.update_step("demo_verify", "completed", "5/5 PASS")

    # Step 3: Scan
    job_service.update_step("demo_scan", "running")
    if not scan_service.start_scan("checklist.yaml"):
        raise RuntimeError("Could not start scan")
    while scan_service.is_running():
        time.sleep(1)
    scan_status = scan_service.get_status()
    if scan_status["state"] == "failed":
        job_service.update_step("demo_scan", "failed", scan_status.get("error", ""))
        raise RuntimeError(scan_status.get("error") or "Scan failed")
    if scan_status.get("report_file"):
        job_service.update_step(
            "demo_scan",
            "completed",
            f"Report: {scan_status['report_file']}",
        )
    else:
        job_service.update_step("demo_scan", "completed", "Scan finished")

    job_service.update_step("demo_done", "completed", "Open findings table below")
    job_service.complete_job(
        {
            "report_file": scan_status.get("report_file"),
            "verify": data,
            "message": "Full demo complete — expect ~8 findings",
        }
    )


def start_full_demo() -> bool:
    if job_service.is_busy() or scan_service.is_running():
        return False
    steps = [dict(s) for s in FULL_DEMO_STEPS]
    return job_service.start_job("full_demo", steps, _full_demo_worker)
