"""Level 3 dashboard data aggregation."""

import os

from reporter.trend_reporter import compute_posture_score
from storage import findings_store
from storage.database import init_db


def ensure_db():
    init_db()


def get_summary() -> dict:
    ensure_db()
    latest_run = findings_store.get_latest_scan_run()
    runs = findings_store.get_recent_scan_runs(limit=30)

    trend_data = []
    for run in reversed(runs):
        trend_data.append(
            {
                "scan_id": run["id"],
                "timestamp": run["started_at"],
                "posture_score": run["posture_score"],
                "health": run["health"],
                "findings": {
                    "new": run["new_findings"],
                    "critical": run["critical_count"],
                },
            }
        )

    direction = "insufficient_data"
    delta = 0.0
    if len(trend_data) >= 2:
        first_score = trend_data[0]["posture_score"] or 100
        last_score = trend_data[-1]["posture_score"] or 100
        delta = last_score - first_score
        if delta > 5:
            direction = "improving"
        elif delta < -5:
            direction = "degrading"
        else:
            direction = "stable"

    open_by_severity = {}
    for severity in ["critical", "high", "medium", "low"]:
        open_by_severity[severity] = len(
            [f for f in findings_store.get_open_findings(limit=500) if f["severity"] == severity]
        )

    return {
        "posture_score": compute_posture_score(),
        "trend_direction": direction,
        "score_delta": round(delta, 1),
        "sla_breached_count": findings_store.get_sla_breached_count(),
        "open_findings_by_severity": open_by_severity,
        "scan_history": trend_data,
        "latest_scan_run": latest_run,
        "slack_configured": bool(os.getenv("SLACK_WEBHOOK_URL")),
    }


def get_findings(status: str | None = None) -> list[dict]:
    ensure_db()
    if status == "open":
        return findings_store.get_open_findings()
    return findings_store.get_all_findings()


def get_audit(limit: int = 50) -> list[dict]:
    ensure_db()
    return findings_store.get_audit_tail(limit=limit)


def get_scan_health(scan_run_id: str | None = None) -> list[dict]:
    ensure_db()
    return findings_store.get_scan_health(scan_run_id)


def get_scan_runs(limit: int = 30) -> list[dict]:
    ensure_db()
    return findings_store.get_recent_scan_runs(limit=limit)
