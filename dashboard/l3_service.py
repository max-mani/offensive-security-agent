"""Level 3 dashboard data aggregation."""

import json
import os
from pathlib import Path

from metrics.calculator import MetricsCalculator
from metrics.models import DetectionMetrics, SpeedMetrics, CoverageMetrics
from reporter.trend_reporter import compute_posture_score
from storage import findings_store
from storage.database import DB_PATH, init_db

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"


def ensure_db():
    init_db()


def _load_agent_metrics_from_reports() -> dict | None:
    """Load metrics from the newest report JSON that includes a metrics block."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(REPORTS_DIR.glob("findings_report_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            metrics = data.get("metrics")
            if metrics:
                return metrics
        except (json.JSONDecodeError, OSError):
            continue
    return None


def _build_fallback_agent_metrics() -> dict:
    """Build partial metrics from SQLite when no report JSON has metrics."""
    level3 = MetricsCalculator().compute_l3_from_db()
    detection = DetectionMetrics()
    speed = SpeedMetrics(scan_duration_seconds=0.0)
    coverage = CoverageMetrics(
        total_checks_attempted=0,
        checks_succeeded=0,
        checks_errored=0,
        check_success_rate=0.0,
    )
    headline = (
        f"Posture:{level3.current_posture_score}/100 ({level3.posture_trend}) | "
        f"SLA:{level3.sla_compliance_rate * 100:.0f}% | "
        f"Reliability:{level3.scan_reliability_rate * 100:.0f}% | "
        f"F1:N/A"
    )
    return {
        "level": 3,
        "headline": headline,
        "detection": detection.model_dump(),
        "speed": speed.model_dump(),
        "coverage": coverage.model_dump(),
        "level2": None,
        "level3": level3.model_dump(),
    }


def get_summary() -> dict:
    ensure_db()
    findings_store.sync_sla_breached_flags()
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

    open_by_severity = findings_store.get_open_counts_by_severity()
    scan_run_count = findings_store.get_scan_run_count()
    total_findings = findings_store.get_total_findings_count()

    posture_score = None
    if scan_run_count > 0 or total_findings > 0:
        posture_score = compute_posture_score()

    if scan_run_count == 1:
        direction = "first_scan"
    elif scan_run_count == 0:
        direction = "no_data"

    data_inconsistent = scan_run_count == 0 and total_findings > 0

    health_records = findings_store.get_scan_health()
    health_errors = sum(1 for h in health_records if h["status"] == "error")
    health_ok = sum(1 for h in health_records if h["status"] == "success")

    agent_metrics = _load_agent_metrics_from_reports()
    if agent_metrics is None and scan_run_count > 0:
        agent_metrics = _build_fallback_agent_metrics()

    return {
        "posture_score": posture_score,
        "trend_direction": direction,
        "score_delta": round(delta, 1),
        "sla_breached_count": findings_store.get_sla_breached_count(),
        "open_findings_by_severity": open_by_severity,
        "open_critical_count": open_by_severity.get("critical", 0),
        "has_scan_data": scan_run_count > 0,
        "data_inconsistent": data_inconsistent,
        "scan_history": trend_data,
        "latest_scan_run": latest_run,
        "slack_configured": bool(os.getenv("SLACK_WEBHOOK_URL")),
        "agent_metrics": agent_metrics,
        "pipeline": {
            "scan_run_count": findings_store.get_scan_run_count(),
            "total_findings": findings_store.get_total_findings_count(),
            "lifecycle_by_status": findings_store.get_lifecycle_counts(),
            "escalated_count": findings_store.get_escalated_count(),
            "health_errors": health_errors,
            "health_ok": health_ok,
            "db_path": DB_PATH,
        },
    }


def get_findings(status: str | None = None) -> list[dict]:
    ensure_db()
    if status == "open":
        return findings_store.get_open_findings()
    if status in ("re-opened", "resolved", "opened", "updated"):
        return findings_store.get_findings_by_status(status)
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


def delete_scan_run(scan_run_id: str) -> bool:
    ensure_db()
    return findings_store.delete_scan_run(scan_run_id)


def _delete_trend_reports() -> int:
    """Remove generated trend report files from reports/."""
    deleted = 0
    if not REPORTS_DIR.exists():
        return 0
    for pattern in ("trend_report_*.json", "trend_report_*.md"):
        for path in REPORTS_DIR.glob(pattern):
            path.unlink(missing_ok=True)
            deleted += 1
    return deleted


def reset_all() -> dict:
    """Clear SQLite L3 data and trend reports so the next scan starts fresh."""
    ensure_db()
    table_counts = findings_store.clear_all_data()
    trend_deleted = _delete_trend_reports()
    return {
        "message": "Level 3 data reset — next scan will run as first-time",
        "tables_cleared": table_counts,
        "trend_reports_deleted": trend_deleted,
    }
