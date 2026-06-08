"""Load and list scan reports from the reports/ directory."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"


class ReportSummary(BaseModel):
    filename: str
    scan_id: str
    scan_name: str
    scan_level: int = 1
    start_time: str
    end_time: str
    duration_seconds: float
    aws_account_id: str
    aws_region: str
    scan_health: str
    total_findings: int
    total_checks_attempted: int
    total_checks_errored: int
    findings_by_severity: dict[str, int]
    metrics_headline: str | None = None
    f1_score: float | None = None


def _reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _refresh_report_metrics(data: dict[str, Any]) -> dict[str, Any]:
    from metrics.calculator import MetricsCalculator

    return MetricsCalculator().refresh_report_metrics(data)


def list_reports() -> list[ReportSummary]:
    """List all JSON reports, newest first."""
    summaries: list[ReportSummary] = []
    for path in sorted(_reports_dir().glob("findings_report_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data = _refresh_report_metrics(data)
            metrics = data.get("metrics") or {}
            detection = metrics.get("detection") or {}
            summaries.append(
                ReportSummary(
                    filename=path.name,
                    scan_id=data.get("scan_id", ""),
                    scan_name=data.get("scan_name", ""),
                    scan_level=int(data.get("scan_level", 1)),
                    start_time=str(data.get("start_time", "")),
                    end_time=str(data.get("end_time", "")),
                    duration_seconds=float(data.get("duration_seconds", 0)),
                    aws_account_id=data.get("aws_account_id", ""),
                    aws_region=data.get("aws_region", ""),
                    scan_health=data.get("scan_health", "unknown"),
                    total_findings=int(data.get("total_findings", 0)),
                    total_checks_attempted=int(data.get("total_checks_attempted", 0)),
                    total_checks_errored=int(data.get("total_checks_errored", 0)),
                    findings_by_severity=data.get("findings_by_severity", {}),
                    metrics_headline=metrics.get("headline"),
                    f1_score=detection.get("f1_score"),
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return summaries


def load_report(filename: str) -> dict[str, Any] | None:
    """Load a full report by filename."""
    path = _reports_dir() / filename
    if not path.exists() or not path.name.startswith("findings_report_"):
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return _refresh_report_metrics(data)


def load_latest_report(level: int | None = None) -> dict[str, Any] | None:
    """Load the most recent report, optionally filtered by scan level."""
    reports = list_reports()
    if level is not None:
        reports = [r for r in reports if r.scan_level == level]
    if not reports:
        return None
    return load_report(reports[0].filename)


def delete_report(filename: str) -> bool:
    """Delete a report JSON (and matching Markdown) by filename."""
    path = _reports_dir() / filename
    if not path.exists() or not path.name.startswith("findings_report_"):
        return False
    path.unlink()
    md_path = path.with_suffix(".md")
    if md_path.exists():
        md_path.unlink()
    return True


def delete_reports(level: int | None = None) -> list[str]:
    """Delete reports, optionally filtered by scan level. Returns deleted filenames."""
    deleted: list[str] = []
    for summary in list_reports():
        if level is not None and summary.scan_level != level:
            continue
        if delete_report(summary.filename):
            deleted.append(summary.filename)
    return deleted
