"""Security posture trend reporting over time."""

import json
import logging
from datetime import datetime
from pathlib import Path

from storage.database import FindingRecord, ScanRun, get_session

logger = logging.getLogger(__name__)

PENALTY = {
    "critical": 25,
    "critical_breached": 40,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def compute_posture_score(session=None) -> float:
    """Compute current security posture score (0–100)."""
    close_session = False
    if session is None:
        session = get_session()
        close_session = True

    try:
        open_findings = (
            session.query(FindingRecord)
            .filter(FindingRecord.status.in_(["opened", "updated", "re-opened"]))
            .all()
        )

        total_penalty = 0
        for f in open_findings:
            if f.severity == "critical" and f.sla_breached:
                total_penalty += PENALTY["critical_breached"]
            else:
                total_penalty += PENALTY.get(f.severity, 0)

        return round(max(0.0, 100.0 - total_penalty), 1)
    finally:
        if close_session:
            session.close()


class TrendReporter:
    """Generate trend reports from scan_runs history."""

    def __init__(self, output_dir: str = "reports", keep_last_n: int = 30):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.keep_last_n = keep_last_n

    def generate(self) -> dict:
        session = get_session()
        try:
            runs = (
                session.query(ScanRun)
                .order_by(ScanRun.started_at.desc())
                .limit(self.keep_last_n)
                .all()
            )

            if not runs:
                return {"error": "No scan runs found"}

            trend_data = []
            for run in reversed(runs):
                trend_data.append(
                    {
                        "scan_id": run.id,
                        "timestamp": run.started_at.isoformat() if run.started_at else None,
                        "posture_score": run.posture_score,
                        "duration_seconds": run.duration_seconds,
                        "health": run.health,
                        "findings": {
                            "total": run.total_findings,
                            "new": run.new_findings,
                            "critical": run.critical_count,
                            "high": run.high_count,
                            "medium": run.medium_count,
                            "low": run.low_count,
                        },
                    }
                )

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
            else:
                direction = "insufficient_data"
                delta = 0

            open_by_severity = {}
            for severity in ["critical", "high", "medium", "low"]:
                open_by_severity[severity] = (
                    session.query(FindingRecord)
                    .filter(
                        FindingRecord.severity == severity,
                        FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                    )
                    .count()
                )

            sla_breached_count = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.sla_breached == True,  # noqa: E712
                    FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                )
                .count()
            )

            current_score = compute_posture_score(session)

            report = {
                "generated_at": datetime.utcnow().isoformat(),
                "current_posture_score": current_score,
                "trend_direction": direction,
                "score_delta": round(delta, 1),
                "open_findings_by_severity": open_by_severity,
                "sla_breached_count": sla_breached_count,
                "scan_history": trend_data,
                "summary": self._generate_summary(
                    current_score, direction, delta, open_by_severity, sla_breached_count
                ),
            }

            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            json_path = self.output_dir / f"trend_report_{ts}.json"
            json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

            md_path = self.output_dir / f"trend_report_{ts}.md"
            md_path.write_text(self._render_markdown(report), encoding="utf-8")

            logger.info("[trend] Report written: %s, %s", json_path, md_path)
            return report
        finally:
            session.close()

    def _generate_summary(self, score, direction, delta, by_severity, sla_count) -> str:
        direction_text = {
            "improving": f"improving (+{delta:.1f} points since first scan)",
            "degrading": f"degrading ({delta:.1f} points since first scan)",
            "stable": "stable (< 5 point change)",
            "insufficient_data": "insufficient data for trend",
        }.get(direction, direction)

        return (
            f"Current posture score: {score}/100. Environment is {direction_text}. "
            f"Open findings: {by_severity.get('critical', 0)} critical, "
            f"{by_severity.get('high', 0)} high, "
            f"{by_severity.get('medium', 0)} medium. "
            f"SLA breaches: {sla_count}."
        )

    def _render_markdown(self, report: dict) -> str:
        score = report["current_posture_score"]
        lines = [
            "# Security Posture Trend Report",
            f"**Generated:** {report['generated_at']}",
            "",
            "## Current Status",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Posture Score | **{score}/100** |",
            f"| Trend | {report['trend_direction'].upper()} |",
            f"| Score Delta | {report['score_delta']:+.1f} points |",
            f"| SLA Breaches | {report['sla_breached_count']} |",
            "",
            "## Open Findings",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, count in report["open_findings_by_severity"].items():
            lines.append(f"| {sev.capitalize()} | {count} |")

        lines += ["", "## Summary", report["summary"], "", "## Scan History"]
        lines += [
            "| Timestamp | Score | Health | New | Critical |",
            "|-----------|-------|--------|-----|----------|",
        ]
        for run in report["scan_history"]:
            ts = (run["timestamp"] or "")[:16]
            score_val = (
                f"{run['posture_score']:.1f}" if run["posture_score"] is not None else "N/A"
            )
            lines.append(
                f"| {ts} | {score_val} | {run['health']} | "
                f"{run['findings']['new']} | {run['findings']['critical']} |"
            )

        return "\n".join(lines)
