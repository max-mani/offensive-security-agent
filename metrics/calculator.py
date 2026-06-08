import logging
from datetime import datetime
from typing import List, Optional

from metrics.ground_truth import compute_verified_recall
from metrics.models import (
    AgentMetrics,
    CoverageMetrics,
    DetectionMetrics,
    Level2Metrics,
    Level3Metrics,
    SpeedMetrics,
)
from models.finding import ValidatedFinding
from models.report import ScanReport

logger = logging.getLogger(__name__)


class MetricsCalculator:
    """Computes all performance metrics for the scan report."""

    def compute_l1(
        self, report: ScanReport, start_time: datetime, end_time: datetime
    ) -> AgentMetrics:
        detection = self._compute_detection(report.findings)
        speed = self._compute_speed(report, start_time, end_time)
        coverage = self._compute_coverage(report)

        metrics = AgentMetrics(
            level=1,
            detection=detection,
            speed=speed,
            coverage=coverage,
            headline=self._headline_l1(detection, speed, coverage),
        )
        logger.info("[metrics] %s", metrics.headline)
        return metrics

    def compute_l2(
        self,
        report: ScanReport,
        start_time: datetime,
        end_time: datetime,
        total_before_dedup: int,
        domain_results: dict,
    ) -> AgentMetrics:
        detection = self._compute_detection(report.findings)
        speed = self._compute_speed(report, start_time, end_time)
        coverage = self._compute_coverage(report)
        level2 = self._compute_l2_extras(report, total_before_dedup, domain_results)

        metrics = AgentMetrics(
            level=2,
            detection=detection,
            speed=speed,
            coverage=coverage,
            level2=level2,
            headline=self._headline_l2(detection, speed, coverage, level2),
        )
        logger.info("[metrics] %s", metrics.headline)
        return metrics

    def compute_l3(
        self,
        report: ScanReport,
        start_time: datetime,
        end_time: datetime,
        total_before_dedup: int,
        domain_results: dict,
    ) -> AgentMetrics:
        detection = self._compute_detection(report.findings)
        speed = self._compute_speed(report, start_time, end_time)
        coverage = self._compute_coverage(report)
        level2 = self._compute_l2_extras(report, total_before_dedup, domain_results)
        level3 = self.compute_l3_from_db()

        metrics = AgentMetrics(
            level=3,
            detection=detection,
            speed=speed,
            coverage=coverage,
            level2=level2,
            level3=level3,
            headline=self._headline_l3(detection, speed, level3),
        )
        logger.info("[metrics] %s", metrics.headline)
        return metrics

    def compute_l3_from_db(self) -> Level3Metrics:
        """Query DB for temporal and reliability metrics (public for dashboard fallback)."""
        try:
            from reporter.trend_reporter import compute_posture_score
            from storage.database import FindingRecord, ScanRun, get_session

            session = get_session()

            total_opened = session.query(FindingRecord).count()
            total_resolved = (
                session.query(FindingRecord)
                .filter(FindingRecord.status == "resolved")
                .count()
            )
            total_reopened = (
                session.query(FindingRecord)
                .filter(FindingRecord.status == "re-opened")
                .count()
            )

            resolution_rate = total_resolved / total_opened if total_opened else 0
            recurrence_rate = total_reopened / total_resolved if total_resolved else 0

            resolved_records = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.status == "resolved",
                    FindingRecord.sla_deadline.isnot(None),
                )
                .all()
            )
            resolved_within_sla = sum(
                1
                for r in resolved_records
                if r.resolved_at and r.sla_deadline and r.resolved_at <= r.sla_deadline
            )
            sla_compliance = (
                resolved_within_sla / len(resolved_records) if resolved_records else 1.0
            )

            active_sla_breaches = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.sla_breached.is_(True),
                    FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                )
                .count()
            )

            total_runs = session.query(ScanRun).count()
            successful_runs = (
                session.query(ScanRun)
                .filter(ScanRun.health.in_(["healthy", "degraded"]))
                .count()
            )
            scan_reliability = successful_runs / total_runs if total_runs else 1.0

            durations = [
                r.duration_seconds
                for r in session.query(ScanRun).all()
                if r.duration_seconds
            ]
            avg_duration = sum(durations) / len(durations) if durations else 0

            recent_runs = (
                session.query(ScanRun)
                .filter(ScanRun.posture_score.isnot(None))
                .order_by(ScanRun.started_at.desc())
                .limit(10)
                .all()
            )
            if len(recent_runs) >= 2:
                first_score = recent_runs[-1].posture_score
                last_score = recent_runs[0].posture_score
                delta = last_score - first_score
                trend = (
                    "improving"
                    if delta > 2
                    else ("degrading" if delta < -2 else "stable")
                )
            else:
                delta = 0
                trend = "insufficient_data"

            current_score = compute_posture_score(session)

            session.close()

            return Level3Metrics(
                total_findings_opened=total_opened,
                total_findings_resolved=total_resolved,
                resolution_rate=round(resolution_rate, 4),
                recurrence_rate=round(recurrence_rate, 4),
                sla_compliance_rate=round(sla_compliance, 4),
                active_sla_breaches=active_sla_breaches,
                total_scan_runs=total_runs,
                successful_scan_runs=successful_runs,
                scan_reliability_rate=round(scan_reliability, 4),
                avg_scan_duration_seconds=round(avg_duration, 2),
                current_posture_score=current_score,
                posture_trend=trend,
                posture_delta=round(delta, 1),
            )

        except Exception as e:
            logger.warning("[metrics] L3 DB metrics failed: %s", e)
            return Level3Metrics()

    def _compute_detection(self, findings: List[ValidatedFinding]) -> DetectionMetrics:
        if not findings:
            return DetectionMetrics()

        confidence_scores = [f.confidence_score for f in findings]
        avg_conf = sum(confidence_scores) / len(confidence_scores)
        high_conf = sum(1 for s in confidence_scores if s >= 80)

        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        known_found, known_total, verified_recall = compute_verified_recall(findings)

        critical_findings = [f for f in findings if f.severity == "critical"]
        fp_critical = sum(1 for f in critical_findings if f.confidence_score < 70)
        verified_precision_critical = (
            (len(critical_findings) - fp_critical) / len(critical_findings)
            if critical_findings
            else 1.0
        )

        p_val = verified_precision_critical or 1.0
        r_val = verified_recall or 0.0
        f1 = (2 * p_val * r_val / (p_val + r_val)) if (p_val + r_val) > 0 else 0.0

        return DetectionMetrics(
            known_misconfigs_total=known_total,
            known_misconfigs_found=known_found,
            verified_recall=round(verified_recall, 4) if verified_recall is not None else None,
            verified_precision_critical=round(verified_precision_critical, 4),
            false_positives_critical=fp_critical,
            f1_score=round(f1, 4),
            avg_confidence_score=round(avg_conf, 1),
            min_confidence_score=min(confidence_scores),
            max_confidence_score=max(confidence_scores),
            high_confidence_pct=round(high_conf / len(confidence_scores) * 100, 1),
            estimated_precision=round(avg_conf / 100, 4),
            estimated_false_positive_rate=round(1 - avg_conf / 100, 4),
            findings_by_severity=severity_counts,
            critical_findings_count=len(critical_findings),
        )

    def _compute_speed(
        self, report: ScanReport, start: datetime, end: datetime
    ) -> SpeedMetrics:
        duration = (end - start).total_seconds()
        total_checks = report.total_checks_attempted

        return SpeedMetrics(
            scan_duration_seconds=round(duration, 2),
            avg_check_duration_ms=round(
                (duration / total_checks * 1000) if total_checks else 0, 1
            ),
            resources_scanned=len({f.resource_arn for f in report.findings}),
            findings_per_second=round(
                report.total_findings / duration if duration > 0 else 0, 2
            ),
        )

    def _compute_coverage(self, report: ScanReport) -> CoverageMetrics:
        attempted = report.total_checks_attempted
        succeeded = report.total_checks_succeeded
        errored = report.total_checks_errored

        return CoverageMetrics(
            total_checks_attempted=attempted,
            checks_succeeded=succeeded,
            checks_errored=errored,
            check_success_rate=round(succeeded / attempted if attempted else 0, 4),
            resources_checked=len({f.resource_arn for f in report.findings}),
            infrastructure_coverage_pct=round(
                succeeded / attempted * 100 if attempted else 0, 1
            ),
        )

    def _compute_l2_extras(
        self, report: ScanReport, total_before_dedup: int, domain_results: dict
    ) -> Level2Metrics:
        domains_attempted = len(domain_results)
        domains_succeeded = sum(1 for v in domain_results.values() if v)
        dedup_removed = max(0, total_before_dedup - report.total_findings)

        findings_per_domain: dict[str, int] = {}
        for f in report.findings:
            d = getattr(f, "domain", "unknown")
            findings_per_domain[d] = findings_per_domain.get(d, 0) + 1

        return Level2Metrics(
            domains_attempted=domains_attempted,
            domains_succeeded=domains_succeeded,
            domain_success_rate=round(
                domains_succeeded / domains_attempted if domains_attempted else 0, 4
            ),
            findings_per_domain=findings_per_domain,
            total_before_dedup=total_before_dedup,
            duplicates_removed=dedup_removed,
            deduplication_rate=round(
                dedup_removed / total_before_dedup if total_before_dedup else 0, 4
            ),
        )

    def _headline_l1(
        self, d: DetectionMetrics, s: SpeedMetrics, c: CoverageMetrics
    ) -> str:
        recall_str = f"{d.verified_recall * 100:.0f}%" if d.verified_recall is not None else "N/A"
        prec_str = (
            f"{d.verified_precision_critical * 100:.0f}%"
            if d.verified_precision_critical is not None
            else "N/A"
        )
        f1_str = f"{d.f1_score:.2f}" if d.f1_score is not None else "N/A"
        return (
            f"Precision(Critical):{prec_str} | Recall:{recall_str} | F1:{f1_str} | "
            f"Scan:{s.scan_duration_seconds}s | "
            f"Coverage:{c.check_success_rate * 100:.0f}% "
            f"({c.checks_succeeded}/{c.total_checks_attempted} checks)"
        )

    def _headline_l2(
        self, d: DetectionMetrics, s: SpeedMetrics, c: CoverageMetrics, l2: Level2Metrics
    ) -> str:
        return (
            self._headline_l1(d, s, c)
            + f" | Domains:{l2.domains_succeeded}/{l2.domains_attempted} | "
            f"Dedup:{l2.duplicates_removed} removed"
        )

    def _headline_l3(
        self, d: DetectionMetrics, s: SpeedMetrics, l3: Level3Metrics
    ) -> str:
        return (
            f"Posture:{l3.current_posture_score}/100 ({l3.posture_trend}) | "
            f"SLA:{l3.sla_compliance_rate * 100:.0f}% | "
            f"Reliability:{l3.scan_reliability_rate * 100:.0f}% | "
            f"F1:{d.f1_score:.2f}"
        )

    def refresh_report_metrics(self, report_data: dict) -> dict:
        """Recompute detection metrics and headline from stored findings."""
        findings_raw = report_data.get("findings") or []
        if not findings_raw:
            return report_data

        try:
            findings = [ValidatedFinding.model_validate(f) for f in findings_raw]
        except Exception as exc:
            logger.warning("[metrics] Could not refresh report metrics: %s", exc)
            return report_data

        detection = self._compute_detection(findings)
        metrics = dict(report_data.get("metrics") or {})
        metrics["detection"] = detection.model_dump()

        level = int(report_data.get("scan_level", metrics.get("level", 1)))
        speed = SpeedMetrics.model_validate(metrics["speed"]) if metrics.get("speed") else None
        coverage = (
            CoverageMetrics.model_validate(metrics["coverage"]) if metrics.get("coverage") else None
        )
        level2 = Level2Metrics.model_validate(metrics["level2"]) if metrics.get("level2") else None
        level3 = Level3Metrics.model_validate(metrics["level3"]) if metrics.get("level3") else None

        if level >= 3 and level3 is not None and speed is not None:
            metrics["headline"] = self._headline_l3(detection, speed, level3)
        elif level >= 2 and level2 is not None and speed is not None and coverage is not None:
            metrics["headline"] = self._headline_l2(detection, speed, coverage, level2)
        elif speed is not None and coverage is not None:
            metrics["headline"] = self._headline_l1(detection, speed, coverage)

        metrics["level"] = level
        report_data["metrics"] = metrics
        return report_data
