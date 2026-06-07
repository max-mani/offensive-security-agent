"""Level 3 orchestrator — persistence, lifecycle, escalation, SLA, trends."""

import logging
import uuid
from datetime import datetime

from agent.auto_remediation import AutoRemediator
from agent.escalation import EscalationEngine
from agent.lifecycle_manager import FindingLifecycleManager
from agent.orchestrator_l2 import OrchestratorL2
from agent.sla_tracker import SLATracker
from checks.api_checks import API_CHECK_CLASSES
from models.config import Level3Config, ScanConfig
from models.report import CheckError, ScanReport
from reporter.trend_reporter import TrendReporter, compute_posture_score
from storage.audit_store import AuditStore
from storage.database import ScanHealthRecord, ScanRun, get_session
from utils.llm_client import LLMConfig

logger = logging.getLogger(__name__)


class OrchestratorL3:
    """Wraps L2 with persistence, lifecycle, escalation, and trend reporting."""

    def __init__(self, config: ScanConfig, llm: LLMConfig):
        self.config = config
        self.l3_config = config.level3 or Level3Config()
        self.l2 = OrchestratorL2(config, llm)
        self.escalation = EscalationEngine(self.l3_config)
        self.sla_tracker = SLATracker()
        self.auto_remediation = AutoRemediator(self.l3_config)
        keep_n = self.l3_config.trend_report.keep_last_n_scans
        self.trend_reporter = TrendReporter(config.scan.output_dir, keep_last_n=keep_n)

    def run(self) -> dict:
        scan_run_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        session = get_session()
        audit = AuditStore(session)

        scan_run = ScanRun(
            id=scan_run_id,
            started_at=start_time,
            config_name=self.config.scan.name,
        )
        session.add(scan_run)
        session.commit()

        audit.log(
            "scan_started",
            "scan_run",
            scan_run_id,
            {"config": self.config.scan.name},
            actor="scheduler",
        )
        session.commit()

        logger.info("=== L3 Scan %s started ===", scan_run_id)

        sla_breaches = self.sla_tracker.get_breached()
        if sla_breaches:
            logger.warning("[l3] %d SLA breaches detected pre-scan", len(sla_breaches))
            self.escalation.check_sla_breaches()

        try:
            l2_report = self.l2.run()
        except Exception as e:
            logger.error("[l3] L2 scan failed: %s", e)
            audit.log("scan_failed", "scan_run", scan_run_id, {"error": str(e)})
            scan_run.health = "failed"
            scan_run.completed_at = datetime.utcnow()
            session.commit()
            session.close()
            return {"error": str(e), "scan_run_id": scan_run_id}

        lifecycle = FindingLifecycleManager(scan_run_id, self.l3_config)
        lifecycle_result = lifecycle.process(l2_report.findings)

        new_findings = lifecycle_result["new"]
        updated_findings = lifecycle_result["updated"]
        reopened_findings = lifecycle_result["reopened"]
        resolved_findings = lifecycle_result["resolved"]

        logger.info(
            "[l3] Lifecycle: %d new, %d updated, %d re-opened, %d resolved",
            len(new_findings),
            len(updated_findings),
            len(reopened_findings),
            len(resolved_findings),
        )

        escalation_candidates = new_findings + reopened_findings
        self.escalation.escalate_critical(escalation_candidates, scan_run_id)

        self._write_scan_health(scan_run_id, l2_report, session, audit)

        self.auto_remediation.process_findings(new_findings)

        posture_score = compute_posture_score(session)

        end_time = datetime.utcnow()
        scan_run.completed_at = end_time
        scan_run.duration_seconds = (end_time - start_time).total_seconds()
        scan_run.health = l2_report.scan_health
        scan_run.total_findings = len(l2_report.findings)
        scan_run.new_findings = len(new_findings)
        scan_run.updated_findings = len(updated_findings)
        scan_run.resolved_findings = len(resolved_findings)
        scan_run.reopened_findings = len(reopened_findings)
        scan_run.posture_score = posture_score

        severity_counts = l2_report.findings_by_severity
        scan_run.critical_count = severity_counts.get("critical", 0)
        scan_run.high_count = severity_counts.get("high", 0)
        scan_run.medium_count = severity_counts.get("medium", 0)
        scan_run.low_count = severity_counts.get("low", 0)

        audit.log(
            "scan_completed",
            "scan_run",
            scan_run_id,
            {
                "duration_seconds": scan_run.duration_seconds,
                "health": scan_run.health,
                "posture_score": posture_score,
                "new_findings": len(new_findings),
                "critical": scan_run.critical_count,
            },
            actor="scheduler",
        )

        duration_seconds = scan_run.duration_seconds
        scan_health = scan_run.health

        session.commit()
        session.close()

        trend = {}
        if self.l3_config.trend_report.generate_after_each_scan:
            trend = self.trend_reporter.generate()

        logger.info(
            "=== L3 Scan complete: %.1fs | Posture: %s/100 | Trend: %s ===",
            duration_seconds,
            posture_score,
            trend.get("trend_direction", "n/a"),
        )

        return {
            "scan_run_id": scan_run_id,
            "posture_score": posture_score,
            "lifecycle": {
                "new": len(new_findings),
                "updated": len(updated_findings),
                "reopened": len(reopened_findings),
                "resolved": len(resolved_findings),
            },
            "sla_breaches": len(sla_breaches),
            "trend": trend.get("trend_direction"),
            "health": scan_health,
            "report": l2_report,
        }

    def _build_check_registry(self) -> list[tuple[str, str]]:
        """Return (check_id, domain) for every check that should run."""
        checks: list[tuple[str, str]] = []

        for check in self.config.get_enabled_checks():
            checks.append((check.id, "aws_infrastructure"))

        for target in self.config.api_targets:
            for check_cls in API_CHECK_CLASSES:
                checks.append((f"{check_cls.check_id}@{target.name}", "api_endpoints"))

        for path in self.config.dependency_scan.paths:
            checks.append((f"dependency_cve@{path}", "dependencies"))

        for path in self.config.secrets_scan.paths:
            checks.append((f"secrets_scan@{path}", "secrets"))

        return checks

    def _match_error(self, check_id: str, domain: str, errors: list[CheckError]) -> CheckError | None:
        base_id = check_id.split("@")[0]
        for err in errors:
            if err.check_id == check_id or err.check_id == base_id:
                if domain == "aws_infrastructure" and err.check_id == check_id:
                    return err
                if domain != "aws_infrastructure" and (
                    err.check_id == base_id or err.check_id == check_id
                ):
                    return err
            if err.check_id == f"domain_{domain}":
                return err
        return None

    def _write_scan_health(
        self,
        scan_run_id: str,
        report: ScanReport,
        session,
        audit: AuditStore,
    ):
        all_checks = self._build_check_registry()
        errored_ids = {e.check_id for e in report.scan_errors}

        for check_id, domain in all_checks:
            base_id = check_id.split("@")[0]
            error = self._match_error(check_id, domain, report.scan_errors)

            if error:
                session.add(
                    ScanHealthRecord(
                        scan_run_id=scan_run_id,
                        check_id=check_id,
                        domain=domain,
                        status="error",
                        error_type=error.error_type,
                        error_message=error.error_message,
                    )
                )
                audit.log(
                    "check_error",
                    "scan_run",
                    scan_run_id,
                    {
                        "check_id": check_id,
                        "error_type": error.error_type,
                        "message": error.error_message,
                    },
                )
                logger.warning(
                    "[health] CHECK FAILED: %s — %s: %s",
                    check_id,
                    error.error_type,
                    error.error_message,
                )
            elif base_id in errored_ids or check_id in errored_ids:
                err = next(
                    (e for e in report.scan_errors if e.check_id in (check_id, base_id)),
                    None,
                )
                if err:
                    session.add(
                        ScanHealthRecord(
                            scan_run_id=scan_run_id,
                            check_id=check_id,
                            domain=domain,
                            status="error",
                            error_type=err.error_type,
                            error_message=err.error_message,
                        )
                    )
                else:
                    session.add(
                        ScanHealthRecord(
                            scan_run_id=scan_run_id,
                            check_id=check_id,
                            domain=domain,
                            status="success",
                        )
                    )
            else:
                session.add(
                    ScanHealthRecord(
                        scan_run_id=scan_run_id,
                        check_id=check_id,
                        domain=domain,
                        status="success",
                    )
                )

        session.commit()
