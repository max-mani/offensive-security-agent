"""Finding lifecycle state machine across scan runs."""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import List

from agent.deduplicator import compute_fingerprint
from models.config import Level3Config
from models.finding import ValidatedFinding
from storage.audit_store import AuditStore
from storage.database import FindingRecord, get_session

logger = logging.getLogger(__name__)

DEFAULT_SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 168,
    "low": 720,
    "info": None,
}


class FindingLifecycleManager:
    """Manage finding lifecycle: opened → updated → resolved → re-opened."""

    def __init__(self, scan_run_id: str, level3_config: Level3Config | None = None):
        self.scan_run_id = scan_run_id
        self.config = level3_config or Level3Config()
        self.auto_resolve_after = self.config.auto_resolve_after_misses
        self.sla_hours = {**DEFAULT_SLA_HOURS, **(self.config.sla_hours or {})}
        self.session = get_session()
        self.audit = AuditStore(self.session)

    def process(self, current_findings: List[ValidatedFinding]) -> dict:
        now = datetime.utcnow()
        current_fps: dict[str, ValidatedFinding] = {}

        for finding in current_findings:
            fp = finding.fingerprint or compute_fingerprint(finding)
            finding.fingerprint = fp
            current_fps[fp] = finding

        new_fps: list[ValidatedFinding] = []
        updated_fps: list[ValidatedFinding] = []
        reopened_fps: list[ValidatedFinding] = []

        for fp, finding in current_fps.items():
            existing = self.session.query(FindingRecord).filter_by(fingerprint=fp).first()

            if existing is None:
                record = self._create_record(finding, fp, now)
                self.session.add(record)
                new_fps.append(finding)
                self.audit.log(
                    "finding_opened",
                    "finding",
                    record.id,
                    {
                        "check_id": finding.check_id,
                        "severity": finding.severity,
                        "resource_arn": finding.resource_arn,
                    },
                )
                logger.info("[lifecycle] NEW: %s / %s", finding.check_id, finding.resource_id)

            elif existing.status == "resolved":
                existing.status = "re-opened"
                existing.last_seen = now
                existing.resolved_at = None
                existing.consecutive_misses = 0
                existing.scan_run_id = self.scan_run_id
                existing.sla_deadline = self._compute_sla(finding.severity, now)
                existing.sla_breached = False
                existing.sla_alert_sent = False
                existing.escalated = False
                existing.confidence_score = finding.confidence_score
                existing.business_impact = finding.business_impact
                existing.remediation_command = finding.remediation_command
                reopened_fps.append(finding)
                self.audit.log(
                    "finding_reopened",
                    "finding",
                    existing.id,
                    {"severity": finding.severity, "previously_resolved": True},
                )
                logger.info("[lifecycle] REOPENED: %s / %s", finding.check_id, finding.resource_id)

            else:
                existing.status = "updated"
                existing.last_seen = now
                existing.consecutive_misses = 0
                existing.scan_run_id = self.scan_run_id
                existing.confidence_score = finding.confidence_score
                existing.business_impact = finding.business_impact
                existing.remediation_command = finding.remediation_command
                updated_fps.append(finding)
                self.audit.log(
                    "finding_updated",
                    "finding",
                    existing.id,
                    {"severity": finding.severity},
                )
                logger.info("[lifecycle] UPDATED: %s / %s", finding.check_id, finding.resource_id)

        resolved_ids = self._process_misses(current_fps, now)
        self.session.commit()
        self.session.close()

        return {
            "new": new_fps,
            "updated": updated_fps,
            "reopened": reopened_fps,
            "resolved": resolved_ids,
        }

    def _create_record(self, finding: ValidatedFinding, fp: str, now: datetime) -> FindingRecord:
        return FindingRecord(
            id=str(uuid.uuid4()),
            fingerprint=fp,
            check_id=finding.check_id,
            domain=finding.domain,
            resource_id=finding.resource_id,
            resource_arn=finding.resource_arn,
            severity=finding.severity,
            title=finding.title,
            status="opened",
            first_seen=now,
            last_seen=now,
            sla_deadline=self._compute_sla(finding.severity, now),
            confidence_score=finding.confidence_score,
            business_impact=finding.business_impact,
            remediation_command=finding.remediation_command,
            raw_evidence=json.dumps(finding.raw_evidence, default=str),
            scan_run_id=self.scan_run_id,
            consecutive_misses=0,
            escalated=False,
        )

    def _compute_sla(self, severity: str, from_time: datetime):
        hours = self.sla_hours.get(severity)
        if hours is None:
            return None
        return from_time + timedelta(hours=float(hours))

    def _process_misses(self, current_fps: dict, now: datetime) -> list:
        resolved = []
        open_records = (
            self.session.query(FindingRecord)
            .filter(FindingRecord.status.in_(["opened", "updated", "re-opened"]))
            .all()
        )

        for record in open_records:
            if record.fingerprint not in current_fps:
                record.consecutive_misses += 1
                if record.consecutive_misses >= self.auto_resolve_after:
                    record.status = "resolved"
                    record.resolved_at = now
                    record.auto_resolved = True
                    resolved.append(record.id)
                    self.audit.log(
                        "finding_resolved",
                        "finding",
                        record.id,
                        {
                            "reason": f"Not seen in {self.auto_resolve_after} consecutive scans",
                            "auto_resolved": True,
                        },
                    )
                    logger.info(
                        "[lifecycle] AUTO-RESOLVED: %s / %s",
                        record.check_id,
                        record.resource_id,
                    )

        return resolved
