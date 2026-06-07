"""SLA deadline tracking for open findings."""

import logging
from datetime import datetime, timedelta

from storage.database import FindingRecord, get_session

logger = logging.getLogger(__name__)


class SLATracker:
    """Check open findings against SLA deadlines."""

    def get_breached(self) -> list:
        session = get_session()
        now = datetime.utcnow()

        try:
            breached = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.sla_deadline < now,
                    FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                )
                .all()
            )

            results = []
            for record in breached:
                hours_overdue = int((now - record.sla_deadline).total_seconds() / 3600)
                results.append(
                    {
                        "id": record.id,
                        "check_id": record.check_id,
                        "severity": record.severity,
                        "resource_arn": record.resource_arn,
                        "first_seen": record.first_seen,
                        "sla_deadline": record.sla_deadline,
                        "hours_overdue": hours_overdue,
                        "sla_breached": record.sla_breached,
                        "alert_sent": record.sla_alert_sent,
                    }
                )
                logger.warning(
                    "[sla] BREACH: %s (%s) — %sh overdue — %s",
                    record.check_id,
                    record.severity,
                    hours_overdue,
                    record.resource_id,
                )
            return results
        finally:
            session.close()

    def get_approaching(self, within_hours: int = 6) -> list:
        session = get_session()
        now = datetime.utcnow()
        threshold = now + timedelta(hours=within_hours)

        try:
            approaching = (
                session.query(FindingRecord)
                .filter(
                    FindingRecord.sla_deadline > now,
                    FindingRecord.sla_deadline < threshold,
                    FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                )
                .all()
            )
            return [
                {
                    "check_id": r.check_id,
                    "severity": r.severity,
                    "sla_deadline": r.sla_deadline,
                }
                for r in approaching
            ]
        finally:
            session.close()
