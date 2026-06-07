"""Slack webhook escalation for Critical findings and SLA breaches."""

import logging
import os
from datetime import datetime

import requests

from models.config import Level3Config
from models.finding import ValidatedFinding
from storage.audit_store import AuditStore
from storage.database import FindingRecord, get_session

logger = logging.getLogger(__name__)


class EscalationEngine:
    """Escalate Critical findings and SLA breaches via Slack webhook."""

    def __init__(self, config: Level3Config | None = None):
        config = config or Level3Config()
        self.slack_webhook = config.slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.slack_webhook)
        if not self.enabled:
            logger.warning("[escalation] No Slack webhook configured — escalation disabled")

    def escalate_critical(self, findings: list, scan_run_id: str):
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)

        for finding in findings:
            if finding.severity != "critical":
                continue

            fp = finding.fingerprint
            record = None
            if fp:
                record = session.query(FindingRecord).filter_by(fingerprint=fp).first()
                if record and record.escalated:
                    continue

            success = self._send_slack_finding(finding)

            if record:
                record.escalated = True

            audit.log(
                "escalation_sent" if success else "escalation_failed",
                "finding",
                getattr(finding, "id", None),
                {
                    "severity": finding.severity,
                    "check_id": finding.check_id,
                    "scan_run_id": scan_run_id,
                    "slack_success": success,
                },
            )

        session.commit()
        session.close()

    def check_sla_breaches(self):
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)
        now = datetime.utcnow()

        breached = (
            session.query(FindingRecord)
            .filter(
                FindingRecord.sla_deadline < now,
                FindingRecord.status.in_(["opened", "updated", "re-opened"]),
                FindingRecord.sla_breached == False,  # noqa: E712
            )
            .all()
        )

        for record in breached:
            record.sla_breached = True
            record.sla_alert_sent = True
            success = self._send_slack_sla_breach(record)
            audit.log(
                "sla_breached",
                "finding",
                record.id,
                {
                    "severity": record.severity,
                    "check_id": record.check_id,
                    "first_seen": str(record.first_seen),
                    "sla_deadline": str(record.sla_deadline),
                    "slack_success": success,
                },
            )
            logger.warning(
                "[escalation] SLA BREACH: %s / %s (deadline: %s)",
                record.check_id,
                record.resource_id,
                record.sla_deadline,
            )

        session.commit()
        session.close()

    def _send_slack_finding(self, finding: ValidatedFinding) -> bool:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Critical Security Finding Detected",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Check ID:*\n`{finding.check_id}`"},
                        {"type": "mrkdwn", "text": f"*Domain:*\n{finding.domain}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.upper()}"},
                        {"type": "mrkdwn", "text": f"*Confidence:*\n{finding.confidence_score}%"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Resource:*\n`{finding.resource_arn}`"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Business Impact:*\n{finding.business_impact}"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n```{finding.remediation_command}```",
                    },
                },
            ]
        }
        return self._post_slack(payload)

    def _send_slack_sla_breach(self, record: FindingRecord) -> bool:
        hours_overdue = int((datetime.utcnow() - record.sla_deadline).total_seconds() / 3600)
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "SLA Breach — Critical Finding Unresolved",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Finding:*\n`{record.check_id}`"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{record.severity.upper()}"},
                        {
                            "type": "mrkdwn",
                            "text": f"*First Seen:*\n{record.first_seen.strftime('%Y-%m-%d %H:%M UTC')}",
                        },
                        {"type": "mrkdwn", "text": f"*Hours Overdue:*\n{hours_overdue}h"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Resource:*\n`{record.resource_arn}`\n"
                            f"*Remediation:*\n```{record.remediation_command or 'See findings report'}```"
                        ),
                    },
                },
            ]
        }
        return self._post_slack(payload)

    def _post_slack(self, payload: dict) -> bool:
        try:
            resp = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                logger.info("[escalation] Slack notification sent successfully")
                return True
            logger.error("[escalation] Slack returned %s: %s", resp.status_code, resp.text)
            return False
        except Exception as e:
            logger.error("[escalation] Slack POST failed: %s", e)
            return False
