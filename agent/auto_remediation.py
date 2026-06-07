"""Optional safe auto-remediation for low-risk findings."""

import logging
import subprocess

from models.config import Level3Config
from storage.audit_store import AuditStore
from storage.database import get_session

logger = logging.getLogger(__name__)

SAFE_AUTO_REMEDIATION_CHECKS = {
    "iam_password_policy",
    "s3_encryption_disabled",
    "cloudtrail_not_logging",
}


class AutoRemediator:
    """Dry-run by default; only LOW severity + allowlisted checks."""

    def __init__(self, config: Level3Config | None = None):
        config = config or Level3Config()
        ar = config.auto_remediation
        self.enabled = ar.enabled
        self.dry_run = ar.dry_run
        if self.enabled and not self.dry_run:
            logger.warning(
                "[remediation] Auto-remediation ENABLED with dry_run=False — commands will execute"
            )
        elif self.enabled:
            logger.info("[remediation] Auto-remediation ENABLED in dry-run mode")

    def process_findings(self, findings: list):
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)

        for finding in findings:
            if not self._is_eligible(finding):
                audit.log(
                    "auto_remediation_skipped",
                    "finding",
                    getattr(finding, "id", None),
                    {
                        "reason": "Not eligible (severity or check_id not in safe list)",
                        "check_id": finding.check_id,
                        "severity": finding.severity,
                    },
                )
                continue

            command = finding.remediation_command
            if not command or command.startswith("#"):
                continue

            if self.dry_run:
                logger.info("[remediation] DRY-RUN: Would execute: %s", command)
                audit.log(
                    "auto_remediation_dry_run",
                    "finding",
                    getattr(finding, "id", None),
                    {"command": command, "dry_run": True, "check_id": finding.check_id},
                )
            else:
                self._execute(command, finding, audit)

        session.commit()
        session.close()

    def _is_eligible(self, finding) -> bool:
        return finding.severity == "low" and finding.check_id in SAFE_AUTO_REMEDIATION_CHECKS

    def _execute(self, command: str, finding, audit: AuditStore):
        logger.info("[remediation] Executing: %s", command)
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            success = result.returncode == 0
            audit.log(
                "auto_remediation_executed" if success else "auto_remediation_failed",
                "finding",
                getattr(finding, "id", None),
                {
                    "command": command,
                    "returncode": result.returncode,
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500],
                    "check_id": finding.check_id,
                    "dry_run": False,
                },
            )
        except Exception as e:
            logger.error("[remediation] EXCEPTION executing %s: %s", command, e)
            audit.log(
                "auto_remediation_failed",
                "finding",
                getattr(finding, "id", None),
                {"error": str(e), "command": command},
            )
