import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Type

import boto3

from agent.intelligence import IntelligenceLayer
from checks.base import BaseCheck
from checks.cloudtrail_checks import CloudTrailNotLoggingCheck, EBSPublicSnapshotCheck
from checks.ec2_checks import EC2UnencryptedVolumesCheck, SGOpenRDPCheck, SGOpenSSHCheck
from checks.iam_checks import (
    IAMPasswordPolicyCheck,
    IAMRootAccessKeysCheck,
    IAMRootMFACheck,
    IAMUnusedAccessKeysCheck,
    IAMUserMFACheck,
)
from checks.s3_checks import S3EncryptionCheck, S3PublicACLCheck, S3PublicPolicyCheck
from models.config import ScanConfig
from models.finding import RawFinding
from models.report import CheckError, ScanReport
from reporter.json_reporter import JSONReporter
from reporter.markdown_reporter import MarkdownReporter

logger = logging.getLogger(__name__)

CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {
    "iam_root_mfa": IAMRootMFACheck,
    "iam_root_access_keys": IAMRootAccessKeysCheck,
    "iam_user_mfa": IAMUserMFACheck,
    "iam_unused_access_keys": IAMUnusedAccessKeysCheck,
    "iam_password_policy": IAMPasswordPolicyCheck,
    "s3_public_acl": S3PublicACLCheck,
    "s3_public_policy": S3PublicPolicyCheck,
    "s3_encryption_disabled": S3EncryptionCheck,
    "sg_open_ssh": SGOpenSSHCheck,
    "sg_open_rdp": SGOpenRDPCheck,
    "ec2_unencrypted_volumes": EC2UnencryptedVolumesCheck,
    "cloudtrail_not_logging": CloudTrailNotLoggingCheck,
    "ebs_public_snapshots": EBSPublicSnapshotCheck,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


from utils.llm_client import LLMConfig


class AgentOrchestrator:
    def __init__(self, config: ScanConfig, llm: LLMConfig):
        self.config = config
        self.session = boto3.Session(region_name=config.scan.aws_region)
        model = config.scan.llm_model or llm.model
        self.intelligence = IntelligenceLayer(
            llm.api_key,
            model=model,
            base_url=llm.base_url,
            provider=llm.provider,
        )

    def run(
        self,
        progress_callback: Optional[Callable[[str, str, str], None]] = None,
    ) -> ScanReport:
        def _progress(step_id: str, status: str, detail: str = "") -> None:
            if progress_callback:
                progress_callback(step_id, status, detail)

        start_time = datetime.now(timezone.utc)
        logger.info("=== Scan started: %s ===", self.config.scan.name)
        _progress("init", "completed", self.config.scan.name)

        enabled_checks = self.config.get_enabled_checks()
        logger.info(
            "Running %d checks with %d workers",
            len(enabled_checks),
            self.config.scan.max_workers,
        )

        raw_findings: List[RawFinding] = []
        scan_errors: List[CheckError] = []
        attempted = 0

        with ThreadPoolExecutor(max_workers=self.config.scan.max_workers) as executor:
            future_to_check = {}
            for check_config in enabled_checks:
                if check_config.id not in CHECK_REGISTRY:
                    logger.warning("Unknown check ID: %s - skipping", check_config.id)
                    scan_errors.append(
                        CheckError(
                            check_id=check_config.id,
                            error_type="unknown",
                            error_message=f"Unknown check ID: {check_config.id}",
                        )
                    )
                    continue

                attempted += 1
                check_class = CHECK_REGISTRY[check_config.id]
                check_instance = check_class(check_config, self.session)
                _progress(check_config.id, "running", check_config.description)
                future = executor.submit(check_instance.run)
                future_to_check[future] = check_config.id

            overall_timeout = self.config.scan.timeout_seconds * len(future_to_check) + 30
            try:
                for future in as_completed(future_to_check, timeout=overall_timeout):
                    check_id = future_to_check[future]
                    try:
                        result = future.result(timeout=self.config.scan.timeout_seconds)
                        if isinstance(result, CheckError):
                            logger.warning("[%s] Check error: %s", check_id, result.error_type)
                            scan_errors.append(result)
                            _progress(check_id, "failed", result.error_message)
                        elif isinstance(result, list):
                            logger.info("[%s] %d findings", check_id, len(result))
                            raw_findings.extend(result)
                            _progress(
                                check_id,
                                "completed",
                                f"{len(result)} finding(s)" if result else "clean",
                            )
                    except FuturesTimeoutError:
                        scan_errors.append(
                            CheckError(
                                check_id=check_id,
                                error_type="timeout",
                                error_message=(
                                    f"Check exceeded {self.config.scan.timeout_seconds}s"
                                ),
                            )
                        )
                        _progress(check_id, "failed", "timeout")
                    except Exception as e:
                        scan_errors.append(
                            CheckError(
                                check_id=check_id,
                                error_type="unknown",
                                error_message=str(e),
                            )
                        )
                        _progress(check_id, "failed", str(e))
            except FuturesTimeoutError:
                for future, check_id in future_to_check.items():
                    if not future.done():
                        scan_errors.append(
                            CheckError(
                                check_id=check_id,
                                error_type="timeout",
                                error_message="Check did not complete within overall scan timeout",
                            )
                        )

        logger.info("Raw findings collected: %d", len(raw_findings))
        logger.info("Check errors: %d", len(scan_errors))

        logger.info("Starting LLM enrichment...")
        _progress("llm_enrichment", "running", f"Enriching {len(raw_findings)} finding(s)")
        validated_findings = self.intelligence.enrich_batch(raw_findings, self.config)
        _progress("llm_enrichment", "completed", f"{len(validated_findings)} enriched")
        validated_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        end_time = datetime.now(timezone.utc)
        try:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            logger.error("Failed to get AWS account ID: %s", e)
            account_id = "unknown"

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in validated_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        errored_ids = {e.check_id for e in scan_errors}
        total_succeeded = max(0, attempted - len(errored_ids))

        if len(scan_errors) == 0:
            health = "healthy"
        elif len(scan_errors) < attempted * 0.3:
            health = "degraded"
        elif total_succeeded > 0:
            health = "partial"
        else:
            health = "failed"

        report = ScanReport(
            scan_name=self.config.scan.name,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            aws_account_id=account_id,
            aws_region=self.config.scan.aws_region,
            total_checks_attempted=attempted,
            total_checks_succeeded=total_succeeded,
            total_checks_errored=len(scan_errors),
            total_findings=len(validated_findings),
            findings_by_severity=severity_counts,
            findings=validated_findings,
            scan_errors=scan_errors,
            scan_health=health,
        )

        _progress("reports", "running", "Writing JSON and Markdown")
        json_path = JSONReporter(self.config.scan.output_dir).write(report)
        md_path = MarkdownReporter(self.config.scan.output_dir).write(report)
        _progress("reports", "completed", json_path.name)

        logger.info(
            "=== Scan complete in %.1fs | Health: %s ===",
            report.duration_seconds,
            health,
        )
        logger.info("Findings: %s", severity_counts)
        logger.info("Reports: %s, %s", json_path, md_path)
        return report
