"""Level 2 multi-domain orchestrator — AWS + API + Dependencies + Secrets."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, List, Optional

import boto3

from agent.deduplicator import deduplicate
from agent.impact_ranker import rank_by_impact
from agent.intelligence import IntelligenceLayer
from agent.orchestrator import CHECK_REGISTRY
from checks.api_checks import run_api_domain
from checks.dependency_checks import run_dependency_domain
from checks.secrets_checks import run_secrets_domain
from models.config import ScanConfig
from models.finding import RawFinding, ValidatedFinding
from models.report import CheckError, ScanReport
from reporter.json_reporter import JSONReporter
from reporter.markdown_reporter import MarkdownReporter
from utils.llm_client import LLMConfig

logger = logging.getLogger(__name__)


class OrchestratorL2:
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
        logger.info("=== Level 2 Scan started: %s ===", self.config.scan.name)
        _progress("init", "completed", self.config.scan.name)

        all_raw: List[RawFinding] = []
        all_errors: List[CheckError] = []
        domains_scanned: List[str] = []
        aws_attempted = 0

        domain_step_ids = {
            "aws_infrastructure": "domain_aws",
            "api_endpoints": "domain_api",
            "dependencies": "domain_deps",
            "secrets": "domain_secrets",
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            futures[executor.submit(self._run_aws_domain)] = "aws_infrastructure"
            _progress("domain_aws", "running", "13 AWS checks")

            if self.config.api_targets:
                futures[executor.submit(run_api_domain, self.config.api_targets, self.config)] = (
                    "api_endpoints"
                )
                _progress("domain_api", "running", f"{len(self.config.api_targets)} target(s)")

            dep_paths = self.config.dependency_scan.paths
            if dep_paths:
                futures[executor.submit(run_dependency_domain, dep_paths)] = "dependencies"
                _progress("domain_deps", "running", f"{len(dep_paths)} file(s)")

            sec_paths = self.config.secrets_scan.paths
            if sec_paths:
                futures[executor.submit(
                    run_secrets_domain, sec_paths, self.config.secrets_scan.exclude
                )] = "secrets"
                _progress("domain_secrets", "running", f"{len(sec_paths)} path(s)")

            for future in as_completed(futures, timeout=180):
                domain = futures[future]
                try:
                    findings, errors = future.result(timeout=120)
                    logger.info("[%s] %d raw findings, %d errors", domain, len(findings), len(errors))
                    all_raw.extend(findings)
                    all_errors.extend(errors)
                    domains_scanned.append(domain)
                    step_id = domain_step_ids.get(domain, f"domain_{domain}")
                    _progress(step_id, "completed", f"{len(findings)} finding(s)")
                    if domain == "aws_infrastructure":
                        aws_attempted = len(self.config.get_enabled_checks())
                except Exception as e:
                    logger.error("[%s] Domain scan failed: %s", domain, e)
                    all_errors.append(
                        CheckError(
                            check_id=f"domain_{domain}",
                            error_type="unknown",
                            error_message=str(e),
                        )
                    )
                    _progress(domain_step_ids.get(domain, f"domain_{domain}"), "failed", str(e))

        logger.info("Total raw findings before enrichment: %d", len(all_raw))

        _progress("llm_enrichment", "running", f"Enriching {len(all_raw)} finding(s)")
        validated = self.intelligence.enrich_batch(all_raw, self.config)
        _progress("llm_enrichment", "completed", f"{len(validated)} enriched")

        _progress("dedup", "running", "Deduplicating cross-domain findings")
        pre_dedup_count = len(validated)
        deduped = deduplicate(validated)
        dedup_removed = pre_dedup_count - len(deduped)
        _progress("dedup", "completed", f"{dedup_removed} removed")

        _progress("ranking", "running", "Ranking by business impact")
        ranked = rank_by_impact(deduped)
        _progress("ranking", "completed", f"Top score: {ranked[0].impact_score if ranked else 0}")

        end_time = datetime.now(timezone.utc)
        try:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            logger.error("Failed to get AWS account ID: %s", e)
            account_id = "unknown"

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        domain_counts: dict[str, int] = {}
        for f in ranked:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            domain_counts[f.domain] = domain_counts.get(f.domain, 0) + 1

        errored_ids = {e.check_id for e in all_errors}
        total_succeeded = max(0, aws_attempted - len([e for e in all_errors if e.check_id in CHECK_REGISTRY]))

        if len(all_errors) == 0:
            health = "healthy"
        elif len(all_errors) < max(aws_attempted, 1) * 0.3:
            health = "degraded"
        elif total_succeeded > 0 or len(ranked) > 0:
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
            total_checks_attempted=aws_attempted,
            total_checks_succeeded=total_succeeded,
            total_checks_errored=len([e for e in all_errors if e.check_id in CHECK_REGISTRY]),
            total_findings=len(ranked),
            findings_by_severity=severity_counts,
            findings=ranked,
            scan_errors=all_errors,
            scan_health=health,
            scan_level=2,
            findings_by_domain=domain_counts,
            deduplication_removed=dedup_removed,
            domains_scanned=sorted(domains_scanned),
        )

        _progress("reports", "running", "Writing JSON and Markdown")
        json_path = JSONReporter(self.config.scan.output_dir).write(report)
        md_path = MarkdownReporter(self.config.scan.output_dir).write(report)
        _progress("reports", "completed", json_path.name)

        logger.info(
            "=== L2 Scan complete in %.1fs | Health: %s | Findings: %s | Domains: %s ===",
            report.duration_seconds,
            health,
            severity_counts,
            domain_counts,
        )
        logger.info("Reports: %s, %s", json_path, md_path)
        return report

    def _run_aws_domain(self) -> tuple[List[RawFinding], List[CheckError]]:
        """Run all Level 1 AWS checks; tag each finding with domain='aws_infrastructure'."""
        findings: List[RawFinding] = []
        errors: List[CheckError] = []

        for check_config in self.config.get_enabled_checks():
            if check_config.id not in CHECK_REGISTRY:
                continue
            check_class = CHECK_REGISTRY[check_config.id]
            check = check_class(check_config, self.session)
            try:
                result = check.run()
                if isinstance(result, CheckError):
                    errors.append(result)
                else:
                    for f in result:
                        f.domain = "aws_infrastructure"
                    findings.extend(result)
            except Exception as e:
                errors.append(
                    CheckError(
                        check_id=check_config.id,
                        error_type="unknown",
                        error_message=str(e),
                    )
                )

        return findings, errors
