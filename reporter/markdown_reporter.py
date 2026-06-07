from pathlib import Path

from models.report import ScanReport

SEVERITY_EMOJI = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

DOMAIN_LABELS = {
    "aws_infrastructure": "AWS Infrastructure",
    "api_endpoints": "API Endpoints",
    "dependencies": "Dependencies",
    "secrets": "Secrets",
}


class MarkdownReporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, report: ScanReport) -> Path:
        timestamp = report.end_time.strftime("%Y%m%d_%H%M%S")
        suffix = "_l2" if report.scan_level >= 2 else ""
        output_path = self.output_dir / f"findings_report_{timestamp}{suffix}.md"
        output_path.write_text(self._render(report), encoding="utf-8")
        return output_path

    def _render(self, report: ScanReport) -> str:
        if report.scan_level >= 2:
            return self._render_l2(report)
        return self._render_l1(report)

    def _render_l1(self, report: ScanReport) -> str:
        health_label = report.scan_health.capitalize()
        date_str = report.start_time.strftime("%Y-%m-%d")

        lines = [
            f"# Security Audit Report - {report.scan_name}",
            f"**Date:** {date_str} | **Account:** {report.aws_account_id} | "
            f"**Region:** {report.aws_region}  ",
            f"**Duration:** {report.duration_seconds:.1f}s | **Health:** {health_label} | "
            f"**Findings:** {report.total_findings}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]

        for sev in SEVERITY_ORDER:
            count = report.findings_by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"| {SEVERITY_EMOJI[sev]} | {count} |")

        lines.extend(["", f"| **Total** | **{report.total_findings}** |", "", "---", ""])
        lines.extend(self._render_metrics(report.metrics))
        lines.extend(["", "---", ""])

        finding_counter = 1
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in report.findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"## {SEVERITY_EMOJI[sev]} Findings")
            lines.append("")

            for finding in sev_findings:
                lines.extend(self._render_finding(finding, finding_counter))
                finding_counter += 1

        lines.extend(self._render_scan_health(report))
        return "\n".join(lines)

    def _render_l2(self, report: ScanReport) -> str:
        health_label = report.scan_health.capitalize()
        date_str = report.start_time.strftime("%Y-%m-%d")

        lines = [
            f"# Security Audit Report (Level 2) - {report.scan_name}",
            f"**Date:** {date_str} | **Account:** {report.aws_account_id} | "
            f"**Region:** {report.aws_region}  ",
            f"**Duration:** {report.duration_seconds:.1f}s | **Health:** {health_label} | "
            f"**Findings:** {report.total_findings} | **Dedup removed:** {report.deduplication_removed}",
            f"**Domains scanned:** {', '.join(report.domains_scanned)}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "### By Severity",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]

        for sev in SEVERITY_ORDER:
            count = report.findings_by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"| {SEVERITY_EMOJI[sev]} | {count} |")

        lines.extend(["", f"| **Total** | **{report.total_findings}** |", ""])

        if report.findings_by_domain:
            lines.extend(["### By Domain", "", "| Domain | Count |", "|---|---|"])
            for domain, count in sorted(report.findings_by_domain.items()):
                label = DOMAIN_LABELS.get(domain, domain)
                lines.append(f"| {label} | {count} |")
            lines.append("")

        lines.extend(["---", ""])
        lines.extend(self._render_metrics(report.metrics))
        lines.extend(["", "---", "", "## Findings (Ranked by Business Impact)", ""])

        for i, finding in enumerate(report.findings, 1):
            lines.extend(self._render_finding(finding, i, l2=True))

        lines.extend(self._render_scan_health(report))
        return "\n".join(lines)

    def _render_finding(self, finding, counter: int, l2: bool = False) -> list[str]:
        fid = f"F{counter:03d}"
        sev_label = SEVERITY_EMOJI.get(finding.severity, finding.severity)
        header = f"### [{fid}] {finding.title}"
        meta = [
            header,
            f"**Severity:** {sev_label} | **Resource:** `{finding.resource_id}` ({finding.resource_type})  ",
            f"**ARN:** `{finding.resource_arn}`  ",
            f"**Confidence:** {finding.confidence_score}%",
        ]
        if l2:
            meta.insert(
                2,
                f"**Domain:** {DOMAIN_LABELS.get(finding.domain, finding.domain)} | "
                f"**Impact Score:** {finding.impact_score}  ",
            )

        evidence = finding.raw_evidence or {}
        cve_block = []
        if finding.check_id == "dependency_cve":
            cve_ids = evidence.get("cve_ids", [])
            if cve_ids:
                cve_block.append(f"**CVE IDs:** {', '.join(cve_ids)}  ")
            if evidence.get("cvss_score") is not None:
                cve_block.append(f"**CVSS Score:** {evidence['cvss_score']}  ")
            if evidence.get("fix_versions"):
                cve_block.append(f"**Fix Versions:** {', '.join(evidence['fix_versions'])}  ")
            if evidence.get("package_name"):
                cve_block.append(
                    f"**Package:** {evidence['package_name']}=={evidence.get('installed_version', '?')}  "
                )

        secret_block = []
        if finding.check_id == "secrets_scan":
            if evidence.get("secret_type"):
                secret_block.append(f"**Secret Type:** {evidence['secret_type']}  ")
            if evidence.get("value_redacted"):
                secret_block.append(f"**Value (redacted):** `{evidence['value_redacted']}`  ")

        lines = meta + [""] + cve_block + secret_block
        if cve_block or secret_block:
            lines.append("")

        lines.extend(
            [
                "**Business Impact**  ",
                finding.business_impact,
                "",
                "**Remediation Steps**  ",
            ]
        )
        for step in finding.remediation_steps:
            lines.append(f"- {step}")

        lines.extend(
            [
                "",
                "**Remediation Command**  ",
                "```bash",
                finding.remediation_command,
                "```",
                "",
                "---",
                "",
            ]
        )
        return lines

    def _render_metrics(self, metrics) -> list[str]:
        if not metrics:
            return []

        d = metrics.detection
        s = metrics.speed
        c = metrics.coverage

        recall_display = (
            f"{d.verified_recall * 100:.0f}%" if d.verified_recall is not None else "N/A"
        )
        prec_display = (
            f"{d.verified_precision_critical * 100:.0f}%"
            if d.verified_precision_critical is not None
            else "N/A"
        )
        f1_display = f"{d.f1_score:.2f}" if d.f1_score is not None else "N/A"

        def status(ok: bool, warn: bool = False) -> str:
            if ok:
                return "PASS"
            return "WARN" if warn else "FAIL"

        lines = [
            "## Agent Performance Metrics",
            "",
            f"> **{metrics.headline}**",
            "",
            "### Detection Quality",
            "",
            "| Metric | Value | Target | Status |",
            "|--------|-------|--------|--------|",
            f"| Precision (Critical findings) | **{prec_display}** | > 95% | "
            f"{status(d.verified_precision_critical is not None and d.verified_precision_critical >= 0.95)} |",
            f"| Recall (Known misconfigs) | **{recall_display}** | > 80% | "
            f"{status(d.verified_recall is not None and d.verified_recall >= 0.80)} |",
            f"| F1 Score | **{f1_display}** | > 0.85 | "
            f"{status(d.f1_score is not None and d.f1_score >= 0.85)} |",
            f"| Avg Confidence Score | **{d.avg_confidence_score}%** | > 75% | "
            f"{status(d.avg_confidence_score >= 75)} |",
            f"| High Confidence Findings | **{d.high_confidence_pct}%** | > 70% | "
            f"{status(d.high_confidence_pct >= 70)} |",
            f"| False Positives (Critical) | **{d.false_positives_critical}** | 0 | "
            f"{status(d.false_positives_critical == 0)} |",
            "",
            "### Speed & Efficiency",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Scan Duration | **{s.scan_duration_seconds}s** |",
            f"| Avg Check Duration | **{s.avg_check_duration_ms}ms** |",
            f"| Findings per Second | **{s.findings_per_second}** |",
            f"| Resources Scanned | **{s.resources_scanned}** |",
            "",
            "### Coverage",
            "",
            "| Metric | Value | Status |",
            "|--------|-------|--------|",
            f"| Checks Succeeded | **{c.checks_succeeded}/{c.total_checks_attempted}** | "
            f"{status(c.checks_errored == 0, warn=c.checks_errored > 0)} |",
            f"| Check Success Rate | **{c.check_success_rate * 100:.1f}%** | "
            f"{status(c.check_success_rate >= 0.90, warn=c.check_success_rate < 0.90)} |",
            f"| Infrastructure Coverage | **{c.infrastructure_coverage_pct}%** | "
            f"{status(c.infrastructure_coverage_pct >= 90, warn=c.infrastructure_coverage_pct < 90)} |",
        ]

        if metrics.level2:
            l2 = metrics.level2
            lines += [
                "",
                "### Multi-Domain Coverage (Level 2)",
                "",
                "| Domain | Findings | Status |",
                "|--------|----------|--------|",
            ]
            for domain, count in l2.findings_per_domain.items():
                label = DOMAIN_LABELS.get(domain, domain)
                lines.append(f"| {label} | {count} | PASS |")
            lines += [
                "",
                f"| Deduplication | Removed **{l2.duplicates_removed}** of {l2.total_before_dedup} "
                f"({l2.deduplication_rate * 100:.1f}%) | PASS |",
                f"| Domain Success | **{l2.domains_succeeded}/{l2.domains_attempted}** | "
                f"{status(l2.domain_success_rate >= 1.0, warn=l2.domain_success_rate < 1.0)} |",
            ]

        if metrics.level3:
            l3 = metrics.level3
            lines += [
                "",
                "### Autonomous Operation (Level 3)",
                "",
                "| Metric | Value | Target | Status |",
                "|--------|-------|--------|--------|",
                f"| Posture Score | **{l3.current_posture_score}/100** | > 50 | "
                f"{status(l3.current_posture_score > 50)} |",
                f"| Posture Trend | **{l3.posture_trend}** (delta {l3.posture_delta:+.1f}) | improving | "
                f"{status(l3.posture_trend == 'improving', warn=l3.posture_trend == 'stable')} |",
                f"| SLA Compliance Rate | **{l3.sla_compliance_rate * 100:.0f}%** | > 80% | "
                f"{status(l3.sla_compliance_rate >= 0.80)} |",
                f"| Scan Reliability | **{l3.scan_reliability_rate * 100:.0f}%** "
                f"({l3.successful_scan_runs}/{l3.total_scan_runs} scans) | > 95% | "
                f"{status(l3.scan_reliability_rate >= 0.95, warn=l3.scan_reliability_rate < 0.95)} |",
                f"| Resolution Rate | **{l3.resolution_rate * 100:.0f}%** | > 50% | "
                f"{status(l3.resolution_rate >= 0.50, warn=l3.resolution_rate < 0.50)} |",
                f"| Recurrence Rate | **{l3.recurrence_rate * 100:.0f}%** | < 10% | "
                f"{status(l3.recurrence_rate <= 0.10)} |",
                f"| Active SLA Breaches | **{l3.active_sla_breaches}** | 0 | "
                f"{status(l3.active_sla_breaches == 0)} |",
            ]

        lines.append("")
        return lines

    def _render_scan_health(self, report: ScanReport) -> list[str]:
        lines = ["## Scan Health", ""]

        if not report.scan_errors:
            lines.append("All checks executed successfully.")
            return lines

        lines.extend(
            [
                f"{len(report.scan_errors)} check(s) failed to execute:",
                "",
                "| Check | Error Type | Details |",
                "|---|---|---|",
            ]
        )

        for err in report.scan_errors:
            lines.append(f"| {err.check_id} | {err.error_type} | {err.error_message} |")

        lines.extend(
            [
                "",
                "> These checks did not run. The resources they cover are **not verified as clean**.",
            ]
        )
        return lines
