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


class MarkdownReporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, report: ScanReport) -> Path:
        timestamp = report.end_time.strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"findings_report_{timestamp}.md"
        output_path.write_text(self._render(report), encoding="utf-8")
        return output_path

    def _render(self, report: ScanReport) -> str:
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

        finding_counter = 1
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in report.findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"## {SEVERITY_EMOJI[sev]} Findings")
            lines.append("")

            for finding in sev_findings:
                fid = f"F{finding_counter:03d}"
                finding_counter += 1
                lines.extend(
                    [
                        f"### [{fid}] {finding.title}",
                        f"**Resource:** `{finding.resource_id}` ({finding.resource_type})  ",
                        f"**ARN:** `{finding.resource_arn}`  ",
                        f"**Confidence:** {finding.confidence_score}%",
                        "",
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

        lines.extend(self._render_scan_health(report))
        return "\n".join(lines)

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
            lines.append(
                f"| {err.check_id} | {err.error_type} | {err.error_message} |"
            )

        lines.extend(
            [
                "",
                "> These checks did not run. The resources they cover are **not verified as clean**.",
            ]
        )
        return lines
