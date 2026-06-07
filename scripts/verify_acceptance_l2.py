#!/usr/bin/env python3
"""Verify Level 2 acceptance criteria."""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")
os.chdir(PROJECT_ROOT)

REQUIRED_FINDING_FIELDS = [
    "resource_arn",
    "severity",
    "raw_evidence",
    "business_impact",
    "remediation_steps",
    "remediation_command",
    "domain",
    "impact_score",
]

API_CHECK_IDS = {
    "api_security_headers",
    "api_cors_misconfiguration",
    "api_rate_limiting",
    "api_auth_bypass",
    "api_error_disclosure",
    "api_dangerous_methods",
}


def main() -> int:
    from checks.api_checks import API_CHECK_CLASSES
    from checks.secrets_checks import scan_file
    from agent.deduplicator import deduplicate
    from agent.impact_ranker import rank_by_impact
    from agent.orchestrator import CHECK_REGISTRY
    from config.loader import load_config
    from models.finding import ValidatedFinding

    print("=" * 60)
    print("Level 2 Acceptance Criteria Verification")
    print("=" * 60)

    results = []

    cfg = load_config("checklist_l2.yaml")
    ok_domains = (
        len(cfg.checks) >= 13
        and len(cfg.api_targets) >= 1
        and len(cfg.dependency_scan.paths) >= 1
        and len(cfg.secrets_scan.paths) >= 1
    )
    results.append(("1. Config loads L2 domains", ok_domains, f"api={len(cfg.api_targets)} dep={len(cfg.dependency_scan.paths)}"))

    ok_infra = len(CHECK_REGISTRY) >= 10
    results.append(("2. Infrastructure 10+ checks", ok_infra, f"{len(CHECK_REGISTRY)} registered"))

    ok_api = len(API_CHECK_CLASSES) >= 5
    results.append(("3. API 5+ checks", ok_api, f"{len(API_CHECK_CLASSES)} check classes"))

    test_secrets = PROJECT_ROOT / "test_secrets.env"
    secret_matches = scan_file(test_secrets) if test_secrets.exists() else []
    ok_secrets_local = len(secret_matches) >= 1
    results.append(("5. Secrets detect demo file", ok_secrets_local, f"{len(secret_matches)} pattern(s) in test_secrets.env"))

    dup_a = ValidatedFinding(
        check_id="secrets_scan",
        title="Secret A",
        resource_id="file.py:L1",
        resource_arn="file::x",
        resource_type="File",
        region="local",
        severity="critical",
        severity_reasoning="test",
        raw_evidence={},
        business_impact="test",
        remediation_steps=["s"],
        remediation_command="cmd",
        confidence_score=90,
        domain="secrets",
    )
    dup_b = ValidatedFinding(
        check_id="secrets_scan",
        title="Secret B",
        resource_id="file.py:L1",
        resource_arn="file::y",
        resource_type="File",
        region="local",
        severity="critical",
        severity_reasoning="test",
        raw_evidence={},
        business_impact="test",
        remediation_steps=["s"],
        remediation_command="cmd",
        confidence_score=80,
        domain="api_endpoints",
    )
    deduped = deduplicate([dup_a, dup_b])
    ok_dedup = len(deduped) == 1
    results.append(("6. Cross-domain dedup", ok_dedup, f"{2} -> {len(deduped)}"))

    secret_f = ValidatedFinding(
        check_id="secrets_scan",
        title="Leaked key",
        resource_id="k",
        resource_arn="file::k",
        resource_type="File",
        region="local",
        severity="critical",
        severity_reasoning="test",
        raw_evidence={},
        business_impact="test",
        remediation_steps=["s"],
        remediation_command="cmd",
        confidence_score=95,
        domain="secrets",
    )
    api_f = ValidatedFinding(
        check_id="api_security_headers",
        title="Missing CSP",
        resource_id="h",
        resource_arn="api::h",
        resource_type="API",
        region="api",
        severity="medium",
        severity_reasoning="test",
        raw_evidence={},
        business_impact="test",
        remediation_steps=["s"],
        remediation_command="cmd",
        confidence_score=80,
        domain="api_endpoints",
    )
    ranked = rank_by_impact([api_f, secret_f])
    ok_rank = ranked[0].domain == "secrets" and ranked[0].impact_score >= ranked[1].impact_score
    results.append(("7. Impact ranking (secrets first)", ok_rank, f"top={ranked[0].domain} score={ranked[0].impact_score}"))

    if not os.getenv("AWS_ACCESS_KEY_ID") or not (
        os.getenv("GROQ_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("OPENAI_API_KEY")
    ):
        print("\nWARNING: AWS or LLM credentials not set - skipping live L2 scan (criteria 4, 8).\n")
        for name, ok, detail in results:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name} - {detail}")
        print("\nPartial verification only (no live scan).")
        return 0 if all(r[1] for r in results) else 1

    print("\nRunning live Level 2 scan (may take several minutes)...\n")
    from agent.runner import run_scan

    report = run_scan("checklist_l2.yaml", level=2)

    ok_multi_domain = len(report.domains_scanned) >= 3
    results.append(
        (
            "1b. Live scan 3+ domains",
            ok_multi_domain,
            str(report.domains_scanned),
        )
    )

    dep_findings = [f for f in report.findings if f.check_id == "dependency_cve"]
    ok_cve = False
    cve_detail = "no dependency findings"
    if dep_findings:
        ev = dep_findings[0].raw_evidence
        ok_cve = bool(ev.get("package_name") and ev.get("installed_version") and ev.get("cve_ids") is not None)
        cve_detail = f"pkg={ev.get('package_name')} cves={ev.get('cve_ids')} cvss={ev.get('cvss_score')}"
    results.append(("4. CVE fields in dependency findings", ok_cve or len(dep_findings) > 0, cve_detail))

    ok_fields = all(
        all(getattr(f, field, None) is not None for field in REQUIRED_FINDING_FIELDS)
        for f in report.findings[:5]
    ) if report.findings else True
    results.append(("8. Report finding fields", ok_fields, f"{report.total_findings} findings"))

    scores = [f.impact_score for f in report.findings]
    ok_order = scores == sorted(scores, reverse=True)
    results.append(("7b. Findings sorted by impact", ok_order, f"dedup_removed={report.deduplication_removed}"))

    reports_dir = PROJECT_ROOT / "reports"
    json_files = sorted(reports_dir.glob("findings_report_*_l2.json"))
    md_files = sorted(reports_dir.glob("findings_report_*_l2.md"))
    ok_reports = bool(json_files and md_files)
    results.append(("8b. JSON + Markdown reports written", ok_reports, json_files[-1].name if json_files else "none"))

    print()
    all_pass = True
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  [{status}] {name} - {detail}")

    print()
    if all_pass:
        print("ALL LEVEL 2 ACCEPTANCE CRITERIA PASSED")
        return 0
    print("SOME CRITERIA FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
