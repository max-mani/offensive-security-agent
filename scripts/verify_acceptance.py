#!/usr/bin/env python3
"""Verify Level 1 acceptance criteria (run after configuring .env)."""

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
]


def main() -> int:
    from config.loader import load_config
    from agent.orchestrator import CHECK_REGISTRY, AgentOrchestrator

    print("=" * 60)
    print("Level 1 Acceptance Criteria Verification")
    print("=" * 60)

    results = []

    # Criterion 1: Reads YAML checklist
    cfg = load_config("checklist.yaml")
    ok1 = cfg.scan.name and len(cfg.checks) == 13
    results.append(("1. Reads YAML checklist config", ok1, f"{len(cfg.checks)} checks loaded"))

    # Criterion 2: 10+ distinct checks
    enabled = cfg.get_enabled_checks()
    ok2 = len(CHECK_REGISTRY) >= 10 and len(enabled) >= 10
    results.append(("2. Executes 10+ distinct checks", ok2, f"{len(CHECK_REGISTRY)} registered, {len(enabled)} enabled"))

    if not os.getenv("AWS_ACCESS_KEY_ID") or not (
        os.getenv("GROQ_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("OPENAI_API_KEY")
    ):
        print("\nWARNING: AWS or LLM credentials not set in .env")
        print("Skipping live scan (criteria 3-7 require credentials).\n")
        for name, ok, detail in results:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name} - {detail}")
        print("\nTo complete verification: copy .env.example to .env and run again.")
        return 0

    # Validate AWS credentials before live scan
    import boto3
    try:
        sts = boto3.Session(region_name=cfg.scan.aws_region).client("sts")
        sts.get_caller_identity()
    except Exception as e:
        print(f"\nWARNING: AWS credentials invalid or unreachable: {e}")
        print("Skipping live scan. Fix .env and run again.\n")
        for name, ok, detail in results:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name} - {detail}")
        return 0

    from utils.llm_client import resolve_llm_config

    # Run live scan
    print("\nRunning live scan against AWS...")
    llm = resolve_llm_config(cfg.scan.llm_model)
    print(f"LLM provider: {llm.provider} ({llm.model})")
    orchestrator = AgentOrchestrator(cfg, llm)
    report = orchestrator.run()

    # Criterion 3: Finding fields complete
    ok3 = True
    for f in report.findings:
        data = f.model_dump()
        for field in REQUIRED_FINDING_FIELDS:
            if field not in data or data[field] is None:
                ok3 = False
    results.append(("3. Findings include all required fields", ok3, f"{report.total_findings} findings checked"))

    # Criterion 4: API errors surfaced (informational - may be 0 errors if permissions OK)
    ok4 = hasattr(report, "scan_errors") and report.scan_health in ("healthy", "degraded", "partial", "failed")
    err_detail = f"{report.total_checks_errored} errors, health={report.scan_health}"
    results.append(("4. API errors logged in report (not swallowed)", ok4, err_detail))

    # Criterion 5: JSON + Markdown output
    reports_dir = Path(cfg.scan.output_dir)
    json_files = list(reports_dir.glob("findings_report_*.json"))
    md_files = list(reports_dir.glob("findings_report_*.md"))
    ok5 = len(json_files) > 0 and len(md_files) > 0
    results.append(("5. Produces JSON and Markdown reports", ok5, f"{len(json_files)} JSON, {len(md_files)} MD"))

    # Criterion 6: Zero false Critical - manual evidence check
    critical_findings = [f for f in report.findings if f.severity == "critical"]
    ok6 = True
    for f in critical_findings:
        ev = f.raw_evidence
        check = f.check_id
        if check == "iam_root_mfa" and ev.get("AccountMFAEnabled") != 0:
            ok6 = False
        elif check in ("sg_open_ssh", "sg_open_rdp") and not ev.get("OpenCIDRs"):
            ok6 = False
        elif check == "s3_public_acl" and not ev.get("PublicGrants"):
            ok6 = False
        elif check == "s3_public_policy" and not ev.get("PolicyStatus", {}).get("IsPublic"):
            ok6 = False
    results.append(("6. Critical findings backed by direct evidence", ok6, f"{len(critical_findings)} critical reviewed"))

    # Root MFA must stay critical when AccountMFAEnabled=0 (evidence floor)
    root_mfa = [f for f in report.findings if f.check_id == "iam_root_mfa"]
    ok6b = True
    if root_mfa:
        f = root_mfa[0]
        if f.raw_evidence.get("AccountMFAEnabled") == 0 and f.severity != "critical":
            ok6b = False
    detail6b = (
        f"iam_root_mfa severity={root_mfa[0].severity}"
        if root_mfa
        else "iam_root_mfa not present (root MFA may be enabled)"
    )
    results.append(("6b. Root MFA finding stays critical when MFA disabled", ok6b, detail6b))

    # Criterion 7: Real infrastructure
    ok7 = bool(report.aws_account_id) and report.aws_account_id.isdigit()
    results.append(("7. Scans real AWS infrastructure", ok7, f"Account {report.aws_account_id}"))

    print()
    all_pass = True
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  [{status}] {name}")
        print(f"         {detail}")

    print()
    if all_pass:
        print("ALL ACCEPTANCE CRITERIA PASSED")
    else:
        print("SOME CRITERIA FAILED - review output above")
    print("=" * 60)
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
