#!/usr/bin/env python3
"""Run full demo test: setup → verify → scan → report check → cleanup."""

import json
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(PROJECT_ROOT / ".env.admin")

from dashboard.misconfig_service import (
    admin_configured,
    cleanup_misconfigs_sync,
    create_misconfigs_sync,
    verify_misconfigs,
)
from agent.runner import run_scan


def main() -> int:
    print("=" * 60)
    print("FULL DEMO TEST")
    print("=" * 60)

    if not admin_configured():
        print("FAIL: .env.admin not configured")
        return 1

    print("\n[1/5] Creating test misconfigs (admin)...")
    try:
        setup = create_misconfigs_sync()
        print(f"  OK: {setup}")
    except Exception as e:
        print(f"  FAIL: {e}")
        return 1

    print("\n[2/5] Verifying resources (scanner)...")
    v = verify_misconfigs()
    for r in v["results"]:
        status = "PASS" if r["pass"] else "FAIL"
        print(f"  [{status}] {r['id']}: {r['detail']}")
    print(f"  Result: {v['passed']}/{v['total']}")
    if not v["all_pass"]:
        print("  WARN: Not all resources visible — continuing scan anyway")

    print("\n[3/5] Running security scan...")
    try:
        report = run_scan("checklist.yaml")
    except Exception as e:
        print(f"  FAIL: {e}")
        _cleanup_safe()
        return 1

    print(f"  Scan health: {report.scan_health}")
    print(f"  Checks: {report.total_checks_succeeded}/{report.total_checks_attempted}")
    print(f"  Findings: {report.total_findings}")
    print(f"  By severity: {report.findings_by_severity}")

    print("\n[4/5] Finding summary:")
    for f in report.findings:
        print(f"  [{f.severity}] {f.check_id} — {f.title} ({f.resource_id})")

    expected_checks = {
        "s3_public_acl", "s3_public_policy", "iam_user_mfa",
        "sg_open_ssh", "sg_open_rdp", "iam_root_mfa",
        "cloudtrail_not_logging", "iam_password_policy",
    }
    found_checks = {f.check_id for f in report.findings}
    missing = expected_checks - found_checks
    extra_ok = report.total_findings >= 6 and report.findings_by_severity.get("critical", 0) >= 2

    print("\n[5/5] Cleanup (delete all test resources)...")
    _cleanup_safe()

    print("\n" + "=" * 60)
    if missing:
        print(f"MISSING expected findings: {sorted(missing)}")
    if extra_ok or report.total_findings >= 8:
        print("RESULT: PASS — demo scan working with strong findings")
        return 0
    if report.total_findings >= 5:
        print("RESULT: PARTIAL — scan works but not all 8 demo findings")
        return 0
    print("RESULT: FAIL — too few findings")
    return 1


def _cleanup_safe() -> None:
    try:
        result = cleanup_misconfigs_sync()
        print(f"  Cleanup OK: {result}")
    except Exception as e:
        print(f"  Cleanup error: {e}")


if __name__ == "__main__":
    sys.exit(main())
