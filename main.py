#!/usr/bin/env python3
"""Offensive Security Agent - Level 1 and Level 2 entry point."""

import argparse
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from agent.runner import run_scan
from utils.llm_client import resolve_llm_config


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aivar Offensive Security Agent - AWS Infrastructure & Multi-Domain Scanner"
    )
    parser.add_argument(
        "--level",
        type=int,
        choices=[1, 2],
        default=1,
        help="Scan level: 1=AWS only, 2=multi-domain (default: 1)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to checklist YAML/JSON config (default: checklist.yaml or checklist_l2.yaml)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    project_root = Path(__file__).resolve().parent
    load_dotenv(project_root / ".env")

    config_path = args.config
    if config_path is None:
        config_path = "checklist_l2.yaml" if args.level >= 2 else "checklist.yaml"

    try:
        resolve_llm_config()
    except ValueError as e:
        logging.error("%s", e)
        return 1

    try:
        report = run_scan(config_path, level=args.level)
    except Exception as e:
        logging.exception("Scan failed: %s", e)
        return 1

    print(f"\nScan complete (Level {report.scan_level}) - {report.total_findings} findings ({report.scan_health})")
    print(f"  Critical: {report.findings_by_severity.get('critical', 0)}")
    print(f"  High:     {report.findings_by_severity.get('high', 0)}")
    print(f"  Medium:   {report.findings_by_severity.get('medium', 0)}")
    if report.scan_level >= 2:
        print(f"  Domains:  {report.domains_scanned}")
        print(f"  By domain: {report.findings_by_domain}")
        print(f"  Dedup removed: {report.deduplication_removed}")
        if report.findings:
            top = report.findings[0]
            print(f"  Top impact: {top.title} (score={top.impact_score})")
    if report.scan_errors:
        print(f"  Errors:   {report.total_checks_errored} check(s) failed")
    print(f"  Reports written to: reports/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
