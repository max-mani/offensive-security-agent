#!/usr/bin/env python3
"""Offensive Security Agent - Level 1 entry point."""

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
        description="Aivar Offensive Security Agent - Level 1 AWS Infrastructure Scanner"
    )
    parser.add_argument(
        "--config",
        default="checklist.yaml",
        help="Path to checklist YAML/JSON config (default: checklist.yaml)",
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

    try:
        resolve_llm_config()
    except ValueError as e:
        logging.error("%s", e)
        return 1

    try:
        report = run_scan(args.config)
    except Exception as e:
        logging.exception("Scan failed: %s", e)
        return 1

    print(f"\nScan complete - {report.total_findings} findings ({report.scan_health})")
    print(f"  Critical: {report.findings_by_severity.get('critical', 0)}")
    print(f"  High:     {report.findings_by_severity.get('high', 0)}")
    print(f"  Medium:   {report.findings_by_severity.get('medium', 0)}")
    if report.scan_errors:
        print(f"  Errors:   {report.total_checks_errored} check(s) failed")
    print(f"  Reports written to: reports/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
