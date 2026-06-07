#!/usr/bin/env python3
"""Offensive Security Agent - Level 1, 2, and 3 entry point."""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from agent.runner import run_scan, run_scan_l3
from utils.llm_client import resolve_llm_config


def setup_logging(verbose: bool, daemon: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if daemon:
        handlers.append(logging.FileHandler("agent.log", mode="a", encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aivar Offensive Security Agent - AWS Infrastructure & Multi-Domain Scanner"
    )
    parser.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Scan level: 1=AWS, 2=multi-domain, 3=autonomous (default: 1)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to checklist YAML/JSON config",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Level 3 only: run continuously on schedule",
    )
    parser.add_argument(
        "--trend",
        action="store_true",
        help="Level 3 only: generate trend report and exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    load_dotenv(project_root / ".env")

    setup_logging(args.verbose, daemon=args.daemon)

    config_path = args.config
    if config_path is None:
        if args.level >= 3:
            config_path = "checklist_l3.yaml"
        elif args.level >= 2:
            config_path = "checklist_l2.yaml"
        else:
            config_path = "checklist.yaml"

    try:
        resolve_llm_config()
    except ValueError as e:
        logging.error("%s", e)
        return 1

    if args.level == 3:
        from config.loader import load_config
        from storage.database import init_db

        config = load_config(project_root / config_path)
        init_db()

        if args.trend:
            from reporter.trend_reporter import TrendReporter

            l3 = config.level3
            keep_n = l3.trend_report.keep_last_n_scans if l3 else 30
            TrendReporter(config.scan.output_dir, keep_last_n=keep_n).generate()
            print("Trend report generated.")
            return 0

        if args.daemon:
            from agent.orchestrator_l3 import OrchestratorL3
            from scheduler.scan_scheduler import ScanScheduler

            llm = resolve_llm_config()
            orch = OrchestratorL3(config, llm)
            l3_cfg = config.level3
            scheduler = ScanScheduler(orch.run, l3_cfg)

            def handle_shutdown(sig, frame):
                logging.info("Shutdown signal received. Stopping scheduler...")
                scheduler.stop()
                sys.exit(0)

            signal.signal(signal.SIGINT, handle_shutdown)
            signal.signal(signal.SIGTERM, handle_shutdown)

            logging.info("=== Offensive Security Agent starting in DAEMON mode ===")
            scheduler.start()

            while True:
                time.sleep(60)

        try:
            result = run_scan_l3(config_path)
        except Exception as e:
            logging.exception("L3 scan failed: %s", e)
            return 1

        lifecycle = result.get("lifecycle", {})
        print(f"\nScan complete (Level 3) — health: {result.get('health')}")
        print(f"  Posture Score: {result.get('posture_score')}/100")
        print(f"  Trend:         {result.get('trend')}")
        print(f"  New findings:  {lifecycle.get('new', 0)}")
        print(f"  Updated:       {lifecycle.get('updated', 0)}")
        print(f"  Resolved:      {lifecycle.get('resolved', 0)}")
        print(f"  Re-opened:     {lifecycle.get('reopened', 0)}")
        print(f"  SLA breaches:  {result.get('sla_breaches', 0)}")
        return 0

    try:
        report = run_scan(config_path, level=args.level)
    except Exception as e:
        logging.exception("Scan failed: %s", e)
        return 1

    print(
        f"\nScan complete (Level {report.scan_level}) - "
        f"{report.total_findings} findings ({report.scan_health})"
    )
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
    print("  Reports written to: reports/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
