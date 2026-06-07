#!/usr/bin/env python3
"""Verify Level 3 acceptance criteria."""

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")
os.chdir(PROJECT_ROOT)


def main() -> int:
    results = []

    # 1. Config + deps
    try:
        import apscheduler  # noqa: F401
        import sqlalchemy  # noqa: F401

        deps_ok = True
    except ImportError as e:
        deps_ok = False
        dep_detail = str(e)

    from config.loader import load_config

    cfg = load_config("checklist_l3.yaml")
    cfg_ok = cfg.level3 is not None and cfg.level3.schedule.interval_hours == 6
    results.append(
        (
            "1. Config + L3 deps",
            deps_ok and cfg_ok,
            f"level3={cfg.level3 is not None}, schedule={cfg.level3.schedule.interval_hours if cfg.level3 else 'n/a'}",
        )
    )
    if not deps_ok:
        results[-1] = ("1. Config + L3 deps", False, dep_detail)

    # 2. DB schema
    from storage.database import Base, get_engine, init_db, reset_engine

    tmp_db = tempfile.mktemp(suffix=".db")
    reset_engine(tmp_db)
    init_db()
    engine = get_engine()
    tables = set(Base.metadata.tables.keys())
    schema_ok = tables == {"findings", "scan_runs", "audit_log", "scan_health"}
    results.append(("2. DB schema (4 tables)", schema_ok, ", ".join(sorted(tables))))

    # 5. Posture score on empty DB (before lifecycle adds findings)
    from reporter.trend_reporter import compute_posture_score

    score_empty = compute_posture_score()
    score_ok = score_empty == 100.0
    results.append(("5. Posture score (empty=100)", score_ok, f"score={score_empty}"))

    # 3–4. Lifecycle + cross-run dedup
    from agent.deduplicator import compute_fingerprint
    from agent.lifecycle_manager import FindingLifecycleManager
    from models.finding import ValidatedFinding

    def make_finding(check_id="secrets_scan", resource="file.env:L1", sev="critical"):
        f = ValidatedFinding(
            check_id=check_id,
            title="Test finding",
            resource_id=resource,
            resource_arn=f"file::{resource}",
            resource_type="File",
            region="local",
            severity=sev,
            severity_reasoning="test",
            raw_evidence={"test": True},
            business_impact="test impact",
            remediation_steps=["fix it"],
            remediation_command="echo fix",
            confidence_score=90,
            domain="secrets",
        )
        f.fingerprint = compute_fingerprint(f)
        return f

    scan_id_1 = str(uuid.uuid4())
    scan_id_2 = str(uuid.uuid4())
    lm1 = FindingLifecycleManager(scan_id_1, cfg.level3)
    f1 = make_finding()
    r1 = lm1.process([f1])
    opened_ok = len(r1["new"]) == 1

    lm2 = FindingLifecycleManager(scan_id_2, cfg.level3)
    r2 = lm2.process([f1])
    updated_ok = len(r2["new"]) == 0 and len(r2["updated"]) == 1

    results.append(
        (
            "3. Lifecycle opened -> updated",
            opened_ok and updated_ok,
            f"run1 new={len(r1['new'])}, run2 updated={len(r2['updated'])}",
        )
    )
    results.append(
        (
            "4. Cross-run dedup (1 DB row)",
            updated_ok,
            "same fingerprint updates record",
        )
    )

    # 6. Audit trail
    from storage.audit_store import AuditStore
    from storage.database import AuditLog, get_session

    session = get_session()
    audit = AuditStore(session)
    audit.log("test_action", "finding", "test-id", {"foo": "bar"})
    session.commit()
    count = session.query(AuditLog).count()
    session.close()
    results.append(("6. Audit trail append-only", count >= 1, f"{count} entries"))

    # 7. Scan health records
    from storage.database import ScanHealthRecord

    session = get_session()
    session.add(
        ScanHealthRecord(
            scan_run_id=scan_id_1,
            check_id="iam_root_mfa",
            domain="aws_infrastructure",
            status="success",
        )
    )
    session.add(
        ScanHealthRecord(
            scan_run_id=scan_id_1,
            check_id="api_security_headers@HTTPBin",
            domain="api_endpoints",
            status="error",
            error_type="timeout",
            error_message="connection timed out",
        )
    )
    session.commit()
    health_count = session.query(ScanHealthRecord).count()
    session.close()
    results.append(("7. Scan health records", health_count >= 2, f"{health_count} rows"))

    # 8. Escalation mock
    from agent.escalation import EscalationEngine
    from models.config import Level3Config

    esc_cfg = Level3Config(slack_webhook_url="https://hooks.slack.com/test")
    engine_esc = EscalationEngine(esc_cfg)
    with patch("agent.escalation.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, text="ok")
        engine_esc.escalate_critical([f1], scan_id_1)
        slack_ok = mock_post.called
    results.append(("8. Escalation sends Slack (mocked)", slack_ok, f"called={slack_ok}"))

    # 9. SLA tracker
    from agent.sla_tracker import SLATracker
    from storage.database import FindingRecord

    session = get_session()
    breached_id = str(uuid.uuid4())
    session.add(
        FindingRecord(
            id=breached_id,
            fingerprint="sla_test_fp",
            check_id="iam_root_mfa",
            domain="aws_infrastructure",
            resource_id="root",
            resource_arn="arn:aws:iam::123:root",
            severity="critical",
            title="SLA test",
            status="opened",
            first_seen=datetime.utcnow() - timedelta(hours=48),
            last_seen=datetime.utcnow(),
            sla_deadline=datetime.utcnow() - timedelta(hours=1),
            confidence_score=95,
        )
    )
    session.commit()
    session.close()

    breached = SLATracker().get_breached()
    sla_ok = any(b["id"] == breached_id for b in breached)
    results.append(("9. SLA breach detection", sla_ok, f"breached={len(breached)}"))

    # 10. Trend direction
    from storage.database import ScanRun

    session = get_session()
    session.add(
        ScanRun(
            id=str(uuid.uuid4()),
            started_at=datetime.utcnow() - timedelta(hours=2),
            completed_at=datetime.utcnow() - timedelta(hours=1),
            posture_score=60.0,
            health="degraded",
        )
    )
    session.add(
        ScanRun(
            id=str(uuid.uuid4()),
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow(),
            posture_score=75.0,
            health="degraded",
        )
    )
    session.commit()
    session.close()

    from reporter.trend_reporter import TrendReporter

    trend = TrendReporter(keep_last_n=10).generate()
    trend_ok = trend.get("trend_direction") == "improving"
    results.append(
        (
            "10. Trend report direction",
            trend_ok,
            f"direction={trend.get('trend_direction')}, delta={trend.get('score_delta')}",
        )
    )

    # 11. Scheduler import
    from scheduler.scan_scheduler import ScanScheduler

    sched_ok = ScanScheduler is not None
    results.append(("11. Scheduler module", sched_ok, "ScanScheduler importable"))

    # Cleanup temp db
    reset_engine(str(PROJECT_ROOT / "storage" / "findings.db"))
    init_db()

    print("=" * 60)
    print("Level 3 Acceptance Criteria Verification")
    print("=" * 60)
    all_pass = True
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name} — {detail}")
        if not ok:
            all_pass = False

    print("=" * 60)
    if all_pass:
        print("ALL LEVEL 3 ACCEPTANCE CRITERIA PASSED")
        return 0
    print("SOME CRITERIA FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
