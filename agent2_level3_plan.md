# Agent 2: Offensive Security Agent — Level 3
## Technical Build Plan — Autonomous Continuous Scanning

**Author:** Manikandan M  
**Deadline:** Monday, 08 June 2026, 11:00 AM  
**Prerequisite:** Level 1 + Level 2 complete and working  

---

## Table of Contents

1. [What Changes in Level 3](#1-what-changes-in-level-3)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Structure Changes](#3-project-structure-changes)
4. [Database Schema — SQLite](#4-database-schema--sqlite)
5. [Finding Lifecycle Manager](#5-finding-lifecycle-manager)
6. [Scheduler — APScheduler](#6-scheduler--apscheduler)
7. [Escalation Engine — Slack Webhook](#7-escalation-engine--slack-webhook)
8. [SLA Tracker](#8-sla-tracker)
9. [Audit Trail](#9-audit-trail)
10. [Trend Reporter — Posture Score](#10-trend-reporter--posture-score)
11. [Scan Health Reporter](#11-scan-health-reporter)
12. [Safe Auto-Remediation (Optional)](#12-safe-auto-remediation-optional)
13. [Level 3 Orchestrator](#13-level-3-orchestrator)
14. [Extended Config Schema](#14-extended-config-schema)
15. [Updated main.py — Daemon Mode](#15-updated-mainpy--daemon-mode)
16. [Implementation Order](#16-implementation-order)
17. [Acceptance Criteria Checklist](#17-acceptance-criteria-checklist)
18. [Demo Script](#18-demo-script)

---

## 1. What Changes in Level 3

Level 2 ran one scan across 4 domains and produced a report.
Level 3 makes the agent run **continuously, autonomously, and with memory**.

```
Level 2 (done)                  Level 3 (new additions)
──────────────────              ──────────────────────────────────────────────
One-shot scan + report    +     APScheduler (runs scan every N hours)
                          +     SQLite database (findings persist across runs)
                          +     Finding lifecycle (opened → updated → resolved → re-opened)
                          +     Cross-run deduplication (recurring finding updates, not creates)
                          +     Slack webhook escalation for Critical findings
                          +     SLA tracking (Critical unresolved > 24h → alert)
                          +     Immutable audit trail (every action logged)
                          +     Security posture score over time (trend report)
                          +     Scan health reporting (failed checks surfaced, not silently skipped)
                          +     Safe auto-remediation (dry-run, human gate for destructive)
```

**Key design principle of Level 3:**
The agent must report its own health and NEVER assume success.
A check that fails to run is not the same as a resource that is clean.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                  main.py --level 3 --daemon                          │
│                  Starts scheduler, runs forever                       │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      APScheduler                                     │
│            BackgroundScheduler — cron or interval trigger            │
│            Default: every 6 hours (configurable)                     │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ fires every N hours
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   OrchestratorL3                                     │
│              (wraps OrchestratorL2 — reuses all L2 logic)            │
│                                                                      │
│  Step 1: Pre-scan — check SLA breaches from previous runs            │
│  Step 2: Run all 4 domains (same as L2 — parallel)                   │
│  Step 3: Enrich findings via LLM (same as L2)                        │
│  Step 4: Dedup within this scan (same as L2)                         │
│  Step 5: Pass to FindingLifecycleManager (NEW in L3)                 │
│  Step 6: Escalate new Critical findings (NEW in L3)                  │
│  Step 7: Write scan health to DB (NEW in L3)                         │
│  Step 8: Compute posture score (NEW in L3)                           │
│  Step 9: Write reports + audit log (NEW in L3)                       │
└──────────┬───────────────┬──────────────────┬───────────────────────┘
           │               │                  │
           ▼               ▼                  ▼
┌──────────────┐  ┌─────────────────┐  ┌────────────────────────────┐
│  SQLite DB   │  │ EscalationEngine│  │     TrendReporter          │
│  storage/    │  │ Slack webhook   │  │  Posture score over time   │
│  findings.db │  │ for Critical    │  │  trend_report.json + .md   │
│              │  │ SLA breach alert│  └────────────────────────────┘
│  Tables:     │  └─────────────────┘
│  - findings  │
│  - scan_runs │
│  - audit_log │
│  - scan_health│
└──────────────┘
```

---

## 3. Project Structure Changes

```
offensive-security-agent/
│
├── main.py                           [UPDATED] add --daemon flag + L3 mode
├── checklist_l3.yaml                 [NEW]     L3 config (schedule, Slack, SLA thresholds)
├── requirements.txt                  [UPDATED] add apscheduler, sqlalchemy
│
├── models/
│   ├── finding.py                    [UPDATED] add status, lifecycle fields
│   └── report.py                     [UPDATED] add posture_score, trend fields
│
├── storage/                          [NEW DIR]
│   ├── __init__.py
│   ├── database.py                   [NEW] SQLAlchemy models + engine setup
│   ├── findings_store.py             [NEW] CRUD operations for findings
│   ├── audit_store.py                [NEW] append-only audit log
│   └── findings.db                   [generated at runtime — not committed]
│
├── agent/
│   ├── orchestrator.py               [REUSED]
│   ├── orchestrator_l2.py            [REUSED]
│   ├── orchestrator_l3.py            [NEW]
│   ├── intelligence.py               [REUSED]
│   ├── deduplicator.py               [REUSED]
│   ├── impact_ranker.py              [REUSED]
│   ├── lifecycle_manager.py          [NEW] finding lifecycle state machine
│   ├── escalation.py                 [NEW] Slack webhook + SLA alerting
│   ├── sla_tracker.py                [NEW] SLA deadline tracking
│   └── auto_remediation.py           [NEW] safe dry-run remediation
│
├── reporter/
│   ├── json_reporter.py              [REUSED]
│   ├── markdown_reporter.py          [REUSED]
│   └── trend_reporter.py             [NEW] posture score over time
│
└── scheduler/
    ├── __init__.py
    └── scan_scheduler.py             [NEW] APScheduler setup + job management
```

---

## 4. Database Schema — SQLite

### Why SQLite?

- Zero external dependencies — just a file on disk
- Inspectable with DB Browser for SQLite during demo
- SQLAlchemy ORM means easy migration to PostgreSQL later
- Perfect for single-machine persistent state

### `storage/database.py`

```python
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean,
    DateTime, Text, func
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

Base = declarative_base()
DB_PATH = os.getenv("DB_PATH", "storage/findings.db")


class FindingRecord(Base):
    """
    Persistent record for a security finding across scan runs.
    One row per unique finding (identified by fingerprint).
    Updated in place when the same finding reappears.
    """
    __tablename__ = "findings"

    id          = Column(String, primary_key=True)      # UUID
    fingerprint = Column(String, nullable=False, unique=True, index=True)
    check_id    = Column(String, nullable=False)
    domain      = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    resource_arn = Column(String, nullable=False)
    severity    = Column(String, nullable=False)
    title       = Column(String, nullable=False)

    # Lifecycle state machine
    # opened → updated → resolved → re-opened
    status      = Column(String, nullable=False, default="opened")

    # Timestamps
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    # SLA
    sla_deadline   = Column(DateTime, nullable=True)   # first_seen + SLA hours
    sla_breached   = Column(Boolean, default=False)
    sla_alert_sent = Column(Boolean, default=False)    # prevent duplicate alerts

    # Finding details
    confidence_score    = Column(Integer, nullable=False)
    business_impact     = Column(Text, nullable=True)
    remediation_command = Column(Text, nullable=True)
    raw_evidence        = Column(Text, nullable=True)  # JSON string

    # Scan tracking
    scan_run_id          = Column(String, nullable=True)  # last scan that saw this
    consecutive_misses   = Column(Integer, default=0)     # scans where not seen
    auto_resolved        = Column(Boolean, default=False) # resolved automatically

    # Escalation
    escalated = Column(Boolean, default=False)  # True if Slack alert sent


class ScanRun(Base):
    """One record per scan execution."""
    __tablename__ = "scan_runs"

    id              = Column(String, primary_key=True)
    started_at      = Column(DateTime, default=datetime.utcnow)
    completed_at    = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    health          = Column(String, nullable=True)  # healthy|degraded|partial|failed
    config_name     = Column(String, nullable=True)

    # Finding counts for this run
    total_findings    = Column(Integer, default=0)
    new_findings      = Column(Integer, default=0)
    updated_findings  = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    reopened_findings = Column(Integer, default=0)

    # Per-severity counts
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    low_count      = Column(Integer, default=0)

    # Posture score at end of this scan
    posture_score = Column(Float, nullable=True)


class AuditLog(Base):
    """
    Append-only audit trail. Every action is logged.
    Never updated, never deleted.
    """
    __tablename__ = "audit_log"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, nullable=False)
    actor       = Column(String, nullable=False)   # "agent" | "scheduler" | "human"
    action      = Column(String, nullable=False)
    # Actions: finding_opened | finding_updated | finding_resolved | finding_reopened
    #          scan_started | scan_completed | scan_failed | sla_breached
    #          escalation_sent | auto_remediation_executed | auto_remediation_skipped
    entity_type = Column(String, nullable=True)    # "finding" | "scan_run"
    entity_id   = Column(String, nullable=True)
    details     = Column(Text, nullable=True)      # JSON with extra context


class ScanHealthRecord(Base):
    """
    Per-check health record for every scan run.
    Captures which checks ran, which failed, and why.
    """
    __tablename__ = "scan_health"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String, nullable=False)
    check_id    = Column(String, nullable=False)
    domain      = Column(String, nullable=False)
    status      = Column(String, nullable=False)  # "success" | "error" | "skipped"
    error_type  = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    timestamp   = Column(DateTime, default=datetime.utcnow)


def get_engine():
    os.makedirs("storage", exist_ok=True)
    return create_engine(f"sqlite:///{DB_PATH}", echo=False)

def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    return engine

def get_session():
    engine = init_db()
    Session = sessionmaker(bind=engine)
    return Session()
```

---

## 5. Finding Lifecycle Manager

### State Machine

```
                    [new fingerprint]
                          │
                          ▼
                      "opened"
                          │
              ┌───────────┴────────────┐
              │ seen again             │ not seen (consecutive_misses += 1)
              ▼                        │
          "updated"                    │
              │                        │ (after 3 consecutive misses)
              │ not seen               ▼
              └──────────────►  "resolved" (auto)
                                       │
                             [seen again in future scan]
                                       │
                                       ▼
                                  "re-opened"
```

### `agent/lifecycle_manager.py`

```python
import json
import logging
from datetime import datetime, timedelta
from typing import List, Tuple

from models.finding import ValidatedFinding
from storage.database import FindingRecord, get_session
from storage.audit_store import AuditStore

logger = logging.getLogger(__name__)

# Number of consecutive missed scans before auto-resolving
AUTO_RESOLVE_AFTER_MISSES = 3

# SLA thresholds in hours per severity
SLA_HOURS = {
    "critical": 24,
    "high":     72,
    "medium":   168,  # 7 days
    "low":      720,  # 30 days
    "info":     None  # No SLA
}


class FindingLifecycleManager:
    """
    Manages the lifecycle of findings across scan runs.

    Given a list of current scan's validated findings, it:
    1. Creates new DB records for findings never seen before (status: opened)
    2. Updates existing records for findings seen again (status: updated)
    3. Marks previously-resolved findings as re-opened if they reappear
    4. Increments consecutive_misses for findings not seen this scan
    5. Auto-resolves findings not seen for AUTO_RESOLVE_AFTER_MISSES scans
    6. Logs every state change to audit_log

    Returns:
    - new_findings: list of ValidatedFinding (brand new this scan)
    - updated_findings: list already in DB, seen again
    - resolved_findings: list auto-resolved this scan
    - reopened_findings: list re-opened this scan
    """

    def __init__(self, scan_run_id: str):
        self.scan_run_id = scan_run_id
        self.session = get_session()
        self.audit = AuditStore(self.session)

    def process(self, current_findings: List[ValidatedFinding]) -> dict:
        """
        Main entry point. Process all findings from the current scan.
        Returns dict with categorized findings and counts.
        """
        now = datetime.utcnow()
        current_fps = {f.fingerprint: f for f in current_findings if hasattr(f, "fingerprint")}

        new_fps = []
        updated_fps = []
        reopened_fps = []

        # Process each finding from current scan
        for fp, finding in current_fps.items():
            existing = self.session.query(FindingRecord).filter_by(fingerprint=fp).first()

            if existing is None:
                # Brand new finding — create record
                record = self._create_record(finding, now)
                self.session.add(record)
                new_fps.append(finding)
                self.audit.log("finding_opened", "finding", record.id, {
                    "check_id": finding.check_id,
                    "severity": finding.severity,
                    "resource_arn": finding.resource_arn
                })
                logger.info(f"[lifecycle] NEW: {finding.check_id} / {finding.resource_id}")

            elif existing.status == "resolved":
                # Was resolved, now reappearing — re-open it
                existing.status = "re-opened"
                existing.last_seen = now
                existing.resolved_at = None
                existing.consecutive_misses = 0
                existing.scan_run_id = self.scan_run_id
                existing.sla_deadline = self._compute_sla(finding.severity, now)
                existing.sla_breached = False
                existing.sla_alert_sent = False
                existing.escalated = False
                reopened_fps.append(finding)
                self.audit.log("finding_reopened", "finding", existing.id, {
                    "severity": finding.severity,
                    "previously_resolved": True
                })
                logger.info(f"[lifecycle] REOPENED: {finding.check_id} / {finding.resource_id}")

            else:
                # Known open finding — update it
                existing.status = "updated"
                existing.last_seen = now
                existing.consecutive_misses = 0
                existing.scan_run_id = self.scan_run_id
                # Update enrichment in case LLM gave better output this time
                existing.confidence_score = finding.confidence_score
                existing.business_impact = finding.business_impact
                existing.remediation_command = finding.remediation_command
                updated_fps.append(finding)
                self.audit.log("finding_updated", "finding", existing.id, {
                    "severity": finding.severity
                })

        # Process findings NOT seen in this scan (potential resolutions)
        resolved_fps = self._process_misses(current_fps, now)

        self.session.commit()
        self.session.close()

        return {
            "new": new_fps,
            "updated": updated_fps,
            "reopened": reopened_fps,
            "resolved": resolved_fps
        }

    def _create_record(self, finding: ValidatedFinding, now: datetime) -> FindingRecord:
        """Create a new FindingRecord from a ValidatedFinding."""
        return FindingRecord(
            id=str(__import__("uuid").uuid4()),
            fingerprint=getattr(finding, "fingerprint", finding.check_id + finding.resource_id),
            check_id=finding.check_id,
            domain=getattr(finding, "domain", "unknown"),
            resource_id=finding.resource_id,
            resource_arn=finding.resource_arn,
            severity=finding.severity,
            title=finding.title,
            status="opened",
            first_seen=now,
            last_seen=now,
            sla_deadline=self._compute_sla(finding.severity, now),
            confidence_score=finding.confidence_score,
            business_impact=finding.business_impact,
            remediation_command=finding.remediation_command,
            raw_evidence=json.dumps(finding.raw_evidence, default=str),
            scan_run_id=self.scan_run_id,
            consecutive_misses=0,
            escalated=False
        )

    def _compute_sla(self, severity: str, from_time: datetime):
        """Compute SLA deadline from first_seen time."""
        hours = SLA_HOURS.get(severity)
        if hours is None:
            return None
        return from_time + timedelta(hours=hours)

    def _process_misses(self, current_fps: dict, now: datetime) -> list:
        """
        For every open finding NOT in current scan:
        - Increment consecutive_misses
        - Auto-resolve if misses >= AUTO_RESOLVE_AFTER_MISSES
        """
        resolved = []

        open_records = self.session.query(FindingRecord).filter(
            FindingRecord.status.in_(["opened", "updated", "re-opened"])
        ).all()

        for record in open_records:
            if record.fingerprint not in current_fps:
                record.consecutive_misses += 1

                if record.consecutive_misses >= AUTO_RESOLVE_AFTER_MISSES:
                    record.status = "resolved"
                    record.resolved_at = now
                    record.auto_resolved = True
                    resolved.append(record.id)
                    self.audit.log("finding_resolved", "finding", record.id, {
                        "reason": f"Not seen in {AUTO_RESOLVE_AFTER_MISSES} consecutive scans",
                        "auto_resolved": True
                    })
                    logger.info(f"[lifecycle] AUTO-RESOLVED: {record.check_id} / {record.resource_id}")

        return resolved
```

---

## 6. Scheduler — APScheduler

### `scheduler/scan_scheduler.py`

```python
import logging
import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED

logger = logging.getLogger(__name__)


class ScanScheduler:
    """
    Wraps APScheduler to run security scans on a configurable schedule.

    Supports two trigger modes:
    1. cron: "0 */6 * * *" — every 6 hours at minute 0
    2. interval: every N minutes/hours — simpler for testing

    The scheduler runs in a background daemon thread.
    The main thread stays alive via an infinite loop.
    """

    def __init__(self, scan_function, config):
        self.scan_function = scan_function
        self.config = config
        self.scheduler = BackgroundScheduler(
            job_defaults={"coalesce": True, "max_instances": 1}
            # coalesce: if scheduler was paused and multiple runs were missed,
            #           run only once when it resumes (don't queue up missed runs)
            # max_instances: never run two scans simultaneously
        )
        self._register_listeners()

    def _register_listeners(self):
        """Log all scheduler events for observability."""
        def on_job_executed(event):
            logger.info(f"[scheduler] Scan job completed successfully")

        def on_job_error(event):
            logger.error(f"[scheduler] Scan job FAILED: {event.exception}")
            # The agent must report its own health — never silently swallow
            from storage.audit_store import AuditStore
            from storage.database import get_session
            session = get_session()
            AuditStore(session).log("scan_failed", "scan_run", None, {
                "error": str(event.exception),
                "scheduled": True
            })
            session.commit()
            session.close()

        self.scheduler.add_listener(on_job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(on_job_error, EVENT_JOB_ERROR)

    def start(self):
        """Start the scheduler and add the scan job."""
        schedule_cfg = self.config.get("schedule", {})
        mode = schedule_cfg.get("mode", "interval")

        if mode == "cron":
            cron_expr = schedule_cfg.get("cron", "0 */6 * * *")
            trigger = CronTrigger.from_crontab(cron_expr)
            logger.info(f"[scheduler] Using cron trigger: {cron_expr}")
        else:
            hours = schedule_cfg.get("interval_hours", 6)
            trigger = IntervalTrigger(hours=hours)
            logger.info(f"[scheduler] Using interval trigger: every {hours} hours")

        self.scheduler.add_job(
            self.scan_function,
            trigger=trigger,
            id="security_scan",
            name="Offensive Security Scan",
            replace_existing=True,
            misfire_grace_time=300  # 5 min grace if job fires slightly late
        )

        self.scheduler.start()
        logger.info("[scheduler] Scheduler started. Scan job registered.")

        # Run once immediately on start (don't wait for first interval)
        if schedule_cfg.get("run_on_start", True):
            logger.info("[scheduler] Running initial scan immediately...")
            self.scan_function()

    def stop(self):
        """Gracefully stop the scheduler."""
        self.scheduler.shutdown(wait=True)
        logger.info("[scheduler] Scheduler stopped.")
```

---

## 7. Escalation Engine — Slack Webhook

### `agent/escalation.py`

```python
import json
import logging
import os
import requests
from datetime import datetime

from models.finding import ValidatedFinding
from storage.database import FindingRecord, get_session
from storage.audit_store import AuditStore

logger = logging.getLogger(__name__)


class EscalationEngine:
    """
    Escalates Critical findings to a configured notification channel immediately.
    Also sends SLA breach alerts for findings unresolved beyond their deadline.

    Currently supports: Slack webhook
    Designed to be extensible: email, PagerDuty, etc.

    Guard rails:
    - Never escalate the same finding twice (escalated=True flag in DB)
    - Never fail silently — log every attempt and outcome
    - Slack failure is logged but does not block scan completion
    """

    def __init__(self, config: dict):
        self.slack_webhook = config.get("slack_webhook_url") or os.getenv("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.slack_webhook)
        if not self.enabled:
            logger.warning("[escalation] No Slack webhook configured — escalation disabled")

    def escalate_critical(self, findings: list, scan_run_id: str):
        """
        Escalate new Critical findings that haven't been escalated yet.
        'New' means status == 'opened' or 're-opened'.
        """
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)

        for finding in findings:
            if finding.severity != "critical":
                continue

            # Check if this finding record is already escalated
            fp = getattr(finding, "fingerprint", None)
            if fp:
                record = session.query(FindingRecord).filter_by(fingerprint=fp).first()
                if record and record.escalated:
                    continue  # Already sent — don't spam

            success = self._send_slack_finding(finding)

            if fp and record:
                record.escalated = True

            audit.log(
                "escalation_sent" if success else "escalation_failed",
                "finding",
                getattr(finding, "id", None),
                {"severity": finding.severity, "check_id": finding.check_id,
                 "slack_success": success}
            )

        session.commit()
        session.close()

    def check_sla_breaches(self):
        """
        Query DB for findings where sla_deadline < NOW and status != resolved.
        Send Slack alert for each breached finding (only once per finding).
        """
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)
        now = datetime.utcnow()

        breached = session.query(FindingRecord).filter(
            FindingRecord.sla_deadline < now,
            FindingRecord.status.in_(["opened", "updated", "re-opened"]),
            FindingRecord.sla_breached == False
        ).all()

        for record in breached:
            record.sla_breached = True
            success = self._send_slack_sla_breach(record)
            audit.log("sla_breached", "finding", record.id, {
                "severity": record.severity,
                "check_id": record.check_id,
                "first_seen": str(record.first_seen),
                "sla_deadline": str(record.sla_deadline),
                "slack_success": success
            })
            logger.warning(
                f"[escalation] SLA BREACH: {record.check_id} / {record.resource_id} "
                f"(first seen: {record.first_seen}, deadline: {record.sla_deadline})"
            )

        session.commit()
        session.close()

    def _send_slack_finding(self, finding: ValidatedFinding) -> bool:
        """Send Critical finding alert to Slack."""
        severity_emoji = {"critical": "🚨", "high": "🔴"}.get(finding.severity, "⚠️")

        payload = {
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": f"{severity_emoji} Critical Security Finding Detected"}},
                {"type": "section",
                 "fields": [
                     {"type": "mrkdwn", "text": f"*Check ID:*\n`{finding.check_id}`"},
                     {"type": "mrkdwn", "text": f"*Domain:*\n{getattr(finding,'domain','unknown')}"},
                     {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.upper()}"},
                     {"type": "mrkdwn", "text": f"*Confidence:*\n{finding.confidence_score}%"},
                 ]},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*Resource:*\n`{finding.resource_arn}`"}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*Business Impact:*\n{finding.business_impact}"}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*Remediation:*\n```{finding.remediation_command}```"}},
                {"type": "divider"},
                {"type": "context",
                 "elements": [{"type": "mrkdwn",
                               "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} "
                                       f"by Offensive Security Agent"}]}
            ]
        }
        return self._post_slack(payload)

    def _send_slack_sla_breach(self, record: FindingRecord) -> bool:
        """Send SLA breach alert to Slack."""
        hours_overdue = int(
            (datetime.utcnow() - record.sla_deadline).total_seconds() / 3600
        )
        payload = {
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": "⏰ SLA Breach — Critical Finding Unresolved"}},
                {"type": "section",
                 "fields": [
                     {"type": "mrkdwn", "text": f"*Finding:*\n`{record.check_id}`"},
                     {"type": "mrkdwn", "text": f"*Severity:*\n{record.severity.upper()}"},
                     {"type": "mrkdwn", "text": f"*First Seen:*\n{record.first_seen.strftime('%Y-%m-%d %H:%M UTC')}"},
                     {"type": "mrkdwn", "text": f"*Hours Overdue:*\n{hours_overdue}h"},
                 ]},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*Resource:*\n`{record.resource_arn}`\n"
                                  f"*Remediation:*\n```{record.remediation_command or 'See findings report'}```"}},
            ]
        }
        return self._post_slack(payload)

    def _post_slack(self, payload: dict) -> bool:
        """POST to Slack webhook. Returns True if successful."""
        try:
            resp = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                logger.info("[escalation] Slack notification sent successfully")
                return True
            else:
                logger.error(f"[escalation] Slack returned {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"[escalation] Slack POST failed: {e}")
            return False
```

---

## 8. SLA Tracker

### `agent/sla_tracker.py`

```python
import logging
from datetime import datetime
from storage.database import FindingRecord, get_session

logger = logging.getLogger(__name__)

SLA_HOURS = {
    "critical": 24,
    "high":     72,
    "medium":   168,
    "low":      720,
}


class SLATracker:
    """
    Checks all open findings against their SLA deadlines.
    Used in pre-scan step to catch breaches before running new scan.
    """

    def get_breached(self) -> list:
        """Return all findings that have breached their SLA deadline."""
        session = get_session()
        now = datetime.utcnow()

        breached = session.query(FindingRecord).filter(
            FindingRecord.sla_deadline < now,
            FindingRecord.status.in_(["opened", "updated", "re-opened"])
        ).all()

        results = []
        for record in breached:
            hours_overdue = int(
                (now - record.sla_deadline).total_seconds() / 3600
            )
            results.append({
                "id": record.id,
                "check_id": record.check_id,
                "severity": record.severity,
                "resource_arn": record.resource_arn,
                "first_seen": record.first_seen,
                "sla_deadline": record.sla_deadline,
                "hours_overdue": hours_overdue,
                "sla_breached": record.sla_breached,
                "alert_sent": record.sla_alert_sent
            })
            logger.warning(
                f"[sla] BREACH: {record.check_id} ({record.severity}) "
                f"— {hours_overdue}h overdue — resource: {record.resource_id}"
            )

        session.close()
        return results

    def get_approaching(self, within_hours: int = 6) -> list:
        """Return findings whose SLA deadline is within N hours (early warning)."""
        from datetime import timedelta
        session = get_session()
        now = datetime.utcnow()
        threshold = now + timedelta(hours=within_hours)

        approaching = session.query(FindingRecord).filter(
            FindingRecord.sla_deadline > now,
            FindingRecord.sla_deadline < threshold,
            FindingRecord.status.in_(["opened", "updated", "re-opened"])
        ).all()

        session.close()
        return [{"check_id": r.check_id, "severity": r.severity,
                 "sla_deadline": r.sla_deadline} for r in approaching]
```

---

## 9. Audit Trail

### `storage/audit_store.py`

```python
import json
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from storage.database import AuditLog

logger = logging.getLogger(__name__)


class AuditStore:
    """
    Append-only audit log. Every action the agent takes is recorded here.
    Records are NEVER updated or deleted.

    Actions logged:
    - finding_opened / finding_updated / finding_resolved / finding_reopened
    - scan_started / scan_completed / scan_failed
    - sla_breached / sla_alert_sent
    - escalation_sent / escalation_failed
    - auto_remediation_executed / auto_remediation_skipped
    - check_error (when a boto3 check fails)
    """

    def __init__(self, session: Session):
        self.session = session

    def log(self, action: str, entity_type: str = None, entity_id: str = None,
            details: dict = None, actor: str = "agent"):
        """
        Append one audit log entry.

        actor: "agent" (automated) | "scheduler" (scheduled job) | "human" (manual)
        """
        entry = AuditLog(
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            details=json.dumps(details or {}, default=str)
        )
        self.session.add(entry)
        # Note: caller is responsible for session.commit()
        logger.debug(f"[audit] {actor} | {action} | {entity_type}:{entity_id}")

    def get_recent(self, limit: int = 50) -> list:
        """Return the N most recent audit log entries."""
        return self.session.query(AuditLog)\
            .order_by(AuditLog.timestamp.desc())\
            .limit(limit)\
            .all()
```

---

## 10. Trend Reporter — Posture Score

### Posture Score Formula

```
posture_score = max(0, 100 - penalty)

penalty = sum over ALL OPEN findings:
  - critical:          25 points each
  - critical + SLA breached: 40 points (additional 15)
  - high:              10 points each
  - medium:             3 points each
  - low:                1 point each

A perfect score of 100 = zero open findings.
Score degrades as findings accumulate.
Score improves when findings are resolved.
```

### `reporter/trend_reporter.py`

```python
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from storage.database import FindingRecord, ScanRun, get_session

logger = logging.getLogger(__name__)

PENALTY = {
    "critical":          25,
    "critical_breached": 40,   # critical + SLA breached
    "high":              10,
    "medium":             3,
    "low":                1,
    "info":               0,
}


def compute_posture_score(session=None) -> float:
    """
    Compute current security posture score (0–100).
    Lower score = more open findings = worse posture.
    """
    if session is None:
        session = get_session()

    open_findings = session.query(FindingRecord).filter(
        FindingRecord.status.in_(["opened", "updated", "re-opened"])
    ).all()

    total_penalty = 0
    for f in open_findings:
        if f.severity == "critical" and f.sla_breached:
            total_penalty += PENALTY["critical_breached"]
        else:
            total_penalty += PENALTY.get(f.severity, 0)

    score = max(0.0, 100.0 - total_penalty)
    return round(score, 1)


class TrendReporter:
    """
    Generates trend reports showing security posture over time.
    Reads from scan_runs table to get historical posture scores.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate(self) -> dict:
        """Generate trend report from historical scan runs."""
        session = get_session()

        runs = session.query(ScanRun)\
            .order_by(ScanRun.started_at.desc())\
            .limit(30)\
            .all()  # Last 30 scans

        if not runs:
            session.close()
            return {"error": "No scan runs found"}

        # Build trend data
        trend_data = []
        for run in reversed(runs):  # oldest first
            trend_data.append({
                "scan_id": run.id,
                "timestamp": run.started_at.isoformat() if run.started_at else None,
                "posture_score": run.posture_score,
                "duration_seconds": run.duration_seconds,
                "health": run.health,
                "findings": {
                    "total": run.total_findings,
                    "new": run.new_findings,
                    "critical": run.critical_count,
                    "high": run.high_count,
                    "medium": run.medium_count,
                    "low": run.low_count,
                }
            })

        # Determine trend direction
        if len(trend_data) >= 2:
            first_score = trend_data[0]["posture_score"] or 100
            last_score = trend_data[-1]["posture_score"] or 100
            delta = last_score - first_score
            if delta > 5:
                direction = "improving"
            elif delta < -5:
                direction = "degrading"
            else:
                direction = "stable"
        else:
            direction = "insufficient_data"
            delta = 0

        # Current open findings summary
        open_by_severity = {}
        for severity in ["critical", "high", "medium", "low"]:
            count = session.query(FindingRecord).filter(
                FindingRecord.severity == severity,
                FindingRecord.status.in_(["opened", "updated", "re-opened"])
            ).count()
            open_by_severity[severity] = count

        sla_breached_count = session.query(FindingRecord).filter(
            FindingRecord.sla_breached == True,
            FindingRecord.status.in_(["opened", "updated", "re-opened"])
        ).count()

        session.close()

        current_score = compute_posture_score()

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "current_posture_score": current_score,
            "trend_direction": direction,
            "score_delta": round(delta, 1),
            "open_findings_by_severity": open_by_severity,
            "sla_breached_count": sla_breached_count,
            "scan_history": trend_data,
            "summary": self._generate_summary(
                current_score, direction, delta, open_by_severity, sla_breached_count
            )
        }

        # Write JSON
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"trend_report_{ts}.json"
        json_path.write_text(json.dumps(report, indent=2, default=str))

        # Write Markdown
        md_path = self.output_dir / f"trend_report_{ts}.md"
        md_path.write_text(self._render_markdown(report))

        logger.info(f"[trend] Report written: {json_path}, {md_path}")
        return report

    def _generate_summary(self, score, direction, delta, by_severity, sla_count) -> str:
        direction_text = {
            "improving": f"improving (+{delta:.1f} points since first scan)",
            "degrading": f"degrading ({delta:.1f} points since first scan)",
            "stable": "stable (< 5 point change)",
            "insufficient_data": "insufficient data for trend"
        }.get(direction, direction)

        return (
            f"Current posture score: {score}/100. Environment is {direction_text}. "
            f"Open findings: {by_severity.get('critical',0)} critical, "
            f"{by_severity.get('high',0)} high, "
            f"{by_severity.get('medium',0)} medium. "
            f"SLA breaches: {sla_count}."
        )

    def _render_markdown(self, report: dict) -> str:
        score = report["current_posture_score"]
        direction_emoji = {
            "improving": "📈", "degrading": "📉", "stable": "➡️"
        }.get(report["trend_direction"], "❓")

        lines = [
            "# Security Posture Trend Report",
            f"**Generated:** {report['generated_at']}",
            "",
            "## Current Status",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Posture Score | **{score}/100** |",
            f"| Trend | {direction_emoji} {report['trend_direction'].upper()} |",
            f"| Score Delta | {report['score_delta']:+.1f} points |",
            f"| SLA Breaches | {report['sla_breached_count']} |",
            "",
            "## Open Findings",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, count in report["open_findings_by_severity"].items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "")
            lines.append(f"| {emoji} {sev.capitalize()} | {count} |")

        lines += ["", "## Summary", report["summary"], "", "## Scan History"]
        lines += ["| Timestamp | Score | Health | New | Critical |",
                  "|-----------|-------|--------|-----|----------|"]
        for run in report["scan_history"]:
            ts = (run["timestamp"] or "")[:16]
            score_val = f"{run['posture_score']:.1f}" if run["posture_score"] is not None else "N/A"
            lines.append(
                f"| {ts} | {score_val} | {run['health']} | "
                f"{run['findings']['new']} | {run['findings']['critical']} |"
            )

        return "\n".join(lines)
```

---

## 11. Scan Health Reporter

The scan health report surfaces which checks failed during each scan.
**A failed check is NOT the same as a clean resource.**
The agent must never assume success when it couldn't even run the check.

```python
# In orchestrator_l3.py, after scan completes:

def _write_scan_health(self, scan_run_id: str, check_errors: list, all_checks: list):
    """
    Write per-check health records to DB.
    Every check gets a record — success or failure.
    """
    session = get_session()
    audit = AuditStore(session)

    successful_check_ids = set(all_checks) - {e.check_id for e in check_errors}

    # Record successful checks
    for check_id in successful_check_ids:
        session.add(ScanHealthRecord(
            scan_run_id=scan_run_id,
            check_id=check_id,
            domain=self._get_domain(check_id),
            status="success"
        ))

    # Record failed checks
    for error in check_errors:
        session.add(ScanHealthRecord(
            scan_run_id=scan_run_id,
            check_id=error.check_id,
            domain=self._get_domain(error.check_id),
            status="error",
            error_type=error.error_type,
            error_message=error.error_message
        ))
        audit.log("check_error", "scan_run", scan_run_id, {
            "check_id": error.check_id,
            "error_type": error.error_type,
            "message": error.error_message
        })
        logger.warning(
            f"[health] CHECK FAILED: {error.check_id} — "
            f"{error.error_type}: {error.error_message}"
        )

    session.commit()
    session.close()
```

---

## 12. Safe Auto-Remediation (Optional)

### Design Principles

- **Read-only by default.** Auto-remediation is OFF unless explicitly enabled in config.
- **Dry-run always first.** Even when enabled, the agent logs what it WOULD do before doing it.
- **Human gate for anything destructive.** Deleting resources, stopping instances → human must approve.
- **Only LOW severity findings.** Medium and above require human review.
- **Full audit log.** Every execution or skip is logged with actor, timestamp, command, and outcome.

### `agent/auto_remediation.py`

```python
import logging
import subprocess
from datetime import datetime
from storage.database import FindingRecord, get_session
from storage.audit_store import AuditStore

logger = logging.getLogger(__name__)

# Only these check_ids are safe to auto-remediate (non-destructive)
# All others require human review
SAFE_AUTO_REMEDIATION_CHECKS = {
    "iam_password_policy",  # aws iam update-account-password-policy → no data loss
    "s3_encryption_disabled",  # aws s3api put-bucket-encryption → non-destructive
    "cloudtrail_not_logging",  # aws cloudtrail start-logging → no data loss
}


class AutoRemediator:
    """
    Optional safe auto-remediation for LOW-severity, pre-approved finding types.

    Modes:
    - dry_run=True (default): log the command, do NOT execute
    - dry_run=False: execute the remediation_command via subprocess
      (Only works if the IAM user has write permissions for the specific action)

    Guard rails:
    - Only SAFE_AUTO_REMEDIATION_CHECKS are eligible
    - Only LOW severity findings
    - Every action logged in audit_log with command and outcome
    - Failed executions are logged, not silently swallowed
    """

    def __init__(self, config: dict):
        self.enabled = config.get("auto_remediation", {}).get("enabled", False)
        self.dry_run = config.get("auto_remediation", {}).get("dry_run", True)
        if self.enabled and not self.dry_run:
            logger.warning("[remediation] Auto-remediation ENABLED with dry_run=False — "
                           "commands will execute against real infrastructure")
        elif self.enabled:
            logger.info("[remediation] Auto-remediation ENABLED in dry-run mode — "
                        "commands logged but NOT executed")

    def process_findings(self, findings: list):
        """Process all findings and apply safe auto-remediation where eligible."""
        if not self.enabled:
            return

        session = get_session()
        audit = AuditStore(session)

        for finding in findings:
            if not self._is_eligible(finding):
                audit.log("auto_remediation_skipped", "finding",
                           getattr(finding, "id", None), {
                               "reason": "Not eligible (severity or check_id not in safe list)",
                               "check_id": finding.check_id,
                               "severity": finding.severity
                           })
                continue

            command = finding.remediation_command
            if not command or command.startswith("#"):
                continue

            if self.dry_run:
                logger.info(f"[remediation] DRY-RUN: Would execute: {command}")
                audit.log("auto_remediation_dry_run", "finding",
                           getattr(finding, "id", None), {
                               "command": command,
                               "dry_run": True,
                               "check_id": finding.check_id
                           })
            else:
                self._execute(command, finding, session, audit)

        session.commit()
        session.close()

    def _is_eligible(self, finding) -> bool:
        """Check if a finding qualifies for auto-remediation."""
        return (
            finding.severity == "low" and
            finding.check_id in SAFE_AUTO_REMEDIATION_CHECKS
        )

    def _execute(self, command: str, finding, session, audit):
        """Execute a remediation command. Log success or failure."""
        logger.info(f"[remediation] Executing: {command}")
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            success = result.returncode == 0
            audit.log(
                "auto_remediation_executed" if success else "auto_remediation_failed",
                "finding",
                getattr(finding, "id", None),
                {
                    "command": command,
                    "returncode": result.returncode,
                    "stdout": result.stdout[:500],
                    "stderr": result.stderr[:500],
                    "check_id": finding.check_id,
                    "dry_run": False,
                    "actor": "agent"
                }
            )
            if success:
                logger.info(f"[remediation] SUCCESS: {finding.check_id}")
            else:
                logger.error(f"[remediation] FAILED: {finding.check_id} — {result.stderr}")
        except Exception as e:
            logger.error(f"[remediation] EXCEPTION executing {command}: {e}")
            audit.log("auto_remediation_failed", "finding",
                       getattr(finding, "id", None), {"error": str(e), "command": command})
```

---

## 13. Level 3 Orchestrator

### `agent/orchestrator_l3.py`

```python
import logging
import uuid
from datetime import datetime

from agent.orchestrator_l2 import OrchestratorL2
from agent.lifecycle_manager import FindingLifecycleManager
from agent.escalation import EscalationEngine
from agent.sla_tracker import SLATracker
from agent.auto_remediation import AutoRemediator
from reporter.trend_reporter import TrendReporter, compute_posture_score
from storage.database import ScanRun, ScanHealthRecord, get_session
from storage.audit_store import AuditStore

logger = logging.getLogger(__name__)


class OrchestratorL3:
    """
    Level 3 orchestrator — wraps L2 and adds persistence, lifecycle,
    escalation, SLA tracking, audit trail, and trend reporting.
    """

    def __init__(self, config, groq_api_key: str):
        self.config = config
        self.l2 = OrchestratorL2(config, groq_api_key)
        self.escalation = EscalationEngine(vars(config).get("level3", {}))
        self.sla_tracker = SLATracker()
        self.auto_remediation = AutoRemediator(vars(config).get("level3", {}))
        self.trend_reporter = TrendReporter(config.scan.output_dir)

    def run(self) -> dict:
        """Full scan cycle with persistence, lifecycle, escalation, SLA, and trends."""
        scan_run_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        session = get_session()
        audit = AuditStore(session)

        # ── STEP 1: Create scan run record ─────────────────────
        scan_run = ScanRun(id=scan_run_id, started_at=start_time,
                           config_name=self.config.scan.name)
        session.add(scan_run)
        session.commit()

        audit.log("scan_started", "scan_run", scan_run_id, {
            "config": self.config.scan.name,
            "actor": "scheduler"
        }, actor="scheduler")
        session.commit()

        logger.info(f"=== L3 Scan {scan_run_id} started ===")

        # ── STEP 2: Pre-scan SLA breach check ─────────────────
        sla_breaches = self.sla_tracker.get_breached()
        if sla_breaches:
            logger.warning(f"[l3] {len(sla_breaches)} SLA breaches detected pre-scan")
            self.escalation.check_sla_breaches()

        # ── STEP 3: Run L2 scan (all 4 domains) ───────────────
        try:
            l2_report = self.l2.run()
            all_findings = l2_report.findings
            all_errors = l2_report.scan_errors
        except Exception as e:
            logger.error(f"[l3] L2 scan failed: {e}")
            audit.log("scan_failed", "scan_run", scan_run_id, {"error": str(e)})
            scan_run.health = "failed"
            scan_run.completed_at = datetime.utcnow()
            session.commit()
            session.close()
            return {"error": str(e), "scan_run_id": scan_run_id}

        # ── STEP 4: Lifecycle management ───────────────────────
        lifecycle = FindingLifecycleManager(scan_run_id)
        lifecycle_result = lifecycle.process(all_findings)

        new_findings = lifecycle_result["new"]
        updated_findings = lifecycle_result["updated"]
        reopened_findings = lifecycle_result["reopened"]
        resolved_findings = lifecycle_result["resolved"]

        logger.info(
            f"[l3] Lifecycle: {len(new_findings)} new, {len(updated_findings)} updated, "
            f"{len(reopened_findings)} re-opened, {len(resolved_findings)} resolved"
        )

        # ── STEP 5: Escalate new/reopened Criticals ────────────
        escalation_candidates = new_findings + reopened_findings
        self.escalation.escalate_critical(escalation_candidates, scan_run_id)

        # ── STEP 6: Write scan health ──────────────────────────
        self._write_scan_health(scan_run_id, all_errors, session)

        # ── STEP 7: Auto-remediation (if enabled) ──────────────
        self.auto_remediation.process_findings(new_findings)

        # ── STEP 8: Compute posture score ──────────────────────
        posture_score = compute_posture_score(session)

        # ── STEP 9: Update scan run record ─────────────────────
        end_time = datetime.utcnow()
        scan_run.completed_at = end_time
        scan_run.duration_seconds = (end_time - start_time).total_seconds()
        scan_run.health = l2_report.scan_health
        scan_run.total_findings = len(all_findings)
        scan_run.new_findings = len(new_findings)
        scan_run.updated_findings = len(updated_findings)
        scan_run.resolved_findings = len(resolved_findings)
        scan_run.reopened_findings = len(reopened_findings)
        scan_run.posture_score = posture_score

        severity_counts = l2_report.findings_by_severity
        scan_run.critical_count = severity_counts.get("critical", 0)
        scan_run.high_count = severity_counts.get("high", 0)
        scan_run.medium_count = severity_counts.get("medium", 0)
        scan_run.low_count = severity_counts.get("low", 0)

        audit.log("scan_completed", "scan_run", scan_run_id, {
            "duration_seconds": scan_run.duration_seconds,
            "health": scan_run.health,
            "posture_score": posture_score,
            "new_findings": len(new_findings),
            "critical": scan_run.critical_count
        }, actor="scheduler")

        session.commit()
        session.close()

        # ── STEP 10: Generate trend report ─────────────────────
        trend = self.trend_reporter.generate()

        logger.info(
            f"=== L3 Scan complete: {scan_run.duration_seconds:.1f}s | "
            f"Posture: {posture_score}/100 | Trend: {trend.get('trend_direction')} ==="
        )

        return {
            "scan_run_id": scan_run_id,
            "posture_score": posture_score,
            "lifecycle": {
                "new": len(new_findings),
                "updated": len(updated_findings),
                "reopened": len(reopened_findings),
                "resolved": len(resolved_findings)
            },
            "sla_breaches": len(sla_breaches),
            "trend": trend.get("trend_direction"),
            "health": scan_run.health
        }

    def _write_scan_health(self, scan_run_id: str, errors: list, session):
        """Write per-check health to DB. Every check result recorded."""
        for error in errors:
            session.add(ScanHealthRecord(
                scan_run_id=scan_run_id,
                check_id=error.check_id,
                domain="unknown",
                status="error",
                error_type=error.error_type,
                error_message=error.error_message
            ))
        session.commit()
```

---

## 14. Extended Config Schema

### `checklist_l3.yaml`

```yaml
scan:
  name: "Aivar Autonomous Security Agent"
  description: "Level 3 — Continuous autonomous scanning with SLA tracking"
  aws_region: "ap-south-1"
  timeout_seconds: 60
  max_workers: 5
  llm_model: "llama-3.3-70b-versatile"
  output_dir: "reports"

# All Level 1 + Level 2 checks (same as checklist_l2.yaml)
checks:
  - id: iam_root_mfa
    enabled: true
    description: "Root account must have MFA"
    severity_cap: critical
    tags: [iam, mfa]
  # ... all 13 checks from L1/L2 unchanged

# Level 2 domains (same as checklist_l2.yaml)
api_targets:
  - url: "http://localhost:8000"
    name: "Local-Agent-Dashboard"
  - url: "https://httpbin.org"
    name: "HTTPBin-Public"

dependency_scan:
  paths: ["requirements.txt"]
  ecosystems: [PyPI]

secrets_scan:
  paths: ["."]

# ── LEVEL 3 NEW SECTION ─────────────────────────────────────────
level3:

  # Scheduler configuration
  schedule:
    mode: "interval"            # "interval" or "cron"
    interval_hours: 6           # Run every 6 hours
    cron: "0 */6 * * *"        # Alternative: cron expression
    run_on_start: true          # Run once immediately when daemon starts

  # Notification channel (Slack)
  slack_webhook_url: "${SLACK_WEBHOOK_URL}"   # Read from env var

  # SLA thresholds (hours to resolve by severity)
  sla_hours:
    critical: 24
    high:     72
    medium:   168               # 7 days
    low:      720               # 30 days

  # Auto-resolution: mark findings as resolved after N consecutive missed scans
  auto_resolve_after_misses: 3

  # Auto-remediation (optional)
  auto_remediation:
    enabled: false              # OFF by default — requires explicit opt-in
    dry_run: true               # Even when enabled, log-only mode
    # allowed_checks:           # Only these check_ids are eligible
    #   - iam_password_policy
    #   - s3_encryption_disabled

  # Database path
  db_path: "storage/findings.db"

  # Trend report generation
  trend_report:
    generate_after_each_scan: true
    keep_last_n_scans: 30       # For posture score history
```

---

## 15. Updated `main.py` — Daemon Mode

```python
import argparse
import logging
import os
import signal
import sys
import time

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("agent.log", mode="a")  # Persistent log file for daemon
    ]
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Offensive Security Agent")
    parser.add_argument("--config", default="checklist.yaml", help="Config file")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--daemon", action="store_true",
                        help="Level 3 only: run continuously on schedule")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--trend", action="store_true",
                        help="Generate trend report and exit (Level 3 only)")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    from config.loader import ConfigLoader
    config = ConfigLoader.load(args.config)
    groq_key = os.getenv("GROQ_API_KEY")

    if args.level == 1:
        from agent.orchestrator import AgentOrchestrator
        orch = AgentOrchestrator(config, groq_key)
        orch.run()

    elif args.level == 2:
        from agent.orchestrator_l2 import OrchestratorL2
        orch = OrchestratorL2(config, groq_key)
        orch.run()

    elif args.level == 3:
        from storage.database import init_db
        init_db()  # Create tables if they don't exist

        if args.trend:
            # Just generate trend report and exit
            from reporter.trend_reporter import TrendReporter
            TrendReporter(config.scan.output_dir).generate()
            print("Trend report generated.")
            return

        from agent.orchestrator_l3 import OrchestratorL3
        orch = OrchestratorL3(config, groq_key)

        if args.daemon:
            # Daemon mode: run on schedule indefinitely
            from scheduler.scan_scheduler import ScanScheduler
            l3_cfg = getattr(config, "level3", {}) or {}
            scheduler = ScanScheduler(orch.run, l3_cfg)

            # Handle Ctrl+C gracefully
            def handle_shutdown(sig, frame):
                logger.info("Shutdown signal received. Stopping scheduler...")
                scheduler.stop()
                sys.exit(0)

            signal.signal(signal.SIGINT, handle_shutdown)
            signal.signal(signal.SIGTERM, handle_shutdown)

            logger.info("=== Offensive Security Agent starting in DAEMON mode ===")
            scheduler.start()

            # Keep main thread alive
            while True:
                time.sleep(60)
        else:
            # One-shot L3 run (with DB persistence, lifecycle, escalation)
            result = orch.run()
            print(f"\nScan complete:")
            print(f"  Posture Score: {result.get('posture_score')}/100")
            print(f"  Trend:         {result.get('trend')}")
            print(f"  New findings:  {result.get('lifecycle', {}).get('new')}")
            print(f"  Health:        {result.get('health')}")


if __name__ == "__main__":
    main()
```

---

## 16. Implementation Order

```
Hour 1 — Database setup
  ✅ storage/database.py — SQLAlchemy models (FindingRecord, ScanRun, AuditLog, ScanHealth)
  ✅ storage/audit_store.py — append-only audit log
  ✅ storage/findings_store.py — basic CRUD
  ✅ Test: python -c "from storage.database import init_db; init_db(); print('DB created')"
  ✅ Verify storage/findings.db is created with all 4 tables

Hour 2 — Finding lifecycle manager
  ✅ agent/lifecycle_manager.py — state machine (opened/updated/resolved/reopened)
  ✅ Add fingerprint field to ValidatedFinding (reuse deduplicator logic)
  ✅ Test: run two scans manually → verify same finding updates, doesn't duplicate

Hour 3 — Escalation engine
  ✅ agent/escalation.py — Slack webhook + SLA breach alerts
  ✅ Get free Slack webhook: create Slack app → Incoming Webhooks → get URL
  ✅ Test: manually call send_slack_finding() with a test Critical finding
  ✅ Verify message appears in Slack channel

Hour 4 — SLA tracker
  ✅ agent/sla_tracker.py — deadline tracking
  ✅ Test: insert a finding with sla_deadline = 1 hour ago → verify it shows in get_breached()
  ✅ Verify escalation sends SLA breach alert

Hour 5 — Trend reporter + posture score
  ✅ reporter/trend_reporter.py — posture score formula + history
  ✅ Test: after 2+ scan runs → python main.py --level 3 --trend
  ✅ Verify trend_report.json shows score history
  ✅ Verify direction = improving/degrading/stable

Hour 6 — Scheduler + daemon mode
  ✅ scheduler/scan_scheduler.py — APScheduler with interval and cron triggers
  ✅ Updated main.py with --daemon flag
  ✅ Test short interval: interval_hours: 0.05 (3 minutes) → verify 2 scans run automatically
  ✅ Verify scan_runs table has 2 rows after test
  ✅ Test Ctrl+C → verify graceful shutdown

Hour 7 — Auto-remediation (optional)
  ✅ agent/auto_remediation.py — dry-run mode
  ✅ Test: enable auto_remediation.enabled: true, dry_run: true
  ✅ Verify audit_log shows auto_remediation_dry_run entries

Hour 8 — L3 orchestrator + end-to-end
  ✅ agent/orchestrator_l3.py — wires everything together
  ✅ Full L3 one-shot run:  python main.py --level 3 --config checklist_l3.yaml
  ✅ Full L3 daemon run:    python main.py --level 3 --config checklist_l3.yaml --daemon
  ✅ Let 2 scans run → verify DB has lifecycle transitions (some findings updated, not new)
  ✅ Verify audit_log has entries for every action
  ✅ Verify Slack received Critical alert
  ✅ requirements.txt: add apscheduler, sqlalchemy
```

---

## 17. Acceptance Criteria Checklist

```
☐  Runs full scans on a configurable schedule with no manual trigger
     → APScheduler BackgroundScheduler
     → python main.py --level 3 --daemon
     → interval_hours or cron expression in checklist_l3.yaml

☐  Stores findings with full lifecycle: opened, updated, resolved, re-opened, SLA status
     → FindingRecord table with status column
     → FindingLifecycleManager state machine
     → sla_deadline, sla_breached, sla_alert_sent columns

☐  Deduplicates across scan runs — recurring finding updates record, not creates new
     → FindingLifecycleManager.process() checks fingerprint in DB
     → Existing record → status="updated", last_seen=NOW()
     → consecutive_misses reset to 0

☐  Escalates Critical findings to configured notification channel immediately
     → EscalationEngine.escalate_critical() called after lifecycle processing
     → Slack webhook POST with finding details
     → escalated=True flag prevents duplicate alerts

☐  SLA tracking: alerts when Critical unresolved > 24 hours
     → SLATracker.get_breached() runs pre-scan
     → EscalationEngine.check_sla_breaches() sends Slack alert
     → sla_breached=True prevents duplicate SLA alerts

☐  Audit trail: all scans, findings, actions logged with actor and timestamp
     → AuditLog table — append-only, never updated
     → Every state change logged: finding_opened, updated, resolved, reopened
     → Every scan logged: scan_started, scan_completed, scan_failed
     → Every escalation logged: escalation_sent, escalation_failed

☐  Trend reporting: security posture score over time
     → compute_posture_score() formula: 100 - penalty(open findings)
     → TrendReporter.generate() reads scan_runs table
     → trend_report.json + trend_report.md with score history
     → direction: improving / degrading / stable

☐  Scan health reporting: failed checks surfaced, never silently skipped
     → ScanHealthRecord written for every check (success or error)
     → Scan health = "degraded" if any checks errored
     → Dashboard shows which checks failed and why

☐  Optional safe auto-remediation with human-approval gate
     → AutoRemediator — disabled by default (auto_remediation.enabled: false)
     → dry_run=true by default — logs command, does not execute
     → Only LOW severity, pre-approved check_ids eligible
     → Every attempt logged in audit_log
```

---

## 18. Demo Script

### Setup for Demo (5 minutes before recording)

```bash
# Start fresh DB
rm -f storage/findings.db

# Set env vars
export GROQ_API_KEY=gsk_your_key
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Set short interval for demo (runs every 3 minutes)
# In checklist_l3.yaml → schedule.interval_hours: 0.05
```

### Demo Video Script (8-10 minutes)

```
0:00 — Architecture recap
"Level 1 scanned AWS. Level 2 added APIs, dependencies, and secrets.
 Level 3 makes the agent autonomous — it runs on a schedule, remembers findings
 across scans, tracks SLAs, and escalates Criticals to Slack."

1:00 — Show checklist_l3.yaml
 Point to: schedule section, slack_webhook_url, sla_hours, auto_remediation.

2:00 — Start daemon mode
  python main.py --level 3 --config checklist_l3.yaml --daemon --verbose
 
 Watch logs: "Scheduler started", "Running initial scan immediately..."
 First scan runs → findings appear → lifecycle: "NEW: iam_root_mfa / root"

3:30 — Show Slack alert
 Open Slack — Critical finding notification should have arrived.
 "The agent sent this alert in real-time when the first Critical was detected."

4:30 — Wait for second scan (3 minutes if using short interval)
 Watch logs: "UPDATED: iam_root_mfa" (same finding, not new — lifecycle working)
 "Lifecycle: 0 new, 3 updated, 0 re-opened, 0 resolved"
 No second Slack alert — escalated=True prevents spam.

6:00 — Show the DB
 Open DB Browser for SQLite → open storage/findings.db
 Show: findings table → 3 rows, status="updated"
 Show: audit_log table → 15+ rows, every action recorded
 Show: scan_runs table → 2 rows with posture scores

7:00 — Generate trend report
 python main.py --level 3 --config checklist_l3.yaml --trend
 Open trend_report.md → show posture score, scan history table, trend direction

8:00 — Show scan health
 Open scan_health table in DB → show successful vs errored checks
 "If a check fails, it appears here. The agent never assumes a clean resource
  just because it couldn't run the check."

8:30 — SLA breach demo
 "If I had let a Critical finding sit for 24 hours, the agent would send a
  separate Slack alert like this:" → show _send_slack_sla_breach() output manually
 OR: set sla_hours.critical: 0.01 (less than 1 min) → wait → SLA breach fires

9:00 — Wrap up
 "This is a fully autonomous security agent. It runs on schedule, remembers
  everything, escalates instantly, tracks SLAs, and reports its own health.
  The only thing it doesn't do is make judgment calls — that's still human."
```

---

### `requirements.txt` additions for Level 3

```
# Level 1 (unchanged)
boto3==1.34.0
botocore==1.34.0
pydantic==2.7.0
pyyaml==6.0.1
python-dotenv==1.0.0
openai==1.30.0

# Level 2 additions (unchanged)
requests==2.31.0
packaging==24.0

# Level 3 new
apscheduler==3.10.4      # Scheduler with cron and interval support
sqlalchemy==2.0.30       # ORM for SQLite findings database
```

### Get a Free Slack Webhook (5 minutes)

```
1. Go to api.slack.com/apps → Create New App → From Scratch
2. Name it "Security Agent" → choose your workspace
3. Left menu → Incoming Webhooks → Activate Incoming Webhooks
4. Add New Webhook to Workspace → choose a channel → Allow
5. Copy the webhook URL → paste in .env as SLACK_WEBHOOK_URL
```

---

*Plan prepared for Aivar Innovations AI/ML Hiring Challenge — June 2026*
*Manikandan M — 19manikandan2005@gmail.com*
