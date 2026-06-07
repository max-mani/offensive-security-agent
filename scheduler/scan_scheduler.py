"""APScheduler wrapper for autonomous Level 3 scanning."""

import logging

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from models.config import Level3Config, ScheduleConfig
from storage.audit_store import AuditStore
from storage.database import get_session

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Run security scans on a configurable schedule."""

    def __init__(self, scan_function, schedule_config: ScheduleConfig | Level3Config | None = None):
        self.scan_function = scan_function
        if isinstance(schedule_config, Level3Config):
            self.schedule_cfg = schedule_config.schedule
        elif schedule_config is not None:
            self.schedule_cfg = schedule_config
        else:
            self.schedule_cfg = ScheduleConfig()

        self.scheduler = BackgroundScheduler(
            job_defaults={"coalesce": True, "max_instances": 1},
        )
        self._register_listeners()

    def _register_listeners(self):
        def on_job_executed(event):
            logger.info("[scheduler] Scan job completed successfully")

        def on_job_error(event):
            logger.error("[scheduler] Scan job FAILED: %s", event.exception)
            session = get_session()
            AuditStore(session).log(
                "scan_failed",
                "scan_run",
                None,
                {"error": str(event.exception), "scheduled": True},
                actor="scheduler",
            )
            session.commit()
            session.close()

        self.scheduler.add_listener(on_job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(on_job_error, EVENT_JOB_ERROR)

    def _build_trigger(self):
        mode = self.schedule_cfg.mode
        if mode == "cron":
            cron_expr = self.schedule_cfg.cron
            logger.info("[scheduler] Using cron trigger: %s", cron_expr)
            return CronTrigger.from_crontab(cron_expr)

        if self.schedule_cfg.interval_minutes:
            minutes = self.schedule_cfg.interval_minutes
            logger.info("[scheduler] Using interval trigger: every %s minutes", minutes)
            return IntervalTrigger(minutes=minutes)

        hours = self.schedule_cfg.interval_hours
        logger.info("[scheduler] Using interval trigger: every %s hours", hours)
        return IntervalTrigger(hours=hours)

    def start(self):
        trigger = self._build_trigger()
        self.scheduler.add_job(
            self.scan_function,
            trigger=trigger,
            id="security_scan",
            name="Offensive Security Scan",
            replace_existing=True,
            misfire_grace_time=300,
        )
        self.scheduler.start()
        logger.info("[scheduler] Scheduler started. Scan job registered.")

        if self.schedule_cfg.run_on_start:
            logger.info("[scheduler] Running initial scan immediately...")
            self.scan_function()

    def stop(self):
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            logger.info("[scheduler] Scheduler stopped.")

    def is_running(self) -> bool:
        return self.scheduler.running

    def get_next_run_time(self):
        job = self.scheduler.get_job("security_scan")
        if job and job.next_run_time:
            return job.next_run_time.isoformat()
        return None
