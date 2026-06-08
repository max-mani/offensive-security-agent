"""Background Level 3 scan and daemon scheduler for the dashboard."""

import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from agent.orchestrator_l3 import OrchestratorL3
from agent.runner import check_level3_dependencies
from config.loader import load_config
from scheduler.scan_scheduler import ScanScheduler
from storage.database import init_db
from utils.llm_client import resolve_llm_config

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_lock = threading.Lock()
_l3_state: str = "idle"  # idle | running | completed | failed
_daemon_state: str = "stopped"  # stopped | running
_started_at: datetime | None = None
_finished_at: datetime | None = None
_error: str | None = None
_last_result: dict | None = None
_log_tail: deque[str] = deque(maxlen=200)
_scheduler: ScanScheduler | None = None
_orchestrator: OrchestratorL3 | None = None
_config_path: str = "checklist_l3.yaml"
DEFAULT_SCHEDULE_HOURS = 6.0
_schedule_info: dict = {
    "mode": "default",
    "interval_hours": DEFAULT_SCHEDULE_HOURS,
    "interval_minutes": None,
    "label": f"Every {int(DEFAULT_SCHEDULE_HOURS)} hours (default)",
}


def _format_schedule_label(mode: str, hours: float | None, minutes: float | None) -> str:
    if mode == "default":
        return f"Every {int(DEFAULT_SCHEDULE_HOURS)} hours (default)"
    if minutes and minutes > 0:
        if minutes >= 60 and minutes % 60 == 0:
            return f"Every {int(minutes / 60)} hours (custom)"
        return f"Every {int(minutes)} minutes (custom)"
    h = hours if hours and hours > 0 else DEFAULT_SCHEDULE_HOURS
    if h == int(h):
        return f"Every {int(h)} hours (custom)"
    return f"Every {h:g} hours (custom)"


def _build_schedule_config(
    schedule_mode: str = "default",
    interval_hours: float | None = None,
    interval_minutes: float | None = None,
) -> tuple:
    """Return (ScheduleConfig, schedule_info dict)."""
    from models.config import ScheduleConfig

    mode = schedule_mode if schedule_mode in ("default", "custom") else "default"
    if mode == "default":
        cfg = ScheduleConfig(
            mode="interval",
            interval_hours=DEFAULT_SCHEDULE_HOURS,
            interval_minutes=None,
            run_on_start=True,
        )
        info = {
            "mode": "default",
            "interval_hours": DEFAULT_SCHEDULE_HOURS,
            "interval_minutes": None,
            "label": _format_schedule_label("default", DEFAULT_SCHEDULE_HOURS, None),
        }
        return cfg, info

    use_minutes = interval_minutes is not None and interval_minutes > 0
    if use_minutes:
        mins = max(15.0, min(float(interval_minutes), 10080.0))
        cfg = ScheduleConfig(
            mode="interval",
            interval_hours=DEFAULT_SCHEDULE_HOURS,
            interval_minutes=mins,
            run_on_start=True,
        )
        info = {
            "mode": "custom",
            "interval_hours": None,
            "interval_minutes": mins,
            "label": _format_schedule_label("custom", None, mins),
        }
        return cfg, info

    hours = float(interval_hours) if interval_hours and interval_hours > 0 else DEFAULT_SCHEDULE_HOURS
    hours = max(0.25, min(hours, 168.0))
    cfg = ScheduleConfig(
        mode="interval",
        interval_hours=hours,
        interval_minutes=None,
        run_on_start=True,
    )
    info = {
        "mode": "custom",
        "interval_hours": hours,
        "interval_minutes": None,
        "label": _format_schedule_label("custom", hours, None),
    }
    return cfg, info


class _L3LogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            _log_tail.append(msg)
        except Exception:
            pass


def _append_log(message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    _log_tail.append(f"{ts} {message}")


def is_busy() -> bool:
    with _lock:
        return _l3_state == "running"


def is_daemon_running() -> bool:
    with _lock:
        return _daemon_state == "running"


def get_status() -> dict:
    with _lock:
        next_run = None
        if _scheduler and _scheduler.is_running():
            next_run = _scheduler.get_next_run_time()
        return {
            "l3_scan_state": _l3_state,
            "daemon_state": _daemon_state,
            "started_at": _started_at.isoformat() if _started_at else None,
            "finished_at": _finished_at.isoformat() if _finished_at else None,
            "error": _error,
            "last_result": _last_result,
            "log_tail": list(_log_tail),
            "next_run_time": next_run,
            "config_path": _config_path,
            "schedule": dict(_schedule_info),
            "default_interval_hours": DEFAULT_SCHEDULE_HOURS,
        }


def _run_once_worker(config_path: str) -> None:
    global _l3_state, _finished_at, _error, _last_result

    handler = _L3LogHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        load_dotenv(PROJECT_ROOT / ".env")
        os.chdir(PROJECT_ROOT)
        check_level3_dependencies()
        llm = resolve_llm_config()

        path = PROJECT_ROOT / config_path
        config = load_config(path)
        init_db()

        orch = OrchestratorL3(config, llm)
        result = orch.run()
        result.pop("report", None)

        with _lock:
            _l3_state = "completed"
            _finished_at = datetime.now(timezone.utc)
            _last_result = result
        _append_log(f"L3 scan complete — posture {result.get('posture_score')}/100")
    except Exception as e:
        logger.exception("L3 scan failed")
        with _lock:
            _l3_state = "failed"
            _finished_at = datetime.now(timezone.utc)
            _error = str(e)
        _append_log(f"ERROR: {e}")
    finally:
        root.removeHandler(handler)


def run_once(config_path: str = "checklist_l3.yaml") -> bool:
    global _l3_state, _started_at, _finished_at, _error, _last_result, _config_path

    with _lock:
        if _l3_state == "running":
            return False
        if _daemon_state == "running":
            return False
        _l3_state = "running"
        _started_at = datetime.now(timezone.utc)
        _finished_at = None
        _error = None
        _last_result = None
        _config_path = config_path
        _log_tail.clear()

    _append_log(f"Starting Level 3 one-shot scan ({config_path})...")
    thread = threading.Thread(
        target=_run_once_worker,
        args=(config_path,),
        daemon=True,
    )
    thread.start()
    return True


def start_daemon(
    config_path: str = "checklist_l3.yaml",
    schedule_mode: str = "default",
    interval_hours: float | None = None,
    interval_minutes: float | None = None,
) -> bool:
    global _daemon_state, _scheduler, _orchestrator, _config_path, _schedule_info

    with _lock:
        if _daemon_state == "running":
            return False
        if _l3_state == "running":
            return False

    try:
        load_dotenv(PROJECT_ROOT / ".env")
        os.chdir(PROJECT_ROOT)
        check_level3_dependencies()
        llm = resolve_llm_config()
        path = PROJECT_ROOT / config_path
        config = load_config(path)
        init_db()

        orch = OrchestratorL3(config, llm)
        schedule_cfg, schedule_meta = _build_schedule_config(
            schedule_mode, interval_hours, interval_minutes
        )

        def scheduled_run():
            global _l3_state, _finished_at, _error, _last_result, _started_at
            with _lock:
                _l3_state = "running"
                _started_at = datetime.now(timezone.utc)
                _error = None
            _append_log("Scheduled L3 scan starting...")
            try:
                result = orch.run()
                result.pop("report", None)
                with _lock:
                    _l3_state = "completed"
                    _finished_at = datetime.now(timezone.utc)
                    _last_result = result
                _append_log(f"Scheduled scan complete — posture {result.get('posture_score')}/100")
            except Exception as e:
                with _lock:
                    _l3_state = "failed"
                    _finished_at = datetime.now(timezone.utc)
                    _error = str(e)
                _append_log(f"Scheduled scan failed: {e}")

        scheduler = ScanScheduler(scheduled_run, schedule_cfg)
        scheduler.start()

        with _lock:
            _scheduler = scheduler
            _orchestrator = orch
            _daemon_state = "running"
            _config_path = config_path
            _schedule_info = schedule_meta

        _append_log(f"Daemon started — {_schedule_info['label']}")
        return True
    except Exception as e:
        logger.exception("Failed to start daemon")
        with _lock:
            _error = str(e)
        return False


def stop_daemon() -> bool:
    global _daemon_state, _scheduler, _orchestrator

    with _lock:
        if _daemon_state != "running" or _scheduler is None:
            return False
        scheduler = _scheduler
        _scheduler = None
        _orchestrator = None
        _daemon_state = "stopped"

    scheduler.stop()
    _append_log("Daemon stopped")
    return True
