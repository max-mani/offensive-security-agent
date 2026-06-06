"""Background scan execution and status tracking."""

import logging
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from agent.runner import run_scan

logger = logging.getLogger(__name__)

ScanState = Literal["idle", "running", "completed", "failed"]

_lock = threading.Lock()
_state: ScanState = "idle"
_started_at: datetime | None = None
_finished_at: datetime | None = None
_error: str | None = None
_report_file: str | None = None
_log_tail: deque[str] = deque(maxlen=100)


class _ScanLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            _log_tail.append(msg)
        except Exception:
            pass


def _find_newest_report(before: set[str]) -> str | None:
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    after = {p.name for p in reports_dir.glob("findings_report_*.json")}
    new_files = after - before
    if not new_files:
        if after:
            return sorted(after)[-1]
        return None
    return sorted(new_files)[-1]


def get_status() -> dict:
    with _lock:
        return {
            "state": _state,
            "started_at": _started_at.isoformat() if _started_at else None,
            "finished_at": _finished_at.isoformat() if _finished_at else None,
            "error": _error,
            "report_file": _report_file,
            "log_tail": list(_log_tail),
        }


def is_running() -> bool:
    with _lock:
        return _state == "running"


def _run_scan_worker(config_path: str, existing_files: set[str]) -> None:
    global _state, _finished_at, _error, _report_file

    handler = _ScanLogHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        run_scan(config_path)
        report_file = _find_newest_report(existing_files)
        with _lock:
            _state = "completed"
            _finished_at = datetime.now(timezone.utc)
            _report_file = report_file
    except Exception as e:
        logger.exception("Dashboard scan failed")
        with _lock:
            _state = "failed"
            _finished_at = datetime.now(timezone.utc)
            _error = str(e)
    finally:
        root.removeHandler(handler)


def start_scan(config_path: str = "checklist.yaml") -> bool:
    """Start a scan in a background thread. Returns False if already running."""
    global _state, _started_at, _finished_at, _error, _report_file

    with _lock:
        if _state == "running":
            return False
        _state = "running"
        _started_at = datetime.now(timezone.utc)
        _finished_at = None
        _error = None
        _report_file = None
        _log_tail.clear()

    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    existing = {p.name for p in reports_dir.glob("findings_report_*.json")}

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(config_path, existing),
        daemon=True,
    )
    thread.start()
    return True
