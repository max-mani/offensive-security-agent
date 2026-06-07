"""Background scan execution with step-by-step progress tracking."""

import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv

from agent.orchestrator import CHECK_REGISTRY
from agent.runner import run_scan
from config.loader import load_config

logger = logging.getLogger(__name__)

ScanState = Literal["idle", "running", "completed", "failed"]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_lock = threading.Lock()
_state: ScanState = "idle"
_started_at: datetime | None = None
_finished_at: datetime | None = None
_error: str | None = None
_report_file: str | None = None
_scan_level: int = 1
_log_tail: deque[str] = deque(maxlen=200)
_steps: list[dict[str, Any]] = []
_current_step_index: int = -1


class _ScanLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            _log_tail.append(msg)
        except Exception:
            pass


def _build_scan_steps(config_path: str, level: int = 1) -> list[dict[str, Any]]:
    load_dotenv(PROJECT_ROOT / ".env")
    config = load_config(PROJECT_ROOT / config_path)
    steps = [{"id": "init", "label": "Load configuration", "status": "pending", "detail": ""}]

    if level >= 2:
        steps.extend([
            {"id": "domain_aws", "label": "AWS Infrastructure (13 checks)", "status": "pending", "detail": ""},
            {"id": "domain_api", "label": "API Endpoint Scanner", "status": "pending", "detail": ""},
            {"id": "domain_deps", "label": "Dependency CVE Scanner", "status": "pending", "detail": ""},
            {"id": "domain_secrets", "label": "Secrets Scanner", "status": "pending", "detail": ""},
            {"id": "llm_enrichment", "label": "LLM enrichment", "status": "pending", "detail": ""},
            {"id": "dedup", "label": "Cross-domain deduplication", "status": "pending", "detail": ""},
            {"id": "ranking", "label": "Business impact ranking", "status": "pending", "detail": ""},
        ])
    else:
        for check in config.get_enabled_checks():
            if check.id in CHECK_REGISTRY:
                steps.append(
                    {
                        "id": check.id,
                        "label": check.description or check.id,
                        "status": "pending",
                        "detail": "",
                    }
                )
        steps.append({"id": "llm_enrichment", "label": "LLM enrichment", "status": "pending", "detail": ""})

    steps.append({"id": "reports", "label": "Generate reports", "status": "pending", "detail": ""})
    return steps


def _update_step(step_id: str, status: str, detail: str = "") -> None:
    global _current_step_index
    with _lock:
        for i, step in enumerate(_steps):
            if step["id"] == step_id:
                step["status"] = status
                step["detail"] = detail
                if status == "running":
                    _current_step_index = i
                break


def _find_newest_report(before: set[str]) -> str | None:
    reports_dir = PROJECT_ROOT / "reports"
    after = {p.name for p in reports_dir.glob("findings_report_*.json")}
    new_files = after - before
    if not new_files:
        if after:
            return sorted(after)[-1]
        return None
    return sorted(new_files)[-1]


def get_status() -> dict:
    with _lock:
        completed = sum(1 for s in _steps if s["status"] == "completed")
        return {
            "state": _state,
            "job_type": "scan",
            "scan_level": _scan_level,
            "started_at": _started_at.isoformat() if _started_at else None,
            "finished_at": _finished_at.isoformat() if _finished_at else None,
            "error": _error,
            "report_file": _report_file,
            "log_tail": list(_log_tail),
            "steps": list(_steps),
            "current_step_index": _current_step_index,
            "steps_completed": completed,
            "steps_total": len(_steps),
        }


def is_running() -> bool:
    with _lock:
        return _state == "running"


def _run_scan_worker(config_path: str, level: int, existing_files: set[str]) -> None:
    global _state, _finished_at, _error, _report_file

    handler = _ScanLogHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        load_dotenv(PROJECT_ROOT / ".env")
        os.chdir(PROJECT_ROOT)

        def on_progress(step_id: str, status: str, detail: str) -> None:
            _update_step(step_id, status, detail)

        logger.info("Dashboard starting Level %d scan with %s", level, config_path)
        run_scan(config_path, level=level, progress_callback=on_progress)
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


def start_scan(config_path: str = "checklist.yaml", level: int = 1) -> bool:
    """Start a scan in a background thread. Returns False if already running."""
    global _state, _started_at, _finished_at, _error, _report_file, _steps, _current_step_index, _scan_level

    with _lock:
        if _state == "running":
            return False
        _state = "running"
        _scan_level = level
        _started_at = datetime.now(timezone.utc)
        _finished_at = None
        _error = None
        _report_file = None
        _log_tail.clear()
        _current_step_index = -1

    try:
        _steps = _build_scan_steps(config_path, level=level)
    except Exception as e:
        with _lock:
            _state = "failed"
            _error = str(e)
        return False

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    existing = {p.name for p in reports_dir.glob("findings_report_*.json")}

    thread = threading.Thread(
        target=_run_scan_worker,
        args=(config_path, level, existing),
        daemon=True,
    )
    thread.start()
    return True
