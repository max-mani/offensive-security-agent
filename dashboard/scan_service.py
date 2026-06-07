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
from config.loader import load_config
from utils.llm_client import resolve_llm_config

logger = logging.getLogger(__name__)

ScanState = Literal["idle", "running", "completed", "failed"]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_lock = threading.Lock()
_state: ScanState = "idle"
_started_at: datetime | None = None
_finished_at: datetime | None = None
_error: str | None = None
_report_file: str | None = None
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


def _build_scan_steps(config_path: str) -> list[dict[str, Any]]:
    load_dotenv(PROJECT_ROOT / ".env")
    config = load_config(PROJECT_ROOT / config_path)
    steps = [{"id": "init", "label": "Load configuration", "status": "pending", "detail": ""}]
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


def _run_scan_worker(config_path: str, existing_files: set[str]) -> None:
    global _state, _finished_at, _error, _report_file

    handler = _ScanLogHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        load_dotenv(PROJECT_ROOT / ".env")
        os.chdir(PROJECT_ROOT)

        llm = resolve_llm_config()
        logger.info("LLM provider: %s (%s)", llm.provider, llm.model)

        path = PROJECT_ROOT / config_path
        config = load_config(path)

        from agent.orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator(config, llm)

        def on_progress(step_id: str, status: str, detail: str) -> None:
            _update_step(step_id, status, detail)

        orchestrator.run(progress_callback=on_progress)
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
    global _state, _started_at, _finished_at, _error, _report_file, _steps, _current_step_index

    with _lock:
        if _state == "running":
            return False
        _state = "running"
        _started_at = datetime.now(timezone.utc)
        _finished_at = None
        _error = None
        _report_file = None
        _log_tail.clear()
        _current_step_index = -1

    try:
        _steps = _build_scan_steps(config_path)
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
        args=(config_path, existing),
        daemon=True,
    )
    thread.start()
    return True
