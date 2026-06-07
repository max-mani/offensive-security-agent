"""Generic background job tracking with step-by-step progress."""

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Literal

JobState = Literal["idle", "running", "completed", "failed"]

_lock = threading.Lock()
_state: JobState = "idle"
_job_type: str | None = None
_started_at: datetime | None = None
_finished_at: datetime | None = None
_error: str | None = None
_steps: list[dict[str, Any]] = []
_current_step_index: int = -1
_log_tail: deque[str] = deque(maxlen=200)
_result: dict[str, Any] | None = None


def _reset_job(job_type: str, steps: list[dict[str, Any]]) -> bool:
    global _state, _job_type, _started_at, _finished_at, _error, _steps, _current_step_index, _result
    with _lock:
        if _state == "running":
            return False
        _state = "running"
        _job_type = job_type
        _started_at = datetime.now(timezone.utc)
        _finished_at = None
        _error = None
        _steps = steps
        _current_step_index = -1
        _result = None
        _log_tail.clear()
    return True


def _append_log(message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    _log_tail.append(f"{ts} {message}")


def update_step(step_id: str, status: str, detail: str = "") -> None:
    global _current_step_index
    with _lock:
        for i, step in enumerate(_steps):
            if step["id"] == step_id:
                step["status"] = status
                step["detail"] = detail
                if status == "running":
                    _current_step_index = i
                break
    label = next((s["label"] for s in _steps if s["id"] == step_id), step_id)
    _append_log(f"[{status.upper()}] {label}" + (f" — {detail}" if detail else ""))


def complete_job(result: dict[str, Any] | None = None) -> None:
    global _state, _finished_at, _result
    with _lock:
        _state = "completed"
        _finished_at = datetime.now(timezone.utc)
        _result = result


def fail_job(error: str) -> None:
    global _state, _finished_at, _error
    with _lock:
        _state = "failed"
        _finished_at = datetime.now(timezone.utc)
        _error = error
    _append_log(f"ERROR: {error}")


def is_busy() -> bool:
    with _lock:
        return _state == "running"


def get_status() -> dict[str, Any]:
    with _lock:
        completed = sum(1 for s in _steps if s["status"] == "completed")
        return {
            "state": _state,
            "job_type": _job_type,
            "started_at": _started_at.isoformat() if _started_at else None,
            "finished_at": _finished_at.isoformat() if _finished_at else None,
            "error": _error,
            "steps": list(_steps),
            "current_step_index": _current_step_index,
            "steps_completed": completed,
            "steps_total": len(_steps),
            "log_tail": list(_log_tail),
            "result": _result,
        }


def start_job(job_type: str, steps: list[dict[str, Any]], worker: Callable[[], None]) -> bool:
    if not _reset_job(job_type, steps):
        return False

    def _wrapper() -> None:
        try:
            worker()
            if _state == "running":
                complete_job()
        except Exception as e:
            fail_job(str(e))

    thread = threading.Thread(target=_wrapper, daemon=True)
    thread.start()
    return True
