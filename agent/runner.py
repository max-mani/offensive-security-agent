"""Shared scan entry point for CLI and dashboard."""

import logging
import os
from pathlib import Path
from typing import Callable, Optional

from dotenv import load_dotenv

from agent.orchestrator import AgentOrchestrator
from config.loader import load_config
from models.report import ScanReport
from utils.llm_client import resolve_llm_config

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def check_level2_dependencies() -> None:
    """Ensure Level 2 Python packages are installed in the active environment."""
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")
    try:
        import packaging  # noqa: F401
    except ImportError:
        missing.append("packaging")
    if missing:
        raise RuntimeError(
            "Level 2 requires packages not installed in this Python environment: "
            f"{', '.join(missing)}. Run: pip install -r requirements.txt "
            "(use the same venv as the dashboard if you use one)."
        )


def check_level3_dependencies() -> None:
    """Ensure Level 3 Python packages are installed."""
    check_level2_dependencies()
    missing = []
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        missing.append("sqlalchemy")
    try:
        import apscheduler  # noqa: F401
    except ImportError:
        missing.append("apscheduler")
    if missing:
        raise RuntimeError(
            "Level 3 requires packages not installed: "
            f"{', '.join(missing)}. Run: pip install -r requirements.txt"
        )


def run_scan(
    config_path: str = "checklist.yaml",
    level: int = 1,
    progress_callback: Optional[Callable[[str, str, str], None]] = None,
) -> ScanReport:
    """Run a full security scan and return the report."""
    load_dotenv(PROJECT_ROOT / ".env")
    os.chdir(PROJECT_ROOT)

    llm = resolve_llm_config()
    logger.info("LLM provider: %s (%s)", llm.provider, llm.model)

    if not os.getenv("AWS_ACCESS_KEY_ID") or not os.getenv("AWS_SECRET_ACCESS_KEY"):
        raise RuntimeError(
            "AWS credentials not set. Copy .env.example to .env and fill in values."
        )

    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    config = load_config(path)

    if level >= 3:
        check_level3_dependencies()
        result = run_scan_l3(str(path), progress_callback=progress_callback)
        return result["report"]

    if level >= 2:
        check_level2_dependencies()
        from agent.orchestrator_l2 import OrchestratorL2

        logger.info("Running Level 2 multi-domain scan")
        orchestrator = OrchestratorL2(config, llm)
        return orchestrator.run(progress_callback=progress_callback)

    orchestrator = AgentOrchestrator(config, llm)
    return orchestrator.run(progress_callback=progress_callback)


def run_scan_l3(
    config_path: str = "checklist_l3.yaml",
    progress_callback: Optional[Callable[[str, str, str], None]] = None,
) -> dict:
    """Run a Level 3 scan with persistence and lifecycle."""
    load_dotenv(PROJECT_ROOT / ".env")
    os.chdir(PROJECT_ROOT)

    check_level3_dependencies()
    llm = resolve_llm_config()

    path = Path(config_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    config = load_config(path)

    from storage.database import init_db
    from agent.orchestrator_l3 import OrchestratorL3

    init_db()
    logger.info("Running Level 3 autonomous scan")
    orchestrator = OrchestratorL3(config, llm)
    result = orchestrator.run()

    if progress_callback and "report" in result:
        progress_callback("l3_complete", "completed", f"posture={result.get('posture_score')}")

    return result
