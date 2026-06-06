"""Shared scan entry point for CLI and dashboard."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from agent.orchestrator import AgentOrchestrator
from config.loader import load_config
from models.report import ScanReport
from utils.llm_client import resolve_llm_config

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_scan(config_path: str = "checklist.yaml") -> ScanReport:
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
    orchestrator = AgentOrchestrator(config, llm)
    return orchestrator.run()
