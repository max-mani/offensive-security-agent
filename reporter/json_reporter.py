import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from models.report import ScanReport

logger = logging.getLogger(__name__)


class JSONReporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, report: ScanReport) -> Path:
        timestamp = report.end_time.strftime("%Y%m%d_%H%M%S")
        suffix = "_l2" if report.scan_level >= 2 else ""
        output_path = self.output_dir / f"findings_report_{timestamp}{suffix}.json"

        payload = json.loads(report.model_dump_json())
        output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

        logger.info("JSON report written: %s", output_path)
        return output_path
