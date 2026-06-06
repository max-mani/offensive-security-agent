from pydantic import BaseModel, Field
from typing import Dict, List, Literal
from datetime import datetime, timezone
import uuid

from models.finding import ValidatedFinding


class CheckError(BaseModel):
    """A check that failed to execute - not a finding."""

    check_id: str
    error_type: Literal["access_denied", "throttled", "timeout", "api_error", "unknown"]
    error_message: str
    http_status: int | None = None
    aws_error_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanReport(BaseModel):
    """Top-level scan report."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    aws_account_id: str
    aws_region: str
    total_checks_attempted: int
    total_checks_succeeded: int
    total_checks_errored: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings: List[ValidatedFinding]
    scan_errors: List[CheckError]
    scan_health: Literal["healthy", "degraded", "partial", "failed"]
