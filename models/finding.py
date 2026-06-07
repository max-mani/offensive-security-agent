from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal
from datetime import datetime, timezone
import uuid

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]


class RawFinding(BaseModel):
    """Output of a security check before LLM enrichment."""

    check_id: str
    resource_id: str
    resource_arn: str
    resource_type: str
    region: str
    raw_evidence: Dict[str, Any]
    preliminary_severity: SeverityLevel
    domain: str = "aws_infrastructure"
    check_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidatedFinding(BaseModel):
    """Final finding after LLM enrichment and severity validation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    check_id: str
    title: str
    resource_id: str
    resource_arn: str
    resource_type: str
    region: str
    severity: SeverityLevel
    severity_reasoning: str
    raw_evidence: Dict[str, Any]
    business_impact: str
    remediation_steps: List[str]
    remediation_command: str
    confidence_score: int = Field(ge=0, le=100)
    domain: str = "aws_infrastructure"
    impact_score: float = 0.0
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
