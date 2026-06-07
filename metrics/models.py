from pydantic import BaseModel, Field
from typing import Dict, Optional


class DetectionMetrics(BaseModel):
    """Precision, recall, F1 — the core ML metrics."""

    known_misconfigs_total: int = 0
    known_misconfigs_found: int = 0
    verified_recall: Optional[float] = None
    verified_precision_critical: Optional[float] = None
    false_positives_critical: int = 0
    f1_score: Optional[float] = None

    avg_confidence_score: float = 0.0
    min_confidence_score: int = 0
    max_confidence_score: int = 0
    high_confidence_pct: float = 0.0
    estimated_precision: float = 0.0
    estimated_false_positive_rate: float = 0.0

    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    critical_findings_count: int = 0


class SpeedMetrics(BaseModel):
    """Scan speed and efficiency metrics."""

    scan_duration_seconds: float
    avg_check_duration_ms: float = 0.0
    resources_scanned: int = 0
    findings_per_second: float = 0.0


class CoverageMetrics(BaseModel):
    """What percentage of the attack surface was checked."""

    total_checks_attempted: int
    checks_succeeded: int
    checks_errored: int
    check_success_rate: float
    resources_checked: int = 0
    infrastructure_coverage_pct: float = 100.0


class Level2Metrics(BaseModel):
    """Additional metrics for Level 2 multi-domain scan."""

    domains_attempted: int
    domains_succeeded: int
    domain_success_rate: float
    findings_per_domain: Dict[str, int] = Field(default_factory=dict)

    total_before_dedup: int = 0
    duplicates_removed: int = 0
    deduplication_rate: float = 0.0
    cross_domain_findings: int = 0


class Level3Metrics(BaseModel):
    """Additional metrics for Level 3 continuous scanning."""

    mean_time_to_detect_seconds: Optional[float] = None

    total_findings_opened: int = 0
    total_findings_resolved: int = 0
    resolution_rate: float = 0.0
    recurrence_rate: float = 0.0

    sla_compliance_rate: float = 0.0
    active_sla_breaches: int = 0

    total_scan_runs: int = 0
    successful_scan_runs: int = 0
    scan_reliability_rate: float = 0.0
    avg_scan_duration_seconds: float = 0.0

    current_posture_score: float = 0.0
    posture_trend: str = "unknown"
    posture_delta: float = 0.0


class AgentMetrics(BaseModel):
    """Top-level metrics object attached to every scan report."""

    level: int
    detection: DetectionMetrics
    speed: SpeedMetrics
    coverage: CoverageMetrics
    level2: Optional[Level2Metrics] = None
    level3: Optional[Level3Metrics] = None
    headline: str = ""
