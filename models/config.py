from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional


class CheckConfig(BaseModel):
    id: str
    enabled: bool = True
    description: str
    severity_cap: Literal["critical", "high", "medium", "low", "info"]
    tags: List[str] = []
    unused_days_threshold: Optional[int] = None


class ScanMeta(BaseModel):
    name: str
    description: str = ""
    aws_region: str
    timeout_seconds: int = 30
    max_workers: int = 5
    llm_model: str = "gpt-4o-mini"
    output_dir: str = "reports"


class APITarget(BaseModel):
    url: str
    name: str
    auth_header: Optional[str] = None


class DependencyScanConfig(BaseModel):
    paths: List[str] = Field(default_factory=list)
    ecosystems: List[str] = Field(default_factory=lambda: ["PyPI", "npm"])


class SecretsScanConfig(BaseModel):
    paths: List[str] = Field(default_factory=list)
    exclude: List[str] = Field(default_factory=list)


class ScheduleConfig(BaseModel):
    mode: Literal["interval", "cron"] = "interval"
    interval_hours: float = 6
    interval_minutes: Optional[float] = None
    cron: str = "0 */6 * * *"
    run_on_start: bool = True


class AutoRemediationConfig(BaseModel):
    enabled: bool = False
    dry_run: bool = True


class TrendReportConfig(BaseModel):
    generate_after_each_scan: bool = True
    keep_last_n_scans: int = 30


class Level3Config(BaseModel):
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    slack_webhook_url: Optional[str] = None
    sla_hours: Dict[str, Optional[float]] = Field(
        default_factory=lambda: {
            "critical": 24,
            "high": 72,
            "medium": 168,
            "low": 720,
            "info": None,
        }
    )
    auto_resolve_after_misses: int = 3
    auto_remediation: AutoRemediationConfig = Field(default_factory=AutoRemediationConfig)
    db_path: str = "storage/findings.db"
    trend_report: TrendReportConfig = Field(default_factory=TrendReportConfig)


class ScanConfig(BaseModel):
    scan: ScanMeta
    checks: List[CheckConfig]
    api_targets: List[APITarget] = Field(default_factory=list)
    dependency_scan: DependencyScanConfig = Field(default_factory=DependencyScanConfig)
    secrets_scan: SecretsScanConfig = Field(default_factory=SecretsScanConfig)
    level3: Optional[Level3Config] = None

    def get_enabled_checks(self) -> List[CheckConfig]:
        return [c for c in self.checks if c.enabled]
