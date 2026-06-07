from pydantic import BaseModel, Field
from typing import List, Literal, Optional


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


class ScanConfig(BaseModel):
    scan: ScanMeta
    checks: List[CheckConfig]
    api_targets: List[APITarget] = Field(default_factory=list)
    dependency_scan: DependencyScanConfig = Field(default_factory=DependencyScanConfig)
    secrets_scan: SecretsScanConfig = Field(default_factory=SecretsScanConfig)

    def get_enabled_checks(self) -> List[CheckConfig]:
        return [c for c in self.checks if c.enabled]
