from pydantic import BaseModel
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


class ScanConfig(BaseModel):
    scan: ScanMeta
    checks: List[CheckConfig]

    def get_enabled_checks(self) -> List[CheckConfig]:
        return [c for c in self.checks if c.enabled]
