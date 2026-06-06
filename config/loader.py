import json
from pathlib import Path

import yaml

from models.config import ScanConfig


def load_config(path: str | Path) -> ScanConfig:
    """Load and validate a YAML or JSON checklist configuration file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    suffix = config_path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(raw_text)
    elif suffix == ".json":
        data = json.loads(raw_text)
    else:
        raise ValueError(f"Unsupported config format: {suffix}. Use .yaml, .yml, or .json")

    return ScanConfig.model_validate(data)
