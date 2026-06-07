import json
import os
import re
from pathlib import Path

import yaml

from models.config import ScanConfig

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _substitute_env_vars(text: str) -> str:
    """Replace ${VAR} placeholders with environment variable values."""

    def replacer(match: re.Match) -> str:
        return os.getenv(match.group(1), "")

    return _ENV_PATTERN.sub(replacer, text)


def load_config(path: str | Path) -> ScanConfig:
    """Load and validate a YAML or JSON checklist configuration file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    raw_text = _substitute_env_vars(raw_text)
    suffix = config_path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(raw_text)
    elif suffix == ".json":
        data = json.loads(raw_text)
    else:
        raise ValueError(f"Unsupported config format: {suffix}. Use .yaml, .yml, or .json")

    config = ScanConfig.model_validate(data)

    if config.level3 and config.level3.db_path:
        os.environ.setdefault("DB_PATH", config.level3.db_path)

    return config
