"""Cross-domain finding deduplication."""

import hashlib
import logging
import re
from typing import List

from models.finding import ValidatedFinding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fingerprint(finding: ValidatedFinding) -> str:
    """Two findings are duplicates if they share check_id + normalized resource_id + severity."""
    resource = finding.resource_id.lower().strip()
    resource = re.sub(r"==[\d.]+$", "", resource)
    key = f"{finding.check_id}::{resource}::{finding.severity}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def deduplicate(findings: List[ValidatedFinding]) -> List[ValidatedFinding]:
    """Remove duplicates across domains; keep higher severity / confidence."""
    seen: dict[str, ValidatedFinding] = {}

    for f in findings:
        fp = _fingerprint(f)
        if fp not in seen:
            seen[fp] = f
        else:
            existing = seen[fp]
            f_better = SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(existing.severity, 99)
            tie_break = f.severity == existing.severity and f.confidence_score > existing.confidence_score
            if f_better or tie_break:
                logger.info(
                    "[dedup] %s/%s replaces %s/%s",
                    f.check_id,
                    f.domain,
                    existing.check_id,
                    existing.domain,
                )
                seen[fp] = f

    result = list(seen.values())
    removed = len(findings) - len(result)
    logger.info(
        "[dedup] %d findings -> %d after deduplication (%d removed)",
        len(findings),
        len(result),
        removed,
    )
    return result
