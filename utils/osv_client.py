import logging
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"


def query_batch(packages: List[Dict]) -> List[List[dict]]:
    """Batch query OSV for up to 1000 packages at once."""
    if not packages:
        return []

    payload = {
        "queries": [
            {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
            for p in packages
        ]
    }

    try:
        resp = requests.post(f"{OSV_API}/querybatch", json=payload, timeout=30)
        if resp.status_code == 200:
            return [r.get("vulns", []) for r in resp.json().get("results", [])]
        logger.warning("[osv] Batch query failed: HTTP %s", resp.status_code)
    except requests.RequestException as e:
        logger.error("[osv] Batch query error: %s", e)

    return [[] for _ in packages]


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
