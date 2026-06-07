"""OSV.dev API client — batch query plus per-vuln detail enrichment."""

import logging
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"

# CVSS v3.1 metric weights (FIRST.org spec)
_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}


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


def fetch_vuln(vuln_id: str, session: requests.Session | None = None) -> Optional[dict]:
    """Fetch full vulnerability record by OSV/GHSA/CVE id."""
    http = session or requests
    try:
        resp = http.get(f"{OSV_API}/vulns/{vuln_id}", timeout=20)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("[osv] Vuln fetch failed for %s: HTTP %s", vuln_id, resp.status_code)
    except requests.RequestException as e:
        logger.warning("[osv] Vuln fetch error for %s: %s", vuln_id, e)
    return None


def fetch_vulns(vuln_ids: List[str], max_workers: int = 8) -> Dict[str, dict]:
    """Fetch full OSV records for unique ids (deduped, parallel)."""
    unique = list(dict.fromkeys(vid for vid in vuln_ids if vid))
    if not unique:
        return {}

    cache: Dict[str, dict] = {}
    session = requests.Session()

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unique))) as pool:
        futures = {pool.submit(fetch_vuln, vid, session): vid for vid in unique}
        for future in as_completed(futures):
            vid = futures[future]
            try:
                data = future.result()
                if data:
                    cache[vid] = data
            except Exception as e:
                logger.warning("[osv] Failed to fetch %s: %s", vid, e)

    logger.info("[osv] Enriched %d/%d vulnerability records", len(cache), len(unique))
    return cache


def parse_cvss_v3_base_score(vector: str) -> Optional[float]:
    """Compute CVSS v3.x base score from a vector string."""
    if not vector or not vector.startswith("CVSS:3"):
        return None

    metrics: Dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metrics for k in required):
        return None

    scope_changed = metrics["S"] == "C"
    pr_table = _CVSS3["PR_C"] if scope_changed else _CVSS3["PR_U"]

    iss = 1.0 - (
        (1.0 - _CVSS3["C"][metrics["C"]])
        * (1.0 - _CVSS3["I"][metrics["I"]])
        * (1.0 - _CVSS3["A"][metrics["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22
        * _CVSS3["AV"][metrics["AV"]]
        * _CVSS3["AC"][metrics["AC"]]
        * pr_table[metrics["PR"]]
        * _CVSS3["UI"][metrics["UI"]]
    )

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    return math.ceil(base * 10) / 10


def extract_cvss_score(vuln: dict) -> Optional[float]:
    """Extract numeric CVSS score from an OSV vulnerability record."""
    for db in (vuln.get("database_specific") or {}, vuln.get("ecosystem_specific") or {}):
        score = db.get("cvss_score") or db.get("severity_score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass

    for sev in vuln.get("severity") or []:
        if sev.get("type", "").startswith("CVSS_V3"):
            score_str = sev.get("score", "")
            if score_str.startswith("CVSS:3"):
                parsed = parse_cvss_v3_base_score(score_str)
                if parsed is not None:
                    return parsed
            try:
                return float(score_str)
            except (TypeError, ValueError):
                pass

    return None


def extract_cve_ids(vuln: dict) -> List[str]:
    """Return CVE aliases from a vulnerability record."""
    return [alias for alias in (vuln.get("aliases") or []) if alias.startswith("CVE-")]


def extract_fix_versions(vuln: dict, package_name: str | None = None) -> List[str]:
    """Return fixed versions from affected ranges (optionally filtered by package)."""
    fixes: List[str] = []
    pkg_lower = (package_name or "").lower().replace("_", "-")

    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if package_name and pkg.get("name", "").lower().replace("_", "-") != pkg_lower:
            continue
        for range_info in affected.get("ranges") or []:
            for event in range_info.get("events") or []:
                fixed = event.get("fixed")
                if fixed and fixed not in fixes:
                    fixes.append(fixed)

    return fixes


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
