"""Dependency CVE scanner — Domain 3 via OSV API."""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple

from models.finding import RawFinding
from models.report import CheckError
from utils.osv_client import cvss_to_severity, query_batch

logger = logging.getLogger(__name__)

MAX_CVES_PER_PACKAGE = 5


def parse_requirements_txt(path: str) -> List[Dict]:
    """Parse requirements.txt into package dicts for OSV."""
    packages = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = re.sub(r"\[.*?\]", "", line)
            match = re.match(
                r"^([A-Za-z0-9_\-\.]+)\s*[=~><]{1,2}\s*([0-9][^\s;#]*)", line
            )
            if match:
                packages.append(
                    {
                        "name": match.group(1).lower().replace("_", "-"),
                        "version": match.group(2).strip(),
                        "ecosystem": "PyPI",
                    }
                )
    return packages


def parse_package_json(path: str) -> List[Dict]:
    """Parse package.json dependencies and devDependencies."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    packages = []
    for dep_type in ["dependencies", "devDependencies"]:
        for name, version in data.get(dep_type, {}).items():
            clean = re.sub(r"^[^0-9]*", "", version)
            if clean and clean[0].isdigit():
                packages.append({"name": name, "version": clean, "ecosystem": "npm"})
    return packages


def _extract_cvss_score(vuln: dict) -> float | None:
    for db in [vuln.get("database_specific", {}), vuln.get("ecosystem_specific", {})]:
        score = db.get("cvss_score") or db.get("severity_score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            try:
                return float(score_str)
            except (TypeError, ValueError):
                pass
    return None


def run_dependency_domain(scan_paths: List[str]) -> Tuple[List[RawFinding], List[CheckError]]:
    """Parse dependency files, batch query OSV, return CVE findings."""
    all_packages: List[Dict] = []
    source_map: Dict[int, Tuple[str, Dict]] = {}
    errors: List[CheckError] = []

    for path in scan_paths:
        p = Path(path)
        if not p.exists():
            logger.warning("[dependencies] File not found: %s", path)
            continue
        if p.name == "requirements.txt" or p.suffix == ".txt":
            pkgs = parse_requirements_txt(str(p))
        elif p.name == "package.json":
            pkgs = parse_package_json(str(p))
        else:
            continue

        logger.info("[dependencies] Parsed %d packages from %s", len(pkgs), path)
        for pkg in pkgs:
            source_map[len(all_packages)] = (str(p), pkg)
            all_packages.append(pkg)

    if not all_packages:
        return [], errors

    results = query_batch(all_packages)
    if not any(results) and all_packages:
        errors.append(
            CheckError(
                check_id="dependency_cve",
                error_type="api_error",
                error_message="OSV batch query returned no results (API may be unreachable)",
            )
        )

    findings: List[RawFinding] = []
    for idx, vulns in enumerate(results):
        if not vulns:
            continue
        file_path, pkg = source_map[idx]

        scored_vulns = []
        for vuln in vulns:
            cvss_score = _extract_cvss_score(vuln)
            scored_vulns.append((cvss_score or 0.0, vuln))
        scored_vulns.sort(key=lambda x: x[0], reverse=True)

        for cvss_score, vuln in scored_vulns[:MAX_CVES_PER_PACKAGE]:
            severity = cvss_to_severity(cvss_score if cvss_score else None)

            fix_versions = []
            for affected in vuln.get("affected", []):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            fix_versions.append(event["fixed"])

            cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]

            findings.append(
                RawFinding(
                    check_id="dependency_cve",
                    resource_id=f"{pkg['name']}=={pkg['version']}",
                    resource_arn=f"dependency::{file_path}::{pkg['name']}",
                    resource_type="Dependency::Package",
                    region="local",
                    domain="dependencies",
                    raw_evidence={
                        "package_name": pkg["name"],
                        "installed_version": pkg["version"],
                        "ecosystem": pkg["ecosystem"],
                        "source_file": file_path,
                        "osv_id": vuln.get("id", "UNKNOWN"),
                        "cve_ids": cve_ids,
                        "cvss_score": cvss_score if cvss_score else None,
                        "fix_versions": fix_versions,
                        "summary": vuln.get("summary", ""),
                        "api_call": "POST api.osv.dev/v1/querybatch",
                    },
                    preliminary_severity=severity,
                )
            )

    logger.info("[dependencies] %d CVE findings from %d packages", len(findings), len(all_packages))
    return findings, errors
