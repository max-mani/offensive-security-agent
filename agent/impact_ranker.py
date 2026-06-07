"""Business impact ranking for multi-domain findings."""

import logging
from typing import List

from models.finding import ValidatedFinding

logger = logging.getLogger(__name__)

SEVERITY_SCORE = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}

DOMAIN_WEIGHT = {
    "secrets": 1.3,
    "aws_infrastructure": 1.1,
    "api_endpoints": 1.0,
    "dependencies": 0.9,
    "local": 0.8,
}

CHECK_BONUS = {
    "secrets_scan": 20,
    "iam_root_mfa": 15,
    "iam_root_access_keys": 15,
    "s3_public_acl": 12,
    "ebs_public_snapshots": 12,
    "api_cors_misconfiguration": 8,
    "dependency_cve": 5,
}


def calculate_impact_score(finding: ValidatedFinding) -> float:
    """impact_score = (severity_score + check_bonus) x domain_weight x (confidence/100)"""
    base = SEVERITY_SCORE.get(finding.severity, 0)
    weight = DOMAIN_WEIGHT.get(finding.domain, 1.0)
    bonus = CHECK_BONUS.get(finding.check_id, 0)
    confidence = finding.confidence_score / 100
    return round((base + bonus) * weight * confidence, 2)


def rank_by_impact(findings: List[ValidatedFinding]) -> List[ValidatedFinding]:
    """Sort findings by business impact score descending; set impact_score on each."""
    scored = [(calculate_impact_score(f), f) for f in findings]
    scored.sort(key=lambda x: x[0], reverse=True)

    ranked: List[ValidatedFinding] = []
    for score, finding in scored:
        finding.impact_score = score
        ranked.append(finding)

    if ranked:
        top = ranked[0]
        logger.info("[ranker] Top finding: %s score=%.2f", top.check_id, top.impact_score)

    return ranked
