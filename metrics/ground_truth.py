"""
Ground truth registry for known intentional misconfigs.

Demo misconfigs align with dashboard/misconfig_service.DEMO_STEPS.
Account baseline checks are always expected in the test AWS account.
Recall uses only *applicable* items (demo set included when demo resources exist).
"""

from typing import Any, Iterable, List, Set

# Created by "Create Misconfigs" in the dashboard demo
DEMO_MISCONFIGS = [
    {
        "id": "gt_001",
        "check_id": "s3_public_acl",
        "description": "S3 bucket with public-read ACL",
        "resource_id": "aivar-test-public",
        "expected_severity": "critical",
        "scope": "demo",
    },
    {
        "id": "gt_002",
        "check_id": "s3_public_policy",
        "description": "S3 bucket with public read policy",
        "resource_id": "aivar-test-policy",
        "expected_severity": "critical",
        "scope": "demo",
    },
    {
        "id": "gt_003",
        "check_id": "iam_user_mfa",
        "description": "IAM console user without MFA (test-no-mfa-user)",
        "resource_id": "test-no-mfa-user",
        "expected_severity": "high",
        "scope": "demo",
    },
    {
        "id": "gt_004",
        "check_id": "sg_open_ssh",
        "description": "Security group with port 22 open to 0.0.0.0/0",
        "resource_id": "open-ssh-sg",
        "expected_severity": "critical",
        "scope": "demo",
    },
    {
        "id": "gt_005",
        "check_id": "sg_open_rdp",
        "description": "Security group with port 3389 open to 0.0.0.0/0",
        "resource_id": "open-rdp-sg",
        "expected_severity": "critical",
        "scope": "demo",
    },
]

# Persistent misconfigs in the test AWS account (not demo-created)
ACCOUNT_BASELINE = [
    {
        "id": "gt_101",
        "check_id": "iam_root_mfa",
        "description": "Root account MFA disabled",
        "resource_id": "root",
        "expected_severity": "critical",
        "scope": "account",
    },
    {
        "id": "gt_102",
        "check_id": "iam_password_policy",
        "description": "Weak or missing account password policy",
        "resource_id": "password-policy",
        "expected_severity": "medium",
        "scope": "account",
    },
    {
        "id": "gt_103",
        "check_id": "cloudtrail_not_logging",
        "description": "CloudTrail not logging in region",
        "resource_id": "cloudtrail",
        "expected_severity": "high",
        "scope": "account",
    },
]

KNOWN_MISCONFIGS: List[dict[str, Any]] = DEMO_MISCONFIGS + ACCOUNT_BASELINE

_DEMO_CHECK_IDS = {kg["check_id"] for kg in DEMO_MISCONFIGS}
_DEMO_RESOURCE_HINTS = (
    "aivar-test-",
    "test-no-mfa-user",
    "open-ssh-sg",
    "open-rdp-sg",
)


def get_total_known() -> int:
    return len(KNOWN_MISCONFIGS)


def _finding_resource_id(finding: Any) -> str:
    if hasattr(finding, "resource_id"):
        return str(getattr(finding, "resource_id") or "")
    if isinstance(finding, dict):
        return str(finding.get("resource_id") or "")
    return ""


def _finding_check_id(finding: Any) -> str:
    if hasattr(finding, "check_id"):
        return str(getattr(finding, "check_id") or "")
    if isinstance(finding, dict):
        return str(finding.get("check_id") or "")
    return ""


def has_demo_context(findings: Iterable[Any]) -> bool:
    """True when demo resources/checks appear in this scan."""
    found_checks: Set[str] = set()
    for finding in findings:
        check_id = _finding_check_id(finding)
        if check_id:
            found_checks.add(check_id)
        resource_id = _finding_resource_id(finding)
        if any(hint in resource_id for hint in _DEMO_RESOURCE_HINTS):
            return True
    return bool(found_checks & _DEMO_CHECK_IDS)


def get_applicable_ground_truth(findings: Iterable[Any]) -> List[dict[str, Any]]:
    """Demo checks count only when demo misconfigs are present in the scan."""
    applicable = list(ACCOUNT_BASELINE)
    if has_demo_context(findings):
        applicable.extend(DEMO_MISCONFIGS)
    return applicable


def ground_truth_matched(kg: dict[str, Any], findings: Iterable[Any]) -> bool:
    """Match by check_id or demo resource identifier."""
    check_id = kg["check_id"]
    resource_hint = kg.get("resource_id", "")
    for finding in findings:
        if _finding_check_id(finding) == check_id:
            return True
        resource_id = _finding_resource_id(finding)
        if resource_hint and resource_hint in resource_id:
            return True
    return False


def compute_verified_recall(findings: Iterable[Any]) -> tuple[int, int, float | None]:
    """Returns (found, total, recall_ratio)."""
    findings_list = list(findings)
    applicable = get_applicable_ground_truth(findings_list)
    if not applicable:
        return 0, 0, None

    known_found = sum(1 for kg in applicable if ground_truth_matched(kg, findings_list))
    known_total = len(applicable)
    recall = known_found / known_total if known_total > 0 else None
    return known_found, known_total, recall
