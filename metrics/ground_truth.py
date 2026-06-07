"""
Ground truth registry for known intentional misconfigs.

Register each misconfig with its expected check_id before demo scans.
After scan, MetricsCalculator checks if each was found for verified recall.
"""

KNOWN_MISCONFIGS = [
    {
        "id": "gt_001",
        "check_id": "iam_root_mfa",
        "description": "Root account MFA disabled (intentionally not set in test account)",
        "resource_id": "root",
        "expected_severity": "critical",
    },
    {
        "id": "gt_002",
        "check_id": "s3_public_acl",
        "description": "S3 bucket with public-read ACL",
        "resource_id": "aivar-test-public",
        "expected_severity": "critical",
    },
    {
        "id": "gt_003",
        "check_id": "sg_open_ssh",
        "description": "Security group with port 22 open to 0.0.0.0/0",
        "resource_id": "open-ssh-sg",
        "expected_severity": "critical",
    },
    {
        "id": "gt_004",
        "check_id": "sg_open_rdp",
        "description": "Security group with port 3389 open to 0.0.0.0/0",
        "resource_id": "open-rdp-sg",
        "expected_severity": "critical",
    },
    {
        "id": "gt_005",
        "check_id": "cloudtrail_not_logging",
        "description": "CloudTrail not configured in ap-south-1",
        "resource_id": "cloudtrail",
        "expected_severity": "high",
    },
    {
        "id": "gt_006",
        "check_id": "iam_password_policy",
        "description": "No custom password policy (AWS defaults are weak)",
        "resource_id": "password-policy",
        "expected_severity": "medium",
    },
]


def get_total_known() -> int:
    return len(KNOWN_MISCONFIGS)
