"""Create, verify, and cleanup AWS demo misconfigurations via boto3."""

import json
import os
import time
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import dotenv_values

from dashboard import job_service

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGION = "ap-south-1"

DEMO_STEPS = [
    {"id": "s3_public_acl", "label": "Public S3 bucket (Critical)", "status": "pending", "detail": ""},
    {"id": "s3_public_policy", "label": "Public S3 bucket policy (Critical)", "status": "pending", "detail": ""},
    {"id": "iam_user_mfa", "label": "IAM user without MFA (High)", "status": "pending", "detail": ""},
    {"id": "sg_open_ssh", "label": "Open SSH security group (Critical)", "status": "pending", "detail": ""},
    {"id": "sg_open_rdp", "label": "Open RDP security group (Critical)", "status": "pending", "detail": ""},
]

VERIFY_STEPS = [
    {"id": "verify_s3_public", "label": "Verify public S3 visible to scanner", "status": "pending", "detail": ""},
    {"id": "verify_s3_policy", "label": "Verify public S3 policy visible", "status": "pending", "detail": ""},
    {"id": "verify_iam", "label": "Verify IAM user without MFA", "status": "pending", "detail": ""},
    {"id": "verify_ssh", "label": "Verify open SSH security group", "status": "pending", "detail": ""},
    {"id": "verify_rdp", "label": "Verify open RDP security group", "status": "pending", "detail": ""},
]

CLEANUP_STEPS = [
    {"id": "cleanup_s3", "label": "Delete test S3 buckets", "status": "pending", "detail": ""},
    {"id": "cleanup_sg", "label": "Delete open SSH/RDP security groups", "status": "pending", "detail": ""},
    {"id": "cleanup_iam", "label": "Delete test-no-mfa-user", "status": "pending", "detail": ""},
]


def _load_admin_env() -> dict[str, str]:
    admin_file = PROJECT_ROOT / ".env.admin"
    if not admin_file.exists():
        raise FileNotFoundError(
            ".env.admin not found. Copy .env.admin.example and add aivar-admin keys."
        )
    values = dotenv_values(admin_file)
    key = values.get("AWS_ACCESS_KEY_ID")
    secret = values.get("AWS_SECRET_ACCESS_KEY")
    if not key or not secret:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY required in .env.admin")
    return {
        "aws_access_key_id": key,
        "aws_secret_access_key": secret,
        "region_name": values.get("AWS_DEFAULT_REGION") or REGION,
    }


def _admin_session() -> boto3.Session:
    return boto3.Session(**_load_admin_env())


def _scanner_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_DEFAULT_REGION", REGION),
    )


def _timestamp() -> str:
    return str(int(time.time()))


def _ensure_sg_rule(ec2, vpc_id: str, group_name: str, description: str, port: int) -> str:
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [group_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    ).get("SecurityGroups", [])

    if sgs:
        sg_id = sgs[0]["GroupId"]
    else:
        sg_id = ec2.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id,
        )["GroupId"]

    for perm in ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0].get(
        "IpPermissions", []
    ):
        fp = perm.get("FromPort", 0)
        tp = perm.get("ToPort", 65535)
        if fp <= port <= tp:
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0":
                    return sg_id

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    return sg_id


def _run_create_misconfigs(update_step) -> dict[str, Any]:
    session = _admin_session()
    region = session.region_name or REGION
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)
    ts = _timestamp()

    # 1. Public S3
    update_step("s3_public_acl", "running")
    bucket_public = f"aivar-test-public-{ts}"
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_public)
        else:
            s3.create_bucket(
                Bucket=bucket_public,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        s3.put_public_access_block(
            Bucket=bucket_public,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        # Newer AWS accounts default to BucketOwnerEnforced (ACLs disabled)
        s3.put_bucket_ownership_controls(
            Bucket=bucket_public,
            OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
        )
        s3.put_bucket_acl(Bucket=bucket_public, ACL="public-read")
        update_step("s3_public_acl", "completed", bucket_public)
    except ClientError as e:
        update_step("s3_public_acl", "failed", str(e))
        raise

    # 2. Public S3 bucket policy (replaces unencrypted bucket — account default encryption
    # prevents ServerSideEncryptionConfigurationNotFoundError on new buckets)
    update_step("s3_public_policy", "running")
    bucket_policy = f"aivar-test-policy-{ts}"
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_policy)
        else:
            s3.create_bucket(
                Bucket=bucket_policy,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        s3.put_public_access_block(
            Bucket=bucket_policy,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_policy}/*",
                    }
                ],
            }
        )
        s3.put_bucket_policy(Bucket=bucket_policy, Policy=policy)
        update_step("s3_public_policy", "completed", bucket_policy)
    except ClientError as e:
        update_step("s3_public_policy", "failed", str(e))
        raise

    # 3. IAM user
    update_step("iam_user_mfa", "running")
    try:
        try:
            iam.create_user(UserName="test-no-mfa-user")
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
        try:
            iam.create_login_profile(
                UserName="test-no-mfa-user",
                Password="TestPass@123!",
                PasswordResetRequired=False,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
        update_step("iam_user_mfa", "completed", "test-no-mfa-user")
    except ClientError as e:
        update_step("iam_user_mfa", "failed", str(e))
        raise

    # 4-5. Security groups
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpc_id = vpcs["Vpcs"][0]["VpcId"] if vpcs.get("Vpcs") else None
    if not vpc_id:
        raise RuntimeError(f"No default VPC in {region}")

    update_step("sg_open_ssh", "running")
    try:
        sg_ssh = _ensure_sg_rule(ec2, vpc_id, "open-ssh-sg", "Test SG with open SSH", 22)
        update_step("sg_open_ssh", "completed", sg_ssh)
    except ClientError as e:
        update_step("sg_open_ssh", "failed", str(e))
        raise

    update_step("sg_open_rdp", "running")
    try:
        sg_rdp = _ensure_sg_rule(ec2, vpc_id, "open-rdp-sg", "Test SG with open RDP", 3389)
        update_step("sg_open_rdp", "completed", sg_rdp)
    except ClientError as e:
        update_step("sg_open_rdp", "failed", str(e))
        raise

    return {
        "public_bucket": bucket_public,
        "policy_bucket": bucket_policy,
        "message": "5 misconfigs created",
    }


def _create_misconfigs_worker() -> None:
    result = _run_create_misconfigs(job_service.update_step)
    job_service.complete_job(result)


def _run_cleanup(update_step) -> dict[str, Any]:
    session = _admin_session()
    region = session.region_name or REGION
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)

    update_step("cleanup_s3", "running")
    deleted = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        if name.startswith("aivar-test-"):
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=name):
                    objs = page.get("Contents", [])
                    if objs:
                        s3.delete_objects(
                            Bucket=name,
                            Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                        )
                s3.delete_bucket(Bucket=name)
                deleted.append(name)
            except ClientError:
                pass
    update_step("cleanup_s3", "completed", f"Deleted {len(deleted)} bucket(s)")

    update_step("cleanup_sg", "running")
    removed_sg = []
    for sg_name in ("open-ssh-sg", "open-rdp-sg"):
        try:
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [sg_name]}]
            ).get("SecurityGroups", [])
            for sg in sgs:
                ec2.delete_security_group(GroupId=sg["GroupId"])
                removed_sg.append(sg_name)
        except ClientError:
            pass
    update_step("cleanup_sg", "completed", f"Removed {len(removed_sg)} SG(s)")

    update_step("cleanup_iam", "running")
    try:
        try:
            iam.delete_login_profile(UserName="test-no-mfa-user")
        except ClientError:
            pass
        keys = iam.list_access_keys(UserName="test-no-mfa-user").get("AccessKeyMetadata", [])
        for k in keys:
            iam.delete_access_key(UserName="test-no-mfa-user", AccessKeyId=k["AccessKeyId"])
        iam.delete_user(UserName="test-no-mfa-user")
        update_step("cleanup_iam", "completed", "test-no-mfa-user removed")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            update_step("cleanup_iam", "completed", "User already absent")
        else:
            update_step("cleanup_iam", "failed", str(e))
            raise

    return {"message": "Cleanup complete", "buckets_deleted": deleted}


def _cleanup_worker() -> None:
    result = _run_cleanup(job_service.update_step)
    job_service.complete_job(result)


def verify_misconfigs() -> dict[str, Any]:
    """Synchronous verify using scanner credentials."""
    session = _scanner_session()
    region = session.region_name or REGION
    s3 = session.client("s3")
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)
    results = []

    # Public S3
    ok = False
    detail = "No aivar-test-public-* bucket with public ACL"
    for b in s3.list_buckets().get("Buckets", []):
        if b["Name"].startswith("aivar-test-public"):
            try:
                acl = s3.get_bucket_acl(Bucket=b["Name"])
                public = [
                    g
                    for g in acl.get("Grants", [])
                    if "AllUsers" in g.get("Grantee", {}).get("URI", "")
                    or "AuthenticatedUsers" in g.get("Grantee", {}).get("URI", "")
                ]
                if public:
                    ok = True
                    detail = b["Name"]
                    break
            except ClientError:
                pass
    results.append({"id": "s3_public_acl", "pass": ok, "detail": detail})

    # Public S3 bucket policy
    ok = False
    detail = "No aivar-test-policy-* bucket with public policy"
    for b in s3.list_buckets().get("Buckets", []):
        if b["Name"].startswith("aivar-test-policy"):
            try:
                status = s3.get_bucket_policy_status(Bucket=b["Name"])
                if status["PolicyStatus"].get("IsPublic", False):
                    ok = True
                    detail = b["Name"]
                    break
            except ClientError:
                pass
    results.append({"id": "s3_public_policy", "pass": ok, "detail": detail})

    # IAM
    ok = False
    detail = "test-no-mfa-user not found"
    try:
        iam.get_login_profile(UserName="test-no-mfa-user")
        mfa = iam.list_mfa_devices(UserName="test-no-mfa-user").get("MFADevices", [])
        if not mfa:
            ok = True
            detail = "test-no-mfa-user (no MFA)"
    except ClientError:
        pass
    results.append({"id": "iam_user_mfa", "pass": ok, "detail": detail})

    # SSH SG
    ok = False
    detail = "open-ssh-sg not found"
    for sg in ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["open-ssh-sg"]}]
    ).get("SecurityGroups", []):
        for rule in sg.get("IpPermissions", []):
            fp, tp = rule.get("FromPort", 0), rule.get("ToPort", 65535)
            if fp <= 22 <= tp:
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])):
                    ok = True
                    detail = sg["GroupId"]
                    break
    results.append({"id": "sg_open_ssh", "pass": ok, "detail": detail})

    # RDP SG
    ok = False
    detail = "open-rdp-sg not found"
    for sg in ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["open-rdp-sg"]}]
    ).get("SecurityGroups", []):
        for rule in sg.get("IpPermissions", []):
            fp, tp = rule.get("FromPort", 0), rule.get("ToPort", 65535)
            if fp <= 3389 <= tp:
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])):
                    ok = True
                    detail = sg["GroupId"]
                    break
    results.append({"id": "sg_open_rdp", "pass": ok, "detail": detail})

    passed = sum(1 for r in results if r["pass"])
    return {"passed": passed, "total": len(results), "results": results, "all_pass": passed == len(results)}


def _verify_worker() -> None:
    mapping = [
        ("verify_s3_public", "s3_public_acl"),
        ("verify_s3_policy", "s3_public_policy"),
        ("verify_iam", "iam_user_mfa"),
        ("verify_ssh", "sg_open_ssh"),
        ("verify_rdp", "sg_open_rdp"),
    ]
    data = verify_misconfigs()
    lookup = {r["id"]: r for r in data["results"]}
    for step_id, check_id in mapping:
        job_service.update_step(step_id, "running")
        r = lookup.get(check_id, {})
        if r.get("pass"):
            job_service.update_step(step_id, "completed", r.get("detail", "OK"))
        else:
            job_service.update_step(step_id, "failed", r.get("detail", "Not found"))
    if data["all_pass"]:
        job_service.complete_job(data)
    else:
        fail_job_msg = f"Only {data['passed']}/{data['total']} resources visible to scanner"
        job_service.fail_job(fail_job_msg)


def create_misconfigs_sync() -> dict[str, Any]:
    """Create all demo misconfigs synchronously (admin creds)."""
    return _run_create_misconfigs(lambda *_: None)


def cleanup_misconfigs_sync() -> dict[str, Any]:
    """Delete all demo resources synchronously (admin creds)."""
    return _run_cleanup(lambda *_: None)


def start_setup() -> bool:
    steps = [dict(s) for s in DEMO_STEPS]
    return job_service.start_job("setup", steps, _create_misconfigs_worker)


def start_cleanup() -> bool:
    steps = [dict(s) for s in CLEANUP_STEPS]
    return job_service.start_job("cleanup", steps, _cleanup_worker)


def start_verify() -> bool:
    steps = [dict(s) for s in VERIFY_STEPS]
    return job_service.start_job("verify", steps, _verify_worker)


def admin_configured() -> bool:
    try:
        _load_admin_env()
        return True
    except (FileNotFoundError, ValueError):
        return False
