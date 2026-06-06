from botocore.exceptions import ClientError

from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from models.report import CheckError
from utils.retry import safe_aws_call


class S3PublicACLCheck(BaseCheck):
    """S3 buckets must not grant public access via ACL."""

    PUBLIC_GROUPS = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ]

    def run(self) -> CheckResult:
        self._log("Checking S3 public ACLs")
        s3 = self.session.client("s3")
        findings = []

        buckets_result = safe_aws_call(s3.list_buckets, self.check_id)
        if isinstance(buckets_result, CheckError):
            return buckets_result

        for bucket in buckets_result.get("Buckets", []):
            name = bucket["Name"]

            acl_result = safe_aws_call(lambda b=name: s3.get_bucket_acl(Bucket=b), self.check_id)
            if isinstance(acl_result, CheckError):
                continue

            public_grants = [
                g
                for g in acl_result.get("Grants", [])
                if g.get("Grantee", {}).get("URI", "") in self.PUBLIC_GROUPS
            ]

            if public_grants:
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=name,
                        resource_arn=f"arn:aws:s3:::{name}",
                        resource_type="AWS::S3::Bucket",
                        region="global",
                        raw_evidence={
                            "BucketName": name,
                            "PublicGrants": public_grants,
                            "api_call": "s3:GetBucketAcl",
                            "note": "Bucket grants read/write access to public internet groups",
                        },
                        preliminary_severity="critical",
                    )
                )
        return findings


class S3PublicPolicyCheck(BaseCheck):
    """S3 bucket policies must not make bucket public."""

    def run(self) -> CheckResult:
        self._log("Checking S3 bucket policy public status")
        s3 = self.session.client("s3")
        findings = []

        buckets_result = safe_aws_call(s3.list_buckets, self.check_id)
        if isinstance(buckets_result, CheckError):
            return buckets_result

        for bucket in buckets_result.get("Buckets", []):
            name = bucket["Name"]
            try:
                status = s3.get_bucket_policy_status(Bucket=name)
                if status["PolicyStatus"].get("IsPublic", False):
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            region="global",
                            raw_evidence={
                                "BucketName": name,
                                "PolicyStatus": {"IsPublic": True},
                                "api_call": "s3:GetBucketPolicyStatus",
                            },
                            preliminary_severity="critical",
                        )
                    )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    continue
            except Exception:
                continue
        return findings


class S3EncryptionCheck(BaseCheck):
    """All S3 buckets must have server-side encryption enabled."""

    def run(self) -> CheckResult:
        self._log("Checking S3 encryption")
        s3 = self.session.client("s3")
        findings = []

        buckets_result = safe_aws_call(s3.list_buckets, self.check_id)
        if isinstance(buckets_result, CheckError):
            return buckets_result

        for bucket in buckets_result.get("Buckets", []):
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                            resource_type="AWS::S3::Bucket",
                            region="global",
                            raw_evidence={
                                "BucketName": name,
                                "EncryptionConfigured": False,
                                "api_call": "s3:GetBucketEncryption",
                                "error": "ServerSideEncryptionConfigurationNotFoundError",
                            },
                            preliminary_severity="high",
                        )
                    )
            except Exception:
                continue
        return findings
