from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from models.report import CheckError
from utils.retry import safe_aws_call


class CloudTrailNotLoggingCheck(BaseCheck):
    """CloudTrail must be enabled and actively logging."""

    def run(self) -> CheckResult:
        self._log("Checking CloudTrail logging status")
        ct = self.session.client("cloudtrail")
        account_id = self._get_account_id()
        region = self.session.region_name or "ap-south-1"

        trails_result = safe_aws_call(
            lambda: ct.describe_trails(includeShadowTrails=False),
            self.check_id,
        )
        if isinstance(trails_result, CheckError):
            return trails_result

        trails = trails_result.get("trailList", [])

        if not trails:
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id="cloudtrail",
                    resource_arn=f"arn:aws:cloudtrail:{region}:{account_id}:trail/*",
                    resource_type="AWS::CloudTrail::Trail",
                    region=region,
                    raw_evidence={
                        "TrailsFound": 0,
                        "IsLogging": False,
                        "api_call": "cloudtrail:DescribeTrails",
                        "note": "No CloudTrail trails configured in this region",
                    },
                    preliminary_severity="high",
                )
            ]

        findings = []
        for trail in trails:
            trail_arn = trail["TrailARN"]
            status_result = safe_aws_call(
                lambda t=trail_arn: ct.get_trail_status(Name=t),
                self.check_id,
            )
            if isinstance(status_result, CheckError):
                continue

            if not status_result.get("IsLogging", False):
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=trail["Name"],
                        resource_arn=trail_arn,
                        resource_type="AWS::CloudTrail::Trail",
                        region=region,
                        raw_evidence={
                            "TrailName": trail["Name"],
                            "TrailARN": trail_arn,
                            "IsLogging": False,
                            "IsMultiRegionTrail": trail.get("IsMultiRegionTrail"),
                            "api_calls": [
                                "cloudtrail:DescribeTrails",
                                "cloudtrail:GetTrailStatus",
                            ],
                        },
                        preliminary_severity="high",
                    )
                )
        return findings


class EBSPublicSnapshotCheck(BaseCheck):
    """EBS snapshots must not be publicly accessible."""

    def run(self) -> CheckResult:
        self._log("Checking for public EBS snapshots")
        ec2 = self.session.client("ec2")
        account_id = self._get_account_id()
        region = self.session.region_name or "ap-south-1"
        findings = []

        snaps_result = safe_aws_call(
            lambda: ec2.describe_snapshots(OwnerIds=["self"]),
            self.check_id,
        )
        if isinstance(snaps_result, CheckError):
            return snaps_result

        for snap in snaps_result.get("Snapshots", []):
            snap_id = snap["SnapshotId"]

            perms_result = safe_aws_call(
                lambda s=snap_id: ec2.describe_snapshot_attribute(
                    SnapshotId=s, Attribute="createVolumePermission"
                ),
                self.check_id,
            )
            if isinstance(perms_result, CheckError):
                continue

            is_public = any(
                p.get("Group") == "all"
                for p in perms_result.get("CreateVolumePermissions", [])
            )

            if is_public:
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=snap_id,
                        resource_arn=f"arn:aws:ec2:{region}:{account_id}:snapshot/{snap_id}",
                        resource_type="AWS::EC2::Snapshot",
                        region=region,
                        raw_evidence={
                            "SnapshotId": snap_id,
                            "Description": snap.get("Description"),
                            "VolumeSize": snap.get("VolumeSize"),
                            "CreateVolumePermissions": [{"Group": "all"}],
                            "api_calls": [
                                "ec2:DescribeSnapshots",
                                "ec2:DescribeSnapshotAttribute",
                            ],
                            "note": (
                                "Snapshot is publicly accessible - "
                                "anyone can create a volume from it"
                            ),
                        },
                        preliminary_severity="critical",
                    )
                )
        return findings
