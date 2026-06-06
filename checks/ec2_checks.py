from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from models.report import CheckError
from utils.retry import safe_aws_call


class SGOpenSSHCheck(BaseCheck):
    """Security groups must not allow SSH (port 22) from 0.0.0.0/0 or ::/0."""

    def run(self) -> CheckResult:
        self._log("Checking security groups for open SSH")
        ec2 = self.session.client("ec2")
        findings = []

        sgs_result = safe_aws_call(ec2.describe_security_groups, self.check_id)
        if isinstance(sgs_result, CheckError):
            return sgs_result

        for sg in sgs_result.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                protocol = rule.get("IpProtocol", "")

                if (from_port <= 22 <= to_port) and protocol in ["tcp", "-1"]:
                    open_cidrs = [
                        r["CidrIp"]
                        for r in rule.get("IpRanges", [])
                        if r.get("CidrIp") == "0.0.0.0/0"
                    ]
                    open_ipv6 = [
                        r["CidrIpv6"]
                        for r in rule.get("Ipv6Ranges", [])
                        if r.get("CidrIpv6") == "::/0"
                    ]

                    if open_cidrs or open_ipv6:
                        account_id = self._get_account_id()
                        region = self.session.region_name or "ap-south-1"
                        findings.append(
                            RawFinding(
                                check_id=self.check_id,
                                resource_id=sg["GroupId"],
                                resource_arn=(
                                    f"arn:aws:ec2:{region}:{account_id}:"
                                    f"security-group/{sg['GroupId']}"
                                ),
                                resource_type="AWS::EC2::SecurityGroup",
                                region=region,
                                raw_evidence={
                                    "GroupId": sg["GroupId"],
                                    "GroupName": sg.get("GroupName"),
                                    "VpcId": sg.get("VpcId"),
                                    "OpenCIDRs": open_cidrs + open_ipv6,
                                    "MatchedRule": {
                                        "IpProtocol": protocol,
                                        "FromPort": from_port,
                                        "ToPort": to_port,
                                    },
                                    "api_call": "ec2:DescribeSecurityGroups",
                                },
                                preliminary_severity="critical",
                            )
                        )
        return findings


class SGOpenRDPCheck(BaseCheck):
    """Security groups must not allow RDP (port 3389) from 0.0.0.0/0."""

    def run(self) -> CheckResult:
        self._log("Checking security groups for open RDP")
        ec2 = self.session.client("ec2")
        findings = []

        sgs_result = safe_aws_call(ec2.describe_security_groups, self.check_id)
        if isinstance(sgs_result, CheckError):
            return sgs_result

        for sg in sgs_result.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                protocol = rule.get("IpProtocol", "")

                if (from_port <= 3389 <= to_port) and protocol in ["tcp", "-1"]:
                    open_cidrs = [
                        r["CidrIp"]
                        for r in rule.get("IpRanges", [])
                        if r.get("CidrIp") == "0.0.0.0/0"
                    ]
                    if open_cidrs:
                        account_id = self._get_account_id()
                        region = self.session.region_name or "ap-south-1"
                        findings.append(
                            RawFinding(
                                check_id=self.check_id,
                                resource_id=sg["GroupId"],
                                resource_arn=(
                                    f"arn:aws:ec2:{region}:{account_id}:"
                                    f"security-group/{sg['GroupId']}"
                                ),
                                resource_type="AWS::EC2::SecurityGroup",
                                region=region,
                                raw_evidence={
                                    "GroupId": sg["GroupId"],
                                    "GroupName": sg.get("GroupName"),
                                    "OpenCIDRs": open_cidrs,
                                    "Port": 3389,
                                    "Protocol": protocol,
                                    "api_call": "ec2:DescribeSecurityGroups",
                                },
                                preliminary_severity="critical",
                            )
                        )
        return findings


class EC2UnencryptedVolumesCheck(BaseCheck):
    """All attached EBS volumes must be encrypted."""

    def run(self) -> CheckResult:
        self._log("Checking for unencrypted EBS volumes")
        ec2 = self.session.client("ec2")
        findings = []

        volumes_result = safe_aws_call(
            lambda: ec2.describe_volumes(
                Filters=[{"Name": "encrypted", "Values": ["false"]}]
            ),
            self.check_id,
        )
        if isinstance(volumes_result, CheckError):
            return volumes_result

        for vol in volumes_result.get("Volumes", []):
            if vol.get("State") == "in-use":
                account_id = self._get_account_id()
                region = self.session.region_name or "ap-south-1"
                attachments = vol.get("Attachments", [])
                instance_id = attachments[0].get("InstanceId") if attachments else "unknown"

                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=vol["VolumeId"],
                        resource_arn=(
                            f"arn:aws:ec2:{region}:{account_id}:volume/{vol['VolumeId']}"
                        ),
                        resource_type="AWS::EC2::Volume",
                        region=region,
                        raw_evidence={
                            "VolumeId": vol["VolumeId"],
                            "Encrypted": False,
                            "State": vol["State"],
                            "AttachedToInstance": instance_id,
                            "VolumeType": vol.get("VolumeType"),
                            "SizeGB": vol.get("Size"),
                            "api_call": "ec2:DescribeVolumes",
                        },
                        preliminary_severity="high",
                    )
                )
        return findings
