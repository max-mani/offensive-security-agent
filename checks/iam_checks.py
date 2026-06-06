from datetime import datetime, timezone
from typing import List

from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from models.report import CheckError
from utils.retry import safe_aws_call


class IAMRootMFACheck(BaseCheck):
    """Root account must have MFA enabled."""

    def run(self) -> CheckResult:
        self._log("Checking root MFA status")
        client = self.session.client("iam")

        result = safe_aws_call(client.get_account_summary, self.check_id)
        if isinstance(result, CheckError):
            return result

        mfa_enabled = result["SummaryMap"].get("AccountMFAEnabled", 0)

        if mfa_enabled == 0:
            account_id = self._get_account_id()
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id="root",
                    resource_arn=f"arn:aws:iam::{account_id}:root",
                    resource_type="AWS::IAM::Root",
                    region="global",
                    raw_evidence={
                        "AccountMFAEnabled": mfa_enabled,
                        "api_call": "iam:GetAccountSummary",
                        "note": "AccountMFAEnabled=0 means root has no MFA device",
                    },
                    preliminary_severity="critical",
                )
            ]

        self._log("Root MFA is enabled - no finding")
        return []


class IAMRootAccessKeysCheck(BaseCheck):
    """Root account must not have active access keys."""

    def run(self) -> CheckResult:
        self._log("Checking root access keys")
        client = self.session.client("iam")

        result = safe_aws_call(client.get_account_summary, self.check_id)
        if isinstance(result, CheckError):
            return result

        keys_present = result["SummaryMap"].get("AccountAccessKeysPresent", 0)
        account_id = self._get_account_id()

        if keys_present > 0:
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id="root",
                    resource_arn=f"arn:aws:iam::{account_id}:root",
                    resource_type="AWS::IAM::Root",
                    region="global",
                    raw_evidence={
                        "AccountAccessKeysPresent": keys_present,
                        "api_call": "iam:GetAccountSummary",
                        "note": "Root account has active programmatic access keys",
                    },
                    preliminary_severity="critical",
                )
            ]
        return []


class IAMUserMFACheck(BaseCheck):
    """All IAM users with console access must have MFA."""

    def run(self) -> CheckResult:
        self._log("Checking IAM user MFA")
        iam = self.session.client("iam")
        findings: List[RawFinding] = []

        users_result = safe_aws_call(iam.list_users, self.check_id)
        if isinstance(users_result, CheckError):
            return users_result

        for user in users_result.get("Users", []):
            username = user["UserName"]
            user_arn = user["Arn"]

            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except iam.exceptions.NoSuchEntityException:
                has_console = False
            except Exception:
                continue

            if not has_console:
                continue

            mfa_result = safe_aws_call(
                lambda u=username: iam.list_mfa_devices(UserName=u),
                self.check_id,
            )
            if isinstance(mfa_result, CheckError):
                continue

            if len(mfa_result.get("MFADevices", [])) == 0:
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=username,
                        resource_arn=user_arn,
                        resource_type="AWS::IAM::User",
                        region="global",
                        raw_evidence={
                            "UserName": username,
                            "HasConsoleAccess": True,
                            "MFADevices": [],
                            "api_calls": [
                                "iam:ListUsers",
                                "iam:GetLoginProfile",
                                "iam:ListMFADevices",
                            ],
                        },
                        preliminary_severity="high",
                    )
                )

        self._log(f"Found {len(findings)} users without MFA")
        return findings


class IAMUnusedAccessKeysCheck(BaseCheck):
    """Access keys unused for 90+ days should be rotated."""

    def run(self) -> CheckResult:
        self._log("Checking for unused access keys")
        iam = self.session.client("iam")
        threshold_days = self.config.unused_days_threshold or 90
        findings: List[RawFinding] = []
        now = datetime.now(timezone.utc)

        users_result = safe_aws_call(iam.list_users, self.check_id)
        if isinstance(users_result, CheckError):
            return users_result

        for user in users_result.get("Users", []):
            username = user["UserName"]

            keys_result = safe_aws_call(
                lambda u=username: iam.list_access_keys(UserName=u),
                self.check_id,
            )
            if isinstance(keys_result, CheckError):
                continue

            for key in keys_result.get("AccessKeyMetadata", []):
                if key["Status"] != "Active":
                    continue

                key_id = key["AccessKeyId"]
                last_used_result = safe_aws_call(
                    lambda k=key_id: iam.get_access_key_last_used(AccessKeyId=k),
                    self.check_id,
                )
                if isinstance(last_used_result, CheckError):
                    continue

                last_used_info = last_used_result.get("AccessKeyLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")

                if last_used_date is None:
                    created = key["CreateDate"]
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    days_old = (now - created).days
                    never_used = True
                else:
                    if last_used_date.tzinfo is None:
                        last_used_date = last_used_date.replace(tzinfo=timezone.utc)
                    days_old = (now - last_used_date).days
                    never_used = False

                if days_old >= threshold_days:
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=key_id,
                            resource_arn=user["Arn"],
                            resource_type="AWS::IAM::AccessKey",
                            region="global",
                            raw_evidence={
                                "AccessKeyId": key_id,
                                "UserName": username,
                                "Status": "Active",
                                "LastUsedDate": str(last_used_date) if last_used_date else "Never",
                                "DaysUnused": days_old,
                                "NeverUsed": never_used,
                                "Threshold": threshold_days,
                            },
                            preliminary_severity="medium",
                        )
                    )
        return findings


class IAMPasswordPolicyCheck(BaseCheck):
    """Account password policy must meet minimum requirements."""

    def run(self) -> CheckResult:
        self._log("Checking account password policy")
        iam = self.session.client("iam")

        try:
            result = iam.get_account_password_policy()
            policy = result["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            account_id = self._get_account_id()
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id="password-policy",
                    resource_arn=f"arn:aws:iam::{account_id}:account-password-policy",
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    region="global",
                    raw_evidence={
                        "PolicyExists": False,
                        "api_call": "iam:GetAccountPasswordPolicy",
                        "note": "No custom password policy set - AWS defaults are weak",
                    },
                    preliminary_severity="medium",
                )
            ]

        issues = []
        if policy.get("MinimumPasswordLength", 0) < 12:
            issues.append(
                f"MinimumPasswordLength={policy.get('MinimumPasswordLength')} (required: 12+)"
            )
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Lowercase characters not required")
        if not policy.get("RequireNumbers", False):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols", False):
            issues.append("Symbols not required")
        max_age = policy.get("MaxPasswordAge")
        if max_age is None or max_age > 90:
            issues.append(f"MaxPasswordAge={max_age} (should be <=90)")

        if issues:
            account_id = self._get_account_id()
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id="password-policy",
                    resource_arn=f"arn:aws:iam::{account_id}:account-password-policy",
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    region="global",
                    raw_evidence={"PasswordPolicy": policy, "issues_detected": issues},
                    preliminary_severity="medium",
                )
            ]
        return []
