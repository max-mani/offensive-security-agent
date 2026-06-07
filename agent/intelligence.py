import json
import logging
from typing import Callable, Dict, List

from openai import OpenAI

from models.config import ScanConfig
from models.finding import RawFinding, ValidatedFinding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

# Non-AWS domains have structured evidence - template enrichment is accurate and saves LLM quota.
TEMPLATE_ONLY_DOMAINS = frozenset({"api_endpoints", "dependencies", "secrets"})

DETERMINISTIC_EVIDENCE: Dict[str, Callable[[dict], bool]] = {
    "iam_root_mfa": lambda e: e.get("AccountMFAEnabled") == 0,
    "iam_root_access_keys": lambda e: e.get("AccountAccessKeysPresent", 0) > 0,
    "s3_public_acl": lambda e: bool(e.get("PublicGrants")),
    "s3_public_policy": lambda e: bool(e.get("PolicyStatus", {}).get("IsPublic")),
    "sg_open_ssh": lambda e: bool(e.get("OpenCIDRs")),
    "sg_open_rdp": lambda e: bool(e.get("OpenCIDRs")),
    "ebs_public_snapshots": lambda e: any(
        p.get("Group") == "all" for p in e.get("CreateVolumePermissions", [])
    ),
}

SYSTEM_PROMPT_AWS = """You are a security intelligence engine for an AI-powered AWS security agent.

You receive a raw security finding from a boto3 API check. Your job is to enrich it with:
1. A validated severity level
2. A specific, accurate business impact statement
3. Exact remediation steps (numbered)
4. A single runnable AWS CLI command for immediate remediation
5. A confidence score (0-100)

SEVERITY RULES (strict - these prevent false positives):
- critical: ONLY if there is direct evidence of data exposure, unauthorized access, or complete security control failure
  Examples: S3 bucket publicly readable, SSH open to 0.0.0.0/0, root account with no MFA
- high: Significant risk that requires prompt action but no confirmed active exposure
  Examples: IAM user without MFA, CloudTrail disabled, unencrypted EBS volume
- medium: Configuration weakness with indirect risk or requires chaining with other issues
- low: Minor deviation from best practice with minimal real-world impact
- info: Informational, no direct risk

CRITICAL RULES:
1. Do NOT upgrade severity beyond what the raw_evidence supports
2. Do NOT invent details not present in raw_evidence
3. Only downgrade below preliminary_severity when raw_evidence is ambiguous. Do NOT downgrade root MFA disabled, public S3 ACLs, or open SSH/RDP rules — these have direct API proof
4. confidence_score reflects: how certain are you this is a real security issue?
   - 90-100: Direct API evidence, no ambiguity
   - 70-89: Strong evidence but some context missing
   - 50-69: Evidence present but could be acceptable in some configurations
   - <50: Uncertain - downgrade severity

Return ONLY valid JSON. No markdown, no explanation outside the JSON.

Schema:
{
  "title": "short descriptive title",
  "severity": "critical|high|medium|low|info",
  "severity_reasoning": "why this severity was chosen based on the evidence",
  "business_impact": "specific attack scenario - what can an adversary do with this?",
  "remediation_steps": ["Step 1...", "Step 2...", "Step 3..."],
  "remediation_command": "exact AWS CLI command",
  "confidence_score": 0-100
}"""

SYSTEM_PROMPT_MULTI_DOMAIN = """You are a security intelligence engine for a multi-domain security scanner.

You receive a raw finding from API scanning, dependency CVE analysis, or secrets detection.
Your job is to enrich it with validated severity, business impact, remediation steps, and confidence.

SEVERITY RULES (strict - prevent false positives on High/Critical):
- critical: Direct credential exposure, authenticated CORS bypass, or confirmed exploitable CVE (CVSS >= 9)
- high: Missing auth on protected endpoints, wildcard CORS, no rate limiting, hardcoded secrets, high CVSS CVEs
- medium: Missing security headers, medium CVEs, dangerous HTTP methods
- low: Minor header gaps, low-severity dependency issues
- info: Informational only

CRITICAL RULES:
1. Do NOT upgrade severity beyond what raw_evidence supports
2. Do NOT invent details not in raw_evidence
3. For secrets: only critical/high if pattern match is unambiguous (not example/placeholder text)
4. For CORS critical: require BOTH reflected origin AND Access-Control-Allow-Credentials: true
5. remediation_command must match domain:
   - dependencies: pip install package==fix_version or npm update
   - api_endpoints: curl/nginx/config example, not AWS CLI
   - secrets: rotation/revocation commands, not AWS CLI unless AWS key

Return ONLY valid JSON. No markdown.

Schema:
{
  "title": "short descriptive title",
  "severity": "critical|high|medium|low|info",
  "severity_reasoning": "why this severity based on evidence",
  "business_impact": "specific attack scenario",
  "remediation_steps": ["Step 1...", "Step 2..."],
  "remediation_command": "runnable fix command for this domain",
  "confidence_score": 0-100
}"""


class IntelligenceLayer:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: str | None = None,
        provider: str = "openai",
    ):
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)
        self.model = model
        self.provider = provider
        self._llm_disabled = False
        self._rate_limit_logged = False
        logger.info("[intelligence] Using %s model: %s", provider, model)

    def reset_batch_state(self) -> None:
        """Reset per-scan circuit breaker state."""
        self._llm_disabled = False
        self._rate_limit_logged = False

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "429" in msg or "rate limit" in msg or "rate_limit" in msg

    def _uses_template_enrichment(self, raw: RawFinding) -> bool:
        return raw.domain in TEMPLATE_ONLY_DOMAINS

    def _get_severity_cap(self, check_id: str, config: ScanConfig, raw: RawFinding) -> str:
        for check in config.checks:
            if check.id == check_id:
                return check.severity_cap
        return raw.preliminary_severity

    def _system_prompt_for(self, raw: RawFinding) -> str:
        if raw.domain == "aws_infrastructure":
            return SYSTEM_PROMPT_AWS
        return SYSTEM_PROMPT_MULTI_DOMAIN

    def _apply_severity_cap(self, severity: str, cap: str) -> str:
        if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(cap, 0):
            logger.warning("LLM severity %s exceeds cap %s - capping", severity, cap)
            return cap
        return severity

    def _downgrade_severity(self, severity: str) -> str:
        idx = SEVERITY_ORDER.get(severity, 99)
        if idx >= len(SEVERITY_LEVELS) - 1:
            return SEVERITY_LEVELS[-1]
        return SEVERITY_LEVELS[idx + 1]

    def _has_definitive_evidence(self, raw: RawFinding) -> bool:
        checker = DETERMINISTIC_EVIDENCE.get(raw.check_id)
        if checker is None:
            return False
        return checker(raw.raw_evidence)

    def _apply_evidence_floor(self, raw: RawFinding, severity: str) -> str:
        """Prevent LLM from downgrading findings with unambiguous boto3 evidence."""
        if not self._has_definitive_evidence(raw):
            return severity
        preliminary = raw.preliminary_severity
        if SEVERITY_ORDER.get(severity, 99) > SEVERITY_ORDER.get(preliminary, 99):
            logger.info(
                "[intelligence] Evidence floor: %s %s -> %s (deterministic API proof)",
                raw.check_id,
                severity,
                preliminary,
            )
            return preliminary
        return severity

    def _fallback_enrichment(self, raw: RawFinding, reason: str = "template") -> ValidatedFinding:
        """Deterministic enrichment when LLM is skipped or unavailable."""
        ev = raw.raw_evidence
        title = f"{raw.check_id} - {raw.resource_id}"
        steps = ["Review and remediate based on raw evidence"]
        command = "# Manual review required"
        impact = "Security weakness detected - see raw evidence for details."
        confidence = 85 if raw.domain in TEMPLATE_ONLY_DOMAINS else 75
        severity = raw.preliminary_severity
        reasoning = f"Template enrichment ({reason})"

        if raw.check_id == "dependency_cve":
            pkg = ev.get("package_name", "package")
            ver = ev.get("installed_version", "?")
            fixes = ev.get("fix_versions") or []
            fix = fixes[0] if fixes else "latest"
            cves = ", ".join(ev.get("cve_ids") or []) or ev.get("osv_id", "unknown")
            title = f"CVE in {pkg}=={ver}"
            impact = f"Vulnerable dependency {pkg}=={ver} ({cves}) may allow exploitation."
            steps = [
                f"Review advisory for {pkg} {ver}",
                f"Upgrade to fixed version {fix} or later",
                "Re-run scan to confirm remediation",
            ]
            command = f"pip install {pkg}=={fix}"
        elif raw.check_id == "secrets_scan":
            title = f"Hardcoded {ev.get('secret_type', 'secret')} in source"
            impact = f"Exposed {ev.get('secret_type', 'credential')} enables unauthorized access if leaked."
            steps = [
                "Rotate or revoke the exposed credential immediately",
                "Remove secret from source control history",
                "Use environment variables or a secrets manager",
            ]
            command = "# Rotate credential via provider console - value redacted in report"
        elif raw.check_id == "api_security_headers":
            header = ev.get("missing_header", "security header")
            url = ev.get("target_url", raw.resource_id)
            title = f"Missing {header} on API endpoint"
            impact = f"Missing {header} weakens browser-side protections for {url}."
            steps = [
                f"Configure {header} on the web server or API gateway",
                "Verify header is present in production responses",
            ]
            command = f"# Add {header} header to responses from {url}"
        elif raw.check_id == "api_cors_misconfiguration":
            title = "CORS misconfiguration allows cross-origin access"
            impact = "Misconfigured CORS may let malicious sites read API responses or act on behalf of users."
            steps = [
                "Restrict Access-Control-Allow-Origin to trusted domains",
                "Avoid reflecting arbitrary Origin with credentials enabled",
            ]
            command = "# Fix CORS policy on API gateway or application server"
        elif raw.check_id == "api_rate_limiting":
            title = "No API rate limiting detected"
            impact = "Missing rate limits enable brute-force, scraping, and application-layer DoS."
            steps = [
                "Add rate limiting at API gateway or application layer",
                "Return HTTP 429 when limits are exceeded",
            ]
            command = "# Enable rate limiting on the API endpoint"
        elif raw.check_id == "api_auth_bypass":
            path = ev.get("path_tested", raw.resource_id)
            title = f"Protected path accessible without auth: {path}"
            impact = f"Endpoint {path} returned HTTP 200 without credentials."
            steps = ["Require authentication on sensitive routes", "Return 401/403 for unauthenticated access"]
            command = f"# Add auth middleware for {path}"
        elif raw.check_id == "api_error_disclosure":
            title = "Error message information disclosure"
            impact = ev.get("description", "Internal error details exposed in API response.")
            steps = ["Disable verbose errors in production", "Use generic error messages for clients"]
            command = "# Set DEBUG=false and configure custom error handlers"
        elif raw.check_id == "api_dangerous_methods":
            title = "Dangerous HTTP method enabled (TRACE/TRACK)"
            impact = "Dangerous methods can enable cross-site tracing or unexpected request handling."
            steps = ["Disable TRACE/TRACK on web server", "Restrict Allow header to required methods only"]
            command = "# Disable TRACE/TRACK in server configuration"
        elif raw.domain == "api_endpoints":
            title = f"API issue: {raw.check_id}"
            impact = f"API security weakness detected by {raw.check_id}."
            steps = ["Review API response evidence", "Apply security hardening"]
            command = f"# Fix {raw.check_id} on {ev.get('target_url', 'endpoint')}"
        elif raw.check_id == "iam_root_mfa":
            title = "Root account MFA disabled"
            impact = "Root without MFA allows full account takeover if credentials are compromised."
            steps = ["Enable MFA on the root account", "Avoid using root for daily operations"]
            command = "# Enable MFA via AWS Console: IAM > Security credentials > MFA"
            severity = "critical"
            confidence = 95
        elif raw.check_id == "iam_user_mfa":
            user = ev.get("UserName", raw.resource_id)
            title = f"IAM user without MFA: {user}"
            impact = f"Console user {user} can be compromised via password-only access."
            steps = [f"Require MFA for IAM user {user}", "Enforce MFA via IAM policy"]
            command = f"aws iam enable-mfa-device --user-name {user} --serial-number ARN --authentication-code1 CODE1 --authentication-code2 CODE2"
        elif raw.check_id == "iam_password_policy":
            title = "Weak or missing IAM password policy"
            impact = "Weak passwords increase risk of credential compromise."
            steps = ["Define a strong account password policy", "Require minimum length, complexity, and rotation"]
            command = "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"
        elif raw.check_id == "s3_public_acl":
            bucket = ev.get("BucketName", raw.resource_id)
            title = f"S3 bucket public via ACL: {bucket}"
            impact = f"Bucket {bucket} grants public access - data may be readable by anyone."
            steps = [f"Remove public ACL grants from {bucket}", "Enable Block Public Access"]
            command = f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            severity = "critical"
            confidence = 95
        elif raw.check_id == "s3_public_policy":
            bucket = ev.get("BucketName", raw.resource_id)
            title = f"S3 bucket public via policy: {bucket}"
            impact = f"Bucket policy on {bucket} allows public access."
            steps = [f"Remove public statements from bucket policy on {bucket}", "Review Block Public Access settings"]
            command = f"aws s3api delete-bucket-policy --bucket {bucket}"
            severity = "critical"
            confidence = 95
        elif raw.check_id == "sg_open_ssh":
            sg = ev.get("GroupId", raw.resource_id)
            title = f"Security group allows SSH from internet: {sg}"
            impact = "SSH open to 0.0.0.0/0 exposes instances to brute-force and unauthorized access."
            steps = [f"Remove 0.0.0.0/0 rule on port 22 for {sg}", "Restrict SSH to known IP ranges or use SSM"]
            command = f"aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 22 --cidr 0.0.0.0/0"
            severity = "critical"
            confidence = 95
        elif raw.check_id == "sg_open_rdp":
            sg = ev.get("GroupId", raw.resource_id)
            title = f"Security group allows RDP from internet: {sg}"
            impact = "RDP open to 0.0.0.0/0 exposes Windows hosts to remote attacks."
            steps = [f"Remove 0.0.0.0/0 rule on port 3389 for {sg}", "Use VPN or bastion for remote desktop access"]
            command = f"aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 3389 --cidr 0.0.0.0/0"
            severity = "critical"
            confidence = 95
        elif raw.check_id == "cloudtrail_not_logging":
            title = "CloudTrail not logging"
            impact = "Without CloudTrail, API activity is not audited - attacks may go undetected."
            steps = ["Enable a multi-region CloudTrail trail", "Send logs to a secure S3 bucket"]
            command = "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name YOUR_TRAIL_BUCKET --is-multi-region-trail"

        severity = self._apply_evidence_floor(raw, severity)

        return ValidatedFinding(
            check_id=raw.check_id,
            title=title,
            resource_id=raw.resource_id,
            resource_arn=raw.resource_arn,
            resource_type=raw.resource_type,
            region=raw.region,
            severity=severity,
            severity_reasoning=reasoning,
            raw_evidence=raw.raw_evidence,
            business_impact=impact,
            remediation_steps=steps,
            remediation_command=command,
            confidence_score=confidence,
            domain=raw.domain,
        )

    def enrich_single(self, raw: RawFinding, config: ScanConfig) -> ValidatedFinding:
        if self._uses_template_enrichment(raw):
            return self._fallback_enrichment(raw, reason="structured domain")

        if self._llm_disabled:
            return self._fallback_enrichment(raw, reason="LLM rate limit")

        user_message = f"""Raw security finding to enrich:

check_id: {raw.check_id}
domain: {raw.domain}
resource_arn: {raw.resource_arn}
resource_type: {raw.resource_type}
preliminary_severity: {raw.preliminary_severity}
raw_evidence: {json.dumps(raw.raw_evidence, indent=2, default=str)}

Enrich this finding. Be specific about the business impact and provide a runnable remediation command."""

        logger.info("[intelligence] Enriching: %s / %s (%s)", raw.check_id, raw.resource_id, raw.domain)

        try:
            request_kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self._system_prompt_for(raw)},
                    {"role": "user", "content": user_message},
                ],
                "max_tokens": 600,
                "temperature": 0.1,
            }
            if self.provider == "openai":
                request_kwargs["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**request_kwargs)

            content = response.choices[0].message.content.strip()
            if content.startswith("```"):
                content = content.split("```", 2)[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            data = json.loads(content)
            severity_cap = self._get_severity_cap(raw.check_id, config, raw)
            final_severity = self._apply_severity_cap(data["severity"], severity_cap)

            confidence = int(data.get("confidence_score", 50))
            if confidence < 70:
                downgraded = self._downgrade_severity(final_severity)
                if downgraded != final_severity:
                    logger.info(
                        "[intelligence] Confidence %d < 70 - downgrading %s -> %s",
                        confidence,
                        final_severity,
                        downgraded,
                    )
                    final_severity = downgraded

            final_severity = self._apply_evidence_floor(raw, final_severity)

            logger.info(
                "[intelligence] %s: %s -> %s (confidence: %s)",
                raw.check_id,
                raw.preliminary_severity,
                final_severity,
                confidence,
            )

            return ValidatedFinding(
                check_id=raw.check_id,
                title=data["title"],
                resource_id=raw.resource_id,
                resource_arn=raw.resource_arn,
                resource_type=raw.resource_type,
                region=raw.region,
                severity=final_severity,
                severity_reasoning=data["severity_reasoning"],
                raw_evidence=raw.raw_evidence,
                business_impact=data["business_impact"],
                remediation_steps=data["remediation_steps"],
                remediation_command=data["remediation_command"],
                confidence_score=confidence,
                domain=raw.domain,
            )

        except Exception as e:
            if self._is_rate_limit_error(e):
                if not self._rate_limit_logged:
                    logger.warning(
                        "[intelligence] Groq/LLM daily rate limit reached - "
                        "using template enrichment for remaining findings this scan"
                    )
                    self._rate_limit_logged = True
                self._llm_disabled = True
                return self._fallback_enrichment(raw, reason="LLM rate limit")
            logger.error("[intelligence] LLM enrichment failed for %s: %s", raw.check_id, e)
            return self._fallback_enrichment(raw, reason="LLM error")

    def enrich_batch(self, raw_findings: List[RawFinding], config: ScanConfig) -> List[ValidatedFinding]:
        self.reset_batch_state()
        template_count = sum(1 for r in raw_findings if self._uses_template_enrichment(r))
        llm_count = len(raw_findings) - template_count
        if template_count:
            logger.info(
                "[intelligence] Enriching %d findings (%d template, %d LLM)",
                len(raw_findings),
                template_count,
                llm_count,
            )
        validated = []
        for raw in raw_findings:
            validated.append(self.enrich_single(raw, config))
        if self._llm_disabled:
            logger.info("[intelligence] Completed with template fallback after rate limit")
        return validated
