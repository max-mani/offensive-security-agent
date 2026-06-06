import json
import logging
from typing import Callable, Dict, List

from openai import OpenAI

from models.config import ScanConfig
from models.finding import RawFinding, ValidatedFinding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

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

SYSTEM_PROMPT = """You are a security intelligence engine for an AI-powered AWS security agent.

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
        logger.info("[intelligence] Using %s model: %s", provider, model)

    def _get_severity_cap(self, check_id: str, config: ScanConfig) -> str:
        for check in config.checks:
            if check.id == check_id:
                return check.severity_cap
        return "critical"

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

    def enrich_single(self, raw: RawFinding, config: ScanConfig) -> ValidatedFinding:
        user_message = f"""Raw security finding to enrich:

check_id: {raw.check_id}
resource_arn: {raw.resource_arn}
resource_type: {raw.resource_type}
preliminary_severity: {raw.preliminary_severity}
raw_evidence: {json.dumps(raw.raw_evidence, indent=2, default=str)}

Enrich this finding. Be specific about the business impact and provide a runnable CLI remediation command."""

        logger.info("[intelligence] Enriching: %s / %s", raw.check_id, raw.resource_id)

        try:
            request_kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
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
            severity_cap = self._get_severity_cap(raw.check_id, config)
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
            )

        except Exception as e:
            logger.error("[intelligence] LLM enrichment failed for %s: %s", raw.check_id, e)
            return ValidatedFinding(
                check_id=raw.check_id,
                title=f"{raw.check_id} - {raw.resource_id}",
                resource_id=raw.resource_id,
                resource_arn=raw.resource_arn,
                resource_type=raw.resource_type,
                region=raw.region,
                severity=raw.preliminary_severity,
                severity_reasoning="LLM enrichment failed - using checker preliminary severity",
                raw_evidence=raw.raw_evidence,
                business_impact="Unable to determine - LLM enrichment failed",
                remediation_steps=["Review AWS documentation for this resource type"],
                remediation_command="# LLM enrichment failed - manual review required",
                confidence_score=50,
            )

    def enrich_batch(self, raw_findings: List[RawFinding], config: ScanConfig) -> List[ValidatedFinding]:
        validated = []
        for raw in raw_findings:
            validated.append(self.enrich_single(raw, config))
        return validated
