# Agent 2: Offensive Security Agent — Level 1
## Technical Build Plan for Aivar Innovations Hiring Challenge

**Author:** Manikandan M  
**Deadline:** Monday, 08 June 2026, 11:00 AM  
**Status:** Level 1 **COMPLETE** (verified) · Level 2 & 3 not started  
**Repository:** https://github.com/max-mani/offensive-security-agent  
**Verified:** 7 June 2026 — 8/8 demo findings, all acceptance criteria pass

---

## 0. Implementation Status (Current — June 2026)

This section reflects what was **actually built and verified**, which may differ slightly from the original plan below.

| Area | Planned | Implemented |
|------|---------|-------------|
| Checks | 13 boto3 checks | ✅ 13 checks in `CHECK_REGISTRY` |
| LLM | OpenAI `gpt-4o-mini` | ✅ Groq `llama-3.3-70b-versatile` (primary); Grok/OpenAI fallback via `utils/llm_client.py` |
| Entry point | `main.py` only | ✅ `main.py` + `agent/runner.py` |
| Dashboard | Not in original plan | ✅ Interactive UI: create/verify/cleanup misconfigs, **Run Full Demo**, step-by-step scan |
| Severity guard | severity_cap + confidence downgrade | ✅ + **evidence floor** (`DETERMINISTIC_EVIDENCE` in `intelligence.py`) |
| Test setup | `setup_test_misconfigs.ps1` | ✅ Idempotent PS1/SH + `verify_test_misconfigs.ps1` + Console guide in README |
| Acceptance | 7 criteria | ✅ All pass via `scripts/verify_acceptance.py` (+ criterion 6b: root MFA stays critical) |
| Demo misconfigs | 5 script + 3 natural = ~8 findings | ✅ **8/8 verified** via `run_full_test_and_cleanup.py` and dashboard (5 Critical, 2 High, 1 Medium) |
| AWS account | ap-south-1 | ✅ Account `563999587682`, region `ap-south-1` |

### 0.1 Verified Demo Results (7 June 2026)

```
Setup:   5/5 misconfigs created (admin via boto3)
Verify:  5/5 PASS (scanner read-only)
Scan:    13/13 checks healthy, 8 findings
         Critical: 5 | High: 2 | Medium: 1
Cleanup: All aivar-test-* resources removed
```

| # | Check ID | Severity | Source |
|---|----------|----------|--------|
| 1 | `s3_public_acl` | Critical | Intentional — public-read ACL bucket |
| 2 | `s3_public_policy` | Critical | Intentional — public read bucket policy |
| 3 | `sg_open_ssh` | Critical | Intentional — port 22 / 0.0.0.0/0 |
| 4 | `sg_open_rdp` | Critical | Intentional — port 3389 / 0.0.0.0/0 |
| 5 | `iam_root_mfa` | Critical | Natural — root MFA disabled |
| 6 | `iam_user_mfa` | High | Intentional — `test-no-mfa-user` |
| 7 | `cloudtrail_not_logging` | High | Natural — no active trail |
| 8 | `iam_password_policy` | Medium | Natural — weak/no policy |

**Demo misconfig change (vs original plan):** The 2nd intentional resource was planned as an unencrypted S3 bucket (`s3_encryption_disabled`). Account-level S3 default encryption on newer AWS accounts prevents creating buckets without encryption. The demo now creates a **public bucket policy** (`s3_public_policy`) instead. The `s3_encryption_disabled` check still runs as part of the 13-check scan.

### Files Added Beyond Original Plan

```
dashboard/                         # Web UI (FastAPI + static frontend)
  misconfig_service.py             # boto3 create/verify/cleanup (no CLI from UI)
  demo_service.py                  # Full demo orchestration
  scan_service.py                  # Step-by-step scan progress
agent/runner.py                    # Shared scan entry for CLI + dashboard
utils/llm_client.py                # Groq / Grok / OpenAI provider resolution
scripts/run_setup_as_admin.ps1
scripts/verify_test_misconfigs.ps1
scripts/verify_acceptance.py
scripts/run_full_test_and_cleanup.py
.env.admin.example                 # Admin creds template (copy → .env.admin)
docs/screenshots/                  # Demo screenshot placeholders (see README Section 8)
```

### Key Code Changes

**Evidence floor** — `agent/intelligence.py` applies `_apply_evidence_floor()` after LLM enrichment so findings with deterministic boto3 proof (e.g. `AccountMFAEnabled=0`, `OpenCIDRs`, `PublicGrants`) cannot be downgraded below `preliminary_severity`.

**Public-policy demo bucket** — `dashboard/misconfig_service.py` and setup scripts create `aivar-test-policy-{timestamp}` with a public `s3:GetObject` policy (Block Public Access disabled on bucket only) instead of `aivar-test-noenc-*`.

---

## Table of Contents

0. [Implementation Status](#0-implementation-status-current--june-2026)
1. [Architecture Overview](#1-architecture-overview)
2. [Project Structure](#2-project-structure)
3. [AWS Test Environment Setup](#3-aws-test-environment-setup)
4. [Component Deep Dives](#4-component-deep-dives)
   - 4.1 checklist.yaml — Config Schema
   - 4.2 models/ — Pydantic Data Models
   - 4.3 checks/ — 13 Boto3 Check Implementations
   - 4.4 agent/ — Orchestrator + LLM Intelligence Layer
   - 4.5 reporter/ — JSON + Markdown Output
   - 4.6 utils/ — AWS Client + Retry Logic
5. [The LLM Intelligence Layer — Design Details](#5-the-llm-intelligence-layer)
6. [Error Handling Strategy](#6-error-handling-strategy)
7. [Output Schemas](#7-output-schemas)
8. [Implementation Order](#8-implementation-order-step-by-step)
9. [Acceptance Criteria Checklist](#9-acceptance-criteria-checklist)
10. [Demo + Submission Guide](#10-demo--submission-guide)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      ENTRY POINT                            │
│                       main.py                               │
│           python main.py --config checklist.yaml            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   CONFIG LAYER                              │
│                 config/loader.py                            │
│  - Reads checklist.yaml                                     │
│  - Validates schema (Pydantic)                              │
│  - Returns: ScanConfig object with enabled checks           │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│               AGENT ORCHESTRATOR                            │
│              agent/orchestrator.py                          │
│  - Resolves check classes from config                       │
│  - Runs checks in parallel (ThreadPoolExecutor)             │
│  - Collects RawFindings + CheckErrors                       │
│  - Passes RawFindings → Intelligence Layer                  │
└──────┬─────────────────────────────────────────┬────────────┘
       │ parallel execution                       │
       ▼                                          ▼
┌─────────────────┐                    ┌──────────────────────┐
│  CHECK LAYER    │                    │   SCAN HEALTH LOG    │
│  checks/        │                    │                      │
│                 │                    │  CheckError objects  │
│ iam_checks.py   │                    │  - access_denied     │
│ s3_checks.py    │                    │  - throttled         │
│ ec2_checks.py   │                    │  - timeout           │
│ ct_checks.py    │                    │  - unknown           │
│                 │                    │                      │
│  boto3 calls    │                    │  Never silently      │
│  → RawFinding   │                    │  skipped             │
└────────┬────────┘                    └──────────────────────┘
         │ raw findings
         ▼
┌─────────────────────────────────────────────────────────────┐
│              LLM INTELLIGENCE LAYER                         │
│              agent/intelligence.py                          │
│                                                             │
│  INPUT:  RawFinding (resource_arn + boto3 evidence)         │
│  OUTPUT: ValidatedFinding (enriched + severity verified)    │
│                                                             │
│  What it does:                                              │
│  1. Validates severity — no hallucinated Critical ratings   │
│  2. Writes specific business_impact                         │
│  3. Generates exact remediation_command (runnable CLI)      │
│  4. Assigns confidence_score (0–100)                        │
│  5. Self-validates: "does evidence support this severity?"  │
│                                                             │
│  Model: Groq llama-3.3-70b-versatile (or gpt-4o-mini)     │
│  Temperature: 0.1 (low hallucination)                       │
│  + evidence floor for deterministic API proof               │
└───────────────────────┬─────────────────────────────────────┘
                        │ validated findings
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                  REPORT GENERATOR                           │
│                   reporter/                                 │
│                                                             │
│  json_reporter.py   → findings_report_{timestamp}.json      │
│  markdown_reporter.py → findings_report_{timestamp}.md      │
│                                                             │
│  Both include:                                              │
│  - Scan metadata (account, region, duration)                │
│  - Findings sorted by severity (critical first)             │
│  - Scan health section (errors + skipped checks)            │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Why |
|---|---|---|
| Parallelism | `ThreadPoolExecutor` | boto3 is I/O bound, not CPU bound. Threads are sufficient and simpler than async. |
| LLM role | Enrichment only, not detection | boto3 detects findings (facts). LLM enriches (intelligence). This prevents hallucinated findings. |
| Severity validation | LLM re-validates before finalizing | Prevents false positives on Critical — the #1 acceptance criterion |
| Error handling | Per-check try/catch, never global | One failing check must not kill the entire scan |
| Config format | YAML | Human-readable, supports comments, easy to extend |

---

## 2. Project Structure

```
offensive-security-agent/
│
├── main.py                    ← CLI entry point
├── checklist.yaml             ← Scan configuration (13 checks)
├── requirements.txt
├── .env.example               ← GROQ_API_KEY / AWS credentials (never commit .env)
├── README.md                  ← Company-facing submission document
├── agent2_level1_plan.md      ← Technical build plan (this file)
│
├── config/loader.py           ← Reads + validates checklist.yaml into ScanConfig
├── models/                    ← ScanConfig, RawFinding, ValidatedFinding, ScanReport
├── checks/                    ← 13 boto3 checks (IAM×5, S3×3, EC2×3, CT×2)
├── agent/
│   ├── orchestrator.py        ← Parallel execution, result collection
│   ├── intelligence.py        ← LLM enrichment + severity cap + evidence floor
│   └── runner.py              ← Shared scan entry (CLI + dashboard)
├── reporter/                  ← JSON + Markdown report generators
├── dashboard/                 ← FastAPI web UI (added post-plan)
├── utils/
│   ├── aws_client.py          ← Boto3 session factory
│   ├── llm_client.py          ← Groq / Grok / OpenAI resolver (added post-plan)
│   └── retry.py               ← safe_aws_call with exponential backoff
├── scripts/
│   ├── setup_test_misconfigs.ps1 / .sh
│   ├── run_setup_as_admin.ps1
│   ├── verify_test_misconfigs.ps1
│   ├── verify_acceptance.py
│   ├── run_full_test_and_cleanup.py
│   └── cleanup_test_misconfigs.ps1
├── docs/screenshots/          ← Demo screenshot placeholders
└── reports/                   ← Generated scan reports
```

---

## 3. AWS Test Environment Setup

> Do this FIRST before writing code. Takes 30 minutes.
> All on AWS Free Tier — cost is ₹0.

### 3.1 Two IAM Users — Scanner + Admin

| User | File | Policies | Used for |
|------|------|----------|----------|
| `aivar-scanner` | `.env` | S3/IAM/EC2/CloudTrail ReadOnly | All scans & dashboard |
| `aivar-admin` | `.env.admin` | `AdministratorAccess` | Setup/cleanup scripts only |

**How to get admin credentials:**

1. Sign in to [AWS Console](https://console.aws.amazon.com) as root
2. IAM → Users → Create user `aivar-admin`
3. Attach policy **`AdministratorAccess`**
4. Security credentials → Create access key (CLI) → copy keys
5. `copy .env.admin.example .env.admin` → paste admin keys
6. **Never** put admin keys in `.env`

**How to get scanner credentials:**

1. IAM → Users → Create user `aivar-scanner`
2. Attach: `AmazonS3ReadOnlyAccess`, `IAMReadOnlyAccess`, `AmazonEC2ReadOnlyAccess`, `AWSCloudTrailReadOnlyAccess`
3. Create access key → paste into `.env`

Region: `ap-south-1` (Mumbai) for both users.

### 3.2 Create Intentional Misconfigs (8-finding demo)

**5 intentional resources** + **3 natural account defaults** = **8 findings** (5 Critical, 2 High, 1 Medium).

| # | Resource created | Check ID | Severity |
|---|------------------|----------|----------|
| 1 | `aivar-test-public-{ts}` — public-read ACL | `s3_public_acl` | Critical |
| 2 | `aivar-test-policy-{ts}` — public read policy | `s3_public_policy` | Critical |
| 3 | `test-no-mfa-user` — console, no MFA | `iam_user_mfa` | High |
| 4 | `open-ssh-sg` — port 22 / 0.0.0.0/0 | `sg_open_ssh` | Critical |
| 5 | `open-rdp-sg` — port 3389 / 0.0.0.0/0 | `sg_open_rdp` | Critical |

Natural (already present): `iam_root_mfa`, `cloudtrail_not_logging`, `iam_password_policy`.

> **Why not unencrypted S3?** Account-level S3 default encryption applies AES256 to all new buckets — `s3_encryption_disabled` cannot be demo'd reliably. Use `s3_public_policy` instead (see README Section 7).

**Recommended — Dashboard (no terminal):**

```powershell
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
# Open http://127.0.0.1:8080 → click "Run Full Demo"
```

**Recommended — Terminal (Windows):**

```powershell
.\scripts\run_setup_as_admin.ps1       # uses .env.admin
.\scripts\verify_test_misconfigs.ps1   # uses .env scanner — expect 5/5 PASS
python main.py --config checklist.yaml --verbose   # expect 8 findings
.\scripts\cleanup_test_misconfigs.ps1   # when done
```

**End-to-end automated test:**

```powershell
python scripts\run_full_test_and_cleanup.py   # setup → verify → scan → cleanup
```

Or run CLI commands manually with admin creds:

```bash
# 1. S3 bucket with public ACL (CRITICAL — s3_public_acl)
aws s3api create-bucket --bucket aivar-test-public-$(date +%s) --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
aws s3api put-bucket-ownership-controls --bucket <bucket-name> \
  --ownership-controls Rules=[{ObjectOwnership=ObjectWriter}]
aws s3api put-bucket-acl --bucket <bucket-name> --acl public-read

# 2. S3 bucket with public read policy (CRITICAL — s3_public_policy)
# Replaces unencrypted bucket — account default encryption blocks s3_encryption_disabled demo
aws s3api create-bucket --bucket aivar-test-policy-$(date +%s) --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
aws s3api put-bucket-policy --bucket <bucket-name> --policy \
  '{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::<bucket-name>/*"}]}'

# 3. IAM user without MFA (HIGH — iam_user_mfa)
aws iam create-user --user-name test-no-mfa-user
aws iam create-login-profile --user-name test-no-mfa-user --password TestPass@123 --no-password-reset-required
# Do NOT attach MFA device — absence is the finding

# 4. IAM access key unused >90 days (MEDIUM finding)
aws iam create-access-key --user-name test-no-mfa-user
# Key creation date will be today — to simulate old key, note the key ID for manual verification

# 5. Security Group with port 22 open to world (CRITICAL finding)
aws ec2 create-security-group --group-name "open-ssh-sg" \
  --description "Test SG with open SSH" --region ap-south-1
aws ec2 authorize-security-group-ingress \
  --group-name "open-ssh-sg" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region ap-south-1

# 6. Security Group with port 3389 open to world (CRITICAL finding)
aws ec2 create-security-group --group-name "open-rdp-sg" \
  --description "Test SG with open RDP" --region ap-south-1
aws ec2 authorize-security-group-ingress \
  --group-name "open-rdp-sg" \
  --protocol tcp --port 3389 --cidr 0.0.0.0/0 --region ap-south-1

# 7. Check root MFA status (manual — check via console)
# Login as root → My Security Credentials → MFA is likely not set in a fresh account

# 8. Disable CloudTrail (if enabled — HIGH finding)
# Go to CloudTrail console → Trails → delete or disable
```

### 3.3 IAM Permissions for Scanner

Your scanner IAM user needs these READ-ONLY policies:
```
AmazonS3ReadOnlyAccess
IAMReadOnlyAccess
AmazonEC2ReadOnlyAccess
AWSCloudTrailReadOnlyAccess
```

---

## 4. Component Deep Dives

### 4.1 `checklist.yaml` — Config Schema

```yaml
# checklist.yaml
scan:
  name: "Aivar Infrastructure Security Audit"
  description: "Level 1 checklist-based AWS infrastructure scan"
  aws_region: "ap-south-1"
  timeout_seconds: 30
  max_workers: 5        # parallel threads
  llm_model: "gpt-4o-mini"
  output_dir: "reports"

checks:
  # ── IAM CHECKS ─────────────────────────────────────────────
  - id: iam_root_mfa
    enabled: true
    description: "Root account must have MFA enabled"
    severity_cap: critical   # LLM cannot exceed this severity
    tags: [iam, mfa, critical-baseline]

  - id: iam_root_access_keys
    enabled: true
    description: "Root account must not have active access keys"
    severity_cap: critical
    tags: [iam, credentials]

  - id: iam_user_mfa
    enabled: true
    description: "All IAM users with console access must have MFA"
    severity_cap: high
    tags: [iam, mfa]

  - id: iam_unused_access_keys
    enabled: true
    description: "Access keys unused for 90+ days must be rotated or deleted"
    severity_cap: medium
    unused_days_threshold: 90
    tags: [iam, credentials, rotation]

  - id: iam_password_policy
    enabled: true
    description: "Account password policy must meet minimum security standards"
    severity_cap: medium
    tags: [iam, policy]

  # ── S3 CHECKS ──────────────────────────────────────────────
  - id: s3_public_acl
    enabled: true
    description: "S3 buckets must not grant public access via ACL"
    severity_cap: critical
    tags: [s3, public-access, data-exposure]

  - id: s3_public_policy
    enabled: true
    description: "S3 bucket policies must not grant public access"
    severity_cap: critical
    tags: [s3, public-access, data-exposure]

  - id: s3_encryption_disabled
    enabled: true
    description: "S3 buckets must have server-side encryption enabled"
    severity_cap: high
    tags: [s3, encryption, compliance]

  # ── EC2 / EBS CHECKS ───────────────────────────────────────
  - id: sg_open_ssh
    enabled: true
    description: "Security groups must not allow SSH (port 22) from 0.0.0.0/0"
    severity_cap: critical
    tags: [ec2, network, ssh]

  - id: sg_open_rdp
    enabled: true
    description: "Security groups must not allow RDP (port 3389) from 0.0.0.0/0"
    severity_cap: critical
    tags: [ec2, network, rdp]

  - id: ec2_unencrypted_volumes
    enabled: true
    description: "All EC2 EBS volumes must be encrypted at rest"
    severity_cap: high
    tags: [ec2, ebs, encryption]

  # ── CLOUDTRAIL CHECKS ──────────────────────────────────────
  - id: cloudtrail_not_logging
    enabled: true
    description: "CloudTrail must be enabled and actively logging in all regions"
    severity_cap: high
    tags: [cloudtrail, logging, audit]

  - id: ebs_public_snapshots
    enabled: true
    description: "EBS snapshots must not be publicly accessible"
    severity_cap: critical
    tags: [ebs, snapshots, data-exposure]
```

---

### 4.2 `models/` — Pydantic Data Models

**`models/finding.py`**
```python
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime
import uuid

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

class RawFinding(BaseModel):
    """
    Output of a boto3 check BEFORE LLM enrichment.
    Contains only factual data from AWS APIs — no interpretation.
    """
    check_id: str
    resource_id: str
    resource_arn: str
    resource_type: str          # e.g. "AWS::S3::Bucket"
    region: str
    raw_evidence: Dict[str, Any]  # Exact boto3 API response fragment
    preliminary_severity: SeverityLevel  # Checker's initial severity (can be adjusted by LLM)
    check_timestamp: datetime = Field(default_factory=datetime.utcnow)

class ValidatedFinding(BaseModel):
    """
    Final finding after LLM enrichment and severity validation.
    This is what goes into the report.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    check_id: str
    title: str
    resource_id: str
    resource_arn: str
    resource_type: str
    region: str
    
    # Severity — validated by LLM, bounded by severity_cap in config
    severity: SeverityLevel
    severity_reasoning: str     # LLM explains why this severity was assigned
    
    # Evidence — raw boto3 data (no hallucinations)
    raw_evidence: Dict[str, Any]
    
    # LLM-generated enrichment
    business_impact: str        # What an attacker can specifically do with this
    remediation_steps: List[str]  # Numbered steps
    remediation_command: str    # Single runnable AWS CLI command
    
    # Confidence
    confidence_score: int = Field(ge=0, le=100)  # LLM's certainty this is a real issue
    
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
```

**`models/report.py`**
```python
from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional
from datetime import datetime
import uuid

class CheckError(BaseModel):
    """
    Represents a check that FAILED to execute (not a finding — a scanner error).
    These are ALWAYS surfaced in the report. Never silently skipped.
    """
    check_id: str
    error_type: Literal["access_denied", "throttled", "timeout", "api_error", "unknown"]
    error_message: str
    http_status: Optional[int] = None
    aws_error_code: Optional[str] = None   # e.g. "AccessDenied", "Throttling"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ScanReport(BaseModel):
    """Top-level scan report. Contains everything."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    
    aws_account_id: str
    aws_region: str
    
    # Stats
    total_checks_attempted: int
    total_checks_succeeded: int
    total_checks_errored: int
    total_findings: int
    findings_by_severity: Dict[str, int]  # {"critical": 2, "high": 3, ...}
    
    # Core data
    findings: List[ValidatedFinding]     # sorted: critical first
    scan_errors: List[CheckError]        # checks that failed to run
    
    # Health
    scan_health: Literal["healthy", "degraded", "partial", "failed"]
    # healthy = all checks ran
    # degraded = some errors but majority ran
    # partial = >30% checks errored
    # failed = no checks completed
```

**`models/config.py`**
```python
from pydantic import BaseModel
from typing import List, Literal, Optional

class CheckConfig(BaseModel):
    id: str
    enabled: bool = True
    description: str
    severity_cap: Literal["critical", "high", "medium", "low", "info"]
    tags: List[str] = []
    unused_days_threshold: Optional[int] = None   # for iam_unused_access_keys

class ScanMeta(BaseModel):
    name: str
    description: str = ""
    aws_region: str
    timeout_seconds: int = 30
    max_workers: int = 5
    llm_model: str = "gpt-4o-mini"
    output_dir: str = "reports"

class ScanConfig(BaseModel):
    scan: ScanMeta
    checks: List[CheckConfig]

    def get_enabled_checks(self) -> List[CheckConfig]:
        return [c for c in self.checks if c.enabled]
```

---

### 4.3 `checks/` — 12 Boto3 Check Implementations

**`checks/base.py`**
```python
from abc import ABC, abstractmethod
from typing import List, Union
from models.finding import RawFinding
from models.report import CheckError
from models.config import CheckConfig
import boto3, logging

logger = logging.getLogger(__name__)

CheckResult = Union[List[RawFinding], CheckError]

class BaseCheck(ABC):
    """
    All checks inherit from this.
    Each check is responsible for:
    1. Making boto3 call(s)
    2. Interpreting the response (is this a finding or not?)
    3. Returning RawFinding list OR CheckError
    
    The check must NEVER interpret severity — that's the LLM's job.
    The check sets preliminary_severity as a HINT only.
    """
    
    def __init__(self, config: CheckConfig, session: boto3.Session):
        self.config = config
        self.session = session
        self.check_id = config.id
    
    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check. Return findings or an error."""
        pass
    
    def _make_arn(self, service: str, resource: str, region: str = "", account: str = "") -> str:
        return f"arn:aws:{service}:{region}:{account}:{resource}"
    
    def _log(self, message: str):
        logger.info(f"[{self.check_id}] {message}")
```

**`checks/iam_checks.py`**
```python
import boto3, botocore
from datetime import datetime, timezone
from typing import List, Union
from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from models.report import CheckError
from utils.retry import safe_aws_call

class IAMRootMFACheck(BaseCheck):
    """
    Check: Root account must have MFA enabled.
    
    boto3 call: iam.get_account_summary()
    Key field: SummaryMap["AccountMFAEnabled"] — 0 means MFA disabled
    
    Why Critical: Root account with no MFA can be taken over with just a password.
    """
    
    def run(self) -> CheckResult:
        self._log("Checking root MFA status")
        client = self.session.client("iam")
        
        result = safe_aws_call(client.get_account_summary, self.check_id)
        if isinstance(result, CheckError):
            return result
        
        mfa_enabled = result["SummaryMap"].get("AccountMFAEnabled", 0)
        
        if mfa_enabled == 0:
            # Root MFA is NOT enabled — this is a finding
            account_id = self.session.client("sts").get_caller_identity()["Account"]
            return [RawFinding(
                check_id=self.check_id,
                resource_id="root",
                resource_arn=f"arn:aws:iam::{account_id}:root",
                resource_type="AWS::IAM::Root",
                region="global",
                raw_evidence={
                    "AccountMFAEnabled": mfa_enabled,
                    "api_call": "iam:GetAccountSummary",
                    "note": "AccountMFAEnabled=0 means root has no MFA device"
                },
                preliminary_severity="critical"
            )]
        
        self._log("Root MFA is enabled — no finding")
        return []


class IAMRootAccessKeysCheck(BaseCheck):
    """
    Check: Root account must not have active access keys.
    
    boto3 call: iam.get_account_summary()
    Key field: SummaryMap["AccountAccessKeysPresent"] — 1 means keys exist
    
    Why Critical: Root access keys give programmatic full-account access.
    AWS best practice: root should never have access keys.
    """
    
    def run(self) -> CheckResult:
        self._log("Checking root access keys")
        client = self.session.client("iam")
        
        result = safe_aws_call(client.get_account_summary, self.check_id)
        if isinstance(result, CheckError):
            return result
        
        keys_present = result["SummaryMap"].get("AccountAccessKeysPresent", 0)
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        
        if keys_present > 0:
            return [RawFinding(
                check_id=self.check_id,
                resource_id="root",
                resource_arn=f"arn:aws:iam::{account_id}:root",
                resource_type="AWS::IAM::Root",
                region="global",
                raw_evidence={
                    "AccountAccessKeysPresent": keys_present,
                    "api_call": "iam:GetAccountSummary",
                    "note": "Root account has active programmatic access keys"
                },
                preliminary_severity="critical"
            )]
        return []


class IAMUserMFACheck(BaseCheck):
    """
    Check: All IAM users with console access must have MFA.
    
    boto3 calls:
      iam.list_users() → get all users
      iam.list_mfa_devices(UserName=...) → check if MFA attached
      iam.get_login_profile(UserName=...) → check if user has console access
    
    Only flag users who CAN login to console (have LoginProfile) but have no MFA.
    """
    
    def run(self) -> CheckResult:
        self._log("Checking IAM user MFA")
        iam = self.session.client("iam")
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        findings = []
        
        users_result = safe_aws_call(iam.list_users, self.check_id)
        if isinstance(users_result, CheckError):
            return users_result
        
        for user in users_result.get("Users", []):
            username = user["UserName"]
            user_arn = user["Arn"]
            
            # Check if user has console access (LoginProfile)
            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except iam.exceptions.NoSuchEntityException:
                has_console = False
            except Exception:
                continue  # Can't determine — skip this user
            
            if not has_console:
                continue  # No console access, MFA not required
            
            # Check MFA devices
            mfa_result = safe_aws_call(
                lambda: iam.list_mfa_devices(UserName=username), 
                self.check_id
            )
            if isinstance(mfa_result, CheckError):
                continue
            
            if len(mfa_result.get("MFADevices", [])) == 0:
                findings.append(RawFinding(
                    check_id=self.check_id,
                    resource_id=username,
                    resource_arn=user_arn,
                    resource_type="AWS::IAM::User",
                    region="global",
                    raw_evidence={
                        "UserName": username,
                        "HasConsoleAccess": True,
                        "MFADevices": [],
                        "api_calls": ["iam:ListUsers", "iam:GetLoginProfile", "iam:ListMFADevices"]
                    },
                    preliminary_severity="high"
                ))
        
        self._log(f"Found {len(findings)} users without MFA")
        return findings


class IAMUnusedAccessKeysCheck(BaseCheck):
    """
    Check: Access keys unused for 90+ days should be rotated.
    
    boto3 calls:
      iam.list_users() → all users
      iam.list_access_keys(UserName=...) → get keys per user
      iam.get_access_key_last_used(AccessKeyId=...) → last used date
    
    Finding condition: key is Active AND last used > 90 days ago (or never used AND created > 90 days ago)
    """
    
    def run(self) -> CheckResult:
        self._log("Checking for unused access keys")
        iam = self.session.client("iam")
        threshold_days = self.config.unused_days_threshold or 90
        findings = []
        now = datetime.now(timezone.utc)
        
        users_result = safe_aws_call(iam.list_users, self.check_id)
        if isinstance(users_result, CheckError):
            return users_result
        
        for user in users_result.get("Users", []):
            username = user["UserName"]
            
            keys_result = safe_aws_call(
                lambda: iam.list_access_keys(UserName=username),
                self.check_id
            )
            if isinstance(keys_result, CheckError):
                continue
            
            for key in keys_result.get("AccessKeyMetadata", []):
                if key["Status"] != "Active":
                    continue
                
                key_id = key["AccessKeyId"]
                last_used_result = safe_aws_call(
                    lambda: iam.get_access_key_last_used(AccessKeyId=key_id),
                    self.check_id
                )
                if isinstance(last_used_result, CheckError):
                    continue
                
                last_used_info = last_used_result.get("AccessKeyLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")
                
                if last_used_date is None:
                    # Never used — use creation date
                    created = key["CreateDate"]
                    days_old = (now - created).days
                    never_used = True
                else:
                    days_old = (now - last_used_date).days
                    never_used = False
                
                if days_old >= threshold_days:
                    findings.append(RawFinding(
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
                            "Threshold": threshold_days
                        },
                        preliminary_severity="medium"
                    ))
        return findings


class IAMPasswordPolicyCheck(BaseCheck):
    """
    Check: Account password policy must meet minimum requirements.
    
    boto3 call: iam.get_account_password_policy()
    
    Minimum requirements checked:
    - MinimumPasswordLength >= 12
    - RequireUppercaseCharacters = True
    - RequireLowercaseCharacters = True
    - RequireNumbers = True
    - RequireSymbols = True
    - MaxPasswordAge <= 90 (days)
    - PasswordReusePrevention >= 5
    """
    
    def run(self) -> CheckResult:
        self._log("Checking account password policy")
        iam = self.session.client("iam")
        
        try:
            result = iam.get_account_password_policy()
            policy = result["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
            return [RawFinding(
                check_id=self.check_id,
                resource_id="password-policy",
                resource_arn=f"arn:aws:iam::{account_id}:account-password-policy",
                resource_type="AWS::IAM::AccountPasswordPolicy",
                region="global",
                raw_evidence={
                    "PolicyExists": False,
                    "api_call": "iam:GetAccountPasswordPolicy",
                    "note": "No custom password policy set — AWS defaults are weak"
                },
                preliminary_severity="medium"
            )]
        
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 12:
            issues.append(f"MinimumPasswordLength={policy.get('MinimumPasswordLength')} (required: 12+)")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireNumbers", False):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols", False):
            issues.append("Symbols not required")
        max_age = policy.get("MaxPasswordAge")
        if max_age is None or max_age > 90:
            issues.append(f"MaxPasswordAge={max_age} (should be <=90)")
        
        if issues:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
            return [RawFinding(
                check_id=self.check_id,
                resource_id="password-policy",
                resource_arn=f"arn:aws:iam::{account_id}:account-password-policy",
                resource_type="AWS::IAM::AccountPasswordPolicy",
                region="global",
                raw_evidence={"PasswordPolicy": policy, "issues_detected": issues},
                preliminary_severity="medium"
            )]
        return []
```

**`checks/s3_checks.py`**
```python
import boto3
from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from utils.retry import safe_aws_call

class S3PublicACLCheck(BaseCheck):
    """
    Check: S3 buckets must not grant public access via ACL.
    
    boto3 calls:
      s3.list_buckets() → all buckets
      s3.get_bucket_acl(Bucket=...) → grants for each bucket
    
    Finding condition: Any grant to AllUsers or AuthenticatedUsers group
    
    AllUsers URI:        http://acs.amazonaws.com/groups/global/AllUsers
    AuthenticatedUsers:  http://acs.amazonaws.com/groups/global/AuthenticatedUsers
    """
    PUBLIC_GROUPS = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
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
            
            acl_result = safe_aws_call(
                lambda: s3.get_bucket_acl(Bucket=name),
                self.check_id
            )
            if isinstance(acl_result, CheckError):
                continue  # Log but don't block other buckets
            
            public_grants = [
                g for g in acl_result.get("Grants", [])
                if g.get("Grantee", {}).get("URI", "") in self.PUBLIC_GROUPS
            ]
            
            if public_grants:
                findings.append(RawFinding(
                    check_id=self.check_id,
                    resource_id=name,
                    resource_arn=f"arn:aws:s3:::{name}",
                    resource_type="AWS::S3::Bucket",
                    region="global",
                    raw_evidence={
                        "BucketName": name,
                        "PublicGrants": public_grants,
                        "api_call": "s3:GetBucketAcl",
                        "note": "Bucket grants read/write access to public internet groups"
                    },
                    preliminary_severity="critical"
                ))
        return findings


class S3PublicPolicyCheck(BaseCheck):
    """
    Check: S3 bucket policies must not make bucket public.
    
    boto3 call: s3.get_bucket_policy_status(Bucket=...)
    Key field: PolicyStatus["IsPublic"] — True means public
    
    Note: Buckets without any policy will raise NoSuchBucketPolicy — handle gracefully.
    """
    
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
                    findings.append(RawFinding(
                        check_id=self.check_id,
                        resource_id=name,
                        resource_arn=f"arn:aws:s3:::{name}",
                        resource_type="AWS::S3::Bucket",
                        region="global",
                        raw_evidence={
                            "BucketName": name,
                            "PolicyStatus": {"IsPublic": True},
                            "api_call": "s3:GetBucketPolicyStatus"
                        },
                        preliminary_severity="critical"
                    ))
            except s3.exceptions.from_code("NoSuchBucketPolicy"):
                pass  # No policy = not publicly accessible via policy
            except Exception:
                pass
        return findings


class S3EncryptionCheck(BaseCheck):
    """
    Check: All S3 buckets must have server-side encryption enabled.
    
    boto3 call: s3.get_bucket_encryption(Bucket=...)
    Finding: ServerSideEncryptionConfiguration not present = no encryption
    """
    
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
                # If no exception, encryption is configured
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append(RawFinding(
                        check_id=self.check_id,
                        resource_id=name,
                        resource_arn=f"arn:aws:s3:::{name}",
                        resource_type="AWS::S3::Bucket",
                        region="global",
                        raw_evidence={
                            "BucketName": name,
                            "EncryptionConfigured": False,
                            "api_call": "s3:GetBucketEncryption",
                            "error": "ServerSideEncryptionConfigurationNotFoundError"
                        },
                        preliminary_severity="high"
                    ))
        return findings
```

**`checks/ec2_checks.py`**
```python
from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from utils.retry import safe_aws_call

class SGOpenSSHCheck(BaseCheck):
    """
    Check: No security group should allow SSH (port 22) from 0.0.0.0/0 or ::/0.
    
    boto3 call: ec2.describe_security_groups()
    Inspect: IpPermissions → IpRanges → CidrIp == "0.0.0.0/0" for FromPort 22
    
    Why Critical: Exposes SSH to entire internet. Enables brute-force and credential attacks.
    """
    
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
                
                # Port 22 is in range AND protocol is tcp or -1 (all)
                if (from_port <= 22 <= to_port) and protocol in ["tcp", "-1"]:
                    open_cidrs = [
                        r["CidrIp"] for r in rule.get("IpRanges", [])
                        if r.get("CidrIp") in ["0.0.0.0/0"]
                    ]
                    open_ipv6 = [
                        r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                        if r.get("CidrIpv6") == "::/0"
                    ]
                    
                    if open_cidrs or open_ipv6:
                        account_id = self.session.client("sts").get_caller_identity()["Account"]
                        region = self.session.region_name
                        findings.append(RawFinding(
                            check_id=self.check_id,
                            resource_id=sg["GroupId"],
                            resource_arn=f"arn:aws:ec2:{region}:{account_id}:security-group/{sg['GroupId']}",
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
                                    "ToPort": to_port
                                },
                                "api_call": "ec2:DescribeSecurityGroups"
                            },
                            preliminary_severity="critical"
                        ))
        return findings


class SGOpenRDPCheck(BaseCheck):
    """Same pattern as SGOpenSSHCheck but for port 3389 (RDP)."""
    
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
                    open_cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
                    if open_cidrs:
                        account_id = self.session.client("sts").get_caller_identity()["Account"]
                        region = self.session.region_name
                        findings.append(RawFinding(
                            check_id=self.check_id,
                            resource_id=sg["GroupId"],
                            resource_arn=f"arn:aws:ec2:{region}:{account_id}:security-group/{sg['GroupId']}",
                            resource_type="AWS::EC2::SecurityGroup",
                            region=region,
                            raw_evidence={
                                "GroupId": sg["GroupId"],
                                "GroupName": sg.get("GroupName"),
                                "OpenCIDRs": open_cidrs,
                                "Port": 3389,
                                "Protocol": protocol,
                                "api_call": "ec2:DescribeSecurityGroups"
                            },
                            preliminary_severity="critical"
                        ))
        return findings


class EC2UnencryptedVolumesCheck(BaseCheck):
    """
    Check: All attached EBS volumes must be encrypted.
    
    boto3 call: ec2.describe_volumes(Filters=[{"Name": "encrypted", "Values": ["false"]}])
    Only flag ATTACHED volumes (State == "in-use") — unattached volumes are lower risk.
    """
    
    def run(self) -> CheckResult:
        self._log("Checking for unencrypted EBS volumes")
        ec2 = self.session.client("ec2")
        findings = []
        
        volumes_result = safe_aws_call(
            lambda: ec2.describe_volumes(
                Filters=[{"Name": "encrypted", "Values": ["false"]}]
            ),
            self.check_id
        )
        if isinstance(volumes_result, CheckError):
            return volumes_result
        
        for vol in volumes_result.get("Volumes", []):
            if vol.get("State") == "in-use":  # Only attached volumes
                account_id = self.session.client("sts").get_caller_identity()["Account"]
                region = self.session.region_name
                attachments = vol.get("Attachments", [])
                instance_id = attachments[0].get("InstanceId") if attachments else "unknown"
                
                findings.append(RawFinding(
                    check_id=self.check_id,
                    resource_id=vol["VolumeId"],
                    resource_arn=f"arn:aws:ec2:{region}:{account_id}:volume/{vol['VolumeId']}",
                    resource_type="AWS::EC2::Volume",
                    region=region,
                    raw_evidence={
                        "VolumeId": vol["VolumeId"],
                        "Encrypted": False,
                        "State": vol["State"],
                        "AttachedToInstance": instance_id,
                        "VolumeType": vol.get("VolumeType"),
                        "SizeGB": vol.get("Size"),
                        "api_call": "ec2:DescribeVolumes"
                    },
                    preliminary_severity="high"
                ))
        return findings
```

**`checks/cloudtrail_checks.py`**
```python
from checks.base import BaseCheck, CheckResult
from models.finding import RawFinding
from utils.retry import safe_aws_call

class CloudTrailNotLoggingCheck(BaseCheck):
    """
    Check: CloudTrail must be enabled and actively logging.
    
    boto3 calls:
      cloudtrail.describe_trails() → list all trails
      cloudtrail.get_trail_status(Name=...) → check IsLogging field
    
    Finding: No trails exist, OR trails exist but IsLogging=False
    """
    
    def run(self) -> CheckResult:
        self._log("Checking CloudTrail logging status")
        ct = self.session.client("cloudtrail")
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        region = self.session.region_name
        
        trails_result = safe_aws_call(
            lambda: ct.describe_trails(includeShadowTrails=False),
            self.check_id
        )
        if isinstance(trails_result, CheckError):
            return trails_result
        
        trails = trails_result.get("trailList", [])
        
        if not trails:
            return [RawFinding(
                check_id=self.check_id,
                resource_id="cloudtrail",
                resource_arn=f"arn:aws:cloudtrail:{region}:{account_id}:trail/*",
                resource_type="AWS::CloudTrail::Trail",
                region=region,
                raw_evidence={
                    "TrailsFound": 0,
                    "IsLogging": False,
                    "api_call": "cloudtrail:DescribeTrails",
                    "note": "No CloudTrail trails configured in this region"
                },
                preliminary_severity="high"
            )]
        
        findings = []
        for trail in trails:
            trail_arn = trail["TrailARN"]
            status_result = safe_aws_call(
                lambda: ct.get_trail_status(Name=trail_arn),
                self.check_id
            )
            if isinstance(status_result, CheckError):
                continue
            
            if not status_result.get("IsLogging", False):
                findings.append(RawFinding(
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
                        "api_calls": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]
                    },
                    preliminary_severity="high"
                ))
        return findings


class EBSPublicSnapshotCheck(BaseCheck):
    """
    Check: EBS snapshots must not be publicly accessible.
    
    boto3 call: ec2.describe_snapshots(OwnerIds=["self"])
    Check permissions: ec2.describe_snapshot_attribute(SnapshotId=..., Attribute="createVolumePermission")
    Finding: createVolumePermission contains {"Group": "all"}
    """
    
    def run(self) -> CheckResult:
        self._log("Checking for public EBS snapshots")
        ec2 = self.session.client("ec2")
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        region = self.session.region_name
        findings = []
        
        snaps_result = safe_aws_call(
            lambda: ec2.describe_snapshots(OwnerIds=["self"]),
            self.check_id
        )
        if isinstance(snaps_result, CheckError):
            return snaps_result
        
        for snap in snaps_result.get("Snapshots", []):
            snap_id = snap["SnapshotId"]
            
            perms_result = safe_aws_call(
                lambda: ec2.describe_snapshot_attribute(
                    SnapshotId=snap_id, Attribute="createVolumePermission"
                ),
                self.check_id
            )
            if isinstance(perms_result, CheckError):
                continue
            
            is_public = any(
                p.get("Group") == "all"
                for p in perms_result.get("CreateVolumePermissions", [])
            )
            
            if is_public:
                findings.append(RawFinding(
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
                        "api_calls": ["ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute"],
                        "note": "Snapshot is publicly accessible — anyone can create a volume from it"
                    },
                    preliminary_severity="critical"
                ))
        return findings
```

---

### 4.4 `agent/orchestrator.py`

```python
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime
from typing import Dict, List, Tuple, Type
import boto3

from checks.base import BaseCheck
from checks.iam_checks import (IAMRootMFACheck, IAMRootAccessKeysCheck,
                                 IAMUserMFACheck, IAMUnusedAccessKeysCheck,
                                 IAMPasswordPolicyCheck)
from checks.s3_checks import S3PublicACLCheck, S3PublicPolicyCheck, S3EncryptionCheck
from checks.ec2_checks import SGOpenSSHCheck, SGOpenRDPCheck, EC2UnencryptedVolumesCheck
from checks.cloudtrail_checks import CloudTrailNotLoggingCheck, EBSPublicSnapshotCheck
from models.config import ScanConfig
from models.finding import RawFinding
from models.report import CheckError, ScanReport
from agent.intelligence import IntelligenceLayer
from reporter.json_reporter import JSONReporter
from reporter.markdown_reporter import MarkdownReporter

logger = logging.getLogger(__name__)

CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {
    "iam_root_mfa": IAMRootMFACheck,
    "iam_root_access_keys": IAMRootAccessKeysCheck,
    "iam_user_mfa": IAMUserMFACheck,
    "iam_unused_access_keys": IAMUnusedAccessKeysCheck,
    "iam_password_policy": IAMPasswordPolicyCheck,
    "s3_public_acl": S3PublicACLCheck,
    "s3_public_policy": S3PublicPolicyCheck,
    "s3_encryption_disabled": S3EncryptionCheck,
    "sg_open_ssh": SGOpenSSHCheck,
    "sg_open_rdp": SGOpenRDPCheck,
    "ec2_unencrypted_volumes": EC2UnencryptedVolumesCheck,
    "cloudtrail_not_logging": CloudTrailNotLoggingCheck,
    "ebs_public_snapshots": EBSPublicSnapshotCheck,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AgentOrchestrator:
    
    def __init__(self, config: ScanConfig, openai_api_key: str):
        self.config = config
        self.session = boto3.Session(region_name=config.scan.aws_region)
        self.intelligence = IntelligenceLayer(openai_api_key, config.scan.llm_model)
        
    def run(self) -> ScanReport:
        start_time = datetime.utcnow()
        logger.info(f"=== Scan started: {self.config.scan.name} ===")
        
        enabled_checks = self.config.get_enabled_checks()
        logger.info(f"Running {len(enabled_checks)} checks with {self.config.scan.max_workers} workers")
        
        raw_findings: List[RawFinding] = []
        scan_errors: List[CheckError] = []
        
        # ── PARALLEL EXECUTION ──────────────────────────────────
        with ThreadPoolExecutor(max_workers=self.config.scan.max_workers) as executor:
            future_to_check = {}
            for check_config in enabled_checks:
                if check_config.id not in CHECK_REGISTRY:
                    logger.warning(f"Unknown check ID: {check_config.id} — skipping")
                    continue
                check_class = CHECK_REGISTRY[check_config.id]
                check_instance = check_class(check_config, self.session)
                future = executor.submit(check_instance.run)
                future_to_check[future] = check_config.id
            
            for future in as_completed(future_to_check, timeout=self.config.scan.timeout_seconds * 2):
                check_id = future_to_check[future]
                try:
                    result = future.result(timeout=self.config.scan.timeout_seconds)
                    if isinstance(result, CheckError):
                        logger.warning(f"[{check_id}] Check error: {result.error_type}")
                        scan_errors.append(result)
                    elif isinstance(result, list):
                        logger.info(f"[{check_id}] {len(result)} findings")
                        raw_findings.extend(result)
                except TimeoutError:
                    scan_errors.append(CheckError(
                        check_id=check_id, error_type="timeout",
                        error_message=f"Check exceeded {self.config.scan.timeout_seconds}s"
                    ))
                except Exception as e:
                    scan_errors.append(CheckError(
                        check_id=check_id, error_type="unknown",
                        error_message=str(e)
                    ))
        
        logger.info(f"Raw findings collected: {len(raw_findings)}")
        logger.info(f"Check errors: {len(scan_errors)}")
        
        # ── LLM ENRICHMENT ─────────────────────────────────────
        logger.info("Starting LLM enrichment...")
        validated_findings = self.intelligence.enrich_batch(raw_findings, self.config)
        
        # Sort by severity
        validated_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        
        # ── BUILD REPORT ────────────────────────────────────────
        end_time = datetime.utcnow()
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        total_ran = len(enabled_checks) - len(scan_errors)
        if len(scan_errors) == 0:
            health = "healthy"
        elif len(scan_errors) < len(enabled_checks) * 0.3:
            health = "degraded"
        elif total_ran > 0:
            health = "partial"
        else:
            health = "failed"
        
        report = ScanReport(
            scan_name=self.config.scan.name,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            aws_account_id=account_id,
            aws_region=self.config.scan.aws_region,
            total_checks_attempted=len(enabled_checks),
            total_checks_succeeded=total_ran,
            total_checks_errored=len(scan_errors),
            total_findings=len(validated_findings),
            findings_by_severity=severity_counts,
            findings=validated_findings,
            scan_errors=scan_errors,
            scan_health=health
        )
        
        # ── GENERATE REPORTS ────────────────────────────────────
        JSONReporter(self.config.scan.output_dir).write(report)
        MarkdownReporter(self.config.scan.output_dir).write(report)
        
        logger.info(f"=== Scan complete in {report.duration_seconds:.1f}s | Health: {health} ===")
        logger.info(f"Findings: {severity_counts}")
        return report
```

---

### 4.5 `agent/intelligence.py` — The LLM Layer

```python
import json, logging
from typing import List
from openai import OpenAI
from models.finding import RawFinding, ValidatedFinding
from models.config import ScanConfig, CheckConfig

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security intelligence engine for an AI-powered AWS security agent.

You receive a raw security finding from a boto3 API check. Your job is to enrich it with:
1. A validated severity level
2. A specific, accurate business impact statement 
3. Exact remediation steps (numbered)
4. A single runnable AWS CLI command for immediate remediation
5. A confidence score (0–100)

SEVERITY RULES (strict — these prevent false positives):
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
3. If preliminary_severity is "critical" but evidence doesn't fully support it, downgrade to "high"
4. confidence_score reflects: how certain are you this is a real security issue? 
   - 90-100: Direct API evidence, no ambiguity
   - 70-89: Strong evidence but some context missing
   - 50-69: Evidence present but could be acceptable in some configurations
   - <50: Uncertain — downgrade severity

Return ONLY valid JSON. No markdown, no explanation outside the JSON.

Schema:
{
  "title": "short descriptive title",
  "severity": "critical|high|medium|low|info",
  "severity_reasoning": "why this severity was chosen based on the evidence",
  "business_impact": "specific attack scenario — what can an adversary do with this?",
  "remediation_steps": ["Step 1...", "Step 2...", "Step 3..."],
  "remediation_command": "exact AWS CLI command",
  "confidence_score": 0-100
}"""


class IntelligenceLayer:
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
    
    def _get_severity_cap(self, check_id: str, config: ScanConfig) -> str:
        """Get the severity_cap for a check from config. LLM cannot exceed this."""
        for check in config.checks:
            if check.id == check_id:
                return check.severity_cap
        return "critical"  # Default: no cap
    
    def _apply_severity_cap(self, severity: str, cap: str) -> str:
        """Ensure LLM severity doesn't exceed the configured cap."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if order.get(severity, 99) < order.get(cap, 0):
            logger.warning(f"LLM severity {severity} exceeds cap {cap} — capping")
            return cap
        return severity
    
    def enrich_single(self, raw: RawFinding, config: ScanConfig) -> ValidatedFinding:
        """Enrich a single RawFinding with LLM intelligence."""
        
        user_message = f"""Raw security finding to enrich:

check_id: {raw.check_id}
resource_arn: {raw.resource_arn}
resource_type: {raw.resource_type}
preliminary_severity: {raw.preliminary_severity}
raw_evidence: {json.dumps(raw.raw_evidence, indent=2, default=str)}

Enrich this finding. Be specific about the business impact and provide a runnable CLI remediation command."""
        
        logger.info(f"[intelligence] Enriching: {raw.check_id} / {raw.resource_id}")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=600,
                temperature=0.1,  # Low temperature = deterministic, fewer hallucinations
                response_format={"type": "json_object"}
            )
            
            data = json.loads(response.choices[0].message.content)
            severity_cap = self._get_severity_cap(raw.check_id, config)
            final_severity = self._apply_severity_cap(data["severity"], severity_cap)
            
            logger.info(f"[intelligence] {raw.check_id}: {raw.preliminary_severity} → {final_severity} (confidence: {data.get('confidence_score')})")
            
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
                confidence_score=data["confidence_score"]
            )
        
        except Exception as e:
            logger.error(f"[intelligence] LLM enrichment failed for {raw.check_id}: {e}")
            # Fallback: return finding with preliminary severity but flag it
            return ValidatedFinding(
                check_id=raw.check_id,
                title=f"{raw.check_id} — {raw.resource_id}",
                resource_id=raw.resource_id,
                resource_arn=raw.resource_arn,
                resource_type=raw.resource_type,
                region=raw.region,
                severity=raw.preliminary_severity,
                severity_reasoning="LLM enrichment failed — using checker preliminary severity",
                raw_evidence=raw.raw_evidence,
                business_impact="Unable to determine — LLM enrichment failed",
                remediation_steps=["Review AWS documentation for this resource type"],
                remediation_command="# LLM enrichment failed — manual review required",
                confidence_score=50
            )
    
    def enrich_batch(self, raw_findings: List[RawFinding], config: ScanConfig) -> List[ValidatedFinding]:
        """Enrich all findings. Sequential to avoid rate limits."""
        validated = []
        for raw in raw_findings:
            validated.append(self.enrich_single(raw, config))
        return validated
```

---

### 4.6 `utils/retry.py` — Error Handling

```python
import time, logging, botocore
from typing import Callable, Any, Union
from models.report import CheckError

logger = logging.getLogger(__name__)

def safe_aws_call(func: Callable, check_id: str, *args, **kwargs) -> Union[Any, CheckError]:
    """
    Wraps a boto3 call with:
    - Exponential backoff on throttling (429 / Throttling)
    - Explicit CheckError on AccessDenied (not assumed clean)
    - Explicit CheckError on timeout
    - Explicit CheckError on unexpected errors
    
    Returns: API response dict OR CheckError (never raises)
    """
    max_retries = 3
    backoff_base = 2.0
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            status = e.response["ResponseMetadata"]["HTTPStatusCode"]
            
            if code in ["AccessDenied", "AccessDeniedException", "AuthorizationError"]:
                logger.warning(f"[{check_id}] Access denied: {code}")
                return CheckError(
                    check_id=check_id,
                    error_type="access_denied",
                    error_message=f"Permission denied: {e.response['Error']['Message']}",
                    http_status=status,
                    aws_error_code=code
                )
            
            if code in ["Throttling", "ThrottlingException", "RequestLimitExceeded"] or status == 429:
                wait = backoff_base ** attempt
                logger.warning(f"[{check_id}] Throttled (attempt {attempt+1}/{max_retries}), waiting {wait}s")
                time.sleep(wait)
                continue
            
            if attempt == max_retries - 1:
                return CheckError(
                    check_id=check_id,
                    error_type="api_error",
                    error_message=str(e),
                    http_status=status,
                    aws_error_code=code
                )
        
        except botocore.exceptions.ConnectTimeoutError:
            if attempt == max_retries - 1:
                return CheckError(
                    check_id=check_id,
                    error_type="timeout",
                    error_message="Connection timeout after 3 attempts"
                )
            time.sleep(backoff_base ** attempt)
        
        except Exception as e:
            return CheckError(
                check_id=check_id,
                error_type="unknown",
                error_message=str(e)
            )
    
    return CheckError(check_id=check_id, error_type="unknown", error_message="Max retries exceeded")
```

---

## 5. The LLM Intelligence Layer

### Why it exists

Without the LLM layer, this is just a boto3 wrapper — the same as Prowler or AWS Config rules.

The LLM layer is what makes this an **AI agent**. It adds:
- **Decision-making**: Does this evidence warrant Critical or just High?
- **Context**: What can an attacker actually DO with this misconfiguration?
- **Action**: Exactly which AWS CLI command fixes this?
- **Self-validation**: Does my output match the evidence?

### Hallucination Prevention Strategy

| Risk | Mitigation |
|---|---|
| LLM invents findings | LLM never creates findings — only boto3 checks do |
| LLM over-rates severity | severity_cap in config bounds maximum severity |
| LLM invents remediation | System prompt demands CLI commands based only on raw_evidence |
| LLM confident when wrong | confidence_score below 70 auto-downgrades severity |
| LLM fails entirely | Fallback to preliminary_severity from checker |

### Prompt Engineering Detail

- `temperature=0.1` — near-deterministic outputs, fewer creative hallucinations
- `response_format={"type": "json_object"}` — forces valid JSON output, no markdown wrapping
- System prompt explicitly lists what "critical" means — prevents ambiguous upgrades
- User prompt includes raw boto3 evidence verbatim — LLM has to work FROM evidence

---

## 6. Error Handling Strategy

```
Every check result is one of three types:
  A) List[RawFinding]  → check ran, found issues
  B) []               → check ran, no issues found (PASS)
  C) CheckError       → check FAILED to run

Case C is NEVER silently dropped. It always appears in scan_errors.
The report's scan_health field reflects how many checks fell into Case C.
```

### HTTP Status Code Handling

| Code | Error | Action |
|---|---|---|
| 403 | AccessDenied | Log + return CheckError (not assumed clean) |
| 429 | Throttling | Exponential backoff × 3, then CheckError |
| 500/503 | AWS internal | Retry × 3, then CheckError |
| Timeout | ConnectTimeout | Retry × 3, then CheckError |
| Any other | Unknown | Log + return CheckError immediately |

---

## 7. Output Schemas

### JSON Report Structure

```json
{
  "scan_id": "a3f2e1b0-...",
  "scan_name": "Aivar Infrastructure Security Audit",
  "start_time": "2026-06-07T18:00:00Z",
  "end_time": "2026-06-07T18:01:23Z",
  "duration_seconds": 83.4,
  "aws_account_id": "123456789012",
  "aws_region": "ap-south-1",
  "total_checks_attempted": 13,
  "total_checks_succeeded": 12,
  "total_checks_errored": 1,
  "total_findings": 7,
  "findings_by_severity": {
    "critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0
  },
  "scan_health": "degraded",
  "findings": [
    {
      "id": "f3a2b1c0",
      "check_id": "sg_open_ssh",
      "title": "Security Group Exposes SSH to Public Internet",
      "resource_id": "sg-0a1b2c3d4e5f",
      "resource_arn": "arn:aws:ec2:ap-south-1:123456789012:security-group/sg-0a1b2c3d4e5f",
      "resource_type": "AWS::EC2::SecurityGroup",
      "region": "ap-south-1",
      "severity": "critical",
      "severity_reasoning": "Port 22 is accessible from 0.0.0.0/0, allowing any internet host to attempt SSH authentication. Direct evidence of complete network perimeter failure.",
      "raw_evidence": {
        "GroupId": "sg-0a1b2c3d4e5f",
        "GroupName": "open-ssh-sg",
        "OpenCIDRs": ["0.0.0.0/0"],
        "MatchedRule": {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22},
        "api_call": "ec2:DescribeSecurityGroups"
      },
      "business_impact": "An attacker can perform automated SSH brute-force against all EC2 instances in this security group. Successful compromise grants shell access to the instance and potential lateral movement to internal network resources.",
      "remediation_steps": [
        "1. Identify all EC2 instances using this security group",
        "2. Determine the legitimate source IPs that need SSH access",
        "3. Remove the 0.0.0.0/0 inbound rule on port 22",
        "4. Add specific CIDR rules for approved source IPs only",
        "5. Consider replacing SSH with AWS Systems Manager Session Manager (no open ports required)"
      ],
      "remediation_command": "aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f --protocol tcp --port 22 --cidr 0.0.0.0/0 --region ap-south-1",
      "confidence_score": 98,
      "scan_timestamp": "2026-06-07T18:00:45Z"
    }
  ],
  "scan_errors": [
    {
      "check_id": "ebs_public_snapshots",
      "error_type": "access_denied",
      "error_message": "Permission denied: ec2:DescribeSnapshotAttribute",
      "http_status": 403,
      "aws_error_code": "AccessDenied",
      "timestamp": "2026-06-07T18:00:52Z"
    }
  ]
}
```

### Markdown Report Structure

```markdown
# Security Audit Report — Aivar Infrastructure
**Date:** 2026-06-07 | **Account:** 123456789012 | **Region:** ap-south-1  
**Duration:** 21.4s | **Health:** ✅ Healthy | **Findings:** 8

---

## Executive Summary

| Severity | Count |
|---|---|
| 🔴 Critical | 5 |
| 🟠 High | 2 |
| 🟡 Medium | 1 |
| Total | 8 |

---

## Critical Findings

### [F001] Security Group Exposes SSH to Public Internet
**Resource:** `sg-0a1b2c3d4e5f` (AWS::EC2::SecurityGroup)  
**ARN:** `arn:aws:ec2:ap-south-1:123456789012:security-group/sg-0a1b2c3d4e5f`  
**Confidence:** 98%

**Business Impact**  
An attacker can perform automated SSH brute-force...

**Remediation**  
```bash
aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region ap-south-1
```

---

## Scan Health

⚠️ 1 check(s) failed to execute:

| Check | Error Type | Details |
|---|---|---|
| ebs_public_snapshots | access_denied | Permission denied: ec2:DescribeSnapshotAttribute |

> These checks did not run. The resources they cover are **not verified as clean**.
```

---

## 8. Implementation Order (Step-by-Step)

```
Hour 1: Setup
  ✅ pip install, .env, AWS free tier account
  ✅ Create 5 intentional misconfigs in AWS (8-finding demo verified)
  ✅ Create project structure (all empty files)

Hour 2: Models + Config
  ✅ models/config.py, models/finding.py, models/report.py
  ✅ config/loader.py (reads checklist.yaml → ScanConfig)
  ✅ checklist.yaml with all 13 checks

Hour 3-4: Checks (IAM first)
  ✅ utils/retry.py (safe_aws_call)
  ✅ checks/base.py
  ✅ checks/iam_checks.py (5 checks)
  ✅ Test manually: python -c "from checks.iam_checks import *; ..."

Hour 5-6: S3 + EC2 + CloudTrail checks
  ✅ checks/s3_checks.py (3 checks)
  ✅ checks/ec2_checks.py (3 checks — SSH, RDP, EBS)
  ✅ checks/cloudtrail_checks.py (2 checks)

Hour 7: Intelligence Layer
  ✅ agent/intelligence.py (LLM enrichment)
  ✅ Test with one RawFinding — verify output JSON is correct

Hour 8: Orchestrator + Reporters
  ✅ agent/orchestrator.py
  ✅ reporter/json_reporter.py
  ✅ reporter/markdown_reporter.py
  ✅ main.py (CLI entry point)

Hour 9: End-to-end run
  ✅ python main.py --config checklist.yaml
  ✅ Verify findings match intentional misconfigs — 8/8 via run_full_test_and_cleanup.py
  ✅ Verify scan_errors appear for any AccessDenied checks
  ✅ Verify output files in reports/

Hour 10: Polish
  ✅ Add logging to every major step
  ✅ README.md (company-facing submission doc + setup guide)
  ✅ requirements.txt
  ✅ Verify all 7 acceptance criteria are met (+ 6b root MFA critical)

Post-Level-1 additions:
  ✅ Web dashboard (FastAPI) with Run Full Demo
  ✅ dashboard/misconfig_service.py — boto3 create/verify/cleanup
  ✅ Groq LLM provider support (utils/llm_client.py)
  ✅ Evidence floor in intelligence.py
  ✅ verify_test_misconfigs.ps1 + idempotent setup scripts
  ✅ run_full_test_and_cleanup.py — automated end-to-end demo test
  ✅ s3_public_policy demo bucket (replaces s3_encryption_disabled on encrypted-by-default accounts)
  ✅ docs/screenshots/ folder for demo evidence
  ✅ README.md — company-facing submission document
```

---

## 9. Acceptance Criteria Checklist

```
✅  Reads a security checklist configuration file in YAML or JSON format
     → config/loader.py reads checklist.yaml → ScanConfig

✅  Executes 10 or more distinct checks
     → 13 checks implemented across IAM, S3, EC2, CloudTrail

✅  Each finding includes: resource ARN, severity, raw evidence,
   business impact, step-by-step remediation
     → ValidatedFinding model has all fields
     → LLM generates business_impact, remediation_steps, remediation_command

✅  Handles API errors gracefully — 403, 429, timeouts logged not swallowed
     → utils/retry.py safe_aws_call handles all error types
     → CheckError objects appear in scan_errors in report

✅  Produces both JSON (machine-readable) and Markdown (human-readable)
     → reporter/json_reporter.py → findings_report_{ts}.json
     → reporter/markdown_reporter.py → findings_report_{ts}.md
     → dashboard/ also serves reports via /api/reports

✅  Zero false positives on Critical severity findings
     → boto3 checks require DIRECT API evidence before creating finding
     → LLM validates severity with explicit Critical criteria in system prompt
     → severity_cap in checklist.yaml bounds maximum severity per check
     → confidence_score < 70 triggers automatic severity downgrade
     → DETERMINISTIC_EVIDENCE evidence floor prevents wrongful downgrades

✅  All checks execute against real infrastructure — no mocked API responses
     → boto3 session uses real AWS credentials from .env
     → Live account: 563999587682, ap-south-1

✅  (Added) Root MFA stays critical when AccountMFAEnabled=0
     → verify_acceptance.py criterion 6b
     → scripts/verify_acceptance.py — ALL ACCEPTANCE CRITERIA PASSED
```

### Creating Demo Misconfigs (5 intentional → 8 total findings) — VERIFIED

See **README.md Section 7** for full instructions.

| Step | Requires | Command |
|------|----------|---------|
| 1. Get admin keys | IAM user `aivar-admin` + `AdministratorAccess` | Save to `.env.admin` |
| 2. Create misconfigs | `.env.admin` | Dashboard **Run Full Demo** or `.\scripts\run_setup_as_admin.ps1` |
| 3. Verify (scanner) | `aivar-scanner` in `.env` | `.\scripts\verify_test_misconfigs.ps1` → **5/5 PASS** |
| 4. Scan | `aivar-scanner` in `.env` | `python main.py --verbose` → **8 findings** (5C / 2H / 1M) |
| 5. Cleanup | Admin credentials | Dashboard **Delete All Test Resources** or `.\scripts\cleanup_test_misconfigs.ps1` |

| Method | Requires | Script / Steps |
|--------|----------|----------------|
| **Dashboard** *(recommended)* | `.env` + `.env.admin` | `uvicorn dashboard.app:app` → **Run Full Demo** |
| AWS Console | Root/admin browser login | README Section 7 (5 resources) |
| CLI script (safe) | `.env.admin` | `scripts/run_setup_as_admin.ps1` |
| CLI script (direct) | Admin env vars in terminal | `scripts/setup_test_misconfigs.ps1` |
| Automated test | Both cred files | `python scripts/run_full_test_and_cleanup.py` |

---

## 10. Demo + Submission Guide

### Demo Video Script (5–8 minutes)

```
0:00 — Intro
"I chose the Offensive Security Agent because of my CNSP and CAP certifications and
leading Team Zero in CTF competitions. I could build this with real domain knowledge,
not just API documentation."

1:00 — Show Architecture
Walk through the flow diagram. Explain why LLM is in the enrichment layer, not the
detection layer. This is the key design decision — mention it explicitly.

2:00 — Show the checklist.yaml
"The agent is config-driven. To add a new check, you add one entry here. No code changes."

3:00 — Run the full demo
Option A: Dashboard → "Run Full Demo" (create misconfigs → verify → scan → 8 findings)
Option B: python main.py --config checklist.yaml --verbose
Show step-by-step progress and 13/13 checks healthy.

5:00 — Open the JSON report
Show a Critical finding. Walk through: resource_arn → raw_evidence → business_impact →
remediation_command. Show that raw_evidence is ACTUAL boto3 response, not made up.

6:30 — Open the Markdown report
Show the scan health section. Explain: "If a check fails, it appears here. The agent
never assumes a resource is clean just because it couldn't check it."

7:30 — Mention what's next
"Level 2 would add API endpoint scanning and CVE dependency checks. Level 3 adds
scheduling and SLA tracking."
```

### Submission Files

```
Google Drive folder structure:
├── resume_manikandan.pdf        ← Updated with this project
├── demo_video.mp4               ← Or Loom link
├── writeup.pdf                  ← Architecture + decisions doc
└── offensive-security-agent.zip
    ├── (all source files)
    └── README.md
```

### requirements.txt (current)

```
boto3>=1.34.0
botocore>=1.34.0
openai>=1.30.0
pydantic>=2.10.0
pyyaml>=6.0.1
python-dotenv>=1.0.0
fastapi>=0.115.0
uvicorn[standard]>=0.32.0
```

### .env.example (current)

```
# AWS Credentials (read-only IAM user: aivar-scanner)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-south-1

# LLM - Groq (preferred) / Grok / OpenAI
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
```

---

## 11. Level 2 & 3 — Not Started

| Level | Status | Notes |
|-------|--------|-------|
| Level 2 | Complete | Multi-domain: APIs, CVEs, secrets, cross-domain ranking - see README Section 9 |
| Level 3 | Not started | Scheduled scans, SLA, deduplication, escalation - see README Section 10 |

Submission document for reviewers: **README.md** (company-facing, includes screenshot placeholders).

---

*Plan prepared for Aivar Innovations AI/ML Hiring Challenge — June 2026*  
*Manikandan M — 19manikandan2005@gmail.com*  
*Last updated: 7 June 2026 — Level 1 complete and verified (8/8 findings, all acceptance criteria pass)*
