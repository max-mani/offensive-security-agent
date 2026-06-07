# Agent 2: Offensive Security Agent

**Aivar Innovations — AI/ML Engineering Hiring Challenge (June 2026)**

| | |
|---|---|
| **Candidate** | Manikandan M |
| **Agent** | Agent 2 — Offensive Security Agent |
| **Status** | **Level 1 complete** (verified 8/8 findings) · **Level 2 complete** · Level 3 not started |
| **Verified** | 7 June 2026 — account `563999587682`, region `ap-south-1` |
| **Repository** | [offensive-security-agent](https://github.com/max-mani/offensive-security-agent) |
| **AWS Region** | `ap-south-1` (Mumbai) |

---

## Table of Contents

1. [About the Challenge — Agent 2](#1-about-the-challenge--agent-2)
2. [Progressive Levels Overview](#2-progressive-levels-overview)
3. [Level 1 — What Was Built](#3-level-1--what-was-built)
4. [Level 1 — Acceptance Criteria](#4-level-1--acceptance-criteria)
5. [Architecture & Design Decisions](#5-architecture--design-decisions)
6. [Setup & Run Guide](#6-setup--run-guide)
7. [How to Get Admin Credentials & Create All 8 Findings](#7-how-to-get-admin-credentials--create-all-8-findings)
8. [Screenshots & Demo Evidence](#8-screenshots--demo-evidence)
9. [Level 2 — Multi-Domain Scanning](#9-level-2--multi-domain-scanning)
10. [Level 3 — Autonomous Continuous Scanning *(Not Started)*](#10-level-3--autonomous-continuous-scanning-not-started)
11. [Project Structure](#11-project-structure)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. About the Challenge — Agent 2

Source: [Aivar AIML Hiring Challenge — Problem Statements (June 2026)](Aivar_AIML_Hiring_R3%20(1).pdf)

### The Problem

With infrastructure shipping daily, manual security reviews happen at best quarterly. Between reviews, misconfigurations and vulnerabilities silently accumulate. Security engineers spend time on routine checks that should be automated.

**Agent 2 — Offensive Security Agent** acts as a paranoid auditor that continuously scans infrastructure for security issues.

### Why It Matters

- Security issues accumulate silently — new code ships, configurations drift, credentials leak.
- Manual reviews are expensive and infrequent — a quarterly review cannot catch a misconfiguration introduced on day two.
- Most checks are mechanical and automatable — port exposure, IAM key rotation, S3 ACLs follow predictable patterns.
- Speed prevents incidents — warnings delivered while code is being written are far more effective than post-deployment alerts.

### What "Production-Ready" Means (Aivar Definition)

| Trait | Requirement |
|-------|-------------|
| No false Critical findings | Critical severity must be backed by direct API evidence, not pattern-match ambiguity |
| Actionable remediation | Not "you have a vulnerability" — provide exact CLI commands to fix it |
| Handles scale | Parallelism and rate-limit handling for many resources |
| Knows what it cannot access | Permission denied or API unreachable → reported explicitly, never assumed clean |
| Observable | Every action, decision, and confidence level is logged and traceable |

### Production-Grade Agent Traits (All Submissions)

1. **Make decisions** — picks the right action based on context, not a hardcoded script
2. **Validate aggressively** — verifies output, detects hallucinations, catches edge cases
3. **Fail clearly** — explains why it failed and what it needs from the operator
4. **Maintain guard rails** — knows its scope and operates strictly within it
5. **Be observable** — every action, decision, and confidence level is logged

---

## 2. Progressive Levels Overview

| Level | What to Build | Key Challenge | Status |
|-------|---------------|---------------|--------|
| **Level 1** | Read a YAML/JSON security checklist and execute each check against real AWS infrastructure | Zero false positives on Critical severity | **Complete** |
| **Level 2** | Extend to AWS infrastructure + live API endpoints + code dependency CVEs; merge and rank by business impact | Each domain has different signal norms | **Complete** |
| **Level 3** | Run on a schedule, deduplicate findings, escalate Critical, track remediation SLAs | Silent scan failures are worse than missed scans | **Not started** |

---

## 3. Level 1 — What Was Built

Level 1 delivers a **checklist-based AWS infrastructure scanner** with an **LLM intelligence layer** for enrichment only (never for detection).

### Core Capabilities

| Capability | Implementation |
|------------|----------------|
| Config-driven scanning | [`checklist.yaml`](checklist.yaml) — 13 checks, enable/disable per check, `severity_cap` per check |
| Real AWS detection | 13 boto3 checks across IAM, S3, EC2/EBS, CloudTrail — no mocked responses |
| Parallel execution | `ThreadPoolExecutor` with 5 workers in [`agent/orchestrator.py`](agent/orchestrator.py) |
| LLM enrichment | [`agent/intelligence.py`](agent/intelligence.py) — business impact, remediation steps, CLI commands, confidence score |
| Severity guard rails | `severity_cap` in config + confidence downgrade (< 70) + **evidence floor** for deterministic API proof |
| Error handling | [`utils/retry.py`](utils/retry.py) — 403, 429, timeout → `CheckError` in report, never silently skipped |
| Reports | JSON + Markdown in `reports/` via [`reporter/`](reporter/) |
| Web dashboard | FastAPI UI at `http://127.0.0.1:8080` — full demo flow (create → verify → scan → cleanup), KPI cards, findings table, scan history |
| Demo misconfig service | [`dashboard/misconfig_service.py`](dashboard/misconfig_service.py) — boto3 create/verify/cleanup (no AWS CLI required from UI) |
| Verification scripts | `scripts/verify_acceptance.py`, `scripts/verify_test_misconfigs.ps1`, `scripts/run_full_test_and_cleanup.py` |

### LLM Provider

Supports **Groq** (primary, free tier), **Grok**, or **OpenAI** via [`utils/llm_client.py`](utils/llm_client.py). Current default: `llama-3.3-70b-versatile` on Groq.

### Security Checks (13)

| ID | Description | Severity Cap |
|----|-------------|--------------|
| `iam_root_mfa` | Root account must have MFA enabled | Critical |
| `iam_root_access_keys` | Root must not have active access keys | Critical |
| `iam_user_mfa` | Console users must have MFA | High |
| `iam_unused_access_keys` | Access keys unused 90+ days | Medium |
| `iam_password_policy` | Password policy meets standards | Medium |
| `s3_public_acl` | S3 buckets must not have public ACLs | Critical |
| `s3_public_policy` | S3 bucket policies must not be public | Critical |
| `s3_encryption_disabled` | S3 buckets must have encryption | High |
| `sg_open_ssh` | No SSH (22) from 0.0.0.0/0 | Critical |
| `sg_open_rdp` | No RDP (3389) from 0.0.0.0/0 | Critical |
| `ec2_unencrypted_volumes` | Attached EBS volumes must be encrypted | High |
| `cloudtrail_not_logging` | CloudTrail must be actively logging | High |
| `ebs_public_snapshots` | EBS snapshots must not be public | Critical |

### Key Design Decision

**boto3 detects facts; the LLM only enriches.** The LLM never creates findings. This prevents hallucinated Critical ratings — the #1 Level 1 acceptance criterion.

```
checklist.yaml → orchestrator → checks/ (boto3) → RawFinding
                                                      ↓
                                            intelligence.py (LLM)
                                                      ↓
                                            ValidatedFinding → JSON + Markdown + Dashboard
```

### My Work Summary

- Built full Level 1 pipeline: config loader, 13 checks, orchestrator, LLM layer, reporters, CLI entry point
- Added evidence-based severity floor so deterministic findings (e.g. root MFA disabled) cannot be downgraded by the LLM
- Built interactive web dashboard with one-click **Run Full Demo** (create 5 misconfigs → verify → scan → 8 findings)
- Created AWS setup, verification, cleanup, and acceptance scripts (PowerShell + bash)
- Verified end-to-end on live AWS account `563999587682` in `ap-south-1` — **all 7 acceptance criteria pass**, **8/8 demo findings**
- Documented Console, CLI, and dashboard paths for creating demo misconfigurations

### Level 1 Verification (Completed)

| Check | Result |
|-------|--------|
| `scripts/verify_acceptance.py` | All 7 criteria (+ 6b root MFA critical) **PASS** |
| `scripts/verify_test_misconfigs.ps1` | **5/5 PASS** (all intentional test resources visible to scanner) |
| `scripts/run_full_test_and_cleanup.py` | **8 findings** — 5 Critical, 2 High, 1 Medium; 13/13 checks healthy; cleanup OK |
| Dashboard **Run Full Demo** | Same flow as above, no terminal required |

**8-finding demo breakdown** (5 intentional + 3 natural account defaults):

| # | Finding | Check ID | Severity | Source |
|---|---------|----------|----------|--------|
| 1 | Public S3 bucket (ACL) | `s3_public_acl` | Critical | Intentional |
| 2 | Public S3 bucket policy | `s3_public_policy` | Critical | Intentional |
| 3 | Open SSH security group | `sg_open_ssh` | Critical | Intentional |
| 4 | Open RDP security group | `sg_open_rdp` | Critical | Intentional |
| 5 | Root MFA disabled | `iam_root_mfa` | Critical | Natural |
| 6 | IAM user without MFA | `iam_user_mfa` | High | Intentional |
| 7 | CloudTrail not logging | `cloudtrail_not_logging` | High | Natural |
| 8 | Weak password policy | `iam_password_policy` | Medium | Natural |

> **Note on `s3_encryption_disabled`:** The check remains in the 13-check scan, but newer AWS accounts enforce **account-level S3 default encryption**, so an unencrypted bucket cannot be created for demo purposes. The 5th intentional misconfig uses a **public bucket policy** (`s3_public_policy`) instead — verified on this account.

---

## 4. Level 1 — Acceptance Criteria

Per the Aivar problem statement, Level 1 requires:

| # | Criterion (Aivar) | Status | How It Is Met |
|---|-------------------|--------|---------------|
| 1 | Reads a security checklist in YAML or JSON | **Pass** | [`config/loader.py`](config/loader.py) loads and validates `checklist.yaml` |
| 2 | Executes 10+ distinct checks (IAM, S3, SGs, encryption, MFA) | **Pass** | 13 checks in `CHECK_REGISTRY` |
| 3 | Each finding: ARN, severity, raw evidence, business impact, remediation | **Pass** | `ValidatedFinding` model + LLM enrichment |
| 4 | API errors (403, 429, timeout) logged, not swallowed | **Pass** | `safe_aws_call` + `scan_errors` in every report |
| 5 | Produces JSON and Markdown reports | **Pass** | `reporter/json_reporter.py` + `markdown_reporter.py` |
| 6 | Zero false positives on Critical findings | **Pass** | Direct API evidence required + severity cap + evidence floor |
| 6b | Root MFA stays Critical when `AccountMFAEnabled=0` | **Pass** | Evidence floor in `intelligence.py` |
| 7 | All checks against real infrastructure — no mocks | **Pass** | boto3 session with real AWS credentials |

Verify locally:

```powershell
python scripts\verify_acceptance.py
```

Expected output: `ALL ACCEPTANCE CRITERIA PASSED`

---

## 5. Architecture & Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Detection | boto3 checks only | Facts from AWS APIs — no LLM hallucination |
| Enrichment | Groq `llama-3.3-70b-versatile` at temp 0.1 | Business impact + remediation; OpenAI/Grok fallback |
| Severity | LLM + `severity_cap` + confidence downgrade + evidence floor | Zero false Critical; keep real Critical findings |
| Parallelism | ThreadPoolExecutor (5 workers) | boto3 is I/O bound |
| Errors | Per-check try/catch, never global | One failure does not kill the scan |
| Config | YAML checklist | Human-readable, easy to extend without code changes |

---

## 6. Setup & Run Guide

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ (tested on 3.14) |
| AWS account | `ap-south-1` region |
| LLM API key | `GROQ_API_KEY` (free tier at [console.groq.com](https://console.groq.com)) |
| AWS CLI | Optional — needed only for CLI setup scripts |

### Install & Configure

```powershell
cd offensive-security-agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# Edit .env: AWS scanner keys + GROQ_API_KEY
```

### Two AWS Users You Need

| User | Purpose | Credentials file | Permissions |
|------|---------|------------------|-------------|
| `aivar-scanner` | Run scans & dashboard | `.env` | Read-only (S3, IAM, EC2, CloudTrail) |
| `aivar-admin` | Create/delete test misconfigs | `.env.admin` | `AdministratorAccess` (setup only) |

**Never put admin keys in `.env`.** The scanner must stay read-only.

### Step A: Create Scanner User (read-only) → `.env`

1. AWS Console → **IAM** → **Users** → **Create user**
2. User name: `aivar-scanner`
3. Attach policies:
   - `AmazonS3ReadOnlyAccess`
   - `IAMReadOnlyAccess`
   - `AmazonEC2ReadOnlyAccess`
   - `AWSCloudTrailReadOnlyAccess`
4. **Security credentials** → **Create access key** → **Local code** → Create
5. Copy keys into `.env`:

```env
AWS_ACCESS_KEY_ID=AKIA...scanner...
AWS_SECRET_ACCESS_KEY=...scanner-secret...
AWS_DEFAULT_REGION=ap-south-1
GROQ_API_KEY=gsk_...
```

### Step B: Create Admin User → `.env.admin` *(see Section 7)*

Required to create the 5 test misconfigs for a full **8-finding** demo report.

### Run Scan (CLI)

```powershell
python main.py --config checklist.yaml --verbose
```

Reports: `reports/findings_report_{timestamp}.json` and `.md`

### Run Dashboard (interactive demo)

```powershell
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
```

Open **http://127.0.0.1:8080**

The dashboard lets you run the full demo without terminal commands:

| Button | What it does |
|--------|----------------|
| **Run Full Demo** | Create 5 misconfigs → verify → scan → show ~8 findings |
| **Create Misconfigs** | Create test S3, IAM, security groups (uses `.env.admin`) |
| **Verify Resources** | Confirm scanner sees all 5 test resources |
| **Delete All Test Resources** | Remove all `aivar-test-*` buckets, SGs, IAM user |
| **Run Scan** | Run 13-check scan with step-by-step progress |

Each operation shows a **live step-by-step pipeline** (which check is running, LLM enrichment, report generation).

---

## 7. How to Get Admin Credentials & Create All 8 Findings

The scanner only reports misconfigurations that **exist in AWS**. A fresh account shows **3 findings** by default. To get **all 8 findings** (5 Critical, 2 High, 1 Medium), you must create **5 intentional test resources** using **admin credentials**.

### Quick Start (full 8-finding demo)

```powershell
# 1. Create aivar-admin in AWS Console (steps below) → copy keys to .env.admin
copy .env.admin.example .env.admin
# Edit .env.admin with admin access keys

# 2. Install AWS CLI v2 if not installed
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Option A — Dashboard (recommended)
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
# Open http://127.0.0.1:8080 → click "Run Full Demo"

# Option B — Terminal
.\scripts\run_setup_as_admin.ps1
.\scripts\verify_test_misconfigs.ps1          # expect 5/5 PASS
python main.py --config checklist.yaml --verbose   # expect ~8 findings
```

---

### How to Get Admin Credentials (step-by-step)

You need an IAM user with permission to create S3 buckets, IAM users, and security groups. **Do not use root access keys for daily work** — create a dedicated admin user instead.

#### 1. Sign in to AWS

- Go to [https://aws.amazon.com](https://aws.amazon.com) → **Sign In to the Console**
- Use your **root account** email/password (the email you used to register AWS)
- Set region to **Asia Pacific (Mumbai) `ap-south-1`** (top-right corner)

#### 2. Create admin IAM user `aivar-admin`

1. Open **IAM** → **Users** → **Create user**
2. User name: `aivar-admin`
3. Click **Next**
4. **Set permissions** → **Attach policies directly**
5. Search and select: **`AdministratorAccess`**
   - This is needed to create S3 buckets, IAM users, and EC2 security groups
   - Use only for demo setup — not for scanning
6. Click **Next** → **Create user**

#### 3. Create access keys for `aivar-admin`

1. Click the new user **`aivar-admin`**
2. Tab **Security credentials**
3. Scroll to **Access keys** → **Create access key**
4. Use case: **Command Line Interface (CLI)**
5. Check the confirmation box → **Next** → **Create access key**
6. **Copy both values immediately** (secret is shown only once):
   - Access key ID → `AKIA...`
   - Secret access key → `wJalr...`

#### 4. Save admin keys in `.env.admin` (NOT `.env`)

```powershell
copy .env.admin.example .env.admin
```

Edit `.env.admin`:

```env
AWS_ACCESS_KEY_ID=AKIA...your-admin-key...
AWS_SECRET_ACCESS_KEY=...your-admin-secret...
AWS_DEFAULT_REGION=ap-south-1
```

> `.env.admin` is in `.gitignore` — never commit it.  
> Keep `.env` as `aivar-scanner` read-only keys for all scans.

#### 5. Install AWS CLI (if not installed)

Download: [AWS CLI v2 for Windows](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

Verify:

```powershell
aws --version
aws sts get-caller-identity
# Should fail until you set admin creds — that's OK
```

#### 6. Run setup with admin credentials

**Recommended** — uses `.env.admin` automatically:

```powershell
.\scripts\run_setup_as_admin.ps1
```

**Alternative** — set admin creds in current terminal only (does not touch any file):

```powershell
$env:AWS_ACCESS_KEY_ID = "AKIA...admin..."
$env:AWS_SECRET_ACCESS_KEY = "...admin-secret..."
$env:AWS_DEFAULT_REGION = "ap-south-1"
.\scripts\setup_test_misconfigs.ps1
# Clear admin creds from session after setup:
Remove-Item Env:AWS_ACCESS_KEY_ID, Env:AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
```

#### 7. Verify & scan (scanner creds from `.env`)

```powershell
.\scripts\verify_test_misconfigs.ps1    # 5/5 PASS
python main.py --config checklist.yaml --verbose
python scripts\verify_acceptance.py
```

#### 8. Expected 8 findings after setup

| # | Finding | Check ID | Severity |
|---|---------|----------|----------|
| 1 | Public S3 bucket | `s3_public_acl` | Critical |
| 2 | Open SSH security group | `sg_open_ssh` | Critical |
| 3 | Open RDP security group | `sg_open_rdp` | Critical |
| 4 | Root MFA disabled | `iam_root_mfa` | Critical |
| 5 | Public S3 bucket policy | `s3_public_policy` | Critical |
| 6 | IAM user without MFA | `iam_user_mfa` | High |
| 7 | CloudTrail not logging | `cloudtrail_not_logging` | High |
| 8 | Weak password policy | `iam_password_policy` | Medium |

#### 9. Cleanup when done

```powershell
# Use admin creds again for cleanup
.\scripts\run_setup_as_admin.ps1   # or set admin env vars
.\scripts\cleanup_test_misconfigs.ps1
```

---

### Creating Test Misconfigurations (Demo Environment)

### What Gets Created vs What Gets Detected

| Type | Count | Source |
|------|-------|--------|
| Intentional test resources | **5** | You create (Console or CLI script) |
| Natural account defaults | **3** | Already present on new AWS accounts |
| **Expected total findings** | **~8** | After all 5 test resources exist |

| # | Resource | Check ID | Expected Severity |
|---|----------|----------|-------------------|
| 1 | S3 bucket with public-read ACL | `s3_public_acl` | Critical |
| 2 | S3 bucket with public read policy | `s3_public_policy` | Critical |
| 3 | IAM user `test-no-mfa-user` (console, no MFA) | `iam_user_mfa` | High |
| 4 | Security group `open-ssh-sg` (port 22 / 0.0.0.0/0) | `sg_open_ssh` | Critical |
| 5 | Security group `open-rdp-sg` (port 3389 / 0.0.0.0/0) | `sg_open_rdp` | Critical |
| 6 | Root MFA disabled *(default)* | `iam_root_mfa` | Critical |
| 7 | No CloudTrail trail *(default)* | `cloudtrail_not_logging` | High |
| 8 | No password policy *(default)* | `iam_password_policy` | Medium |

---

### Option A: AWS Console (recommended if you only have scanner CLI keys)

Log into [AWS Console](https://console.aws.amazon.com) as **root or admin** in browser. Region: **ap-south-1**. Keep `.env` pointed at `aivar-scanner` for scanning.

#### 1. Public S3 Bucket (Critical — `s3_public_acl`)

1. Go to **S3** → **Create bucket**
2. Bucket name: `aivar-test-public-manual` (or any name starting with `aivar-test-public`)
3. Region: **Asia Pacific (Mumbai) ap-south-1**
4. **Uncheck all 4** "Block Public Access" settings → acknowledge the warning
5. Create bucket
6. Open bucket → **Permissions** → **Access control list (ACL)** → **Edit**
7. Enable ACLs if prompted
8. Under **Public access**, grant **Everyone (public access)** → **List** and **Read** (or `public-read`)
9. Save

#### 2. Public S3 Bucket Policy (Critical — `s3_public_policy`)

> **Note:** Newer AWS accounts enforce **account-level S3 default encryption**, so an unencrypted bucket (`s3_encryption_disabled`) cannot be created reliably. The demo uses a **public bucket policy** instead.

1. **S3** → **Create bucket**
2. Name: `aivar-test-policy-manual` (or `aivar-test-policy-*`)
3. Region: **ap-south-1**
4. **Uncheck all 4** Block Public Access settings → acknowledge
5. Create bucket → **Permissions** → **Bucket policy** → **Edit**
6. Paste a policy that allows `s3:GetObject` for `"Principal": "*"` on `arn:aws:s3:::BUCKET_NAME/*`
7. Save — **Access** column should show **Public**

#### 3. IAM User Without MFA (High — `iam_user_mfa`)

1. Go to **IAM** → **Users** → **Create user**
2. User name: `test-no-mfa-user`
3. Enable **Provide user access to the AWS Management Console**
4. Set a custom password (e.g. `TestPass@123!`)
5. Uncheck "User must create a new password at next sign-in" if shown
6. Create user — **do not** attach any MFA device

#### 4. Open SSH Security Group (Critical — `sg_open_ssh`)

1. Go to **EC2** → **Security Groups** → **Create security group**
2. Name: `open-ssh-sg`
3. VPC: default VPC in `ap-south-1`
4. **Inbound rules** → Add rule:
   - Type: **SSH**
   - Port: **22**
   - Source: **0.0.0.0/0**
5. Create security group

#### 5. Open RDP Security Group (Critical — `sg_open_rdp`)

1. **EC2** → **Security Groups** → **Create security group**
2. Name: `open-rdp-sg`
3. VPC: default VPC in `ap-south-1`
4. **Inbound rules** → Add rule:
   - Type: **RDP**
   - Port: **3389**
   - Source: **0.0.0.0/0**
5. Create security group

---

### Option B: CLI Setup Script (requires admin credentials)

**Do not** use `aivar-scanner` keys. Use admin credentials via `.env.admin`:

**Windows (recommended):**
```powershell
.\scripts\run_setup_as_admin.ps1
```

**Or directly** (if admin creds already in terminal env):
```powershell
.\scripts\setup_test_misconfigs.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/setup_test_misconfigs.sh
./scripts/setup_test_misconfigs.sh
```

The script is idempotent (get-or-create security groups, PASS/FAIL per resource) and auto-runs verification when finished.

**Resources created by script:**

| Resource | Name pattern |
|----------|--------------|
| Public S3 bucket | `aivar-test-public-{timestamp}` |
| Public-policy S3 bucket | `aivar-test-policy-{timestamp}` |
| IAM user | `test-no-mfa-user` |
| Security group | `open-ssh-sg` |
| Security group | `open-rdp-sg` |

---

### Verify Test Resources (scanner read-only creds)

After creating resources, confirm the scanner can see them:

```powershell
.\scripts\verify_test_misconfigs.ps1
```

Expected: **5/5 PASS**

Then run a scan:

```powershell
python main.py --config checklist.yaml --verbose
python scripts\verify_acceptance.py
```

### Cleanup After Demo

```powershell
.\scripts\cleanup_test_misconfigs.ps1
```

---

## 8. Screenshots & Demo Evidence

Level 1 **code and verification are complete**. Remaining submission items are evidence capture (screenshots, demo video, writeup PDF).

Place screenshots in `docs/screenshots/` and reference them below. Replace `PLACEHOLDER` paths after capturing.

> **Tip:** Capture screenshots at 1920×1080. Use the same AWS account and region (`ap-south-1`) in all shots.

### Recommended Screenshots for Submission

| # | What to Capture | Save As | Insert In README |
|---|-----------------|---------|------------------|
| 1 | Architecture / data flow (draw.io or exported diagram) | `docs/screenshots/01-architecture.png` | [Section 5](#5-architecture--design-decisions) |
| 2 | `checklist.yaml` showing 13 enabled checks | `docs/screenshots/02-checklist-yaml.png` | [Section 3](#3-level-1--what-was-built) |
| 3 | Terminal: `python main.py --verbose` scan running | `docs/screenshots/03-scan-running.png` | [Section 6](#6-setup--run-guide) |
| 4 | Dashboard — KPI cards + findings table (full demo with ~8 findings) | `docs/screenshots/04-dashboard-findings.png` | [Section 3](#3-level-1--what-was-built) |
| 5 | Dashboard — expanded finding (evidence + remediation CLI) | `docs/screenshots/05-finding-detail.png` | [Section 4](#4-level-1--acceptance-criteria) |
| 6 | JSON report — Critical finding with `raw_evidence` | `docs/screenshots/06-json-report.png` | [Section 4](#4-level-1--acceptance-criteria) |
| 7 | Markdown report — Scan Health section | `docs/screenshots/07-scan-health.png` | [Section 4](#4-level-1--acceptance-criteria) |
| 8 | `verify_acceptance.py` — ALL CRITERIA PASSED | `docs/screenshots/08-acceptance-pass.png` | [Section 4](#4-level-1--acceptance-criteria) |
| 9 | AWS Console — public S3 bucket ACL + public policy bucket | `docs/screenshots/09-aws-s3-public.png` | [Section 7](#7-how-to-get-admin-credentials--create-all-8-findings) |
| 10 | AWS Console — open SSH security group rule | `docs/screenshots/10-aws-open-ssh-sg.png` | [Section 7](#7-creating-test-misconfigurations-demo-environment) |
| 11 | `verify_test_misconfigs.ps1` — 5/5 PASS | `docs/screenshots/11-verify-misconfigs.png` | [Section 7](#7-creating-test-misconfigurations-demo-environment) |
| 12 | IAM scanner user with read-only policies | `docs/screenshots/12-iam-scanner-user.png` | [Section 6](#6-setup--run-guide) |

### Screenshot Placeholders (replace after capture)

#### Architecture
<!-- Replace with: ![Architecture](docs/screenshots/01-architecture.png) -->
> `[PLACEHOLDER: docs/screenshots/01-architecture.png]`

#### Dashboard — Findings Overview
<!-- Replace with: ![Dashboard](docs/screenshots/04-dashboard-findings.png) -->
> `[PLACEHOLDER: docs/screenshots/04-dashboard-findings.png]`

#### JSON Report — Critical Finding
<!-- Replace with: ![JSON Report](docs/screenshots/06-json-report.png) -->
> `[PLACEHOLDER: docs/screenshots/06-json-report.png]`

#### Acceptance Verification
<!-- Replace with: ![Acceptance](docs/screenshots/08-acceptance-pass.png) -->
> `[PLACEHOLDER: docs/screenshots/08-acceptance-pass.png]`

#### Test Misconfigs Verification (5/5 PASS)
<!-- Replace with: ![Verify Misconfigs](docs/screenshots/11-verify-misconfigs.png) -->
> `[PLACEHOLDER: docs/screenshots/11-verify-misconfigs.png]`

### Demo Video

Link your Loom / YouTube demo here:

> `[PLACEHOLDER: Demo video URL]`

### Level 1 Submission Checklist

| Item | Status |
|------|--------|
| 13 boto3 checks implemented | Done |
| LLM enrichment + severity guard rails | Done |
| JSON + Markdown reports | Done |
| Interactive dashboard + full demo | Done |
| `verify_acceptance.py` — all criteria pass | Done |
| 8-finding demo verified on live AWS | Done |
| Screenshots in `docs/screenshots/` | **Pending** — capture per table above |
| Demo video (5-8 min) | **Pending** - script in `agent2_level1_plan.md` Section 10 |
| Writeup PDF (architecture + decisions) | **Pending** |
| Updated resume | **Pending** |

---

## 9. Level 2 — Multi-Domain Scanning

Per Aivar problem statement — **implemented and verified.**

### Goal

Expand beyond AWS infrastructure to:

- **Live API endpoints** — authentication bypass, CORS, rate limiting, security headers, error disclosure, dangerous HTTP methods (6 checks)
- **Code dependencies** — CVE detection via OSV API with package name, version, CVE ID, CVSS, fix version
- **Secrets scanning** — 12 regex patterns for AWS keys, API tokens, passwords in repos/config files
- **Cross-domain merge** — deduplicate and rank all findings by business impact (`impact_score`)

### What Was Built

| Component | File(s) | Description |
|-----------|---------|-------------|
| API scanner | `checks/api_checks.py`, `utils/http_client.py` | 6 HTTP checks against configured URLs |
| Dependency scanner | `checks/dependency_checks.py`, `utils/osv_client.py` | Parses `requirements.txt` / `package.json`, OSV batch query |
| Secrets scanner | `checks/secrets_checks.py` | Local regex scan with false-positive suppression |
| Deduplicator | `agent/deduplicator.py` | Fingerprint-based cross-domain dedup |
| Impact ranker | `agent/impact_ranker.py` | `(severity + bonus) × domain_weight × confidence` |
| L2 orchestrator | `agent/orchestrator_l2.py` | 4 domains in parallel → LLM → dedup → rank |
| Config | `checklist_l2.yaml` | AWS + API targets + dependency paths + secrets paths |
| Demo fixtures | `test_secrets.env`, `test_vulnerable_requirements.txt` | Safe fake secrets and known CVE pins for demo |

### Run Level 2

**CLI:**

```powershell
pip install -r requirements.txt
python main.py --level 2 --config checklist_l2.yaml --verbose
```

**Dashboard:**

```powershell
uvicorn dashboard.app:app --reload --port 8000
```

Open http://127.0.0.1:8080 and use the **Level tabs** at the top:

- **Level 1 tab** - demo environment, Run Full Demo, and **Run Level 1 Scan** (AWS only)
- **Level 2 tab** - **Run Level 2 Scan** (multi-domain audit with impact-ranked findings)
- **Level 3 tab** - preview of planned continuous scanning features (not yet implemented)

Each level shows its own reports in scan history (filtered by level).

### Level 2 Acceptance Criteria

| Criterion | Status |
|-----------|--------|
| Scans 3+ domains: AWS, APIs, dependencies (+ secrets bonus) | Done |
| Infrastructure: 10+ checks | Done (13 from Level 1) |
| APIs: 5+ checks | Done (6 checks) |
| Dependencies: accurate CVE detection | Done (OSV API) |
| Secrets scanning | Done (12 patterns) |
| Cross-domain deduplication | Done |
| False positive rate < 5% on High/Critical | Done (LLM rules + skip patterns) |
| Findings ranked by business impact | Done (`impact_score` descending) |

**Verify:**

```powershell
python scripts\verify_acceptance_l2.py
```

Expected: `ALL LEVEL 2 ACCEPTANCE CRITERIA PASSED`

### L2 Architecture

```
checklist_l2.yaml
       │
       ▼
OrchestratorL2 (4 parallel domains)
  ├── AWS (13 boto3 checks)
  ├── API (6 HTTP checks → httpbin.org)
  ├── Dependencies (OSV batch → test_vulnerable_requirements.txt)
  └── Secrets (regex → test_secrets.env)
       │
       ▼
LLM enrichment → deduplicate → rank_by_impact → JSON + Markdown reports
```

### L2 Troubleshooting

| Issue | Fix |
|-------|-----|
| Groq 429 / daily token limit | Level 2 uses template enrichment for API, CVE, and secrets (no LLM). Only AWS findings call Groq. If quota is exhausted, AWS findings use templates too. Wait ~15 min for daily reset. |
| OSV API timeout | Check network; retry scan - dependency domain may show `api_error` in scan health |
| No API findings | Ensure `https://httpbin.org` is reachable; localhost target optional |
| Rate-limit check slow | Sends 30 requests per API target — normal (~30s per target) |
| Secrets not found | Confirm `test_secrets.env` exists; `.env` / `.env.admin` are excluded from scan |
| L1 regression | Run `python main.py --level 1` and `python scripts\verify_acceptance.py` |

---

## 10. Level 3 — Autonomous Continuous Scanning *(Not Started)*

Per Aivar problem statement — **planned, not yet implemented.**

### Goal

Operate as a persistent service:

- Scheduled scans (no manual trigger)
- Finding lifecycle: opened → updated → resolved → re-opened → SLA status
- Deduplication across runs
- Critical findings escalate to notification channel immediately
- SLA alerts when Critical unresolved beyond 24 hours
- Audit trail and trend reporting (posture score over time)
- Scan health reporting — never silently skip failed checks

### Level 3 Acceptance Criteria (Reference)

| Criterion | Status |
|-----------|--------|
| Configurable schedule, no manual trigger | Not started |
| Finding lifecycle + deduplication | Not started |
| Critical escalation to notification channel | Not started |
| SLA tracking (24h Critical) | Not started |
| Audit trail | Not started |
| Trend reporting / posture score | Not started |
| Scan health reporting | Partially done in Level 1 (`scan_health` field) |
| Optional safe auto-remediation with approval gate | Not started |

> **I will update this section after Level 3 is implemented.**

---

## 11. Project Structure

```
offensive-security-agent/
├── main.py                      # CLI entry point (--level 1 or 2)
├── checklist.yaml               # Level 1 scan config (13 checks)
├── checklist_l2.yaml            # Level 2 multi-domain config
├── test_secrets.env             # Demo fake secrets for L2 scanner
├── test_vulnerable_requirements.txt  # Demo CVE pins for L2
├── requirements.txt
├── agent2_level1_plan.md        # Technical build plan (Level 1)
├── agent2_level2_plan.md        # Technical build plan (Level 2)
├── config/loader.py             # YAML/JSON config loader
├── models/                      # Pydantic: ScanConfig, RawFinding, ValidatedFinding, ScanReport
├── checks/
│   ├── iam_checks.py            # 5 IAM checks
│   ├── s3_checks.py             # 3 S3 checks
│   ├── ec2_checks.py            # 3 EC2/EBS checks
│   ├── cloudtrail_checks.py     # 2 CloudTrail/EBS snapshot checks
│   ├── api_checks.py            # 6 API endpoint checks (L2)
│   ├── dependency_checks.py     # OSV CVE scanner (L2)
│   └── secrets_checks.py        # Regex secrets scanner (L2)
├── agent/
│   ├── orchestrator.py          # L1 parallel execution + report assembly
│   ├── orchestrator_l2.py       # L2 multi-domain orchestrator
│   ├── deduplicator.py          # Cross-domain dedup (L2)
│   ├── impact_ranker.py         # Business impact scoring (L2)
│   ├── intelligence.py          # LLM enrichment + severity guard rails
│   └── runner.py                # Scan entry for CLI and dashboard
├── reporter/                    # JSON + Markdown report generators
├── dashboard/                   # FastAPI web UI (L1 + L2)
│   ├── app.py                   # API routes
│   ├── misconfig_service.py     # Create/verify/cleanup demo misconfigs
│   ├── demo_service.py          # Full demo orchestration
│   ├── scan_service.py          # Scan with step-by-step progress
│   └── static/                  # index.html, app.js, app.css
├── utils/
│   ├── aws_client.py            # Boto3 session factory
│   ├── http_client.py           # API scanner HTTP session (L2)
│   ├── osv_client.py              # OSV batch API client (L2)
│   ├── llm_client.py            # Groq / Grok / OpenAI resolver
│   └── retry.py                 # safe_aws_call with backoff
├── scripts/
│   ├── verify_acceptance.py              # Level 1 acceptance check
│   ├── verify_acceptance_l2.py           # Level 2 acceptance check
│   └── ...
└── reports/                     # Generated scan reports (*_l2.json for Level 2)
```

---

## 12. Troubleshooting

| Issue | Fix |
|-------|-----|
| Only 3 findings in dashboard | Create admin user (Section 7), click **Run Full Demo** or run `run_setup_as_admin.ps1` + `verify_test_misconfigs.ps1` |
| 7 findings instead of 8 | Account-level S3 default encryption blocks unencrypted-bucket demo; use updated setup (`s3_public_policy` bucket) — see Section 7 note |
| Dashboard shows stale report | Click **Run Full Demo** again after restart, or **Run Scan** after creating misconfigs |
| `aws` CLI not found | Install [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| `.env.admin not found` | `copy .env.admin.example .env.admin` and add `aivar-admin` keys |
| Setup script AccessDenied | Admin user needs `AdministratorAccess` policy |
| `InvalidClientTokenId` | Check AWS keys in `.env` match `aivar-scanner` |
| `AccessDenied` in scan_errors | Attach missing read-only policy to scanner user |
| S3 public ACL setup fails | Disable Block Public Access on the test bucket only |
| LLM enrichment fails | Verify `GROQ_API_KEY` at [console.groq.com](https://console.groq.com) |
| Root MFA rated High not Critical | Fixed via evidence floor in `intelligence.py` — re-run scan |
| Python 3.14 install errors | Use `pydantic>=2.10.0` (already in requirements.txt) |

---

## Contact

**Manikandan M**  
Email: 19manikandan2005@gmail.com  

Built for the **Aivar Innovations AI/ML Hiring Challenge — June 2026**.
