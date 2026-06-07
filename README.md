# Agent 2: Offensive Security Agent

**Aivar Innovations — AI/ML Engineering Hiring Challenge (June 2026)**

| | |
|---|---|
| **Candidate** | Manikandan M |
| **Agent** | Agent 2 — Offensive Security Agent |
| **Status** | Level 1 complete · Level 2 & 3 not started |
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
7. [Creating Test Misconfigurations (Demo Environment)](#7-creating-test-misconfigurations-demo-environment)
8. [Screenshots & Demo Evidence](#8-screenshots--demo-evidence)
9. [Level 2 — Multi-Domain Scanning *(Not Started)*](#9-level-2--multi-domain-scanning-not-started)
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
| **Level 2** | Extend to AWS infrastructure + live API endpoints + code dependency CVEs; merge and rank by business impact | Each domain has different signal norms | **Not started** |
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
| Web dashboard | FastAPI dashboard at `http://127.0.0.1:8080` — KPI cards, findings table, scan history, Run Scan button |
| Verification scripts | `scripts/verify_acceptance.py`, `scripts/verify_test_misconfigs.ps1` |

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
- Built web dashboard for demo and scan history
- Created AWS setup, verification, cleanup, and acceptance scripts
- Tested against live AWS account `563999587682` in `ap-south-1` — all 7 acceptance criteria pass
- Documented Console and CLI paths for creating demo misconfigurations

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

### Create Scanner IAM User (read-only)

In AWS Console → IAM, create user `aivar-scanner` with:

- `AmazonS3ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `AWSCloudTrailReadOnlyAccess`

Paste access keys into `.env`. **Never use root credentials for scanning.**

### Run Scan (CLI)

```powershell
python main.py --config checklist.yaml --verbose
```

Reports: `reports/findings_report_{timestamp}.json` and `.md`

### Run Dashboard

```powershell
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
```

Open **http://127.0.0.1:8080**

---

## 7. Creating Test Misconfigurations (Demo Environment)

The scanner only reports misconfigurations that **exist in AWS**. A fresh account has ~3 natural findings (root MFA, CloudTrail, password policy). For a full demo with **~8 findings and 4+ Critical**, create **5 intentional test resources** plus the 3 natural ones.

### What Gets Created vs What Gets Detected

| Type | Count | Source |
|------|-------|--------|
| Intentional test resources | **5** | You create (Console or CLI script) |
| Natural account defaults | **3** | Already present on new AWS accounts |
| **Expected total findings** | **~8** | After all 5 test resources exist |

| # | Resource | Check ID | Expected Severity |
|---|----------|----------|-------------------|
| 1 | S3 bucket with public-read ACL | `s3_public_acl` | Critical |
| 2 | S3 bucket without encryption | `s3_encryption_disabled` | High |
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

#### 2. Unencrypted S3 Bucket (High — `s3_encryption_disabled`)

1. **S3** → **Create bucket**
2. Name: `aivar-test-noenc-manual` (or `aivar-test-noenc-*`)
3. Region: **ap-south-1**
4. Leave **Default encryption** as **Disabled**
5. Create bucket (do not enable encryption afterward)

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

### Option B: CLI Setup Script (requires admin AWS CLI credentials)

**Do not** use `aivar-scanner` keys for this step. Configure admin credentials in your AWS CLI profile or environment.

**Windows:**
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
| Unencrypted S3 bucket | `aivar-test-noenc-{timestamp}` |
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
| 9 | AWS Console — public S3 bucket ACL (test misconfig) | `docs/screenshots/09-aws-s3-public.png` | [Section 7](#7-creating-test-misconfigurations-demo-environment) |
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

---

## 9. Level 2 — Multi-Domain Scanning *(Not Started)*

Per Aivar problem statement — **planned, not yet implemented.**

### Goal

Expand beyond AWS infrastructure to:

- **Live API endpoints** — authentication bypass, CORS, rate limiting, security headers, error disclosure
- **Code dependencies** — CVE detection with package name, version, CVE ID, CVSS, fix version
- **Secrets scanning** — AWS keys, API tokens, password patterns in repos/config files
- **Cross-domain merge** — deduplicate and rank all findings by business impact

### Level 2 Acceptance Criteria (Reference)

| Criterion | Status |
|-----------|--------|
| Scans 3+ domains: AWS, APIs, dependencies | Not started |
| Infrastructure: 10+ checks | Done in Level 1 |
| APIs: 5+ checks | Not started |
| Dependencies: accurate CVE detection | Not started |
| Secrets scanning | Not started |
| Cross-domain deduplication | Not started |
| False positive rate < 5% on High/Critical | Not started |
| Findings ranked by business impact | Not started |

> **I will update this section after Level 2 is implemented.**

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
├── main.py                      # CLI entry point
├── checklist.yaml               # Scan configuration (13 checks)
├── requirements.txt
├── .env.example
├── agent2_level1_plan.md        # Technical build plan (Level 1)
├── config/loader.py             # YAML/JSON config loader
├── models/                      # Pydantic: ScanConfig, RawFinding, ValidatedFinding, ScanReport
├── checks/                      # 13 boto3 check implementations
│   ├── iam_checks.py            # 5 IAM checks
│   ├── s3_checks.py             # 3 S3 checks
│   ├── ec2_checks.py            # 3 EC2/EBS checks
│   └── cloudtrail_checks.py     # 2 CloudTrail/EBS snapshot checks
├── agent/
│   ├── orchestrator.py          # Parallel execution + report assembly
│   ├── intelligence.py          # LLM enrichment + severity guard rails
│   └── runner.py                # Scan entry for CLI and dashboard
├── reporter/                    # JSON + Markdown report generators
├── dashboard/                   # FastAPI web UI
├── utils/
│   ├── aws_client.py            # Boto3 session factory
│   ├── llm_client.py            # Groq / Grok / OpenAI resolver
│   └── retry.py                 # safe_aws_call with backoff
├── scripts/
│   ├── setup_test_misconfigs.ps1 / .sh   # Create demo misconfigs (admin)
│   ├── verify_test_misconfigs.ps1        # Verify misconfigs (scanner)
│   ├── verify_acceptance.py              # Level 1 acceptance check
│   └── cleanup_test_misconfigs.ps1       # Remove test resources
├── docs/screenshots/            # Demo screenshots (see Section 8)
└── reports/                     # Generated scan reports
```

---

## 12. Troubleshooting

| Issue | Fix |
|-------|-----|
| Only 3 findings in dashboard | Create the 5 test misconfigs (Section 7); run `verify_test_misconfigs.ps1` |
| `InvalidClientTokenId` | Check AWS keys in `.env` match `aivar-scanner` |
| `AccessDenied` in scan_errors | Attach missing read-only policy to scanner user |
| S3 public ACL setup fails | Disable Block Public Access on the test bucket only |
| LLM enrichment fails | Verify `GROQ_API_KEY` at [console.groq.com](https://console.groq.com) |
| Root MFA rated High not Critical | Fixed via evidence floor in `intelligence.py` — re-run scan |
| `aws` CLI not found | Use Console setup (Option A) or install [AWS CLI v2](https://aws.amazon.com/cli/) |
| Python 3.14 install errors | Use `pydantic>=2.10.0` (already in requirements.txt) |

---

## Contact

**Manikandan M**  
Email: 19manikandan2005@gmail.com  

Built for the **Aivar Innovations AI/ML Hiring Challenge — June 2026**.
