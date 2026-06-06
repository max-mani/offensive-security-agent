# Offensive Security Agent - Level 1

AI-powered AWS infrastructure security scanner for the **Aivar Innovations AI/ML Hiring Challenge**. Reads a YAML checklist, executes 13 real boto3 checks against live AWS infrastructure, enriches findings with GPT-4o-mini, and produces JSON + Markdown reports.

## Architecture

```
main.py --> config/loader.py --> agent/orchestrator.py
                                      |
                    +-----------------+------------------+
                    |                 |                  |
              checks/ (13)    agent/intelligence.py   scan_errors
              boto3 APIs      LLM enrichment               |
                    |                 |                  |
                    +--------> ValidatedFinding <--------+
                                      |
                         reporter/json + markdown
```

**Key design:** boto3 detects facts; the LLM only enriches (never creates findings). This prevents hallucinated Critical severity ratings.

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ (tested on 3.14) |
| AWS account | ap-south-1 region |
| LLM API key | Groq (`GROQ_API_KEY`, free tier) preferred; Grok or OpenAI as fallback |
| AWS CLI | Optional (for setup scripts) |

## Quick Start

```powershell
cd offensive-security-agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# Edit .env with AWS scanner credentials and GROQ_API_KEY (free tier at console.groq.com)
python main.py --config checklist.yaml --verbose
```

Reports are written to `reports/findings_report_{timestamp}.json` and `.md`.

## Web Dashboard

Launch a local dashboard to view findings, scan history, and trigger scans from the browser:

```powershell
cd offensive-security-agent
.\venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
```

Open **http://127.0.0.1:8080** in your browser.

| Feature | Description |
|---------|-------------|
| KPI cards | Critical / High / Medium / Total findings at a glance |
| Scan metadata | Account, region, health, duration, check stats |
| Findings table | Expandable rows with evidence, business impact, remediation steps |
| Copy CLI | One-click copy of `remediation_command` (no auto-execution) |
| Run Scan | Triggers the same scan pipeline as `python main.py` |
| Scan history | Dropdown to view past reports from `reports/` |

**Security note:** The dashboard binds to `127.0.0.1` only. Do not expose it publicly — it uses AWS credentials from `.env`.

## AWS Setup

### Step 1: Create Scanner IAM User (read-only)

In the AWS Console (IAM), create user `aivar-scanner` with these managed policies:

- `AmazonS3ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `AWSCloudTrailReadOnlyAccess`

Generate access keys and paste into `.env`. **Never use root credentials for scanning.**

### Step 2: Create Test Misconfigurations

You need **admin credentials** to create test resources. The scanner user (`aivar-scanner`) is read-only and cannot create them.

#### Option A: AWS Console (no admin CLI keys required)

Log into the [AWS Console](https://console.aws.amazon.com) as root or an admin IAM user. Set region to **ap-south-1**. Keep `.env` pointed at `aivar-scanner` for scanning.

| # | Resource | Console steps |
|---|----------|---------------|
| 1 | Public S3 bucket | S3 → Create bucket `aivar-test-public-manual` → uncheck all 4 "Block Public Access" boxes → Permissions → ACL → grant **Public read** |
| 2 | Unencrypted S3 | S3 → Create bucket `aivar-test-noenc-manual` → do **not** enable default encryption |
| 3 | IAM no MFA | IAM → Users → Create `test-no-mfa-user` → enable console access → do **not** attach MFA |
| 4 | Open SSH SG | EC2 → Security Groups → Create `open-ssh-sg` → inbound TCP **22** from `0.0.0.0/0` |
| 5 | Open RDP SG | EC2 → Security Groups → Create `open-rdp-sg` → inbound TCP **3389** from `0.0.0.0/0` |

Verify resources are visible to the scanner (uses read-only `.env` creds):

```powershell
.\scripts\verify_test_misconfigs.ps1
```

#### Option B: CLI setup script (requires admin AWS CLI credentials)

**Windows (PowerShell):**
```powershell
.\scripts\setup_test_misconfigs.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/setup_test_misconfigs.sh
./scripts/setup_test_misconfigs.sh
```

The setup script is idempotent and runs `verify_test_misconfigs.ps1` automatically when finished.

This creates:

| Resource | Check ID | Expected Severity |
|----------|----------|-------------------|
| S3 bucket with public-read ACL | `s3_public_acl` | Critical |
| S3 bucket without encryption | `s3_encryption_disabled` | High |
| IAM user `test-no-mfa-user` (console, no MFA) | `iam_user_mfa` | High |
| Security group `open-ssh-sg` (port 22 / 0.0.0.0/0) | `sg_open_ssh` | Critical |
| Security group `open-rdp-sg` (port 3389 / 0.0.0.0/0) | `sg_open_rdp` | Critical |
| Root MFA disabled (default on new accounts) | `iam_root_mfa` | Critical |
| No CloudTrail trail (default) | `cloudtrail_not_logging` | High |
| No password policy (default) | `iam_password_policy` | Medium |

**Note:** If S3 Block Public Access blocks ACL changes, the setup script disables BPA on test buckets only.

### Step 3: Verify Test Resources (scanner creds)

```powershell
.\scripts\verify_test_misconfigs.ps1
```

All five checks should show **PASS** before running a demo scan.

### Step 4: Verify Connectivity

```powershell
aws sts get-caller-identity --region ap-south-1
```

### Step 5: Run Scan

```powershell
python main.py --config checklist.yaml --verbose
```

### Step 6: Verify Acceptance Criteria

```powershell
python scripts\verify_acceptance.py
```

## Configuration

Edit `checklist.yaml` to enable/disable checks or adjust settings:

```yaml
scan:
  aws_region: "ap-south-1"
  max_workers: 5          # parallel check threads
  llm_model: "llama-3.3-70b-versatile"   # Groq model; or grok-3-mini / gpt-4o-mini
  output_dir: "reports"

checks:
  - id: sg_open_ssh
    enabled: true
    severity_cap: critical   # LLM cannot exceed this severity
```

| Field | Description |
|-------|-------------|
| `enabled` | Set `false` to skip a check |
| `severity_cap` | Maximum severity the LLM can assign |
| `unused_days_threshold` | Days before flagging unused IAM keys (default: 90) |

## Security Checks (13 total)

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

## Output

### JSON Report (`reports/findings_report_{timestamp}.json`)

Machine-readable report with scan metadata, findings sorted by severity, and scan health errors.

Each finding includes:
- `resource_arn`, `severity`, `raw_evidence` (actual boto3 API data)
- `business_impact`, `remediation_steps`, `remediation_command`
- `confidence_score` (0-100)

### Markdown Report (`reports/findings_report_{timestamp}.md`)

Human-readable report with executive summary, findings grouped by severity, and a Scan Health section listing any checks that failed to execute.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Detection | boto3 checks only | Facts from AWS APIs, no LLM hallucination |
| Enrichment | GPT-4o-mini at temp 0.1 | Business impact + remediation commands |
| Severity | LLM validates + `severity_cap` + confidence downgrade | Zero false Critical findings |
| Parallelism | ThreadPoolExecutor (5 workers) | boto3 is I/O bound |
| Errors | Per-check try/catch, never global | One failure does not kill the scan |
| Config | YAML checklist | Human-readable, easy to extend |

## Level 1 Acceptance Criteria

| # | Criterion | Implementation |
|---|-----------|----------------|
| 1 | Reads YAML/JSON checklist | `config/loader.py` + `checklist.yaml` |
| 2 | 10+ distinct checks | 13 checks in `CHECK_REGISTRY` |
| 3 | Complete finding fields | `ValidatedFinding` model + LLM enrichment |
| 4 | API errors not swallowed | `utils/retry.py` + `scan_errors` in report |
| 5 | JSON + Markdown output | `reporter/json_reporter.py` + `markdown_reporter.py` |
| 6 | Zero false Critical | Direct API evidence required + severity cap + confidence downgrade |
| 7 | Real infrastructure | boto3 session with real AWS credentials |

Run `python scripts/verify_acceptance.py` after configuring `.env` to validate all criteria.

## Project Structure

```
offensive-security-agent/
├── main.py                 # CLI entry point
├── checklist.yaml          # Scan configuration
├── requirements.txt
├── .env.example
├── config/loader.py        # YAML config loader
├── models/                 # Pydantic data models
├── checks/                 # 13 boto3 check implementations
├── agent/                  # Orchestrator + LLM intelligence + runner
├── dashboard/              # Web UI (FastAPI + static frontend)
├── reporter/               # JSON + Markdown report generators
├── utils/                  # AWS client + retry logic
├── scripts/                # AWS setup, cleanup, verification
└── reports/                # Generated scan reports
```

## Cost Estimate

All test resources are free-tier eligible. Each scan costs approximately $0.01-0.05 in OpenAI API usage (depends on finding count).

## Cleanup

After demo/submission, remove test resources:

```powershell
.\scripts\cleanup_test_misconfigs.ps1
```

Also delete the `aivar-scanner` IAM user access keys if no longer needed.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `InvalidClientTokenId` | Check AWS keys in `.env` match the scanner IAM user |
| `AccessDenied` in scan_errors | Attach missing read-only policy to scanner user |
| S3 public ACL setup fails | Account Block Public Access may need disabling on test buckets |
| LLM enrichment fails | Verify `GROK_API_KEY` or `OPENAI_API_KEY`; add credits at console.x.ai or platform.openai.com |
| Python 3.14 install errors | Use `pydantic>=2.10.0` (prebuilt wheels) |

## License

Built for the Aivar Innovations AI/ML Hiring Challenge - June 2026.
