# Offensive Security Agent

**Aivar Innovations — AI/ML Engineering Hiring Challenge (June 2026)**

| | |
|---|---|
| **Candidate** | Manikandan M |
| **Agent** | Agent 2 — Offensive Security Agent |
| **Status** | Level 1, 2, and 3 complete |
| **Verified** | 7 June 2026 — account `563999587682`, region `ap-south-1` |
| **Repository** | [offensive-security-agent](https://github.com/max-mani/offensive-security-agent) |

---

## What this does

This agent scans real AWS infrastructure (and, at higher levels, live APIs, dependency CVEs, and secrets) for security misconfigurations. Detection is always deterministic — boto3, HTTP checks, OSV, regex. An LLM layer adds business impact, remediation steps, and confidence scores. It never invents findings.

Three progressive levels:

| Level | Scope | What makes it hard |
|-------|--------|-------------------|
| **L1** | 13 AWS checks from `checklist.yaml` | Zero false Critical findings |
| **L2** | AWS + API + CVE + secrets, merged and ranked | Each domain has different signal norms |
| **L3** | L2 on a schedule with SQLite memory, SLAs, Slack escalation | Silent scan failures are worse than missed scans |

---

## Quick start

**Requirements:** Python 3.10+, AWS credentials for `ap-south-1`, a Groq API key (`GROQ_API_KEY` in `.env`).

```powershell
cd offensive-security-agent
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Add AWS scanner keys + GROQ_API_KEY to .env
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
```

Open **http://127.0.0.1:8080**. The dashboard covers all three levels — no terminal required for demos.

CLI scans:

```powershell
python main.py --config checklist.yaml --verbose              # L1
python main.py --level 2 --config checklist_l2.yaml --verbose # L2
python main.py --level 3 --config checklist_l3.yaml --verbose # L3
```

Reports land in `reports/` as JSON and Markdown. L3 also persists to `storage/findings.db`.

---

## Architecture

```
checklist.yaml → orchestrator → checks/ (boto3, HTTP, OSV, regex) → RawFinding
                                                      ↓
                                            intelligence.py (LLM enrich only)
                                                      ↓
                              ValidatedFinding → JSON + Markdown + Dashboard (+ SQLite at L3)
```

| Decision | Choice | Why |
|----------|--------|-----|
| Detection | boto3 / HTTP / OSV only | Facts from APIs — no LLM hallucination |
| Enrichment | Groq `llama-3.3-70b-versatile` | Business impact + remediation at temp 0.1 |
| Severity | `severity_cap` + evidence floor + confidence downgrade | Keeps real Criticals, blocks false ones |
| Parallelism | ThreadPoolExecutor (5 workers) | boto3 is I/O bound |
| Errors | Per-check try/catch | One failure does not kill the scan |
| Config | YAML checklists | Extend checks without code changes |

![Architecture overview](docs/screenshots/01-architecture.png)

---

## Agent accuracy and metrics

Every scan report includes a `metrics` block. The dashboard **Agent Performance** panel shows the same numbers after each run.

### Detection (ground truth)

Known intentional misconfigs are registered in [`metrics/ground_truth.py`](metrics/ground_truth.py). After a demo scan, the agent compares findings against that list:

| Metric | Meaning |
|--------|---------|
| **Verified precision (Critical)** | Share of Critical findings backed by direct API evidence |
| **Verified recall** | Share of known misconfigs the agent found |
| **F1 score** | Harmonic mean of precision and recall |
| **Avg confidence** | LLM confidence proxy for findings outside the controlled set |

Example headline from a live L1 demo run:

```
Precision(Critical):100% | Recall:100% (6/6 known) | F1:1.00 | Duration:87s | Checks:13/13 OK
```

![Agent metrics — L1/L2](docs/screenshots/13-agent-metrics-l1.png)

### Speed and coverage

| Metric | Meaning |
|--------|---------|
| Scan duration | Wall-clock time for the full run |
| Check success rate | Checks that completed vs errored (403/429 logged, never swallowed) |
| Findings per second | Throughput after enrichment |

### Level 2 extras

Domain success rate, deduplication stats, and findings per domain (AWS, API, dependencies, secrets).

![Agent metrics — L2 domains](docs/screenshots/14-agent-metrics-l2.png)

### Level 3 extras

| Metric | Meaning |
|--------|---------|
| Posture score | 0–100 derived from open findings (Critical = −25 pts each) |
| SLA compliance | Open findings still within their deadline |
| Scan reliability | Successful scan runs / total runs |
| Resolution rate | Findings resolved vs opened over time |

![L3 metrics KPIs](docs/screenshots/16-l3-metrics.png)

---

## Level 1

13 boto3 checks across IAM, S3, EC2/EBS, and CloudTrail. Config in [`checklist.yaml`](checklist.yaml).

**Design rule:** boto3 detects facts; the LLM only enriches. Critical severity requires direct API evidence — root MFA disabled, public S3 ACL, open SSH/RDP, etc. cannot be downgraded by the model.

![Dashboard — findings overview](docs/screenshots/04-dashboard-findings.png)

![Finding detail — evidence and remediation](docs/screenshots/05-finding-detail.png)

### Acceptance criteria

| Criterion | Status |
|-----------|--------|
| Reads YAML/JSON checklist | Pass |
| 10+ distinct checks (IAM, S3, SGs, encryption, MFA) | Pass — 13 checks |
| Each finding: ARN, severity, evidence, impact, remediation | Pass |
| API errors logged, not swallowed | Pass |
| JSON + Markdown reports | Pass |
| Zero false Critical findings | Pass |
| Real infrastructure, no mocks | Pass |

Verify: `python scripts\verify_acceptance.py` → `ALL ACCEPTANCE CRITERIA PASSED`

![Acceptance verification](docs/screenshots/08-acceptance-pass.png)

---

## Level 2

Four domains run in parallel ([`agent/orchestrator_l2.py`](agent/orchestrator_l2.py)):

- **AWS** — same 13 L1 checks
- **API** — 6 HTTP checks against configured targets (default: httpbin.org)
- **Dependencies** — OSV CVE scan on `requirements.txt` paths
- **Secrets** — 12 regex patterns with false-positive suppression

Findings are deduplicated ([`agent/deduplicator.py`](agent/deduplicator.py)) and ranked by business impact ([`agent/impact_ranker.py`](agent/impact_ranker.py)). API, CVE, and secrets domains use template enrichment (no LLM quota burn).

Verify: `python scripts\verify_acceptance_l2.py`

---

## Level 3 — continuous scanning

L3 wraps the full L2 pipeline and adds SQLite persistence, finding lifecycle, SLA tracking, Slack escalation, and posture trends.

### Finding lifecycle

| Status | When |
|--------|------|
| **opened** | Fingerprint seen for the first time |
| **updated** | Same fingerprint in a later scan |
| **resolved** | Missing for N consecutive scans (default 3) |
| **re-opened** | Previously resolved finding appears again |

![L3 lifecycle table](docs/screenshots/17-l3-lifecycle.png)

### Posture score and trend

```
posture_score = max(0, 100 − penalty)

penalty per open finding:
  critical:              25 pts  (40 if SLA breached)
  high:                  10 pts
  medium:                 3 pts
  low:                    1 pt
```

**Why the dashboard shows "Baseline" after the first L3 scan**

Trend direction needs **two or more scan runs** to compare scores. The first run only establishes a baseline posture score. With many open Critical findings, a score of **0/100 is normal** (e.g. 7 Criticals × 25 = 175 penalty).

| Scans completed | Trend KPI shows |
|-----------------|-----------------|
| 0 | Run first scan |
| 1 | **Baseline · N/100** — run again to compare |
| 2+ | Stable / Improving / Degrading (±5 point threshold) |

Run **Run L3 Once** twice (or start the daemon) to see trend direction change from baseline to Stable/Improving/Degrading.

![L3 posture and trend after 2+ scans](docs/screenshots/15-l3-posture-trend.png)

Optional: set `SLACK_WEBHOOK_URL` in `.env` for Critical escalation alerts.

![Slack escalation](docs/screenshots/18-l3-slack.png)

Verify: `python scripts\verify_acceptance_l3.py`

---

## Demo setup (8 findings)

A fresh AWS account shows ~3 natural findings (root MFA, CloudTrail, password policy). To reach **8 findings** for submission, create 5 intentional test resources using an admin IAM user.

| User | Purpose | Credentials |
|------|---------|-------------|
| `aivar-scanner` | All scans | `.env` (read-only policies) |
| `aivar-admin` | Create/delete test resources | `.env.admin` (setup only) |

**Never put admin keys in `.env`.**

Fastest path: dashboard → **Run Full Demo** (creates 5 misconfigs, verifies, scans, shows ~8 findings).

Or from terminal with admin creds in `.env.admin`:

```powershell
.\scripts\run_setup_as_admin.ps1
.\scripts\verify_test_misconfigs.ps1
python main.py --config checklist.yaml --verbose
```

Expected findings:

| Finding | Check | Severity |
|---------|-------|----------|
| Public S3 bucket (ACL) | `s3_public_acl` | Critical |
| Public S3 bucket policy | `s3_public_policy` | Critical |
| Open SSH security group | `sg_open_ssh` | Critical |
| Open RDP security group | `sg_open_rdp` | Critical |
| Root MFA disabled | `iam_root_mfa` | Critical |
| IAM user without MFA | `iam_user_mfa` | High |
| CloudTrail not logging | `cloudtrail_not_logging` | High |
| Weak password policy | `iam_password_policy` | Medium |

Cleanup: `.\scripts\cleanup_test_misconfigs.ps1` (admin creds required).

![Verify test misconfigs — 5/5 PASS](docs/screenshots/11-verify-misconfigs.png)

---

## Screenshots for submission

Place PNG files in `docs/screenshots/`. Markdown embeds above reference these paths — images appear once you capture them.

| File | Capture this |
|------|-------------|
| `01-architecture.png` | Data flow diagram |
| `04-dashboard-findings.png` | L1 tab — KPI cards + findings table |
| `05-finding-detail.png` | Expanded row with evidence + remediation |
| `08-acceptance-pass.png` | `verify_acceptance.py` all pass |
| `11-verify-misconfigs.png` | `verify_test_misconfigs.ps1` 5/5 PASS |
| `13-agent-metrics-l1.png` | Agent Performance panel (Precision, Recall, F1) |
| `14-agent-metrics-l2.png` | L2 domain breakdown + impact ranking |
| `15-l3-posture-trend.png` | L3 tab after **second** scan — trend direction visible |
| `16-l3-metrics.png` | L3 F1, SLA compliance, reliability, resolution rate |
| `17-l3-lifecycle.png` | L3 findings with status filters |
| `18-l3-slack.png` | Slack Critical alert (optional) |

Tip: capture at 1920×1080, same account and region (`ap-south-1`) throughout.

---

## Project structure

```
offensive-security-agent/
├── agent/              # Orchestrators (L1, L2, L3), LLM intelligence, lifecycle, SLA
├── checks/             # boto3, API, dependency, secrets check implementations
├── config/             # YAML loader
├── dashboard/          # FastAPI UI + static frontend
├── metrics/            # Precision/recall/F1 calculator + ground truth
├── models/             # Pydantic models (findings, config, reports)
├── reporter/           # JSON, Markdown, trend reporters
├── scheduler/          # APScheduler daemon for L3
├── scripts/            # Setup, verify, acceptance tests
├── storage/            # SQLite persistence (L3)
├── checklist.yaml      # L1 config
├── checklist_l2.yaml   # L2 config
├── checklist_l3.yaml   # L3 config
└── main.py             # CLI entry point
```

---

## Troubleshooting

**PowerShell blocks venv activation**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or call Python directly: `.\venv\Scripts\python.exe main.py --verbose`

**LLM enrichment fails / model not found**

Check `GROQ_API_KEY` is set in `.env` (not commented out). Default model: `llama-3.3-70b-versatile`.

**L3 trend stuck on "Baseline"**

Run a second L3 scan. Trend direction compares posture scores across scan history — one scan is not enough.

**L3 data looks wrong after clearing reports**

Use **Reset L3 Data** on the Continuous tab (clears SQLite fully). Clearing report history on L3 now resets all persistence data, not just scan run records.

**Port 8080 already in use**

Stop the existing uvicorn process or use a different port: `--port 8081`

---

## Verification commands

| Level | Command | Expected |
|-------|---------|----------|
| L1 | `python scripts\verify_acceptance.py` | ALL ACCEPTANCE CRITERIA PASSED |
| L2 | `python scripts\verify_acceptance_l2.py` | ALL LEVEL 2 ACCEPTANCE CRITERIA PASSED |
| L3 | `python scripts\verify_acceptance_l3.py` | ALL LEVEL 3 ACCEPTANCE CRITERIA PASSED |
| Dashboard | `python scripts\verify_dashboard_buttons.py` | All dashboard button API checks passed |
