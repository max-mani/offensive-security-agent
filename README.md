# Agent 2: Offensive Security Agent

**Aivar Innovations — AI/ML Engineering Hiring Challenge, June 2026**

**Candidate:** Manikandan M — [github.com/max-mani/offensive-security-agent](https://github.com/max-mani/offensive-security-agent)

**Verified on:** AWS account `563999587682`, region `ap-south-1` (Mumbai), 7 June 2026

All three levels complete and verified.

---

## The problem this solves

Security misconfigurations don't announce themselves. A developer opens port 22 to `0.0.0.0/0` on a test instance, forgets about it, and it stays open for six months. A credential gets hardcoded in a config file during a late-night fix. An IAM user never gets MFA enabled because nobody checked after the account was created. These aren't exotic attacks — they're the mundane, boring failures that show up in most breach post-mortems.

Manual security reviews happen quarterly at best. Automated scanners exist, but most either produce so many false positives they get ignored, or they're so conservative they miss obvious things. The goal here was to build something that behaves like a careful engineer doing the review: confident about things that are genuinely dangerous, honest about uncertainty, and explicit when it cannot access something.

---

## The one decision that everything else follows from

**The LLM never creates findings. It only enriches them.**

This is the most important design decision in the entire project. Every critical severity finding comes from a direct API call — `AccountMFAEnabled=0`, `PublicGrants` on an S3 bucket, `0.0.0.0/0` in a security group inbound rule. If the API says it's a problem, it's a problem. The LLM gets handed that evidence and adds a business impact statement, a remediation command, and a confidence score. It cannot upgrade or invent findings.

The reason this matters: LLMs are pattern matchers. They will confidently assign "critical" severity to ambiguous situations because that's what security reports usually do. The `DETERMINISTIC_EVIDENCE` map in `agent/intelligence.py` enforces a floor — specific high-stakes checks cannot be downgraded even if the model expresses uncertainty, because the API evidence is unambiguous. Root MFA is either enabled or it isn't. An S3 bucket either has public grants or it doesn't.

This made it straightforward to hit the zero false positives requirement. The harder thing was making sure the LLM didn't also downgrade findings that should stay critical.

---

## Level 1 — AWS Infrastructure Scanner

The core pipeline: `checklist.yaml` defines 13 checks, the orchestrator runs them in parallel via `ThreadPoolExecutor`, each check calls boto3 and returns a `RawFinding`, the intelligence layer enriches it to a `ValidatedFinding`, and the reporters write JSON and Markdown.

13 checks covering root MFA, access keys, IAM user MFA, unused keys, password policy, S3 public ACLs, S3 public policies, S3 encryption, open SSH/RDP security groups, unencrypted EBS volumes, CloudTrail logging, and public EBS snapshots. The YAML config lets you enable/disable individual checks and set a `severity_cap` per check — useful for environments where a specific finding class is known and accepted.

One thing I got wrong in an early version: error handling was too global. If the IAM check hit a 403, the whole scan would surface a generic error. Changed it so every check has its own try/catch and any API failure produces a `CheckError` that goes into the report's `scan_errors` list. The scan continues. A permission denied on one check does not mean the resource is clean — it means you couldn't check, and that distinction matters.

```
Verified on live infrastructure: 8 findings across 13 checks
Precision (Critical): 100%  — 0 false positives
Recall: 100%  — all 6 known intentional misconfigs detected
F1: 1.00
Duration: 87s  — 13 parallel checks
Check success rate: 13/13
```

![Dashboard — findings table with KPI cards](docs/screenshots/04-dashboard-findings.png)

![Single finding — raw evidence and remediation command](docs/screenshots/05-finding-detail.png)

![verify_acceptance.py — all criteria passed](docs/screenshots/08-acceptance-pass.png)

---

## Level 2 — Multi-Domain Scanner

The challenge at Level 2 is that "security finding" means something different depending on where it comes from. A public S3 bucket and a missing `X-Frame-Options` header are both findings, but one is directly exploitable and one is a hardening recommendation. Ranking them alphabetically or by domain is useless. The solution is a weighted impact score:

```
impact_score = (severity_score + check_bonus) × domain_weight × (confidence / 100)
```

Domain weights reflect real-world exploitability: hardcoded secrets (1.3×) sit above AWS infrastructure misconfigs (1.1×) which sit above API findings (1.0×) which sit above CVEs (0.9×) — CVEs are weighted lower because a vulnerable package in a dependency manifest is not the same as a vulnerable package running in production. Individual checks get bonuses for things that are disproportionately dangerous regardless of domain (root access keys, direct credential exposure, CORS with credentials).

Four domains run in parallel:

- **AWS infrastructure** — same 13 checks from Level 1
- **API endpoints** — 6 HTTP checks: authentication bypass, CORS misconfiguration, rate limiting, security headers, error disclosure, method exposure
- **Dependency CVEs** — OSV batch query with per-vulnerability detail fetch (CVE ID, CVSS, fixed version)
- **Secrets** — 12 regex patterns covering AWS keys, API tokens, private keys, connection strings, with false-positive suppression for obvious placeholders

The deduplication fingerprint is `SHA-256(check_id + resource_id + severity)`. This handles the case where two domains independently detect the same underlying issue — you get one finding, not two.

LLM enrichment is only used for AWS findings. API, CVE, and secrets domains have structured evidence with deterministic remediation steps — running LLM enrichment on "this package has CVE-2024-12345, fix is version 2.1.0" would waste quota and add nothing. The template layer handles those directly.

![Agent Performance panel — Level 2 metrics](docs/screenshots/14-agent-metrics-l2.png)

---

## Level 3 — Continuous Autonomous Scanning

Level 3 is where the design gets interesting, because the hardest problem isn't the scheduling — it's making sure the agent never lies about what it knows.

The failure mode I was most careful to avoid: a check that errors silently, which makes the report look clean when it isn't. Every check attempted at Level 3 writes a row to `scan_health` — either `success` or `error` with the specific error type and message. The dashboard surfaces this directly. If CloudTrail checks fail with a 403, you see that explicitly. You don't see "no CloudTrail findings" and assume everything is fine.

**Finding lifecycle** across scan runs is handled by `FindingLifecycleManager`. The fingerprint ties each finding to a single database record across its lifetime. On each scan, a finding is either new, updated (same fingerprint, still present), re-opened (was resolved, now present again), or absent. Absent findings increment a `consecutive_misses` counter — after 3 consecutive misses, the finding auto-resolves. This mirrors how you'd actually want to think about remediation: you don't declare a problem fixed the moment it disappears from one scan, because it might have just been a transient API error.

**SLA tracking** is per-severity: Critical has 24 hours, High 72 hours, Medium 7 days. These are set at first detection and evaluated on every scan. A breached SLA raises the posture penalty from 25 to 40 points per finding. Slack escalation fires once on first detection of a Critical — not on every scan, because alert fatigue is itself a failure mode.

**Posture score** is a simple penalty formula applied to all currently open findings:

```
score = max(0, 100 − total_penalty)

Critical: 25 pts
Critical + SLA breached: 40 pts
High: 10 pts
Medium: 3 pts
Low: 1 pt
```

A single scan with 7 open Critical findings produces a score of 0/100. That's intentional. The score isn't meant to make you feel good — it's meant to give teams a number they can track across deployments. Trend direction (Stable / Improving / Degrading) is computed as the delta between the first and most recent posture score in history, requiring at least two scan runs to establish direction.

![L3 dashboard — lifecycle table with status filters](docs/screenshots/17-l3-lifecycle.png)

![L3 posture trend after two scans](docs/screenshots/15-l3-posture-trend.png)

![L3 metrics — F1, SLA compliance, scan reliability](docs/screenshots/16-l3-metrics.png)

---

## Metrics and evaluation

Security scanning is a binary classification problem: for each resource, the agent either reports a finding or it doesn't. Precision and recall are the natural way to evaluate it.

The ground truth is defined in `metrics/ground_truth.py` — a registry of known intentional misconfigs created for the demo (public S3 buckets, open security groups, root MFA disabled, etc.). After a scan, the metrics calculator compares the agent's findings against this list.

| Metric | Live result (L1 demo run) |
|--------|--------------------------|
| Verified precision (Critical) | 100% |
| Verified recall | 100% (demo + account baseline checks found) |
| F1 score | 1.00 |
| Avg confidence score | 93.5 |
| Scan duration | 87s |
| Check success rate | 13/13 |

These metrics are embedded in every scan report JSON and shown in the dashboard **Agent Performance** panel after each run. Level 3 adds reliability rate (successful scans / total scans) and resolution rate (findings resolved over time).

![Agent Performance panel](docs/screenshots/13-agent-metrics-l1.png)

---

## Running it

**Requirements:** Python 3.10+, AWS credentials in `ap-south-1`, a free Groq API key (`GROQ_API_KEY`).

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Add AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION, GROQ_API_KEY to .env
```

Dashboard (all three levels, no terminal needed for demos):

```powershell
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080 --reload
```

Open **http://127.0.0.1:8080**, pick a level tab, click Run.

CLI if you prefer:

```powershell
python main.py --config checklist.yaml --verbose              # Level 1
python main.py --level 2 --config checklist_l2.yaml --verbose # Level 2
python main.py --level 3 --config checklist_l3.yaml --verbose # Level 3 (one shot)
python main.py --level 3 --config checklist_l3.yaml --daemon  # Level 3 continuous
```

For a full 8-finding demo (5 intentional + 3 natural account defaults), you need a second IAM user with admin permissions to create the test resources. The dashboard **Run Full Demo** button handles the whole flow — creates 5 misconfigs, verifies the scanner can see them, runs the scan, and shows results. No admin CLI needed.

| User | Role | Credentials file |
|------|------|-----------------|
| `aivar-scanner` | Run all scans | `.env` — read-only policies |
| `aivar-admin` | Create/delete test resources | `.env.admin` — admin, for setup only |

Expected 8 findings:

| Finding | Severity |
|---------|----------|
| Root MFA disabled | Critical |
| Public S3 bucket (ACL) | Critical |
| Public S3 bucket (policy) | Critical |
| Open SSH security group | Critical |
| Open RDP security group | Critical |
| IAM user without MFA | High |
| CloudTrail not logging | High |
| Weak password policy | Medium |

After setup: `python scripts\verify_acceptance.py` should show `ALL ACCEPTANCE CRITERIA PASSED`.

---

## Verification

```
python scripts\verify_acceptance.py        → ALL ACCEPTANCE CRITERIA PASSED
python scripts\verify_acceptance_l2.py     → ALL LEVEL 2 ACCEPTANCE CRITERIA PASSED
python scripts\verify_acceptance_l3.py     → ALL LEVEL 3 ACCEPTANCE CRITERIA PASSED
python scripts\verify_dashboard_buttons.py → All dashboard button API checks passed
```

---

## Structure

```
agent/          orchestrators (L1/L2/L3), LLM intelligence, lifecycle, SLA, impact ranking
checks/         boto3 checks, API checks, CVE scanner, secrets scanner
config/         YAML/JSON checklist loader
dashboard/      FastAPI app, static frontend (vanilla JS + CSS), service layer
metrics/        Precision/recall/F1 calculator, ground truth registry
models/         Pydantic models for findings, config, reports
reporter/       JSON reporter, Markdown reporter, trend reporter
scheduler/      APScheduler-based daemon for Level 3
scripts/        Setup, verify, acceptance test scripts
storage/        SQLite database models, findings store, audit store
checklist.yaml      Level 1 config — 13 AWS checks
checklist_l2.yaml   Level 2 config — adds API, CVE, secrets
checklist_l3.yaml   Level 3 config — adds schedule, SLA, Slack, auto-remediation settings
main.py             CLI entry point
```

---

## Screenshots

*(Images go in `docs/screenshots/` — filename references above will auto-render once added)*

| Filename | What to capture |
|----------|-----------------|
| `01-architecture.png` | Architecture diagram |
| `04-dashboard-findings.png` | L1 tab — KPI cards + findings table (8 findings) |
| `05-finding-detail.png` | Expanded finding — raw evidence + remediation command |
| `08-acceptance-pass.png` | Terminal: `verify_acceptance.py` all pass |
| `11-verify-misconfigs.png` | `verify_test_misconfigs.ps1` 5/5 PASS |
| `13-agent-metrics-l1.png` | Agent Performance panel — Precision, Recall, F1 |
| `14-agent-metrics-l2.png` | L2 tab — domain breakdown, impact-ranked findings |
| `15-l3-posture-trend.png` | L3 tab — after second scan, trend direction shown |
| `16-l3-metrics.png` | L3 metrics — F1, SLA compliance, scan reliability |
| `17-l3-lifecycle.png` | L3 findings table — lifecycle status filters |
| `18-l3-slack.png` | Slack Critical escalation alert |
