# Video Script — Offensive Security Agent
## (ElevenLabs Voiceover Edition)

**Total runtime:** ~5 minutes  
**Format:** Screen recording with ElevenLabs narration. Show the live dashboard only — no slides except the architecture image in the intro.  
**ElevenLabs tip:** Paste each **SAY** block as a separate generation. Commas = short pause. Em dashes — = medium pause. Periods = full stop.

---

## Before you record

| Task | Done? |
|------|-------|
| Dashboard running on port 8080 | |
| `.env` configured (GROQ_API_KEY, AWS keys) | |
| Level 3 data reset if needed | |
| Browser on Level 1 tab, dark theme, 100% zoom | |
| Notifications off, screen at 1920×1080 | |

---

## Part 1 — Introduction and System Design
**Time: 0:00 – 0:55**

**SHOW:** First, show the three-level architecture image full screen for 10–15 seconds. Then switch to the live dashboard.

**SAY:**

"Hi, I'm Manikandan. I built this Offensive Security Agent for the Aivar hiring challenge.

Before I show you the dashboard, I want to explain the design, because the design is the interesting part.

The system has three levels — and each level builds on the one before it.

Level 1 is a checklist-driven AWS scanner. It runs thirteen checks across IAM, S3, EC2, and CloudTrail — all using real boto3 API calls — and uses a language model to explain the impact of what it finds.

Level 2 takes that same scanner and adds three more attack surfaces: API endpoint testing, dependency CVE scanning using the OSV database, and secrets detection using regex patterns. Four domains run in parallel, and a deduplication and impact ranking layer merges the results.

Level 3 is where it becomes autonomous. A scheduler runs Level 2 on a regular interval, findings are persisted in SQLite with fingerprints, each finding goes through a lifecycle — opened, updated, resolved, or re-opened — and critical findings have a twenty-four-hour SLA with Slack escalation.

Now — the task said I could build one or more agents. I chose to build one, and go deep on it. Quality over quantity. Every line in this codebase is something I understood and tested, and I think that shows more than shipping three shallow demos.

Let me walk you through it."

---

## Part 2 — Level 1: AWS Infrastructure
**Time: 0:55 – 2:05**

**SHOW:** Level 1 tab. Overview section — asset cards (total findings, critical, resources scanned, scan health). Demo Environment section at the bottom.

**SAY:**

"This is Level 1. The overview cards show totals from the last scan — findings, critical count, resources touched, and scan health.

Before I run anything, notice the two-user security model. There is a read-only scanner account that only ever needs describe permissions. There is a separate admin account that exists only to create demo misconfigurations. The scanner never needs write access — and that separation is enforced in config, not just convention.

I'll click Run Full Demo. That creates five intentional misconfigurations on the AWS account, verifies the scanner can detect them, runs the full scan, and loads the report."

**[Click Run Full Demo]**

**SHOW:** The Full Demo Pipeline — checklist steps lighting up one by one on the left, AWS terminal log streaming on the right. Then the four-stage Scan Pipeline: Config, AWS Checks, LLM Enrichment, Reports.

**SAY:**

"You can watch the pipeline live. Two public S3 buckets, an IAM user without MFA, security groups with port twenty-two and port three-three-eight-nine open to the entire internet.

Thirteen checks run in parallel, so this finishes in about ninety seconds even with LLM enrichment."

**[Scan completes — overview cards populate, findings table visible]**

**SHOW:** Expand one Critical finding — root MFA or a demo S3 bucket. Show the raw API evidence JSON and the remediation steps below it.

**SAY:**

"Eight findings — five Critical. Five of those are the misconfigs I just created. Three are real baseline issues on this account: root MFA disabled, CloudTrail not enabled, and a weak password policy.

Here is the important design decision. See this evidence field — AccountMFAEnabled: zero. That came directly from the AWS API. The language model wrote the business impact and the remediation steps. It did not decide the severity, and it cannot downgrade a Critical finding. Detection is deterministic. Explanation is AI.

Scroll down to Agent Performance — precision on Critical findings is one hundred percent, and recall catches every known misconfig when the demo environment is active."

---

## Part 3 — Level 2: Multi-Domain
**Time: 2:05 – 3:05**

**SHOW:** Click the Multi-Domain tab. Show the hero section, then the Run Level 2 Scan button.

**SAY:**

"Level 2 adds three attack surfaces: API endpoints, dependency CVEs, and secrets scanning.

Watch the nine-stage pipeline on the left as I start the scan — config, four parallel domain scans, LLM enrichment, deduplication, impact ranking, and reports."

**[Click Run Level 2 Scan — let the pipeline animate step by step]**

**SHOW:** Pipeline steps advance sequentially with glowing connectors. Pan across the live pipeline graph on the right.

**SAY:**

"The live graph shows data flowing between domains as each stage finishes. All four domains — AWS, API, dependencies, and secrets — run in parallel in the backend. The UI shows them sequentially so it's easy to follow.

When the same issue appears in two domains, the deduplication layer keeps one row. Everything else is ranked by a weighted impact score. Secrets and AWS misconfigs float to the top because they are exploitable right now — not just theoretical."

**[Scan done — findings table sorted by impact score]**

**SAY:**

"You get CVE identifiers and fix versions on dependency hits, plus domain-level metrics in Agent Performance: duplicates removed, findings per domain, and success rate for each domain."

---

## Part 4 — Level 3: Continuous SOC
**Time: 3:05 – 4:10**

**SHOW:** Click the Continuous tab. The glass SOC hero — posture score, trend badge, KPI grid. Schedule panel on the right.

**SAY:**

"Level 3 is the autonomous security operations view. The KPI grid at the top shows posture score, trend direction, open Critical count, SLA compliance, scan reliability, F1 score, and resolution rate — all updating after each scan.

On the right is the scan schedule. Default is every six hours, but you can set any interval in hours or minutes. I'll run once manually."

**[Click Run L3 Once]**

**SHOW:** Security Scan Pipeline hero animates. The seven-stage Autonomous Pipeline lights up: Scans, Database, Deduplication, Lifecycle, SLA, Slack, Trend. KPI cards update with new values.

**SAY:**

"Seven stages beyond Level 2. Findings persist in SQLite with fingerprints across runs. The first time a finding appears, it is marked opened. Repeat scans mark it updated. If it disappears for three consecutive scans, it is marked resolved. If it comes back after that, it is re-opened — with the full history preserved.

Critical findings get a twenty-four-hour SLA. New Criticals and breaches post to Slack once per finding — not every scan, so there is no alert fatigue.

The posture score drops when Criticals are open — intentionally. After a second scan, trend moves from Baseline to Stable or Improving as issues get fixed."

**SHOW:** Scroll the Posture over time chart, then the Activity feed, then the lifecycle findings table — show first_seen, last_seen, and status columns.

**SAY:**

"To go fully hands-off, set a schedule and click Start Continuous Scans. The daemon runs on that interval and keeps everything here updated without any manual intervention."

---

## Part 5 — Close
**Time: 4:10 – 4:45**

**SHOW:** Stay on Level 3 SOC view with KPI row visible. Or briefly flash the terminal showing: ALL ACCEPTANCE CRITERIA PASSED.

**SAY:**

"All three levels are covered by automated acceptance scripts. I ran them against this build — Level 1 infrastructure, multi-domain Level 2, and continuous Level 3 with lifecycle tracking, SLA enforcement, audit trail, and scan health. Everything passes.

The repository is on GitHub at github dot com slash max-mani slash offensive-security-agent.

The design philosophy throughout was simple: let code decide what is a vulnerability, and let AI explain why it matters and how to fix it. Never the other way around.

Thanks for watching."

---

## Timing reference

| Section | Duration | Cumulative |
|---------|----------|------------|
| Intro + architecture | 0:55 | 0:55 |
| Level 1 | 1:10 | 2:05 |
| Level 2 | 1:00 | 3:05 |
| Level 3 | 1:05 | 4:10 |
| Close | 0:35 | 4:45 |

---

## Recording tips

**Show:** Architecture image for 10–15 seconds at the start. Run Full Demo once. One expanded finding with evidence. L2 live pipeline graph for a few seconds. L3 KPI row, one run, and the lifecycle table.

**Do not show:** Full acceptance test runs (just mention them). Line-by-line reading of the findings table. Long silences — narrate over scan progress.

**If running long:** Cut the Level 2 graph pan. Skip the L3 activity feed scroll.

**If Groq rate-limits:** Say "template enrichment kicks in when the LLM quota is hit — findings and severity stay exactly the same."

**ElevenLabs voice settings:** Stability around 0.5, similarity around 0.75, slight pause after each em dash and after section-ending sentences.

---

## Architecture image

Save the generated architecture diagram to `docs/architecture.png` and use it as the first screen in the video intro (0:00–0:15 before switching to the dashboard).

The image is at:  
`C:\Users\Gopi\.cursor\projects\d-offensive-security-agent-offensive-security-agent\assets\three-level-architecture.png`

Copy it to your project's docs folder before recording:

```
docs/
  architecture.png        ← show this for the first 10–15 seconds
  video-script.md         ← this file
```

---

## Pre-recording verification (off camera)

```powershell
python scripts/verify_acceptance.py
python scripts/verify_acceptance_l2.py
python scripts/verify_acceptance_l3.py
python scripts/verify_dashboard_buttons.py
```
