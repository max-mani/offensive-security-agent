# Video Script — Agent 2: Offensive Security Agent

**Total time:** ~4 minutes  
**Format:** Screen recording with voiceover. Show the live dashboard — no slides.

**Pace:** ~140–150 words per minute. Move quickly through tables; pause only on architecture, one expanded finding, and the Level 3 SOC view.

---

## Before you record

| Task | Done? |
|------|-------|
| Dashboard running: `python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8080` | |
| `.env` (scanner) and `.env.admin` (demo) configured | |
| Level 3 data reset if needed (Continuous tab → **Reset L3 Data**) | |
| Browser on **Level 1** tab, dark theme looks good at 100% zoom | |
| Mic tested, notifications off, screen 1920×1080 | |

---

## Part 1 — Introduction
**Time: 0:00 – 0:25**

**SHOW:** Dashboard home — header, three tabs (AWS Infrastructure · Multi-Domain · Continuous), Level 1 **Infrastructure overview** section.

**SAY:**

"Hi, I'm Manikandan. This is my Offensive Security Agent for the Aivar challenge.

Everything you see runs against a real AWS account — real boto3 calls, real HTTP checks, real CVE lookups. No mocked findings.

The core design: **detection is deterministic, explanation is AI.** The scanner decides what is a finding using API evidence. The LLM only explains impact and remediation — it never downgrades or removes a Critical finding.

I'll walk through all three levels in four minutes."

---

## Part 2 — Level 1: AWS Infrastructure
**Time: 0:25 – 1:35**

**SHOW:** Level 1 tab. Point to the overview — check breakdown chart, asset cards (total findings, critical, resources scanned, scan health). Scroll to **Demo Environment**.

**SAY:**

"Level 1 is a checklist-driven AWS scanner — thirteen checks across IAM, S3, EC2, and CloudTrail.

I use two AWS users: a read-only **scanner** for every scan, and an **admin** user only to create demo misconfigurations. The scanner never needs write access.

I'll click **Run Full Demo**. That creates five intentional misconfigs, verifies the scanner can see them, runs the scan, and loads the report."

**[Click Run Full Demo]**

**SHOW:** Full Demo Pipeline — checklist steps lighting up plus the AWS terminal log on the right. Then the four-stage **Scan Pipeline** (Config → AWS → LLM → Reports).

**SAY:**

"You get a live pipeline and terminal output while it works — two public S3 buckets, an IAM user without MFA, security groups with SSH and RDP open to the internet. Thirteen checks run in parallel, so this finishes in about ninety seconds."

**[When complete — scroll overview cards and findings]**

**SHOW:** Asset cards populated (e.g. 8 findings, 5 Critical). Expand one Critical finding — root MFA or a demo S3 bucket. Show raw evidence JSON and remediation CLI.

**SAY:**

"Eight findings — five Critical. Five are the misconfigs I just created; three are real baseline issues on this account — root MFA off, CloudTrail not logging, weak password policy.

Every Critical finding is backed by direct API evidence — for example `AccountMFAEnabled: 0`. The LLM wrote the business impact and fix steps; severity came from the check, not the model.

Scroll to **Agent Performance** — precision on Critical is one hundred percent, and recall hits every known misconfig in our ground truth when the demo is active."

---

## Part 3 — Level 2: Multi-Domain
**Time: 1:35 – 2:35**

**SHOW:** Click **Multi-Domain** tab. Hero section, then **Run Level 2 Scan**.

**SAY:**

"Level 2 adds three more attack surfaces on top of AWS: API endpoints, dependency CVEs via OSV, and secrets regex scanning.

Watch the nine-stage pipeline on the left — config, four scan domains, LLM enrichment, deduplication, impact ranking, and reports."

**[Click Run Level 2 Scan — let pipeline animate]**

**SHOW:** Steps advance with glowing connectors. Pan the **Live Pipeline** graph on the right (zoom controls if helpful).

**SAY:**

"The live graph shows data flowing between domains as each stage completes — AWS, API, dependencies, and secrets in one run.

When the same issue appears in two domains, deduplication keeps one row. Everything else is ranked by a weighted impact score — secrets and AWS misconfigs float to the top because they're exploitable right now, not just theoretical."

**[Scan done — findings table sorted by impact]**

**SAY:**

"You get CVE IDs and fix versions on dependency hits, plus domain-level metrics in Agent Performance — duplicates removed, findings per domain, and domain success rates."

---

## Part 4 — Level 3: Continuous SOC
**Time: 2:35 – 3:35**

**SHOW:** Click **Continuous** tab. Glass SOC hero — schedule panel, control buttons, KPI grid.

**SAY:**

"Level 3 turns this into an autonomous security operations view. The dashboard is a live SOC — posture score, trend, open Critical count, SLA breaches, daemon status, F1, compliance, reliability, and resolution rate.

Up here is the **Scan Schedule**: default every six hours, or a custom interval in hours or minutes. I'll run once manually to show the pipeline."

**[Click Run L3 Once]**

**SHOW:** **Security Scan Pipeline** hero animates. **Autonomous Pipeline** seven stages light up (Scans → DB → Dedup → Lifecycle → SLA → Slack → Trend). KPI cards update.

**SAY:**

"Seven stages beyond Level 2. Findings persist in SQLite with fingerprints — first sighting is **opened**, repeat scans **updated**, missing for three consecutive runs **resolved**.

Critical findings get a twenty-four-hour SLA. New Criticals and breaches can post to Slack once per finding — no alert fatigue.

Posture score drops when Criticals are open — that's intentional, not a bug. After a second run, trend moves from Baseline to Stable or Improving as things get fixed."

**SHOW:** Briefly scroll **Posture over time** chart, **Activity feed**, **Critical findings** cards, and the lifecycle findings table (first_seen / last_seen / status).

**SAY:**

"To go fully hands-off, pick a schedule and click **Start Continuous Scans**. The daemon runs L3 on that interval and keeps this view updated."

---

## Part 5 — Close
**Time: 3:35 – 4:00**

**SHOW:** Stay on Level 3 SOC view with KPIs visible, or flash terminal with one line: `ALL ACCEPTANCE CRITERIA PASSED`.

**SAY:**

"All three levels are covered by automated acceptance scripts — Level 1, multi-domain Level 2, and continuous Level 3 with lifecycle, SLA, audit trail, and scan health. I ran them against this build; everything passes.

Repo: github.com/max-mani/offensive-security-agent. Thanks for watching."

---

## Timing cheat sheet

| Section | Duration | Cumulative |
|---------|----------|------------|
| Intro | 0:25 | 0:25 |
| Level 1 | 1:10 | 1:35 |
| Level 2 | 1:00 | 2:35 |
| Level 3 | 1:00 | 3:35 |
| Close | 0:25 | 4:00 |

---

## Recording tips (4-minute cut)

**Do show:** Run Full Demo once, one expanded finding, L2 live pipeline graph for a few seconds, L3 KPI row + schedule panel + one L3 run.

**Do not show on camera:** Full acceptance test runs (mention only), line-by-line reading of the findings table, long waits in silence — narrate over scan progress instead.

**If you're running long:** Shorten Level 2 graph pan; skip L3 activity feed scroll. **If you're short:** Expand root MFA evidence for ten extra seconds.

**If Groq rate-limits:** Say "template enrichment kicks in when the LLM quota is hit — findings and severity are unchanged."

**Talk like a colleague:** short sentences, point at UI labels that match the script (`Run Full Demo`, `Multi-Domain`, `Start Continuous Scans`).

---

## Quick verification (run before recording, not on camera)

```powershell
python scripts/verify_acceptance.py
python scripts/verify_acceptance_l2.py
python scripts/verify_acceptance_l3.py
python scripts/verify_dashboard_buttons.py
```

Optional full demo smoke test:

```powershell
python scripts/run_full_test_and_cleanup.py
```
