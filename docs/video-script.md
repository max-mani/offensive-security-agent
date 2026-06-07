# Video Script — Agent 2: Offensive Security Agent

**Total time:** ~12 minutes  
**Format:** Screen recording with your voice. Show the running system. No slides needed.

**Before you start recording:**
- Dashboard running at `http://127.0.0.1:8080`
- Terminal open, in the project folder, venv active
- VS Code open with the repo
- L3 data reset (go to Continuous tab → Reset L3 Data)
- Browser on Level 1 tab

---

## Part 1 — Introduction
**Time: 0:00 – 0:40**

**SHOW:** Dashboard home page, Level 1 tab open, nothing run yet.

**SAY:**

"Hi, I'm Manikandan. This is my submission for the Offensive Security Agent challenge from Aivar.

I'll walk you through all three levels. Everything you're going to see is running against a real AWS account — no mocked data, no fake responses.

Let me start with what this agent does in one line: it scans your AWS infrastructure, your APIs, your code dependencies, and your config files for security problems — and at Level 3, it does this on its own, on a schedule, without anyone clicking a button.

The most important design decision I made — and I'll show you the code in a moment — is that the AI never decides what's a security problem. It only explains the problems that the scanner already found. I'll come back to why that matters."

---

## Part 2 — Quick code tour
**Time: 0:40 – 1:40**

**SHOW:** Switch to VS Code. Show the folder tree on the left side. Then open `agent/intelligence.py` and scroll to lines 18–28 where `DETERMINISTIC_EVIDENCE` is defined.

**SAY:**

"Quick look at the structure. The `checks` folder has all the detection code — boto3 API calls, HTTP requests, CVE lookups, regex patterns. None of that uses an LLM.

The `agent/intelligence.py` file is where the AI comes in. But look at this — there's a map called `DETERMINISTIC_EVIDENCE`. This is a list of specific checks where we verify the raw API response directly in code. For example, if the boto3 response says `AccountMFAEnabled` equals zero, root MFA is disabled. That's a fact. The AI gets to explain it and suggest a fix — but it cannot say 'actually this is fine' and remove it.

This is how we get zero false positives on Critical findings. We don't trust the LLM to make the call on the dangerous stuff. We make the call ourselves using the API response.

Okay, let's see it in action."

---

## Part 3 — Level 1 Demo
**Time: 1:40 – 4:30**

**SHOW:** Switch back to the dashboard, Level 1 tab.

**SAY:**

"I'm on the Level 1 tab. Before I run anything, let me explain the setup quickly.

I have two AWS users. `aivar-scanner` has read-only access and runs all the scans. `aivar-admin` has admin access and is only used to create test misconfigurations for the demo. The scanner never needs write permissions — that's an important security boundary.

I'll click **Run Full Demo**. This will create five intentional misconfigurations in my AWS account, verify the scanner can see them, run the full scan, and show the results."

**[Click Run Full Demo button]**

**SHOW:** The pipeline panel. Four steps light up one by one — Create Misconfigs, Verify Resources, Run Scan, Load Report.

**SAY:**

"You can see the four steps running. It's creating two public S3 buckets, one IAM user without MFA, and two security groups with ports 22 and 3389 open to the whole internet. Then it verifies those exist. Then the scan runs.

The 13 security checks run in parallel, so this finishes in about 90 seconds instead of taking several minutes."

**[Wait for scan to finish. Findings table appears.]**

**SHOW:** KPI cards at the top — 8 findings, 5 Critical. Findings table below with all findings listed.

**SAY:**

"Eight findings total. Five Critical, two High, one Medium.

Five of those I just created intentionally. The other three were already there — root MFA is disabled on this account, CloudTrail isn't logging, and there's no password policy. Those are real misconfigurations that exist on most fresh AWS accounts.

Zero false positives on Critical. Every single Critical finding has direct API evidence backing it up."

**[Click on the root MFA finding to expand it]**

**SHOW:** The expanded finding — resource ARN, raw evidence JSON (`AccountMFAEnabled: 0`), business impact text, remediation steps, and a runnable CLI command at the bottom.

**SAY:**

"This is what a finding looks like. You have the resource — in this case the root account. You have the raw evidence from the AWS API — `AccountMFAEnabled` is 0. That's the actual response boto3 got. Then you have the business impact — what can an attacker actually do with this — and a step-by-step fix with a CLI command you can run immediately.

The business impact and the remediation steps were written by the LLM. The severity and whether this finding exists at all — that came from the API call. Those two things are never mixed up."

**[Scroll down to Agent Performance section if visible on the page]**

**SHOW:** Agent Performance panel — Precision 100%, Recall 100%, F1 1.00

**SAY:**

"The Agent Performance panel shows the accuracy metrics. I have a ground truth file that lists all the known intentional misconfigs. After every scan, the system checks how many of those were found.

Precision is 100% — no false positives on Critical. Recall is 100% — all 6 known misconfigs detected. F1 score is 1.00. These numbers are also saved inside the report JSON, so they're verifiable."

---

## Part 4 — Level 2 Demo
**Time: 4:30 – 7:30**

**SHOW:** Click the Level 2 tab in the dashboard.

**SAY:**

"Level 2 expands the scanner to four domains. Let me run it."

**[Click Run Level 2 Scan]**

**SHOW:** L2 pipeline — four parallel steps running: AWS, API Endpoints, Dependencies, Secrets.

**SAY:**

"Four domains run at the same time. AWS infrastructure is the same 13 checks from Level 1. API endpoints — the scanner sends real HTTP requests and checks for things like CORS misconfigurations, missing authentication, no rate limiting, insecure headers. Dependencies — it queries the OSV database for known CVEs in your requirements files. Secrets — twelve regex patterns looking for AWS keys, API tokens, private keys, connection strings.

The interesting problem here isn't running the checks. It's what you do with everything afterwards. You end up with findings from four completely different places and you need to sort them by how dangerous they actually are."

**[Scan finishes. Show the findings table sorted by impact score.]**

**SHOW:** Findings table — impact_score column visible, mix of different domain findings, sorted highest to lowest.

**SAY:**

"The findings are ranked by a weighted impact score. The formula is the severity score, plus a bonus for certain high-value checks, multiplied by a domain weight, multiplied by the confidence level.

The domain weights reflect real-world risk. Hardcoded secrets get the highest weight — a leaked credential is exploitable from anywhere, immediately. AWS misconfigs come second. API findings third. CVEs are weighted a bit lower — not because they don't matter, but because a vulnerable package in a requirements file doesn't mean you're actually running that vulnerable code. A public S3 bucket is exploitable right now. A vulnerable dependency might be. That's a meaningful difference when you're deciding what to fix first.

Also — if two different domains find the same underlying issue, you only get one finding in the table, not two. The deduplication uses a fingerprint based on the check ID, resource ID, and severity."

**[Show Agent Performance panel for L2]**

**SHOW:** L2 metrics section — domain success rates, dedup count, findings per domain.

**SAY:**

"The metrics for Level 2 show which domains succeeded, how many duplicates were removed, and how findings are distributed across the attack surface."

---

## Part 5 — Level 3 Demo
**Time: 7:30 – 10:30**

**SHOW:** Click the Continuous tab (Level 3).

**SAY:**

"Level 3 is where it becomes a proper autonomous service. It runs on a schedule, remembers findings across scans, tracks whether they get fixed, and escalates Critical issues to Slack immediately.

Let me run it once to show you what the first scan looks like."

**[Click Run L3 Once]**

**SHOW:** The 7-stage L3 pipeline lighting up: Scans → DB → Dedup → Lifecycle → SLA → Slack → Trend.

**SAY:**

"The pipeline now has seven stages. The first three are the same as Level 2 — run the scan, save to the database, deduplicate. Then four new things happen.

Stage 4 is lifecycle management. Every finding gets a fingerprint. First time the fingerprint appears, the finding is marked as 'opened'. Same fingerprint on the next scan — it's 'updated'. If something was resolved and comes back — it's 're-opened'. This gives you a full history per finding, not just per scan.

Stage 5 is SLA tracking. Critical findings get a 24-hour deadline. High severity gets 72 hours. If the finding isn't resolved in that window, the system sends a Slack alert and the posture score penalty increases.

Stage 6 is Slack escalation. New Critical findings send an alert immediately. But only once per finding — not on every scan. Alert fatigue is a real problem. If your security system sends the same alert 10 times, people start ignoring it.

Stage 7 writes the posture score and trend report."

**[Scan finishes. Show the KPI cards — posture score is very low, trend says Baseline.]**

**SHOW:** L3 KPI cards — Posture Score showing 0/100 or a low number, Trend card says "Baseline · 0/100".

**SAY:**

"Posture score is 0 out of 100. That's not a bug — that's correct. We have seven open Critical findings. Each Critical finding subtracts 25 points. Seven times 25 is 175. The score floors at zero.

The Trend card says 'Baseline'. That means this is the first scan, and we need at least two scans to calculate a direction. Let me run it again."

**[Click Run L3 Once again. Wait for it to finish.]**

**SHOW:** After the second scan completes, the Trend card now shows "Stable" or a delta.

**SAY:**

"On the second scan, the lifecycle manager recognizes all the same fingerprints. Nothing is new — everything is 'updated'. The posture score is the same. The trend direction is now 'Stable' because the score didn't change significantly.

If I fix some of those Critical findings in AWS and run again, the score would go up and the trend would change to 'Improving'. That's the number teams would track over time."

**[Scroll to the findings lifecycle table]**

**SHOW:** L3 findings table — status column shows "updated" for all rows. first_seen and last_seen are different.

**SAY:**

"Look at the table. Every finding shows 'updated'. The first_seen timestamp is from the first run. The last_seen timestamp is from the second run. There's one row per misconfiguration in the database — not one row per scan. That's the whole point of persistence.

The auto-resolution logic is worth mentioning too. If a finding disappears from three consecutive scans, it automatically gets marked as resolved. Three scans, not one — because a single scan failure or a temporary API error shouldn't mark a real security problem as fixed."

**[Scroll to Scan Health section]**

**SHOW:** Scan Health table — all checks listed with success/error status.

**SAY:**

"The scan health table is one of my favorite parts of Level 3. Every check that was attempted shows here — either success or error with the exact error message. If a check hits a 403 permission denied, you see it explicitly.

This means you can never get a false clean report because a check failed quietly. That's a failure mode in a lot of security tools — they just skip the check and you think nothing's wrong. This system makes every failure visible."

---

## Part 6 — Verification
**Time: 10:30 – 11:30**

**SHOW:** Switch to the terminal. Clear the screen.

**SAY:**

"Let me run the acceptance tests for all three levels."

**[Run: `python scripts\verify_acceptance.py`]**

**SHOW:** Terminal output ending with: `ALL ACCEPTANCE CRITERIA PASSED`

**SAY:**

"Level 1 — all seven criteria pass."

**[Run: `python scripts\verify_acceptance_l2.py`]**

**SHOW:** Terminal output ending with: `ALL LEVEL 2 ACCEPTANCE CRITERIA PASSED`

**SAY:**

"Level 2 — passes."

**[Run: `python scripts\verify_acceptance_l3.py`]**

**SHOW:** Terminal output — 11 criteria with PASS next to each, then `ALL LEVEL 3 ACCEPTANCE CRITERIA PASSED`

**SAY:**

"Level 3 — eleven criteria. All pass. This includes the lifecycle state machine, cross-run deduplication, SLA breach detection, audit trail, trend reporting, and scan health.

These scripts test the actual behavior — they're not just checking if imports work. They create real database entries and verify the state transitions."

---

## Part 7 — Close
**Time: 11:30 – 12:00**

**SHOW:** Go back to the dashboard. Stay on the Level 3 tab. The posture score and trend are visible.

**SAY:**

"To wrap up — the whole project is built around one idea: separate detection from explanation. The API calls decide what the findings are. The LLM explains them and tells you how to fix them. That separation is what makes the Critical severity findings trustworthy.

All three levels are complete and verified on a real AWS account. The repo is at github.com/max-mani/offensive-security-agent.

Thanks for watching."

---

## Before you record — checklist

Go through this before hitting record:

| Task | Done? |
|------|-------|
| Dashboard running at `http://127.0.0.1:8080` | |
| Terminal open in project directory, venv active | |
| VS Code open with `agent/intelligence.py` ready to show | |
| Level 3 data reset (Continuous tab → Reset L3 Data) | |
| 5 test misconfigs exist in AWS (so Run Full Demo takes ~90s not 5min) | |
| Browser zoom at 100% — table text is readable | |
| Screen is 1920×1080 | |
| Mic tested, no background noise | |
| Notifications turned off | |

---

## A few tips for when you're recording

**Don't rush when the scan is running.** It takes 90 seconds. Just say "this takes about 90 seconds, all 13 checks are running in parallel" and let it run. Silence while something is working looks natural.

**Don't read the findings table out loud line by line.** Point to the numbers — "8 findings, 5 Critical" — and move on. The person watching can pause and read. If you read every row, it gets boring fast.

**The two places to slow down and be clear:**
1. When you show the `DETERMINISTIC_EVIDENCE` code — this is the key architectural decision and it's worth 20-30 extra seconds of explanation.
2. When you explain the lifecycle states during Level 3 — opened, updated, resolved, re-opened. Say each state with a one-sentence explanation.

**Talk like you're explaining to a colleague, not presenting to a committee.** Simple words, direct sentences. If you make a small mistake, just continue — don't restart the whole recording for a minor stumble.
