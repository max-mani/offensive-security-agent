# Agent 2: Offensive Security Agent — Level 2
## Technical Build Plan — Multi-Domain Scanning

**Author:** Manikandan M  
**Deadline:** Monday, 08 June 2026, 11:00 AM  
**Prerequisite:** Level 1 complete and working  

---

## Table of Contents

1. [What Changes in Level 2](#1-what-changes-in-level-2)
2. [Architecture Overview](#2-architecture-overview)
3. [Project Structure Changes](#3-project-structure-changes)
4. [Domain 2 — API Scanner (6 checks)](#4-domain-2--api-scanner)
5. [Domain 3 — Dependency CVE Scanner](#5-domain-3--dependency-cve-scanner)
6. [Domain 4 — Secrets Scanner](#6-domain-4--secrets-scanner)
7. [Cross-Domain Deduplicator](#7-cross-domain-deduplicator)
8. [Business Impact Ranker](#8-business-impact-ranker)
9. [Extended Orchestrator L2](#9-extended-orchestrator-l2)
10. [Extended Config Schema](#10-extended-config-schema)
11. [Updated Report Schema](#11-updated-report-schema)
12. [Implementation Order](#12-implementation-order)
13. [Acceptance Criteria Checklist](#13-acceptance-criteria-checklist)
14. [Test Targets for Demo](#14-test-targets-for-demo)

---

## 1. What Changes in Level 2

Level 1 scanned one domain (AWS Infrastructure).
Level 2 adds three more domains and wires them all together.

```
Level 1 (done)          Level 2 (new additions)
──────────────          ────────────────────────────────────────────
AWS Infrastructure  +   API Endpoint Scanner    (Domain 2)
                    +   Dependency CVE Scanner  (Domain 3)
                    +   Secrets Scanner         (Domain 4)
                    +   Cross-Domain Deduplicator
                    +   Business Impact Ranker
                    +   Merged unified report (all domains, sorted by impact)
```

**Key challenge of Level 2:** Each domain produces findings with different signal norms.
A leaked AWS key is more dangerous than a missing security header even though both
are findings. The ranker must reflect real business risk, not domain order.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    main.py  (--level 2)                          │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                  OrchestratorL2                                   │
│                agent/orchestrator_l2.py                          │
│  Runs all 4 domain scanners in parallel (ThreadPoolExecutor)     │
└──┬───────────┬──────────────┬──────────────┬─────────────────────┘
   │           │              │              │
   ▼           ▼              ▼              ▼
Domain 1    Domain 2       Domain 3       Domain 4
AWS Infra   API Scanner    Dep CVEs       Secrets
(Level 1)   api_checks.py  dep_checks.py  secrets_checks.py
boto3       requests       OSV API        regex scan
   │           │              │              │
   └───────────┴──────────────┴──────────────┘
                        │ all raw findings combined
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│                 LLM Intelligence Layer                            │
│              agent/intelligence.py  (reused from L1)             │
└───────────────────────┬──────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│              Cross-Domain Deduplicator                           │
│              agent/deduplicator.py                               │
│  Same vuln found by 2 scanners → appears ONCE                    │
└───────────────────────┬──────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│              Business Impact Ranker                              │
│              agent/impact_ranker.py                              │
│  Scores: severity × domain_weight × confidence                   │
│  Result: secrets > critical infra > high api > medium deps       │
└───────────────────────┬──────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│              Report Generator (JSON + Markdown)                  │
│  Includes: all domains, deduped, ranked by impact                │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Project Structure Changes

Files marked `[NEW]` are added in Level 2.
Files marked `[UPDATED]` are modified. Files marked `[REUSED]` are unchanged.

```
offensive-security-agent/
├── main.py                         [UPDATED] add --level flag
├── checklist.yaml                  [REUSED]  Level 1 config
├── checklist_l2.yaml               [NEW]     Level 2 config
├── requirements.txt                [UPDATED] add requests, packaging
│
├── models/
│   ├── finding.py                  [UPDATED] add domain field
│   └── report.py                   [UPDATED] add findings_by_domain
│
├── checks/
│   ├── iam_checks.py               [REUSED]
│   ├── s3_checks.py                [REUSED]
│   ├── ec2_checks.py               [REUSED]
│   ├── cloudtrail_checks.py        [REUSED]
│   ├── api_checks.py               [NEW] 6 API security checks
│   ├── dependency_checks.py        [NEW] CVE detection via OSV API
│   └── secrets_checks.py           [NEW] regex secrets scanning
│
├── agent/
│   ├── orchestrator.py             [REUSED]
│   ├── orchestrator_l2.py          [NEW]
│   ├── intelligence.py             [REUSED]
│   ├── deduplicator.py             [NEW]
│   └── impact_ranker.py            [NEW]
│
├── reporter/
│   ├── json_reporter.py            [UPDATED]
│   └── markdown_reporter.py        [UPDATED]
│
└── utils/
    ├── aws_client.py               [REUSED]
    ├── retry.py                    [REUSED]
    ├── osv_client.py               [NEW]
    └── http_client.py              [NEW]
```

---

## 4. Domain 2 — API Scanner

### Overview

Makes real HTTP requests to configured URLs. Checks for 6 security weaknesses.
Never modifies state — only reads responses. Uses `requests` library.

### `utils/http_client.py`

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def build_http_client(timeout: int = 10) -> requests.Session:
    """
    Safe HTTP client for API scanning.
    - Short timeouts (don't hang on slow endpoints)
    - Retry on connection errors ONLY (not 4xx/5xx — we WANT to see those)
    """
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=False, status=False, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "OffensiveSecurityAgent/1.0 (Security Scanner)"})
    return session
```

### `checks/api_checks.py` — 6 Checks

#### Check 1: Missing Security Headers

```python
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"severity": "high",
        "impact": "Missing HSTS allows HTTPS downgrade to HTTP by MITM attacker."},
    "X-Frame-Options":           {"severity": "medium",
        "impact": "Missing X-Frame-Options allows clickjacking attacks."},
    "X-Content-Type-Options":    {"severity": "medium",
        "impact": "Missing XCTO allows MIME sniffing — browser may execute files as scripts."},
    "Content-Security-Policy":   {"severity": "medium",
        "impact": "Missing CSP broadens XSS attack surface — no script restrictions."},
    "Referrer-Policy":           {"severity": "low",
        "impact": "Missing Referrer-Policy leaks URL parameters to third parties."},
}

class SecurityHeadersCheck:
    """
    GET request to target URL → inspect response headers.
    One RawFinding per missing header.
    boto3 equivalent: GET {url} → check headers dict.
    """
    check_id = "api_security_headers"

    def run(self) -> list:
        resp = self.http.get(self.target.url, timeout=10)
        existing = {k.lower() for k in resp.headers}
        findings = []
        for header, meta in REQUIRED_HEADERS.items():
            if header.lower() not in existing:
                findings.append(RawFinding(
                    check_id=self.check_id,
                    resource_id=f"{self.target.name}::{header}",
                    resource_arn=f"api::{self.target.url}",
                    resource_type="API::Endpoint",
                    region="api",
                    domain="api_endpoints",
                    raw_evidence={
                        "target_url": self.target.url,
                        "missing_header": header,
                        "response_status": resp.status_code,
                        "existing_headers": dict(resp.headers),
                        "api_call": f"GET {self.target.url}"
                    },
                    preliminary_severity=meta["severity"]
                ))
        return findings
```

#### Check 2: CORS Misconfiguration

```python
class CORSMisconfigCheck:
    """
    Attack: If API reflects arbitrary Origin + Access-Control-Allow-Credentials: true
    → attacker page can make authenticated requests on behalf of logged-in user.

    Test method:
    1. Send GET with Origin: https://evil-attacker-test.com
    2. Check if ACAO header reflects that exact origin
    3. Check if ACAC: true is also present

    Finding conditions:
    - Reflected origin + credentials = CRITICAL
    - Wildcard (*) ACAO = HIGH
    """
    check_id = "api_cors_misconfiguration"

    def run(self):
        evil_origin = "https://evil-attacker-test.com"
        resp = self.http.get(self.target.url,
                             headers={"Origin": evil_origin}, timeout=10)

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "false").lower()

        if acao == evil_origin and acac == "true":
            # CRITICAL: authenticated CORS attack possible
            return [RawFinding(..., preliminary_severity="critical",
                raw_evidence={"Access-Control-Allow-Origin": acao,
                              "Access-Control-Allow-Credentials": acac,
                              "sent_origin": evil_origin})]

        if acao == "*":
            # HIGH: any site can read responses
            return [RawFinding(..., preliminary_severity="high",
                raw_evidence={"Access-Control-Allow-Origin": "*"})]

        return []
```

#### Check 3: Missing Rate Limiting

```python
class RateLimitCheck:
    """
    Send 30 rapid requests. If no 429 and no X-RateLimit-* headers → no rate limiting.

    Why 30 requests: Enough to trigger most rate limiters without DoS risk.

    Finding: No rate limiting on any of 30 requests → HIGH severity
    (enables brute-force, scraping, and application-layer DoS)
    """
    check_id = "api_rate_limiting"

    def run(self):
        rate_limited = False
        status_codes = []

        for i in range(30):
            resp = self.http.get(self.target.url, timeout=5)
            status_codes.append(resp.status_code)

            if resp.status_code == 429:
                rate_limited = True
                break

            rl_headers = {k: v for k, v in resp.headers.items()
                if any(x in k.lower() for x in ["ratelimit", "rate-limit", "retry-after"])}
            if rl_headers:
                rate_limited = True
                break

        if not rate_limited:
            return [RawFinding(..., preliminary_severity="high",
                raw_evidence={"requests_sent": len(status_codes),
                              "got_429": False,
                              "rate_limit_headers_found": False})]
        return []
```

#### Check 4: Authentication Bypass

```python
PROTECTED_PATHS = [
    "/admin", "/api/admin", "/dashboard", "/api/users",
    "/api/config", "/internal", "/metrics", "/debug"
]

class AuthBypassCheck:
    """
    Try each common protected path WITHOUT any auth headers.
    Finding: Protected-looking endpoint returns HTTP 200 with no credentials.

    Legitimate behavior: 401 Unauthorized or 403 Forbidden.
    Finding condition: 200 OK with no auth header sent.
    """
    check_id = "api_auth_bypass"

    def run(self):
        findings = []
        for path in PROTECTED_PATHS:
            url = self.target.url + path
            try:
                resp = self.http.get(url, timeout=5, headers={"Authorization": ""})
                if resp.status_code == 200:
                    findings.append(RawFinding(..., preliminary_severity="high",
                        raw_evidence={"path_tested": path,
                                      "http_status": 200,
                                      "auth_header_sent": None,
                                      "response_size_bytes": len(resp.content)}))
            except requests.exceptions.ConnectionError:
                pass  # Path doesn't exist — not a finding
        return findings
```

#### Check 5: Error Message Disclosure

```python
ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace exposed"),
    (r"at\s+[\w.$]+\([\w.]+:\d+\)",         "Java/Node.js stack trace exposed"),
    (r"/home/\w+/",                           "Linux home path disclosed"),
    (r"C:\\Users\\",                          "Windows path disclosed"),
    (r"SQL syntax.*MySQL",                    "MySQL error with query details"),
    (r"psycopg2\.OperationalError",           "PostgreSQL connection details"),
    (r"django\.core\.exceptions",             "Django exception class exposed"),
    (r"werkzeug\.exceptions",                 "Flask debug info exposed"),
    (r"AKIA[0-9A-Z]{16}",                    "AWS access key in error response"),
]

MALFORMED_PAYLOADS = [
    ("GET",  "/?id=1'--"),                # SQL injection probe
    ("GET",  "/?input=<script>"),          # XSS probe
    ("GET",  "/../../../../etc/passwd"),    # Path traversal
    ("POST", "/", '{"key": null}'),        # Malformed JSON
]

class ErrorDisclosureCheck:
    """
    Send deliberately malformed inputs → inspect response body for
    stack traces, internal paths, DB errors.

    NOT attempting exploitation — only checking for information disclosure.
    """
    check_id = "api_error_disclosure"

    def run(self):
        findings = []
        for method, path, *body in MALFORMED_PAYLOADS:
            url = self.target.url + path
            resp = self._send(method, url, body[0] if body else None)
            if resp is None:
                continue
            for pattern, description in ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    findings.append(RawFinding(..., preliminary_severity="high",
                        raw_evidence={"payload_sent": path,
                                      "pattern_matched": pattern,
                                      "description": description,
                                      "response_excerpt": resp.text[:300]}))
                    break
        return findings
```

#### Check 6: Dangerous HTTP Methods

```python
class DangerousHTTPMethodsCheck:
    """
    TRACE method enables Cross-Site Tracing (XST) attacks —
    can steal HttpOnly cookies via script even when HttpOnly is set.

    Test:
    1. OPTIONS request → check Allow header for TRACE/TRACK
    2. Active TRACE request → check if response echoes the request back
    """
    check_id = "api_dangerous_methods"

    def run(self):
        findings = []
        # Via OPTIONS
        resp = self.http.options(self.target.url, timeout=5)
        allow = resp.headers.get("Allow", "")
        dangerous = [m for m in ["TRACE", "TRACK"] if m in allow.upper()]
        if dangerous:
            findings.append(RawFinding(..., preliminary_severity="medium",
                raw_evidence={"Allow_header": allow, "dangerous_methods": dangerous}))

        # Active TRACE test
        resp = self.http.request("TRACE", self.target.url, timeout=5)
        if resp.status_code == 200 and "TRACE" in resp.text.upper():
            findings.append(RawFinding(..., preliminary_severity="medium",
                raw_evidence={"TRACE_echoes_request": True,
                              "vulnerability": "Cross-Site Tracing (XST) possible"}))
        return findings
```

### API Domain Runner

```python
def run_api_domain(targets: list, config) -> tuple:
    """Run all 6 API checks against all configured targets."""
    http = build_http_client()
    all_findings, all_errors = [], []

    for target_cfg in targets:
        target = APITarget(url=target_cfg["url"], name=target_cfg["name"])
        checkers = [
            SecurityHeadersCheck(target, http),
            CORSMisconfigCheck(target, http),
            RateLimitCheck(target, http),
            AuthBypassCheck(target, http),
            ErrorDisclosureCheck(target, http),
            DangerousHTTPMethodsCheck(target, http),
        ]
        for checker in checkers:
            result = checker.run()
            if isinstance(result, CheckError):
                all_errors.append(result)
            else:
                all_findings.extend(result)

    return all_findings, all_errors
```

---

## 5. Domain 3 — Dependency CVE Scanner

### Overview

Uses **OSV API** (osv.dev) — completely free, no API key required.
Parses dependency files → batch queries OSV → returns structured CVE findings.

### `utils/osv_client.py`

```python
import requests, logging
from typing import List, Dict, Optional

OSV_API = "https://api.osv.dev/v1"

def query_batch(packages: List[Dict]) -> List[List[dict]]:
    """
    Batch query OSV for up to 1000 packages at once.
    Much faster than sequential single queries.

    Input:  [{"name": "django", "version": "3.2.0", "ecosystem": "PyPI"}, ...]
    Output: [[vuln1, vuln2], [], [vuln3], ...]  (one list per package)
    """
    payload = {
        "queries": [
            {"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
             "version": p["version"]}
            for p in packages
        ]
    }
    resp = requests.post(f"{OSV_API}/querybatch", json=payload, timeout=30)
    if resp.status_code == 200:
        return [r.get("vulns", []) for r in resp.json().get("results", [])]
    return [[] for _ in packages]


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None: return "medium"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"
```

### `checks/dependency_checks.py`

```python
def parse_requirements_txt(path: str) -> List[Dict]:
    """
    Parse requirements.txt → [{name, version, ecosystem}, ...]

    Handles:  django==4.2.0    requests>=2.28.0    flask~=2.3.0
    Skips:    comments          -r includes          bare names
    """
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = re.sub(r"\[.*?\]", "", line)  # strip extras like django[rest]
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><]{1,2}\s*([0-9][^\s;#]*)", line)
            if match:
                packages.append({
                    "name": match.group(1).lower().replace("_", "-"),
                    "version": match.group(2).strip(),
                    "ecosystem": "PyPI"
                })
    return packages


def parse_package_json(path: str) -> List[Dict]:
    """
    Parse package.json dependencies + devDependencies.
    Strips version prefixes: ^1.2.3 → 1.2.3, ~2.0.0 → 2.0.0
    """
    with open(path) as f:
        data = json.load(f)
    packages = []
    for dep_type in ["dependencies", "devDependencies"]:
        for name, version in data.get(dep_type, {}).items():
            clean = re.sub(r"^[^0-9]*", "", version)
            if clean and clean[0].isdigit():
                packages.append({"name": name, "version": clean, "ecosystem": "npm"})
    return packages


def run_dependency_domain(scan_paths: List[str]) -> Tuple[list, list]:
    """
    1. Parse all dependency files
    2. Batch query OSV API
    3. Create RawFinding for each CVE found
    """
    all_packages = []
    source_map = {}

    for path in scan_paths:
        p = Path(path)
        if not p.exists():
            continue
        if p.name == "requirements.txt":
            pkgs = parse_requirements_txt(path)
        elif p.name == "package.json":
            pkgs = parse_package_json(path)
        else:
            continue
        for pkg in pkgs:
            source_map[len(all_packages)] = (path, pkg)
            all_packages.append(pkg)

    if not all_packages:
        return [], []

    results = query_batch(all_packages)
    findings = []

    for idx, vulns in enumerate(results):
        if not vulns:
            continue
        file_path, pkg = source_map[idx]

        for vuln in vulns:
            # Extract CVSS score from OSV response
            cvss_score = None
            for db in [vuln.get("database_specific", {}), vuln.get("ecosystem_specific", {})]:
                score = db.get("cvss_score") or db.get("severity_score")
                if score:
                    try: cvss_score = float(score)
                    except: pass

            severity = cvss_to_severity(cvss_score)

            # Extract fix version from affected ranges
            fix_versions = []
            for affected in vuln.get("affected", []):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            fix_versions.append(event["fixed"])

            cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]

            findings.append(RawFinding(
                check_id="dependency_cve",
                resource_id=f"{pkg['name']}=={pkg['version']}",
                resource_arn=f"dependency::{file_path}::{pkg['name']}",
                resource_type="Dependency::Package",
                region="local",
                domain="dependencies",
                raw_evidence={
                    "package_name": pkg["name"],
                    "installed_version": pkg["version"],
                    "ecosystem": pkg["ecosystem"],
                    "source_file": file_path,
                    "osv_id": vuln.get("id", "UNKNOWN"),
                    "cve_ids": cve_ids,                  # e.g. ["CVE-2024-1234"]
                    "cvss_score": cvss_score,             # e.g. 9.1
                    "fix_versions": fix_versions,         # e.g. ["4.2.4"]
                    "summary": vuln.get("summary", ""),
                    "api_call": "POST api.osv.dev/v1/querybatch"
                },
                preliminary_severity=severity
            ))

    return findings, []
```

---

## 6. Domain 4 — Secrets Scanner

### Overview

Entirely local — no API calls. Scans files using regex patterns.
Fast, reliable, zero rate limits.

### `checks/secrets_checks.py`

```python
SECRET_PATTERNS = [
    ("aws_access_key",    r"AKIA[0-9A-Z]{16}",
     "AWS Access Key ID",                   "critical"),

    ("aws_secret_key",    r"(?i)aws[_\-\s]?secret[_\-\s]?key[\s=:\"']+([A-Za-z0-9/+]{40})",
     "AWS Secret Access Key",               "critical"),

    ("github_token",      r"ghp_[a-zA-Z0-9]{36}",
     "GitHub Personal Access Token",        "critical"),

    ("openai_key",        r"sk-[a-zA-Z0-9]{48}",
     "OpenAI API Key",                      "critical"),

    ("groq_key",          r"gsk_[a-zA-Z0-9]{52}",
     "Groq API Key",                        "high"),

    ("private_key",       r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private key in file",                 "critical"),

    ("jwt_token",         r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
     "JWT token hardcoded in source",       "high"),

    ("generic_api_key",   r"(?i)api[_\-]?key[\s'\"]*[=:]+[\s'\"]*([a-zA-Z0-9_\-]{20,})",
     "Generic API key",                     "high"),

    ("generic_password",  r"(?i)password[\s'\"]*[=:]+[\s'\"]*([^\s'\"]{8,})",
     "Hardcoded password",                  "high"),

    ("database_url",      r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",
     "Database URL with credentials",       "critical"),
]

# False positive reduction — skip these line patterns
SKIP_PATTERNS = [
    r"^\s*#",        # Comment
    r"example",      # Example values
    r"your[_\-]?key",
    r"\$\{",         # ${ENV_VAR} references
    r"os\.getenv",   # Python env lookup
    r"process\.env", # Node.js env lookup
]

SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__", ".tox", "dist"}
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yaml", ".yml",
                   ".json", ".txt", ".cfg", ".ini", ".sh", ".conf"}


def scan_file(file_path: Path) -> list:
    """Scan one file. Return list of (pattern_id, description, redacted, line_num, severity)."""
    matches = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    for line_num, line in enumerate(content.splitlines(), 1):
        # Skip false-positive-prone lines
        if any(re.search(p, line, re.IGNORECASE) for p in SKIP_PATTERNS):
            continue
        for pattern_id, pattern, description, severity in SECRET_PATTERNS:
            if re.search(pattern, line):
                matched = re.search(pattern, line).group(0)
                # Redact middle of secret for safe logging
                redacted = matched[:4] + "****" + matched[-4:] if len(matched) > 8 else "****"
                matches.append((pattern_id, description, redacted, line_num, severity))
                break  # One finding per line
    return matches


def run_secrets_domain(scan_paths: List[str]) -> Tuple[list, list]:
    """Walk all configured directories. Report secrets found."""
    findings = []
    for base_path in scan_paths:
        for root, dirs, files in os.walk(base_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for filename in files:
                file_path = Path(root) / filename
                if file_path.suffix.lower() not in SCAN_EXTENSIONS:
                    continue
                for pattern_id, description, redacted, line_num, severity in scan_file(file_path):
                    findings.append(RawFinding(
                        check_id="secrets_scan",
                        resource_id=f"{file_path}:L{line_num}",
                        resource_arn=f"file::{file_path}::L{line_num}",
                        resource_type="File::SourceCode",
                        region="local",
                        domain="secrets",
                        raw_evidence={
                            "file_path": str(file_path),
                            "line_number": line_num,
                            "pattern_matched": pattern_id,
                            "secret_type": description,
                            "value_redacted": redacted,
                            "note": "Actual value redacted for safety"
                        },
                        preliminary_severity=severity
                    ))
    return findings, []
```

---

## 7. Cross-Domain Deduplicator

### `agent/deduplicator.py`

```python
import hashlib, re, logging
from typing import List
from models.finding import ValidatedFinding

def _fingerprint(finding: ValidatedFinding) -> str:
    """
    Two findings are duplicates if they share check_id + normalized resource_id + severity.

    Normalization: lowercase + strip whitespace + remove version suffixes
    So "requests==2.28.0" and "requests==2.28" produce the same fingerprint.
    """
    resource = finding.resource_id.lower().strip()
    resource = re.sub(r"==[\d.]+$", "", resource)  # strip version
    key = f"{finding.check_id}::{resource}::{finding.severity}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def deduplicate(findings: List[ValidatedFinding]) -> List[ValidatedFinding]:
    """
    Remove duplicates across domains.

    When two findings share a fingerprint:
    - Keep the one with HIGHER severity
    - Tie-break: keep HIGHER confidence score
    - Log every dedup event (observable)
    """
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen = {}

    for f in findings:
        fp = _fingerprint(f)
        if fp not in seen:
            seen[fp] = f
        else:
            existing = seen[fp]
            if (SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(existing.severity, 99)
                or (f.severity == existing.severity
                    and f.confidence_score > existing.confidence_score)):
                logging.getLogger(__name__).info(
                    f"[dedup] {f.check_id}/{getattr(f,'domain','?')} replaces "
                    f"{existing.check_id}/{getattr(existing,'domain','?')}"
                )
                seen[fp] = f

    result = list(seen.values())
    logging.getLogger(__name__).info(
        f"[dedup] {len(findings)} findings → {len(result)} after deduplication "
        f"({len(findings)-len(result)} removed)"
    )
    return result
```

---

## 8. Business Impact Ranker

### `agent/impact_ranker.py`

```python
from typing import List
from models.finding import ValidatedFinding

SEVERITY_SCORE = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}

DOMAIN_WEIGHT = {
    "secrets":           1.3,   # Immediate credential exposure — highest priority
    "aws_infrastructure": 1.1,  # Wide blast radius
    "api_endpoints":      1.0,
    "dependencies":       0.9,  # Usually needs chaining with other conditions
    "local":              0.8,
}

CHECK_BONUS = {
    "secrets_scan":          20,
    "iam_root_mfa":          15,
    "iam_root_access_keys":  15,
    "s3_public_acl":         12,
    "ebs_public_snapshots":  12,
    "api_cors_misconfiguration": 8,
    "dependency_cve":         5,
}


def calculate_impact_score(finding: ValidatedFinding) -> float:
    """
    impact_score = (severity_score + check_bonus) × domain_weight × (confidence/100)

    Example:
      Critical leaked secret:      (100 + 20) × 1.3 × 0.95 = 148.2  ← ranks #1
      High root MFA missing:       (70 + 15)  × 1.1 × 0.90 = 84.2
      Medium missing CSP header:   (40 + 0)   × 1.0 × 0.80 = 32.0
      Medium Django CVE:           (40 + 5)   × 0.9 × 0.85 = 34.4
    """
    base = SEVERITY_SCORE.get(finding.severity, 0)
    domain = getattr(finding, "domain", "unknown")
    weight = DOMAIN_WEIGHT.get(domain, 1.0)
    bonus = CHECK_BONUS.get(finding.check_id, 0)
    confidence = finding.confidence_score / 100
    return round((base + bonus) * weight * confidence, 2)


def rank_by_impact(findings: List[ValidatedFinding]) -> List[ValidatedFinding]:
    """Sort findings by business impact score descending."""
    scored = [(calculate_impact_score(f), f) for f in findings]
    scored.sort(key=lambda x: x[0], reverse=True)
    if scored:
        top_score, top_f = scored[0]
        import logging
        logging.getLogger(__name__).info(
            f"[ranker] Top finding: {top_f.check_id} score={top_score}"
        )
    return [f for _, f in scored]
```

---

## 9. Extended Orchestrator L2

### `agent/orchestrator_l2.py`

```python
import logging, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from agent.intelligence import IntelligenceLayer
from agent.deduplicator import deduplicate
from agent.impact_ranker import rank_by_impact
from checks.api_checks import run_api_domain
from checks.dependency_checks import run_dependency_domain
from checks.secrets_checks import run_secrets_domain

logger = logging.getLogger(__name__)


class OrchestratorL2:

    def __init__(self, config, groq_api_key: str):
        self.config = config
        self.intelligence = IntelligenceLayer(groq_api_key, config.scan.llm_model)

    def run(self):
        start_time = datetime.utcnow()
        logger.info(f"=== Level 2 Scan started: {self.config.scan.name} ===")

        all_raw, all_errors = [], []

        # ── PARALLEL DOMAIN EXECUTION ──────────────────────────
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            # Domain 1: AWS Infrastructure (reuse L1 checks)
            futures[executor.submit(self._run_aws_domain)] = "aws_infrastructure"

            # Domain 2: API Endpoints
            if getattr(self.config, "api_targets", None):
                futures[executor.submit(
                    run_api_domain, self.config.api_targets, self.config
                )] = "api_endpoints"

            # Domain 3: Dependencies
            dep_cfg = getattr(self.config, "dependency_scan", {})
            if dep_cfg.get("paths"):
                futures[executor.submit(
                    run_dependency_domain, dep_cfg["paths"]
                )] = "dependencies"

            # Domain 4: Secrets
            sec_cfg = getattr(self.config, "secrets_scan", {})
            if sec_cfg.get("paths"):
                futures[executor.submit(
                    run_secrets_domain, sec_cfg["paths"]
                )] = "secrets"

            for future in as_completed(futures, timeout=120):
                domain = futures[future]
                try:
                    findings, errors = future.result(timeout=60)
                    logger.info(f"[{domain}] {len(findings)} raw findings, {len(errors)} errors")
                    all_raw.extend(findings)
                    all_errors.extend(errors)
                except Exception as e:
                    logger.error(f"[{domain}] Domain scan failed: {e}")

        logger.info(f"Total raw findings before enrichment: {len(all_raw)}")

        # ── LLM ENRICHMENT ─────────────────────────────────────
        validated = self.intelligence.enrich_batch(all_raw, self.config)

        # ── DEDUPLICATION ──────────────────────────────────────
        deduped = deduplicate(validated)

        # ── IMPACT RANKING ─────────────────────────────────────
        ranked = rank_by_impact(deduped)

        # ── BUILD + WRITE REPORT ───────────────────────────────
        end_time = datetime.utcnow()
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        domain_counts = {}
        for f in ranked:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            d = getattr(f, "domain", "unknown")
            domain_counts[d] = domain_counts.get(d, 0) + 1

        # Build ScanReport (same model as L1, extended fields)
        report = self._build_report(ranked, all_errors, severity_counts,
                                    domain_counts, start_time, end_time)

        from reporter.json_reporter import JSONReporter
        from reporter.markdown_reporter import MarkdownReporter
        JSONReporter(self.config.scan.output_dir).write(report, suffix="l2")
        MarkdownReporter(self.config.scan.output_dir).write(report, suffix="l2")

        logger.info(f"=== L2 Scan complete: {report.duration_seconds:.1f}s | "
                    f"Findings: {severity_counts} | Domains: {domain_counts} ===")
        return report

    def _run_aws_domain(self):
        """Run all Level 1 AWS checks. Tag each finding with domain='aws_infrastructure'."""
        import boto3
        from agent.orchestrator import CHECK_REGISTRY
        from models.report import CheckError

        session = boto3.Session(region_name=self.config.scan.aws_region)
        findings, errors = [], []

        for check_config in self.config.get_enabled_checks():
            if check_config.id not in CHECK_REGISTRY:
                continue
            check = CHECK_REGISTRY[check_config.id](check_config, session)
            result = check.run()
            if isinstance(result, CheckError):
                errors.append(result)
            else:
                for f in result:
                    f.domain = "aws_infrastructure"
                findings.extend(result)

        return findings, errors
```

---

## 10. Extended Config Schema

### `checklist_l2.yaml`

```yaml
scan:
  name: "Aivar Multi-Domain Security Audit"
  description: "Level 2 — AWS + API + Dependencies + Secrets"
  aws_region: "ap-south-1"
  timeout_seconds: 60
  max_workers: 5
  llm_model: "llama-3.3-70b-versatile"
  output_dir: "reports"

# Domain 1: AWS Infrastructure (all 13 Level 1 checks unchanged)
checks:
  - id: iam_root_mfa
    enabled: true
    description: "Root account must have MFA"
    severity_cap: critical
    tags: [iam, mfa]
  - id: iam_root_access_keys
    enabled: true
    description: "Root must not have access keys"
    severity_cap: critical
    tags: [iam, credentials]
  - id: iam_user_mfa
    enabled: true
    description: "IAM console users must have MFA"
    severity_cap: high
    tags: [iam, mfa]
  - id: iam_unused_access_keys
    enabled: true
    description: "Access keys unused 90+ days"
    severity_cap: medium
    unused_days_threshold: 90
    tags: [iam, rotation]
  - id: iam_password_policy
    enabled: true
    description: "Password policy must meet standards"
    severity_cap: medium
    tags: [iam, policy]
  - id: s3_public_acl
    enabled: true
    description: "No S3 buckets with public ACL"
    severity_cap: critical
    tags: [s3, public-access]
  - id: s3_public_policy
    enabled: true
    description: "No S3 buckets with public policy"
    severity_cap: critical
    tags: [s3, public-access]
  - id: s3_encryption_disabled
    enabled: true
    description: "S3 buckets must have SSE enabled"
    severity_cap: high
    tags: [s3, encryption]
  - id: sg_open_ssh
    enabled: true
    description: "No SG port 22 open to 0.0.0.0/0"
    severity_cap: critical
    tags: [ec2, ssh]
  - id: sg_open_rdp
    enabled: true
    description: "No SG port 3389 open to 0.0.0.0/0"
    severity_cap: critical
    tags: [ec2, rdp]
  - id: ec2_unencrypted_volumes
    enabled: true
    description: "All EBS volumes must be encrypted"
    severity_cap: high
    tags: [ec2, encryption]
  - id: cloudtrail_not_logging
    enabled: true
    description: "CloudTrail must be enabled"
    severity_cap: high
    tags: [cloudtrail, logging]
  - id: ebs_public_snapshots
    enabled: true
    description: "No public EBS snapshots"
    severity_cap: critical
    tags: [ebs, snapshots]

# Domain 2: API Endpoint Targets
api_targets:
  - url: "http://localhost:8000"   # your local agent dashboard (if running)
    name: "Local-Agent-Dashboard"
    auth_header: null

  - url: "https://httpbin.org"     # public test API — safe to scan, designed for it
    name: "HTTPBin-Public"
    auth_header: null

# Domain 3: Dependency Scanning
dependency_scan:
  paths:
    - "requirements.txt"
    - "package.json"
  ecosystems:
    - PyPI
    - npm

# Domain 4: Secrets Scanning
secrets_scan:
  paths:
    - "."                          # scan entire project directory
  exclude:
    - ".git"
    - "venv"
    - "node_modules"
    - "__pycache__"
```

---

## 11. Updated Report Schema

### New fields on `RawFinding` and `ValidatedFinding`

```python
class RawFinding(BaseModel):
    # ... all Level 1 fields unchanged ...
    domain: str = "aws_infrastructure"
    # One of: aws_infrastructure | api_endpoints | dependencies | secrets | local

class ValidatedFinding(BaseModel):
    # ... all Level 1 fields unchanged ...
    domain: str = "aws_infrastructure"
    impact_score: float = 0.0  # Set by impact_ranker — used for sorting in report
```

### New fields on `ScanReport`

```python
class ScanReport(BaseModel):
    # ... all Level 1 fields unchanged ...
    findings_by_domain: Dict[str, int] = {}
    # e.g. {"aws_infrastructure": 3, "api_endpoints": 4, "dependencies": 8, "secrets": 2}

    deduplication_removed: int = 0
    domains_scanned: List[str] = []
```

---

## 12. Implementation Order

```
Hour 1 — Model updates + config
  ✅ Add domain field to RawFinding, ValidatedFinding models
  ✅ Add findings_by_domain to ScanReport model
  ✅ Update config/loader.py to parse api_targets, dependency_scan, secrets_scan
  ✅ Create checklist_l2.yaml

Hour 2 — Secrets scanner (fastest — local only, no API)
  ✅ checks/secrets_checks.py
  ✅ Test: create test_secrets.env with fake AKIA key → verify it's found
  ✅ Verify false-positive suppression on os.getenv() lines

Hour 3 — Dependency scanner
  ✅ utils/osv_client.py
  ✅ checks/dependency_checks.py
  ✅ Test: add django==2.2.0 to requirements.txt → verify CVE findings with CVSS scores

Hour 4 — API scanner
  ✅ utils/http_client.py
  ✅ checks/api_checks.py (all 6 checks)
  ✅ Test against https://httpbin.org → should get missing headers + CORS finding

Hour 5 — Deduplicator + ranker
  ✅ agent/deduplicator.py
  ✅ agent/impact_ranker.py
  ✅ Unit test: insert 2 identical findings from different domains → verify 1 in output
  ✅ Unit test: verify secrets findings rank above medium API findings

Hour 6 — L2 orchestrator + main.py
  ✅ agent/orchestrator_l2.py
  ✅ Update main.py: python main.py --level 2 --config checklist_l2.yaml
  ✅ Update reporters: add domain breakdown section to both JSON and Markdown

Hour 7 — End-to-end run
  ✅ python main.py --level 2 --config checklist_l2.yaml
  ✅ Verify findings from all 4 domains in report
  ✅ Verify deduplication_removed count > 0
  ✅ Verify findings_by_domain shows all domains
  ✅ Verify ordering: impact_score descending, not alphabetical or by domain

Hour 8 — Polish + false positive check
  ✅ Manually review all Critical and High findings — must be real issues
  ✅ README.md: add Level 2 usage instructions
  ✅ requirements.txt: add requests==2.31.0, packaging==24.0
```

---

## 13. Acceptance Criteria Checklist

```
☐  Scans minimum 3 domains
     → Domain 1: AWS Infrastructure (13 checks, L1 reused)
     → Domain 2: API Endpoints (6 checks via requests)
     → Domain 3: Dependencies (OSV API batch query)
     → Domain 4: Secrets (bonus — 12 regex patterns, entirely local)

☐  Infrastructure: 10+ checks covering IAM, S3, SG, encryption, unused resources
     → 13 checks unchanged from Level 1

☐  APIs: 5+ checks — auth bypass, CORS, rate limiting, security headers, error disclosure
     → 6 checks: headers, CORS, rate limit, auth bypass, error disclosure, HTTP methods

☐  Dependencies: CVE with package name, version, CVE ID, CVSS score, fix version
     → OSV API returns all fields
     → dependency_checks.py maps: package_name, installed_version, cve_ids, cvss_score, fix_versions

☐  Secrets scanning: AWS keys, API tokens, passwords in repos/config files
     → 12 patterns: AWS, GitHub, OpenAI, Groq, JWT, database URLs, generic patterns

☐  Cross-domain deduplication — same vuln appears once
     → agent/deduplicator.py: fingerprint = check_id + normalized_resource + severity
     → Keeps higher severity, tie-breaks on confidence score, logs every removal

☐  False positive rate <5% on High and Critical findings
     → LLM validates severity with strict rules (from L1)
     → secrets scanner skips: comments, os.getenv(), ${VAR} references, example values
     → CORS check requires BOTH reflected origin AND credentials=true for Critical

☐  Findings ranked by business impact — not alphabetically or by domain
     → impact_ranker.py: (severity_score + check_bonus) × domain_weight × confidence
     → A critical secret outranks a critical infra finding due to domain weight
     → A medium secrets finding outranks a medium API finding
```

---

## 14. Test Targets for Demo

### API Scanner — safe public test targets

```
https://httpbin.org           ← designed for HTTP testing, has permissive CORS
http://localhost:8000          ← your agent dashboard (if running)
```

`httpbin.org` will trigger: missing security headers, CORS wildcard, possibly rate limiting.

### Dependency Scanner — known vulnerable packages

Add to `requirements.txt` for demo:

```
django==2.2.0      # CVE-2020-7471 SQL injection, multiple others
requests==2.6.0    # Several older CVEs
pillow==5.2.0      # Multiple image processing CVEs
pyyaml==3.13       # CVE-2017-18342 arbitrary code execution via yaml.load
```

### Secrets Scanner — safe fake secrets for demo

Create `test_secrets.env` (with rotated/fake values only):

```bash
# FAKE credentials for scanner testing — not real, never used
FAKE_AWS_KEY=AKIAIOSFODNN7EXAMPLE
FAKE_DB_URL=postgres://admin:hunter2@localhost/prod
FAKE_API_KEY=sk-FakeKeyForTestingPurposesOnlyNotRealAtAll123
```

Scanner finds these → proves secrets detection works in video demo.

### Demo Video Script (Level 2 — 8 minutes)

```
0:00  "Level 1 found 3 findings across AWS infrastructure in 7.7 seconds.
       Level 2 extends this to 4 domains: AWS, APIs, dependencies, and secrets."

1:00  Show checklist_l2.yaml — point out api_targets, dependency_scan, secrets_scan sections.

2:00  Run live:  python main.py --level 2 --config checklist_l2.yaml --verbose

3:30  Watch domain logs come in as scan runs:
        [aws_infrastructure] 3 findings
        [api_endpoints] 5 findings
        [dependencies] 8 findings
        [secrets] 2 findings
        [dedup] 18 findings → 16 after deduplication (2 removed)

5:00  Open Markdown report. Show findings_by_domain section.
      Point out: findings sorted by impact score, NOT by domain.
      The secrets finding ranks #1 even though it came from the last domain.

6:00  Show one CVE finding in detail:
        package_name: django
        installed_version: 2.2.0
        cve_ids: [CVE-2020-7471]
        cvss_score: 9.8
        fix_versions: [2.2.10]
        remediation_command: pip install django==2.2.10

7:00  Show the deduplication working — explain fingerprinting approach.

7:30  "Level 3 would add scheduling, SLA tracking, and Slack escalation for Critical findings."
```

---

### `requirements.txt` additions for Level 2

```
# Level 1 (unchanged)
boto3==1.34.0
botocore==1.34.0
pydantic==2.7.0
pyyaml==6.0.1
python-dotenv==1.0.0
openai==1.30.0

# Level 2 new
requests==2.31.0       # API scanner HTTP client
packaging==24.0        # Dependency version string parsing
```

---

*Plan prepared for Aivar Innovations AI/ML Hiring Challenge — June 2026*
*Manikandan M — 19manikandan2005@gmail.com*
