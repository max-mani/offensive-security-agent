"""Secrets scanner — Domain 4 via local regex patterns."""

import logging
import os
import re
from pathlib import Path
from typing import List, Tuple

from models.finding import RawFinding
from models.report import CheckError

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (
        "aws_secret_key",
        r"(?i)aws[_\-\s]?secret[_\-\s]?key[\s=:\"']+([A-Za-z0-9/+]{40})",
        "AWS Secret Access Key",
        "critical",
    ),
    ("github_token", r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "critical"),
    ("openai_key", r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", "critical"),
    ("groq_key", r"gsk_[a-zA-Z0-9]{52}", "Groq API Key", "high"),
    (
        "private_key",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Private key in file",
        "critical",
    ),
    (
        "jwt_token",
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
        "JWT token hardcoded in source",
        "high",
    ),
    (
        "generic_api_key",
        r"(?i)api[_\-]?key[\s'\"]*[=:]+[\s'\"]*([a-zA-Z0-9_\-]{20,})",
        "Generic API key",
        "high",
    ),
    (
        "generic_password",
        r"(?i)password[\s'\"]*[=:]+[\s'\"]*([^\s'\"]{8,})",
        "Hardcoded password",
        "high",
    ),
    (
        "database_url",
        r"(?i)(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",
        "Database URL with credentials",
        "critical",
    ),
]

SKIP_PATTERNS = [
    r"^\s*#",
    r"(?i)(your[_\-]?key|placeholder|changeme|replace.?me|not.?real)",
    r"\$\{",
    r"os\.getenv",
    r"process\.env",
]

SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__", ".tox", "dist", ".cursor"}
SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".txt",
    ".cfg",
    ".ini",
    ".sh",
    ".conf",
}


def _should_skip_file(file_path: Path, exclude: set[str]) -> bool:
    name = file_path.name
    if name in exclude:
        return True
    for part in file_path.parts:
        if part in exclude:
            return True
    return False


def scan_file(file_path: Path) -> list:
    """Scan one file. Return list of (pattern_id, description, redacted, line_num, severity)."""
    matches = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    for line_num, line in enumerate(content.splitlines(), 1):
        if any(re.search(p, line, re.IGNORECASE) for p in SKIP_PATTERNS):
            continue
        for pattern_id, pattern, description, severity in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if m:
                matched = m.group(0)
                redacted = matched[:4] + "****" + matched[-4:] if len(matched) > 8 else "****"
                matches.append((pattern_id, description, redacted, line_num, severity))
                break
    return matches


def run_secrets_domain(
    scan_paths: List[str],
    exclude: List[str] | None = None,
) -> Tuple[List[RawFinding], List[CheckError]]:
    """Walk configured directories and report secrets found."""
    exclude_set = set(exclude or [])
    exclude_set.update(SKIP_DIRS)
    findings: List[RawFinding] = []

    for base_path in scan_paths:
        base = Path(base_path)
        if base.is_file():
            files_to_scan = [base]
        elif base.is_dir():
            files_to_scan = []
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d not in exclude_set]
                for filename in files:
                    file_path = Path(root) / filename
                    if file_path.suffix.lower() not in SCAN_EXTENSIONS:
                        continue
                    if _should_skip_file(file_path, exclude_set):
                        continue
                    files_to_scan.append(file_path)
        else:
            logger.warning("[secrets] Path not found: %s", base_path)
            continue

        for file_path in files_to_scan:
            if _should_skip_file(file_path, exclude_set):
                continue
            for pattern_id, description, redacted, line_num, severity in scan_file(file_path):
                findings.append(
                    RawFinding(
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
                            "note": "Actual value redacted for safety",
                        },
                        preliminary_severity=severity,
                    )
                )

    logger.info("[secrets] %d secret findings", len(findings))
    return findings, []
