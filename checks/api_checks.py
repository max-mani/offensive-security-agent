"""API endpoint security checks — Domain 2."""

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

import requests

from models.config import APITarget, ScanConfig
from models.finding import RawFinding
from models.report import CheckError
from utils.http_client import build_http_client

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"severity": "high"},
    "X-Frame-Options": {"severity": "medium"},
    "X-Content-Type-Options": {"severity": "medium"},
    "Content-Security-Policy": {"severity": "medium"},
    "Referrer-Policy": {"severity": "low"},
}

PROTECTED_PATHS = [
    "/admin",
    "/api/admin",
    "/dashboard",
    "/api/users",
    "/api/config",
    "/internal",
    "/metrics",
    "/debug",
]

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace exposed"),
    (r"at\s+[\w.$]+\([\w.]+:\d+\)", "Java/Node.js stack trace exposed"),
    (r"/home/\w+/", "Linux home path disclosed"),
    (r"C:\\Users\\", "Windows path disclosed"),
    (r"SQL syntax.*MySQL", "MySQL error with query details"),
    (r"psycopg2\.OperationalError", "PostgreSQL connection details"),
    (r"django\.core\.exceptions", "Django exception class exposed"),
    (r"werkzeug\.exceptions", "Flask debug info exposed"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key in error response"),
]

MALFORMED_PAYLOADS: List[Tuple] = [
    ("GET", "/?id=1'--"),
    ("GET", "/?input=<script>"),
    ("GET", "/../../../../etc/passwd"),
    ("POST", "/", '{"key": null}'),
]


@dataclass
class APITargetContext:
    url: str
    name: str
    auth_header: str | None = None

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")


class SecurityHeadersCheck:
    check_id = "api_security_headers"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def run(self) -> List[RawFinding]:
        findings = []
        try:
            resp = self.http.get(self.target.base_url, timeout=10)
            existing = {k.lower() for k in resp.headers}
            for header, meta in REQUIRED_HEADERS.items():
                if header.lower() not in existing:
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=f"{self.target.name}::{header}",
                            resource_arn=f"api::{self.target.base_url}",
                            resource_type="API::Endpoint",
                            region="api",
                            domain="api_endpoints",
                            raw_evidence={
                                "target_url": self.target.base_url,
                                "missing_header": header,
                                "response_status": resp.status_code,
                                "existing_headers": dict(resp.headers),
                                "api_call": f"GET {self.target.base_url}",
                            },
                            preliminary_severity=meta["severity"],
                        )
                    )
        except requests.RequestException as e:
            logger.warning("[%s] %s: %s", self.check_id, self.target.name, e)
        return findings


class CORSMisconfigCheck:
    check_id = "api_cors_misconfiguration"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def run(self) -> List[RawFinding]:
        evil_origin = "https://evil-attacker-test.com"
        try:
            resp = self.http.get(
                self.target.base_url,
                headers={"Origin": evil_origin},
                timeout=10,
            )
        except requests.RequestException as e:
            logger.warning("[%s] %s: %s", self.check_id, self.target.name, e)
            return []

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "false").lower()

        if acao == evil_origin and acac == "true":
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id=f"{self.target.name}::cors_credentials",
                    resource_arn=f"api::{self.target.base_url}",
                    resource_type="API::Endpoint",
                    region="api",
                    domain="api_endpoints",
                    raw_evidence={
                        "Access-Control-Allow-Origin": acao,
                        "Access-Control-Allow-Credentials": acac,
                        "sent_origin": evil_origin,
                        "api_call": f"GET {self.target.base_url} (Origin: {evil_origin})",
                    },
                    preliminary_severity="critical",
                )
            ]

        if acao == "*":
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id=f"{self.target.name}::cors_wildcard",
                    resource_arn=f"api::{self.target.base_url}",
                    resource_type="API::Endpoint",
                    region="api",
                    domain="api_endpoints",
                    raw_evidence={
                        "Access-Control-Allow-Origin": "*",
                        "api_call": f"GET {self.target.base_url} (Origin: {evil_origin})",
                    },
                    preliminary_severity="high",
                )
            ]

        return []


class RateLimitCheck:
    check_id = "api_rate_limiting"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def run(self) -> List[RawFinding]:
        rate_limited = False
        status_codes = []

        for _ in range(30):
            try:
                resp = self.http.get(self.target.base_url, timeout=5)
                status_codes.append(resp.status_code)

                if resp.status_code == 429:
                    rate_limited = True
                    break

                rl_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if any(x in k.lower() for x in ["ratelimit", "rate-limit", "retry-after"])
                }
                if rl_headers:
                    rate_limited = True
                    break
            except requests.RequestException:
                break

        if not rate_limited and status_codes:
            return [
                RawFinding(
                    check_id=self.check_id,
                    resource_id=f"{self.target.name}::no_rate_limit",
                    resource_arn=f"api::{self.target.base_url}",
                    resource_type="API::Endpoint",
                    region="api",
                    domain="api_endpoints",
                    raw_evidence={
                        "requests_sent": len(status_codes),
                        "got_429": False,
                        "rate_limit_headers_found": False,
                        "status_codes_sample": status_codes[:5],
                        "api_call": f"GET x30 {self.target.base_url}",
                    },
                    preliminary_severity="high",
                )
            ]
        return []


class AuthBypassCheck:
    check_id = "api_auth_bypass"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def run(self) -> List[RawFinding]:
        findings = []
        for path in PROTECTED_PATHS:
            url = urljoin(self.target.base_url + "/", path.lstrip("/"))
            try:
                resp = self.http.get(url, timeout=5, headers={"Authorization": ""})
                if resp.status_code == 200:
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=f"{self.target.name}::{path}",
                            resource_arn=f"api::{url}",
                            resource_type="API::Endpoint",
                            region="api",
                            domain="api_endpoints",
                            raw_evidence={
                                "path_tested": path,
                                "http_status": 200,
                                "auth_header_sent": None,
                                "response_size_bytes": len(resp.content),
                                "api_call": f"GET {url}",
                            },
                            preliminary_severity="high",
                        )
                    )
            except requests.exceptions.ConnectionError:
                pass
            except requests.RequestException as e:
                logger.debug("[%s] %s %s: %s", self.check_id, self.target.name, path, e)
        return findings


class ErrorDisclosureCheck:
    check_id = "api_error_disclosure"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def _send(self, method: str, url: str, body: str | None = None):
        try:
            if method == "POST":
                return self.http.post(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
            return self.http.get(url, timeout=5)
        except requests.RequestException:
            return None

    def run(self) -> List[RawFinding]:
        findings = []
        for item in MALFORMED_PAYLOADS:
            method, path = item[0], item[1]
            body = item[2] if len(item) > 2 else None
            url = urljoin(self.target.base_url + "/", path.lstrip("/"))
            resp = self._send(method, url, body)
            if resp is None:
                continue
            for pattern, description in ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    findings.append(
                        RawFinding(
                            check_id=self.check_id,
                            resource_id=f"{self.target.name}::{path}",
                            resource_arn=f"api::{url}",
                            resource_type="API::Endpoint",
                            region="api",
                            domain="api_endpoints",
                            raw_evidence={
                                "payload_sent": path,
                                "pattern_matched": pattern,
                                "description": description,
                                "response_excerpt": resp.text[:300],
                                "api_call": f"{method} {url}",
                            },
                            preliminary_severity="high",
                        )
                    )
                    break
        return findings


class DangerousHTTPMethodsCheck:
    check_id = "api_dangerous_methods"

    def __init__(self, target: APITargetContext, http: requests.Session):
        self.target = target
        self.http = http

    def run(self) -> List[RawFinding]:
        findings = []
        try:
            resp = self.http.options(self.target.base_url, timeout=5)
            allow = resp.headers.get("Allow", "")
            dangerous = [m for m in ["TRACE", "TRACK"] if m in allow.upper()]
            if dangerous:
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=f"{self.target.name}::allow_header",
                        resource_arn=f"api::{self.target.base_url}",
                        resource_type="API::Endpoint",
                        region="api",
                        domain="api_endpoints",
                        raw_evidence={
                            "Allow_header": allow,
                            "dangerous_methods": dangerous,
                            "api_call": f"OPTIONS {self.target.base_url}",
                        },
                        preliminary_severity="medium",
                    )
                )

            trace_resp = self.http.request("TRACE", self.target.base_url, timeout=5)
            if trace_resp.status_code == 200 and "TRACE" in trace_resp.text.upper():
                findings.append(
                    RawFinding(
                        check_id=self.check_id,
                        resource_id=f"{self.target.name}::trace_echo",
                        resource_arn=f"api::{self.target.base_url}",
                        resource_type="API::Endpoint",
                        region="api",
                        domain="api_endpoints",
                        raw_evidence={
                            "TRACE_echoes_request": True,
                            "vulnerability": "Cross-Site Tracing (XST) possible",
                            "api_call": f"TRACE {self.target.base_url}",
                        },
                        preliminary_severity="medium",
                    )
                )
        except requests.RequestException as e:
            logger.warning("[%s] %s: %s", self.check_id, self.target.name, e)
        return findings


API_CHECK_CLASSES = [
    SecurityHeadersCheck,
    CORSMisconfigCheck,
    RateLimitCheck,
    AuthBypassCheck,
    ErrorDisclosureCheck,
    DangerousHTTPMethodsCheck,
]


def run_api_domain(
    targets: List[APITarget],
    config: ScanConfig,
) -> Tuple[List[RawFinding], List[CheckError]]:
    """Run all 6 API checks against all configured targets."""
    http = build_http_client()
    all_findings: List[RawFinding] = []
    all_errors: List[CheckError] = []

    for target_cfg in targets:
        target = APITargetContext(
            url=target_cfg.url.rstrip("/"),
            name=target_cfg.name,
            auth_header=target_cfg.auth_header,
        )
        logger.info("[api_endpoints] Scanning target: %s (%s)", target.name, target.base_url)

        for check_cls in API_CHECK_CLASSES:
            checker = check_cls(target, http)
            try:
                result = checker.run()
                all_findings.extend(result)
                logger.info("[%s] %s: %d findings", checker.check_id, target.name, len(result))
            except Exception as e:
                logger.error("[%s] %s failed: %s", checker.check_id, target.name, e)
                all_errors.append(
                    CheckError(
                        check_id=checker.check_id,
                        error_type="api_error",
                        error_message=str(e),
                    )
                )

    return all_findings, all_errors
