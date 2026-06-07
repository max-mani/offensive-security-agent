import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_http_client(timeout: int = 10) -> requests.Session:
    """Safe HTTP client for API scanning with connect-only retries."""
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=False, status=False, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "OffensiveSecurityAgent/1.0 (Security Scanner)"})
    return session
