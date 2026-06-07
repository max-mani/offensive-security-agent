"""Smoke-test dashboard API endpoints used by UI buttons."""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8080"


def req(method: str, path: str, expect: int | tuple[int, ...] = 200) -> dict | list | str:
    url = BASE + path
    r = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            body = resp.read().decode()
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
        body = e.read().decode()
    if isinstance(expect, int):
        expect = (expect,)
    if code not in expect:
        raise AssertionError(f"{method} {path} -> {code}, expected {expect}: {body[:200]}")
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def main() -> int:
    errors: list[str] = []

    def check(name: str, fn):
        try:
            fn()
            print(f"OK  {name}")
        except Exception as e:
            errors.append(f"{name}: {e}")
            print(f"FAIL {name}: {e}")

    check("index", lambda: req("GET", "/"))
    check("health", lambda: req("GET", "/api/health"))
    check("reports list", lambda: req("GET", "/api/reports"))
    check("l3 trend", lambda: req("GET", "/api/l3/trend"))
    check("l3 findings filters", lambda: req("GET", "/api/l3/findings?status=resolved"))
    check("l3 reset", lambda: req("DELETE", "/api/l3/reset"))

    reports = req("GET", "/api/reports")
    if reports:
        fname = reports[-1]["filename"]  # oldest
        check("report get", lambda: req("GET", f"/api/reports/{fname}"))
        # delete + verify 404
        req("DELETE", f"/api/reports/{fname}")
        req("GET", f"/api/reports/{fname}", expect=404)
        print(f"OK  report delete ({fname})")
    else:
        check("report delete 404", lambda: req("DELETE", "/api/reports/nonexistent.json", expect=404))

    if errors:
        print("\nFailed:", len(errors))
        return 1
    print("\nAll dashboard button API checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
