"""
response_analyser.py — Detect vulnerability signals in injection responses.

WHY THIS EXISTS?
Firing a payload and getting a 200 back does not mean the injection
succeeded. We need to look INSIDE the response and compare it against
what a normal (baseline) response looks like. This file does that.

DETECTION STRATEGIES (one per signal type):

  error       — DB error strings leaked in the response body or message
  auth        — A login endpoint returned success after an injection
  data        — Response returned MORE rows than the baseline
  content_change — Response content differs meaningfully from baseline
  timing      — Response took significantly longer than baseline

Each strategy returns a Finding dict if a vulnerability is detected,
or None if no signal was found.

FINDING dict:
{
    "vulnerable":    True,
    "signal":        "error",
    "severity":      "HIGH",
    "title":         "SQL Error Leaked",
    "evidence":      "near 'OR 1=1': syntax error",
    "inject_point":  "body.username",
    "payload":       { ...payload dict... },
    "request_name":  "Login",
    "url":           "http://...",
    "method":        "POST",
    "response_time": 0.043,
    "recommendation": "Use parameterised queries..."
}
"""

import json
import re


# ─────────────────────────────────────────────────────────────
# Error strings we look for in responses
# ─────────────────────────────────────────────────────────────

# SQL error patterns — these strings appearing in a response
# mean the DB error was leaked directly to the client.
SQL_ERROR_PATTERNS = [
    r"sqlite3?\.OperationalError",
    r"sqlite3?\.ProgrammingError",
    r"syntax error",
    r"near [\"'].*[\"']: syntax error",
    r"unrecognized token",
    r"no such (table|column)",
    r"SQL syntax.*MySQL",
    r"ORA-\d{5}",                     # Oracle errors
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"Microsoft.*ODBC.*SQL Server",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"SQLiteException",
    r"System\.Data\.SQLite",
    r"SQLSTATE",
    r"Invalid column name",
    r"Column count doesn't match",
]

# NoSQL error patterns
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoServerError",
    r"BSONTypeError",
    r"CastError",
    r"\$where.*failed",
    r"unknown operator",
    r"bad \$regex",
    r"invalid operator",
    r"SyntaxError.*\$where",
    r"ReferenceError.*this\.",
    r"TypeError.*document",
]

# Auth success signals — what a successful login response looks like
AUTH_SUCCESS_SIGNALS = [
    r'"success"\s*:\s*true',
    r'"token"\s*:',
    r'"access_token"\s*:',
    r'"authenticated"\s*:\s*true',
    r'"user"\s*:\s*\{',
    r'"role"\s*:\s*"admin"',
    r'"username"\s*:',
    r'"logged_in"\s*:\s*true',
]

# Timing threshold — responses slower than this multiplier of the
# baseline are flagged as potential time-based injection
TIMING_MULTIPLIER = 2.5
TIMING_MIN_DELTA  = 2.0    # minimum absolute seconds over baseline


# ─────────────────────────────────────────────────────────────
# Main analyser
# ─────────────────────────────────────────────────────────────

def analyse(result: dict, baseline: dict | None = None) -> dict | None:
    """
    Analyse a single InjectionResult dict for vulnerability signals.

    Parameters:
      result   — one InjectionResult from injector.inject_all()
      baseline — InjectionResult from a clean (non-injected) request.
                 Pass None to skip content_change and timing comparisons.

    Returns a Finding dict if a vulnerability is detected, else None.
    """
    if result.get("error") == "connection_refused":
        return None

    payload    = result.get("payload", {})
    detect_in  = payload.get("detect_in", [])
    body_str   = _flatten_response(result.get("response_body", {}))
    status     = result.get("status_code", 0)

    # Run each applicable detection strategy
    finding = None

    if "error" in detect_in:
        finding = finding or _check_error_leak(result, body_str)

    if "auth" in detect_in:
        finding = finding or _check_auth_bypass(result, body_str, status)

    if "data" in detect_in:
        finding = finding or _check_data_exposure(result, body_str, baseline)

    if "timing" in detect_in or result.get("error") == "timeout":
        finding = finding or _check_timing(result, baseline)

    if "content_change" in detect_in and baseline:
        finding = finding or _check_content_change(result, body_str, baseline)

    return finding


def analyse_all(results: list[dict],
                baseline: dict | None = None) -> list[dict]:
    """
    Analyse a list of InjectionResults and return all findings.
    Deduplicates findings with the same inject_point + technique.
    """
    findings = []
    seen     = set()

    for result in results:
        finding = analyse(result, baseline)
        if finding:
            key = (
                finding.get("inject_point", ""),
                finding.get("payload", {}).get("technique", ""),
                finding.get("signal", ""),
            )
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    return findings


def get_baseline(request: dict, timeout: float = 5.0) -> dict | None:
    """
    Send the original (unmodified) request and capture the response.
    This is used as the comparison baseline for content_change
    and timing detections.

    Returns an InjectionResult dict or None if the request fails.
    """
    try:
        from .injector import _send
        dummy_payload = {
            "value":       "__baseline__",
            "category":    "baseline",
            "technique":   "baseline",
            "description": "Baseline (clean) request",
            "detect_in":   [],
        }
        return _send(request, "baseline", dummy_payload, timeout)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Detection strategies
# ─────────────────────────────────────────────────────────────

def _check_error_leak(result: dict, body_str: str) -> dict | None:
    """
    Detect database error strings leaked in the response.

    A DB error in the response is always HIGH severity — it confirms
    injection AND leaks internal structure at the same time.
    """
    payload   = result.get("payload", {})
    category  = payload.get("category", "sqli")
    patterns  = SQL_ERROR_PATTERNS if category == "sqli" else NOSQL_ERROR_PATTERNS

    for pattern in patterns:
        match = re.search(pattern, body_str, re.IGNORECASE)
        if match:
            return _make_finding(
                result  = result,
                signal  = "error",
                severity = "HIGH",
                title   = (
                    "SQL Error Leaked in Response"
                    if category == "sqli"
                    else "NoSQL Error Leaked in Response"
                ),
                evidence = f"Error pattern matched: '{match.group()}'",
                recommendation = (
                    "Use parameterised queries (prepared statements). "
                    "Never expose raw database errors to clients. "
                    "Implement a generic error handler."
                    if category == "sqli" else
                    "Sanitise query operators before passing to the database. "
                    "Use an allowlist of permitted fields and operators. "
                    "Never expose raw database errors to clients."
                ),
            )
    return None


def _check_auth_bypass(result: dict, body_str: str,
                       status: int) -> dict | None:
    """
    Detect successful authentication achieved through injection.

    Signals:
      - HTTP 200 on a login endpoint (was expecting 401 for wrong creds)
      - Response body contains auth success patterns
    """
    url = result.get("url", "").lower()

    # Only run on likely auth endpoints
    auth_endpoint_hints = ["login", "auth", "signin", "token", "session"]
    if not any(h in url for h in auth_endpoint_hints):
        return None

    payload  = result.get("payload", {})
    category = payload.get("category", "sqli")

    if status == 200:
        for pattern in AUTH_SUCCESS_SIGNALS:
            if re.search(pattern, body_str, re.IGNORECASE):
                return _make_finding(
                    result   = result,
                    signal   = "auth",
                    severity = "CRITICAL",
                    title    = (
                        "SQL Injection — Authentication Bypass"
                        if category == "sqli"
                        else "NoSQL Injection — Authentication Bypass"
                    ),
                    evidence = (
                        f"Login succeeded with injected credentials. "
                        f"Payload: {payload.get('value')}"
                    ),
                    recommendation = (
                        "Use parameterised queries for all authentication logic. "
                        "Never concatenate user input into SQL WHERE clauses."
                        if category == "sqli" else
                        "Validate and sanitise all query operators. "
                        "Use an ODM like Mongoose with schema validation. "
                        "Reject requests where field values are objects/arrays "
                        "when a primitive is expected."
                    ),
                )
    return None


def _check_data_exposure(result: dict, body_str: str,
                          baseline: dict | None) -> dict | None:
    """
    Detect when an injection returns MORE data than the baseline.

    Strategy:
      1. Count rows in the injected response
      2. Count rows in the baseline response
      3. If injected > baseline → data exposure confirmed

    Also checks for known sensitive field names appearing in the
    response (password, secret, token, ssn, credit_card).
    """
    payload  = result.get("payload", {})
    category = payload.get("category", "sqli")

    injected_count = _count_rows(result.get("response_body", {}))
    baseline_count = _count_rows(baseline.get("response_body", {})) if baseline else 0

    # Significantly more rows returned after injection
    if injected_count > 0 and injected_count > baseline_count:
        severity = "CRITICAL" if injected_count > baseline_count + 1 else "HIGH"
        return _make_finding(
            result   = result,
            signal   = "data",
            severity = severity,
            title    = (
                "SQL Injection — Unauthorised Data Exposure"
                if category == "sqli"
                else "NoSQL Injection — Unauthorised Data Exposure"
            ),
            evidence = (
                f"Baseline returned {baseline_count} row(s). "
                f"Injection returned {injected_count} row(s)."
            ),
            recommendation = (
                "Use parameterised queries. Apply row-level access controls. "
                "Validate that responses only contain data the user is "
                "authorised to see."
                if category == "sqli" else
                "Sanitise NoSQL operator injection. Use schema validation. "
                "Apply principle of least privilege to DB queries."
            ),
        )

    # Sensitive field names present in response
    sensitive_fields = [
        "password", "passwd", "secret", "token",
        "ssn", "credit_card", "api_key", "private_key"
    ]
    for field in sensitive_fields:
        if re.search(rf'"{field}"\s*:', body_str, re.IGNORECASE):
            return _make_finding(
                result   = result,
                signal   = "data",
                severity = "HIGH",
                title    = (
                    "SQL Injection — Sensitive Field Exposed"
                    if category == "sqli"
                    else "NoSQL Injection — Sensitive Field Exposed"
                ),
                evidence = f"Sensitive field '{field}' found in response body.",
                recommendation = (
                    "Never return sensitive fields in API responses. "
                    "Apply field-level filtering before serialising responses."
                ),
            )

    return None


def _check_timing(result: dict, baseline: dict | None) -> dict | None:
    """
    Detect time-based blind injection via response timing.

    A response is flagged if:
      - It timed out (timeout = strong signal), OR
      - It took TIMING_MULTIPLIER × longer than baseline AND
        the absolute delta is at least TIMING_MIN_DELTA seconds
    """
    payload = result.get("payload", {})

    if result.get("error") == "timeout":
        return _make_finding(
            result   = result,
            signal   = "timing",
            severity = "HIGH",
            title    = "Time-Based Blind SQL Injection — Request Timeout",
            evidence = (
                f"Request timed out after the injector timeout limit. "
                f"Payload: {payload.get('value')}"
            ),
            recommendation = (
                "Use parameterised queries. Set strict DB query timeouts. "
                "Monitor for abnormally slow queries."
            ),
        )

    if baseline:
        injected_time = result.get("response_time", 0)
        baseline_time = baseline.get("response_time", 0)

        if baseline_time > 0:
            multiplier = injected_time / baseline_time
            delta      = injected_time - baseline_time

            if multiplier >= TIMING_MULTIPLIER and delta >= TIMING_MIN_DELTA:
                return _make_finding(
                    result   = result,
                    signal   = "timing",
                    severity = "HIGH",
                    title    = "Time-Based Blind SQL Injection Detected",
                    evidence = (
                        f"Baseline: {baseline_time:.3f}s. "
                        f"Injected: {injected_time:.3f}s. "
                        f"Delta: +{delta:.3f}s ({multiplier:.1f}× slower)."
                    ),
                    recommendation = (
                        "Use parameterised queries. Set strict DB query timeouts. "
                        "Monitor for abnormally slow queries in production."
                    ),
                )

    return None


def _check_content_change(result: dict, body_str: str,
                           baseline: dict) -> dict | None:
    """
    Detect boolean blind injection by comparing response content
    against the baseline.

    A meaningful content change suggests the injection altered the
    SQL condition and the DB returned different data.
    """
    payload       = result.get("payload", {})
    baseline_str  = _flatten_response(baseline.get("response_body", {}))
    injected_rows = _count_rows(result.get("response_body", {}))
    baseline_rows = _count_rows(baseline.get("response_body", {}))

    # Row count changed
    if injected_rows != baseline_rows and injected_rows > 0:
        return _make_finding(
            result   = result,
            signal   = "content_change",
            severity = "MEDIUM",
            title    = "Boolean Blind SQL Injection — Content Change Detected",
            evidence = (
                f"Baseline returned {baseline_rows} row(s), "
                f"injection returned {injected_rows} row(s). "
                f"Payload: {payload.get('value')}"
            ),
            recommendation = (
                "Use parameterised queries. Boolean-based blind injection "
                "allows full database enumeration even without visible errors."
            ),
        )

    # Significant body length change (>20%)
    len_baseline = len(baseline_str)
    len_injected = len(body_str)
    if len_baseline > 0:
        change_ratio = abs(len_injected - len_baseline) / len_baseline
        if change_ratio > 0.20 and len_injected != len_baseline:
            return _make_finding(
                result   = result,
                signal   = "content_change",
                severity = "MEDIUM",
                title    = "Boolean Blind SQL Injection — Response Size Change",
                evidence = (
                    f"Baseline response: {len_baseline} chars. "
                    f"Injected response: {len_injected} chars "
                    f"({change_ratio*100:.0f}% change)."
                ),
                recommendation = (
                    "Use parameterised queries. Investigate why injected "
                    "payloads alter the response size."
                ),
            )

    return None


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_finding(result: dict, signal: str, severity: str,
                  title: str, evidence: str,
                  recommendation: str) -> dict:
    """Construct a standardised Finding dict."""
    return {
        "vulnerable":      True,
        "signal":          signal,
        "severity":        severity,
        "title":           title,
        "evidence":        evidence,
        "inject_point":    result.get("inject_point", ""),
        "payload":         result.get("payload", {}),
        "request_name":    result.get("request_name", ""),
        "url":             result.get("url", ""),
        "method":          result.get("method", ""),
        "status_code":     result.get("status_code", 0),
        "response_time":   result.get("response_time", 0),
        "recommendation":  recommendation,
    }


def _flatten_response(body) -> str:
    """Convert a response body (dict, list, or str) to a flat string."""
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body)
    except Exception:
        return str(body)


def _count_rows(body) -> int:
    """
    Estimate the number of data rows in a response body.

    Checks common response shapes:
      {"data": [...]}           → len(data)
      {"users": [...]}          → len(users)
      [...]                     → len(list)
      {"data": {"field": [...]}} → len of nested list
    """
    if isinstance(body, list):
        return len(body)

    if isinstance(body, dict):
        # Direct data key
        for key in ("data", "users", "results", "items", "records"):
            val = body.get(key)
            if isinstance(val, list):
                return len(val)
            # GraphQL nests data one level deeper
            if isinstance(val, dict):
                for inner_key, inner_val in val.items():
                    if isinstance(inner_val, list):
                        return len(inner_val)
                    if isinstance(inner_val, dict):
                        data = inner_val.get("data")
                        if isinstance(data, list):
                            return len(data)

        # Count key — explicit row count field
        count = body.get("count")
        if isinstance(count, int):
            return count

    return 0


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.response_analyser)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 65)
    print("  RESPONSE ANALYSER — SELF TEST")
    print("═" * 65)

    tests = []

    # ── Test 1: SQL error leak ────────────────────────────────
    r1 = {
        "url": "http://localhost:5000/api/users/1",
        "method": "GET", "inject_point": "params.id",
        "status_code": 400, "response_time": 0.01,
        "request_name": "Get User",
        "payload": {
            "value": "'", "category": "sqli",
            "technique": "error_based", "detect_in": ["error"]
        },
        "response_body": {
            "error": "near \"'\": syntax error",
            "data": []
        }
    }
    f1 = analyse(r1)
    tests.append(("SQL error leak detected",
                  f1 is not None and f1["signal"] == "error"))

    # ── Test 2: Auth bypass ───────────────────────────────────
    r2 = {
        "url": "http://localhost:5000/api/login",
        "method": "POST", "inject_point": "body.username",
        "status_code": 200, "response_time": 0.01,
        "request_name": "Login",
        "payload": {
            "value": "admin'--", "category": "sqli",
            "technique": "auth_bypass", "detect_in": ["auth"]
        },
        "response_body": {
            "success": True,
            "user": {"username": "admin", "role": "admin"}
        }
    }
    f2 = analyse(r2)
    tests.append(("Auth bypass detected",
                  f2 is not None and f2["signal"] == "auth"
                  and f2["severity"] == "CRITICAL"))

    # ── Test 3: Data exposure via UNION ───────────────────────
    baseline = {
        "response_body": {"data": [{"id": 1, "name": "Laptop"}]},
        "response_time": 0.01
    }
    r3 = {
        "url": "http://localhost:5000/api/products/search",
        "method": "GET", "inject_point": "params.q",
        "status_code": 200, "response_time": 0.01,
        "request_name": "Search",
        "payload": {
            "value": "' UNION SELECT id,username,password,email FROM users--",
            "category": "sqli", "technique": "union",
            "detect_in": ["data"]
        },
        "response_body": {
            "data": [
                {"id": 1, "name": "admin",   "price": "admin123",  "stock": "admin@corp.com"},
                {"id": 2, "name": "alice",   "price": "alice456",  "stock": "alice@corp.com"},
                {"id": 3, "name": "bob",     "price": "bob789",    "stock": "bob@corp.com"},
                {"id": 4, "name": "charlie", "price": "charlie000","stock": "charlie@corp.com"},
            ]
        }
    }
    f3 = analyse(r3, baseline)
    tests.append(("UNION data exposure detected",
                  f3 is not None and f3["signal"] == "data"))

    # ── Test 4: Timing detection ──────────────────────────────
    baseline_fast = {"response_body": {}, "response_time": 0.05}
    r4 = {
        "url": "http://localhost:5000/api/orders",
        "method": "GET", "inject_point": "params.user_id",
        "status_code": 200, "response_time": 3.2,
        "request_name": "Orders",
        "payload": {
            "value": "1 AND (SELECT COUNT(*) FROM sqlite_master WHERE randomblob(300000000))>0",
            "category": "sqli", "technique": "time_based",
            "detect_in": ["timing"]
        },
        "response_body": {}
    }
    f4 = analyse(r4, baseline_fast)
    tests.append(("Time-based detection works",
                  f4 is not None and f4["signal"] == "timing"))

    # ── Test 5: NoSQLi auth bypass ────────────────────────────
    r5 = {
        "url": "http://localhost:5000/api/nosql/login",
        "method": "POST", "inject_point": "body.password",
        "status_code": 200, "response_time": 0.01,
        "request_name": "NoSQL Login",
        "payload": {
            "value": {"$ne": ""}, "category": "nosqli",
            "technique": "operator_injection", "detect_in": ["auth"]
        },
        "response_body": {
            "success": True,
            "user": {"username": "admin", "role": "admin"}
        }
    }
    f5 = analyse(r5)
    tests.append(("NoSQLi auth bypass detected",
                  f5 is not None and f5["signal"] == "auth"
                  and f5["severity"] == "CRITICAL"))

    # ── Test 6: Clean request — no finding ────────────────────
    r6 = {
        "url": "http://localhost:5000/api/login",
        "method": "POST", "inject_point": "body.username",
        "status_code": 401, "response_time": 0.01,
        "request_name": "Login",
        "payload": {
            "value": "safe_value", "category": "sqli",
            "technique": "auth_bypass", "detect_in": ["auth"]
        },
        "response_body": {"success": False, "message": "Invalid credentials"}
    }
    f6 = analyse(r6)
    tests.append(("Clean request returns no finding", f6 is None))

    # ── Results ───────────────────────────────────────────────
    print()
    all_pass = True
    for name, passed in tests:
        icon = "✅" if passed else "❌"
        if not passed:
            all_pass = False
        print(f"  {icon}  {name}")

    print("\n" + "═" * 65)
    print("  ✅ All tests passed!" if all_pass
          else "  ❌ Some tests failed — check above")
    print("═" * 65 + "\n")