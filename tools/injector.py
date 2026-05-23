"""
injector.py — Craft and send injection requests to the target API.

WHY THIS EXISTS?
Having payloads is not enough. We need to know WHERE to put them
and HOW to send the modified request. This file handles both.

INJECTION STRATEGIES:
  REST endpoints:
    → Query params  — append/replace ?key=<payload>
    → Body fields   — replace individual JSON/form field values
    → Headers       — replace suspicious header values

  GraphQL endpoints:
    → GQL arguments — find argument values inside the query string
                      and replace them with the payload
    → Variables     — replace values inside the variables dict

Each injection attempt produces an InjectionResult dict that the
response analyser and reporter consume downstream.

OUTPUT (one per injection attempt):
{
    "request_name":  "Login",
    "url":           "http://localhost:5000/api/login",
    "method":        "POST",
    "inject_point":  "body.username",
    "payload":       { ...payload dict from payload_library... },
    "status_code":   200,
    "response_body": {...},
    "response_time": 0.043,
    "error":         None
}
"""

import json
import copy
import time
import re
import httpx


# ─────────────────────────────────────────────────────────────
# Public entry points
# ─────────────────────────────────────────────────────────────

def inject_all(request: dict, payloads: list[dict],
               endpoint_info: dict, timeout: float = 10.0) -> list[dict]:
    """
    Run every payload against every injectable point in the request.

    Parameters:
      request       — parsed request dict from curl_parser / collection_parser
      payloads      — list of payload dicts from payload_library
      endpoint_info — result dict from endpoint_detector
      timeout       — per-request timeout in seconds

    Returns a flat list of InjectionResult dicts — one per
    (injection_point × payload) combination.
    """
    results = []
    endpoint_type = endpoint_info.get("type", "rest")

    if endpoint_type == "graphql":
        results = _inject_graphql(request, payloads, timeout)
    else:
        results = _inject_rest(request, payloads, timeout)

    return results


def inject_single(request: dict, payload: dict,
                  inject_point: str, timeout: float = 10.0) -> dict:
    """
    Fire one payload at one specific injection point.

    inject_point format:
      "params.role"        — query parameter named 'role'
      "body.username"      — body field named 'username'
      "body.password"      — body field named 'password'
      "header.X-User-Id"   — header named X-User-Id
      "gql.id"             — GraphQL argument named 'id'
      "gql.query"          — entire GraphQL query string replaced

    Returns a single InjectionResult dict.
    """
    modified = copy.deepcopy(request)
    parts    = inject_point.split(".", 1)
    location = parts[0]
    field    = parts[1] if len(parts) > 1 else ""

    if location == "body" and isinstance(payload["value"], (dict, list)):
        payload_val = payload["value"]
    else:
        payload_val = _serialise_payload(payload["value"])

    if location == "params":
        modified["params"][field] = payload_val

    elif location == "body":
        if isinstance(modified.get("body"), dict):
            modified["body"][field] = payload_val
        else:
            modified["body"] = payload_val

    elif location == "header":
        modified["headers"][field] = payload_val

    elif location == "gql":
        gql_body = modified.get("body", {})
        if isinstance(gql_body, dict) and "query" in gql_body:
            gql_body["query"] = _inject_gql_argument(
                gql_body["query"], field, payload_val
            )

    return _send(modified, inject_point, payload, timeout)


# ─────────────────────────────────────────────────────────────
# REST injection
# ─────────────────────────────────────────────────────────────

def _inject_rest(request: dict, payloads: list[dict],
                 timeout: float) -> list[dict]:
    """
    Inject payloads into every REST injection point:
      - each query parameter
      - each body field (if body is a dict)
      - suspicious headers

    Skips whole-body replacement payloads (auth_bypass dicts) for
    individual field injection — those go through body-level injection.
    """
    results = []

    # ── Collect all injection points ──────────────────────────
    points = []

    for key in request.get("params", {}):
        points.append(("params", key))

    body = request.get("body")
    if isinstance(body, dict):
        for key in body:
            points.append(("body", key))
    elif isinstance(body, str) and body:
        # Try to parse the raw string as JSON before giving up
        import json as _json
        try:
            parsed = _json.loads(body)
            if isinstance(parsed, dict):
                for key in parsed:
                    points.append(("body", key))
                # Update the request body to the parsed dict
                request = dict(request)
                request["body"] = parsed
        except _json.JSONDecodeError:
            points.append(("body", "__raw__"))

    suspicious_headers = {
        "x-user-id", "x-username", "x-forwarded-for",
        "authorization", "x-api-key", "x-token"
    }
    for h in request.get("headers", {}):
        if h.lower() in suspicious_headers:
            points.append(("header", h))

    # ── For NoSQLi auth-bypass — also try full body replacement ─
    full_body_payloads = [
        p for p in payloads
        if p["technique"] == "auth_bypass"
        and isinstance(p["value"], dict)
        and any(k in p["value"] for k in ["username", "password"])
    ]
    for payload in full_body_payloads:
        result = _send_full_body(request, payload, timeout)
        results.append(result)

    # ── Regular field-level injection ─────────────────────────
    for location, field in points:
        for payload in payloads:
            # Skip full-body auth bypass payloads for field injection
            if (payload["technique"] == "auth_bypass"
                    and isinstance(payload["value"], dict)
                    and location == "body"):
                continue

            inject_point = f"{location}.{field}"
            result = inject_single(request, payload, inject_point, timeout)
            results.append(result)

    return results


# ─────────────────────────────────────────────────────────────
# GraphQL injection
# ─────────────────────────────────────────────────────────────

def _inject_graphql(request: dict, payloads: list[dict],
                    timeout: float) -> list[dict]:
    """
    Inject payloads into GraphQL arguments.

    Strategy:
      1. Extract all argument names from the GQL query string
      2. For each argument × each payload → replace arg value
         and fire the request
      3. Also try injecting into the variables dict if present
    """
    results  = []
    body     = request.get("body", {})
    gql_body = body if isinstance(body, dict) else {}
    query    = gql_body.get("query", "")

    if not query:
        return results

    # Find all argument names in the query
    arg_names = _extract_gql_arg_names(query)

    if not arg_names:
        # No named args found — inject into the raw query string
        for payload in payloads:
            inject_point = "gql.query"
            result = inject_single(request, payload, inject_point, timeout)
            results.append(result)
        return results

    # Inject into each argument
    for arg_name in arg_names:
        for payload in payloads:
            inject_point = f"gql.{arg_name}"
            result = inject_single(request, payload, inject_point, timeout)
            results.append(result)

    # Also inject into variables if present
    variables = gql_body.get("variables", {})
    if isinstance(variables, dict):
        for var_name in variables:
            for payload in payloads:
                modified = copy.deepcopy(request)
                modified["body"]["variables"][var_name] = \
                    _serialise_payload(payload["value"])
                result = _send(
                    modified, f"variables.{var_name}", payload, timeout
                )
                results.append(result)

    return results


# ─────────────────────────────────────────────────────────────
# GraphQL query manipulation helpers
# ─────────────────────────────────────────────────────────────

def _extract_gql_arg_names(query: str) -> list[str]:
    """
    Extract all argument names from a GraphQL query string.

    Example:
      'query { sqlUser(id: "1") { id } sqlLogin(username: "a") { success } }'
      → ['id', 'username']
    """
    # Match content inside parentheses after a field name
    arg_blocks = re.findall(r'\w+\s*\(([^)]+)\)', query)
    names = []
    for block in arg_blocks:
        # Each  key: value  pair
        for match in re.finditer(r'(\w+)\s*:', block):
            name = match.group(1)
            if name not in names:
                names.append(name)
    return names


def _inject_gql_argument(query: str, arg_name: str,
                          payload_str: str) -> str:
    """
    Replace the value of a named argument in a GraphQL query string.

    Example:
      query   = 'query { sqlUser(id: "1") { id username } }'
      arg     = 'id'
      payload = "1 OR 1=1--"
      result  = 'query { sqlUser(id: "1 OR 1=1--") { id username } }'

    Handles both quoted string values and unquoted numeric values.
    """
    # Replace quoted string value:  argName: "value"
    quoted_pattern = rf'({re.escape(arg_name)}\s*:\s*)"[^"]*"'
    new_query, n = re.subn(
        quoted_pattern,
        rf'\1"{payload_str}"',
        query
    )
    if n > 0:
        return new_query

    # Replace unquoted value:  argName: 123
    unquoted_pattern = rf'({re.escape(arg_name)}\s*:\s*)[^\s,)}}]+'
    new_query, n = re.subn(
        unquoted_pattern,
        rf'\1"{payload_str}"',
        query
    )
    if n > 0:
        return new_query

    # Argument not found — return original query unchanged
    return query


# ─────────────────────────────────────────────────────────────
# HTTP sender
# ─────────────────────────────────────────────────────────────

def _send(request: dict, inject_point: str,
          payload: dict, timeout: float) -> dict:
    """
    Send a modified request and return an InjectionResult dict.
    Records the response status, body, and elapsed time.
    """
    method  = request.get("method", "GET").upper()
    url     = request.get("url", "")
    headers = dict(request.get("headers", {}))
    params  = request.get("params", {})
    body    = request.get("body")

    # Default Content-Type if sending a dict body
    if isinstance(body, dict) and "content-type" not in {
        k.lower() for k in headers
    }:
        headers["Content-Type"] = "application/json"

    start = time.perf_counter()
    error = None
    status_code   = 0
    response_body = {}

    try:
        with httpx.Client(timeout=timeout) as client:
            if method == "GET":
                all_params = {**params}
                resp = client.get(url, headers=headers, params=all_params)
            elif method in ("POST", "PUT", "PATCH"):
                if isinstance(body, dict):
                    resp = client.request(
                        method, url,
                        headers=headers,
                        params=params,
                        json=body,
                    )
                else:
                    resp = client.request(
                        method, url,
                        headers=headers,
                        params=params,
                        content=str(body or "").encode(),
                    )
            else:
                resp = client.request(
                    method, url,
                    headers=headers,
                    params=params,
                )

        status_code = resp.status_code
        try:
            response_body = resp.json()
        except Exception:
            response_body = {"raw": resp.text}

    except httpx.TimeoutException:
        error = "timeout"
        # Timeout itself can be a timing-based injection signal
    except httpx.ConnectError:
        error = "connection_refused"
    except Exception as e:
        error = str(e)

    elapsed = time.perf_counter() - start

    return {
        "request_name":  request.get("name", ""),
        "url":           url,
        "method":        method,
        "inject_point":  inject_point,
        "payload":       payload,
        "status_code":   status_code,
        "response_body": response_body,
        "response_time": round(elapsed, 4),
        "error":         error,
    }


def _send_full_body(request: dict, payload: dict,
                    timeout: float) -> dict:
    """
    Replace the entire request body with the payload value.
    Used for NoSQLi auth-bypass payloads that specify a complete
    {username: ..., password: ...} dict rather than a single field.
    """
    modified = copy.deepcopy(request)
    modified["body"] = payload["value"]
    return _send(modified, "body.__full__", payload, timeout)


# ─────────────────────────────────────────────────────────────
# Payload value serialiser
# ─────────────────────────────────────────────────────────────

def _serialise_payload(value) -> str:
    """
    Convert a payload value to a string suitable for injection.

    - str  → returned as-is
    - dict → JSON-encoded string (for NoSQLi operator dicts)
    - list → JSON-encoded string
    - other → str() conversion
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.injector)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from .payload_library import get_sqli_payloads, get_nosqli_payloads
    from .endpoint_detector import detect_endpoint_type

    print("\n" + "═" * 65)
    print("  INJECTOR — SELF TEST")
    print("  Make sure the mock server is running on port 5000")
    print("═" * 65)

    # ── Test 1: REST SQLi on /api/login ───────────────────────
    rest_request = {
        "name":    "SQL Login",
        "method":  "POST",
        "url":     "http://127.0.0.1:5000/api/login",
        "headers": {"Content-Type": "application/json"},
        "body":    {"username": "admin", "password": "x"},
        "params":  {},
        "raw_body": "",
    }
    endpoint_info = detect_endpoint_type(rest_request)
    payloads = get_sqli_payloads(["auth_bypass"])[:2]  # just 2 for speed

    print(f"\n  Test 1 — REST SQLi on {rest_request['url']}")
    results = inject_all(rest_request, payloads, endpoint_info, timeout=5.0)
    for r in results:
        status = r["status_code"]
        elapsed = r["response_time"]
        point   = r["inject_point"]
        val     = str(r["payload"]["value"])[:40]
        err     = f" ⚠ {r['error']}" if r["error"] else ""
        print(f"    [{status}] {elapsed:.3f}s  {point:<25} {val}{err}")

    # ── Test 2: REST NoSQLi on /api/nosql/login ───────────────
    nosql_request = {
        "name":    "NoSQL Login",
        "method":  "POST",
        "url":     "http://127.0.0.1:5000/api/nosql/login",
        "headers": {"Content-Type": "application/json"},
        "body":    {"username": "admin", "password": "x"},
        "params":  {},
        "raw_body": "",
    }
    endpoint_info2 = detect_endpoint_type(nosql_request)
    payloads2 = get_nosqli_payloads(["operator_injection"])[:2]

    print(f"\n  Test 2 — REST NoSQLi on {nosql_request['url']}")
    results2 = inject_all(nosql_request, payloads2, endpoint_info2, timeout=5.0)
    for r in results2:
        status  = r["status_code"]
        elapsed = r["response_time"]
        point   = r["inject_point"]
        val     = str(r["payload"]["value"])[:40]
        err     = f" ⚠ {r['error']}" if r["error"] else ""
        print(f"    [{status}] {elapsed:.3f}s  {point:<25} {val}{err}")

    # ── Test 3: GraphQL SQLi on /graphql ─────────────────────
    gql_request = {
        "name":    "GraphQL sqlUser",
        "method":  "POST",
        "url":     "http://127.0.0.1:5000/graphql",
        "headers": {"Content-Type": "application/json"},
        "body":    {"query": 'query { sqlUser(id: "1") { id username email } }'},
        "params":  {},
        "raw_body": "",
    }
    endpoint_info3 = detect_endpoint_type(gql_request)
    payloads3 = get_sqli_payloads(["auth_bypass"])[:2]

    print(f"\n  Test 3 — GraphQL SQLi on {gql_request['url']}")
    results3 = inject_all(gql_request, payloads3, endpoint_info3, timeout=5.0)
    for r in results3:
        status  = r["status_code"]
        elapsed = r["response_time"]
        point   = r["inject_point"]
        val     = str(r["payload"]["value"])[:40]
        err     = f" ⚠ {r['error']}" if r["error"] else ""
        print(f"    [{status}] {elapsed:.3f}s  {point:<25} {val}{err}")

    print("\n" + "═" * 65)
    print("  ✅ Injector self-test complete")
    print("═" * 65 + "\n")