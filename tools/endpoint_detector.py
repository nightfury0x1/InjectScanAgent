"""
endpoint_detector.py — Detect whether a request targets a REST or GraphQL endpoint.

WHY THIS EXISTS?
The injector needs to know which strategy to use when crafting payloads:

  REST     → inject into query params, body fields, headers independently
  GraphQL  → inject into arguments INSIDE the query string

This detector looks at multiple signals from the parsed request dict
and returns a confident classification. It never makes network calls —
everything is decided from the request structure alone.

OUTPUT:
{
    "type":       "graphql",          # "rest" or "graphql"
    "confidence": "high",             # "high", "medium", "low"
    "signals":    ["url contains /graphql", "body has query key"],
    "operation":  "query",            # graphql only: "query"/"mutation"/"unknown"
    "fields":     ["sqlUser"],        # graphql only: top-level field names
    "endpoint_label": "POST /graphql" # human-readable label for the reporter
}
"""

import re
import json


# ─────────────────────────────────────────────────────────────
# GraphQL signals we look for
# ─────────────────────────────────────────────────────────────

# URL paths that strongly indicate a GraphQL endpoint
_GQL_URL_PATTERNS = [
    r"/graphql",
    r"/gql",
    r"/api/graphql",
    r"/v\d+/graphql",
    r"/graph$",
]

# Body keys that indicate a GraphQL request
_GQL_BODY_KEYS = {"query", "mutation", "subscription", "variables", "operationName"}

# GraphQL operation keywords
_GQL_OPERATION_RE = re.compile(
    r'^\s*(query|mutation|subscription)\s*[\w\s]*\{', re.IGNORECASE
)

# Header values that suggest GraphQL
_GQL_HEADER_HINTS = {"application/graphql"}


# ─────────────────────────────────────────────────────────────
# Main detector
# ─────────────────────────────────────────────────────────────

def detect_endpoint_type(request: dict) -> dict:
    """
    Analyse a parsed request dict and classify it as REST or GraphQL.

    Checks (in descending weight):
      1. URL path matches known GraphQL patterns
      2. Body contains a 'query' key whose value looks like a GQL operation
      3. Body contains 'variables' or 'operationName' keys
      4. Content-Type is application/graphql
      5. Body has a query key that contains { } structure

    Returns a detection result dict.
    """
    signals  = []
    gql_score = 0

    url     = request.get("url", "").lower()
    method  = request.get("method", "GET").upper()
    headers = {k.lower(): v for k, v in request.get("headers", {}).items()}
    body    = request.get("body") or {}

    # ── Signal 1: URL path ────────────────────────────────────
    for pattern in _GQL_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            gql_score += 3
            signals.append(f"URL matches GraphQL pattern '{pattern}'")
            break

    # ── Signal 2: body has 'query' key with GQL operation ────
    query_value = None
    if isinstance(body, dict):
        query_value = body.get("query") or body.get("mutation") or body.get("subscription")

    if query_value and isinstance(query_value, str):
        if _GQL_OPERATION_RE.match(query_value):
            gql_score += 3
            signals.append("Body 'query' value is a GraphQL operation")
        elif "{" in query_value and "}" in query_value:
            gql_score += 2
            signals.append("Body 'query' value contains { } structure")

    # ── Signal 3: body has GraphQL-specific keys ──────────────
    if isinstance(body, dict):
        gql_keys_present = _GQL_BODY_KEYS & set(body.keys())
        if "variables" in gql_keys_present or "operationName" in gql_keys_present:
            gql_score += 2
            signals.append(f"Body contains GraphQL keys: {gql_keys_present}")
        elif "query" in gql_keys_present:
            gql_score += 1
            signals.append("Body contains 'query' key")

    # ── Signal 4: Content-Type is application/graphql ─────────
    ct = headers.get("content-type", "")
    if "application/graphql" in ct:
        gql_score += 2
        signals.append("Content-Type is application/graphql")

    # ── Signal 5: raw body looks like a GQL query string ──────
    raw_body = request.get("raw_body", "")
    if isinstance(raw_body, str) and _GQL_OPERATION_RE.search(raw_body):
        if gql_score == 0:   # only add if no other signals found
            gql_score += 1
            signals.append("Raw body contains GraphQL operation keyword")

    # ── Classification ────────────────────────────────────────
    if gql_score >= 3:
        endpoint_type = "graphql"
        confidence    = "high" if gql_score >= 5 else "medium"
    elif gql_score > 0:
        endpoint_type = "graphql"
        confidence    = "low"
    else:
        endpoint_type = "rest"
        confidence    = "high"
        signals.append("No GraphQL signals detected — classified as REST")

    # ── GraphQL-specific extras ───────────────────────────────
    operation = "unknown"
    fields    = []

    if endpoint_type == "graphql" and query_value:
        operation = _detect_gql_operation(query_value)
        fields    = _extract_gql_fields(query_value)

    # ── Build label ───────────────────────────────────────────
    parsed_path  = "/" + "/".join(request.get("url", "").split("/")[3:])
    endpoint_label = f"{method} {parsed_path}"

    return {
        "type":           endpoint_type,
        "confidence":     confidence,
        "signals":        signals,
        "operation":      operation,
        "fields":         fields,
        "endpoint_label": endpoint_label,
        "url":            request.get("url", ""),
        "method":         method,
    }


# ─────────────────────────────────────────────────────────────
# GraphQL helpers
# ─────────────────────────────────────────────────────────────

def _detect_gql_operation(query_string: str) -> str:
    """
    Detect whether the GraphQL operation is a query, mutation,
    or subscription. Returns 'unknown' if it cannot be determined.
    """
    s = query_string.strip().lower()
    if s.startswith("mutation"):
        return "mutation"
    if s.startswith("subscription"):
        return "subscription"
    if s.startswith("query") or s.startswith("{"):
        return "query"
    return "unknown"


def _extract_gql_fields(query_string: str) -> list[str]:
    """
    Extract the top-level field names from a GraphQL query string.

    Example:
      'query { sqlUser(id: "1") { id username } }'
      → ['sqlUser']

      'query { sqlLogin(username: "a") { success } sqlSearch(q: "x") { name } }'
      → ['sqlLogin', 'sqlSearch']
    """
    # Strip outer query/mutation/subscription wrapper first
    inner = re.sub(
        r'^\s*(?:query|mutation|subscription)\s*\w*\s*\{', '', query_string
    ).strip()

    # Match field names — word followed by ( or {
    fields = re.findall(r'\b(\w+)\s*(?:\(|{)', inner)

    # Filter out common GraphQL keywords
    excluded = {"query", "mutation", "subscription", "fragment", "on"}
    return [f for f in fields if f.lower() not in excluded]


# ─────────────────────────────────────────────────────────────
# Convenience wrapper — detect from a raw cURL string
# ─────────────────────────────────────────────────────────────

def detect_from_curl(curl_string: str) -> dict:
    """
    Parse a cURL string and immediately detect the endpoint type.
    Convenience function used by the agents directly.
    """
    from .curl_parser import parse_curl
    request = parse_curl(curl_string)
    return detect_endpoint_type(request)


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.endpoint_detector)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    test_cases = [
        {
            "label": "REST — GET with query param",
            "request": {
                "method": "GET",
                "url": "http://127.0.0.1:5000/api/users",
                "headers": {},
                "body": None,
                "params": {"role": "admin"},
                "raw_body": "",
            }
        },
        {
            "label": "REST — POST login",
            "request": {
                "method": "POST",
                "url": "http://127.0.0.1:5000/api/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "admin", "password": "x"},
                "params": {},
                "raw_body": '{"username":"admin","password":"x"}',
            }
        },
        {
            "label": "GraphQL — sqlUser query",
            "request": {
                "method": "POST",
                "url": "http://127.0.0.1:5000/graphql",
                "headers": {"Content-Type": "application/json"},
                "body": {"query": 'query { sqlUser(id: "1") { id username } }'},
                "params": {},
                "raw_body": '{"query":"query { sqlUser(id: \\"1\\") { id username } }"}',
            }
        },
        {
            "label": "GraphQL — nosqlLogin mutation style",
            "request": {
                "method": "POST",
                "url": "http://127.0.0.1:5000/graphql",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "query": 'query { nosqlLogin(username: "admin", password: "x") { success } }',
                    "variables": {}
                },
                "params": {},
                "raw_body": "",
            }
        },
        {
            "label": "GraphQL — URL only signal (no body yet)",
            "request": {
                "method": "POST",
                "url": "http://api.example.com/graphql",
                "headers": {},
                "body": {},
                "params": {},
                "raw_body": "",
            }
        },
    ]

    print("\n" + "═" * 65)
    print("  ENDPOINT DETECTOR — SELF TEST")
    print("═" * 65)

    all_pass = True
    expected_types = ["rest", "rest", "graphql", "graphql", "graphql"]

    for i, (tc, expected) in enumerate(zip(test_cases, expected_types)):
        result = detect_endpoint_type(tc["request"])
        passed = result["type"] == expected
        icon   = "✅" if passed else "❌"
        if not passed:
            all_pass = False

        print(f"\n{icon} Test {i+1}: {tc['label']}")
        print(f"   Type       : {result['type']}  (confidence: {result['confidence']})")
        print(f"   Signals    : {result['signals']}")
        if result["type"] == "graphql":
            print(f"   Operation  : {result['operation']}")
            print(f"   GQL Fields : {result['fields']}")

    print("\n" + "═" * 65)
    print("✅ All tests passed!" if all_pass else "❌ Some tests failed — check above")
    print("═" * 65 + "\n")