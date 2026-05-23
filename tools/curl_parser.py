"""
curl_parser.py — Parse a raw cURL command into a clean request dict.

WHY THIS EXISTS?
The agents accept cURL commands as input. Before any injection can
happen, we need to break the cURL string down into its parts:
method, URL, headers, body, and query parameters.

OUTPUT FORMAT (used by every tool downstream):
{
    "method":  "POST",
    "url":     "http://localhost:5000/api/login",
    "headers": {"Content-Type": "application/json"},
    "body":    {"username": "admin", "password": "x"},
    "params":  {},
    "raw_body": '{"username": "admin", "password": "x"}',
    "source":  "curl"
}

This same dict format is also produced by collection_parser.py so
every tool downstream works identically regardless of whether the
input was a cURL command or a collection file.
"""

import re
import json
import shlex
from urllib.parse import urlparse, parse_qs


# ─────────────────────────────────────────────────────────────
# Main parser
# ─────────────────────────────────────────────────────────────

def parse_curl(curl_string: str) -> dict:
    """
    Parse a cURL command string into a structured request dict.

    Supports:
      -X / --request      HTTP method
      -H / --header       request headers
      -d / --data         request body (JSON or form)
      --data-raw          same as -d but never reads from file
      -u / --user         basic auth → Authorization header
      --url               explicit URL flag
      Positional URL      curl http://... (no flag)

    Returns a request dict on success.
    Raises ValueError if the cURL string cannot be parsed.
    """
    curl_string = _normalise(curl_string)

    try:
        tokens = shlex.split(curl_string)
    except ValueError as e:
        raise ValueError(f"Could not tokenise cURL string: {e}")

    if not tokens or tokens[0].lower() != "curl":
        raise ValueError("Input does not start with 'curl'")

    method  = "GET"
    url     = None
    headers = {}
    raw_body = None

    tokens = tokens[1:]   # drop the 'curl' token
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # ── Method ───────────────────────────────────────────
        if tok in ("-X", "--request"):
            method = tokens[i + 1].upper()
            i += 2

        # ── Headers ──────────────────────────────────────────
        elif tok in ("-H", "--header"):
            header_str = tokens[i + 1]
            if ":" in header_str:
                k, v = header_str.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2

        # ── Body ─────────────────────────────────────────────
        elif tok in ("-d", "--data", "--data-raw", "--data-binary"):
            raw_body = tokens[i + 1]
            # If method not explicitly set, default to POST for -d
            if method == "GET":
                method = "POST"
            i += 2

        # ── Basic auth → Authorization header ────────────────
        elif tok in ("-u", "--user"):
            import base64
            encoded = base64.b64encode(tokens[i + 1].encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
            i += 2

        # ── Explicit URL flag ─────────────────────────────────
        elif tok == "--url":
            url = tokens[i + 1]
            i += 2

        # ── Flags we safely ignore ────────────────────────────
        elif tok in ("-s", "--silent", "-v", "--verbose",
                     "-k", "--insecure", "-L", "--location",
                     "-i", "--include", "--compressed"):
            i += 1

        # ── Flags with a value we safely ignore ───────────────
        elif tok in ("-o", "--output", "--max-time",
                     "--connect-timeout", "-A", "--user-agent"):
            i += 2

        # ── Positional URL (no flag) ───────────────────────────
        elif not tok.startswith("-"):
            if url is None:
                url = tok
            i += 1

        else:
            # Unknown flag — skip it and its value if present
            i += 1

    if not url:
        raise ValueError("No URL found in cURL command")

    # ── Parse URL into base + query params ───────────────────
    parsed     = urlparse(url)
    base_url   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params     = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    # ── Parse body ───────────────────────────────────────────
    body = _parse_body(raw_body, headers)

    return {
        "method":   method,
        "url":      base_url,
        "headers":  headers,
        "body":     body,
        "params":   params,
        "raw_body": raw_body or "",
        "source":   "curl",
    }


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _normalise(curl_string: str) -> str:
    """
    Clean up common cURL formatting issues before tokenising.

    Handles:
      - Multiline cURL with backslash continuations
      - Windows-style CRLF line endings
      - Leading/trailing whitespace
    """
    # Join backslash-continued lines into one line
    curl_string = re.sub(r'\\\s*\n', ' ', curl_string)
    # Normalise CRLF → space
    curl_string = curl_string.replace('\r\n', ' ').replace('\r', ' ')
    return curl_string.strip()


def _parse_body(raw_body: str | None, headers: dict) -> dict | str | None:
    """
    Try to parse the raw body string into a Python dict.

    - If Content-Type is application/json → parse as JSON
    - If Content-Type is application/x-www-form-urlencoded → parse as form
    - Otherwise return the raw string so nothing is lost
    """
    if not raw_body:
        return None

    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break

    # JSON body
    if "application/json" in content_type or raw_body.strip().startswith("{"):
        try:
            return json.loads(raw_body)
        except json.JSONDecodeError:
            pass

    # Form-encoded body  key=value&key2=value2
    if "form" in content_type or "=" in raw_body:
        try:
            pairs = {}
            for part in raw_body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    pairs[k.strip()] = v.strip()
            if pairs:
                return pairs
        except Exception:
            pass

    # Return as plain string — agent can still inject into it
    return raw_body


# ─────────────────────────────────────────────────────────────
# Utility — identify injectable fields in a parsed request
# ─────────────────────────────────────────────────────────────

def get_injectable_fields(request: dict) -> dict:
    """
    Given a parsed request dict, return all locations where
    a payload can be injected, grouped by injection point type.

    Used by the injector to know WHERE to put payloads.

    Returns:
    {
        "params":  ["role", "q", ...],
        "body":    ["username", "password", ...],
        "headers": ["Authorization", ...]   ← only suspicious ones
    }
    """
    injectable = {"params": [], "body": [], "headers": []}

    # Query parameters — all are injectable
    injectable["params"] = list(request.get("params", {}).keys())

    # Body fields — injectable if body is a dict
    body = request.get("body")
    if isinstance(body, dict):
        injectable["body"] = list(body.keys())

    # Headers — only flag ones that commonly carry user-controlled values
    suspicious_headers = {
        "x-user-id", "x-username", "x-forwarded-for",
        "authorization", "x-api-key", "x-token"
    }
    for h in request.get("headers", {}):
        if h.lower() in suspicious_headers:
            injectable["headers"].append(h)

    return injectable


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.curl_parser)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    samples = [
        'curl http://127.0.0.1:5000/api/users/1',

        'curl -X GET "http://127.0.0.1:5000/api/users?role=admin"',

        '''curl -X POST http://127.0.0.1:5000/api/login \
           -H "Content-Type: application/json" \
           -d "{\\"username\\":\\"admin\\",\\"password\\":\\"x\\"}"''',

        'curl -X POST http://127.0.0.1:5000/graphql '
        '-H "Content-Type: application/json" '
        '-d "{\\"query\\":\\"query { sqlUser(id: \\\\\\"2\\\\\\") { id username } }\\"}"',
    ]

    for s in samples:
        print("\n" + "─" * 60)
        print("INPUT :", s[:80])
        try:
            r = parse_curl(s)
            print("METHOD:", r["method"])
            print("URL   :", r["url"])
            print("PARAMS:", r["params"])
            print("BODY  :", r["body"])
            fields = get_injectable_fields(r)
            print("INJECT:", fields)
        except ValueError as e:
            print("ERROR :", e)