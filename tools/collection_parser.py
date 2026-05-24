"""
collection_parser.py — Parse API collection files into request dicts.

This parser reads a collection file and returns a list of request dicts in the exact same format that curl_parser.py produces.
That means everything downstream (injector, analyser, reporter) works identically whether the input a cURL or a collection.

SUPPORTED FORMATS:

  1. Postman Collection v2.1  (.json)
     The standard export format from Postman and Thunder Client.
     File has: { "info": {...}, "item": [...] }

  2. Simple custom format  (.json)
     A plain list of requests — easy to write by hand.
     [
       {
         "name": "Login",
         "method": "POST",
         "url": "http://localhost:5000/api/login",
         "headers": {"Content-Type": "application/json"},
         "body": {"username": "admin", "password": "x"}
       }
     ]

OUTPUT:
  List of request dicts — same format as curl_parser.parse_curl()
"""

import json
import os
from urllib.parse import urlparse, parse_qs, urlencode


# ─────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────

def parse_collection(filepath: str) -> list[dict]:
    """
    Parse a collection file and return a list of request dicts.

    Automatically detects whether the file is:
      - Postman Collection v2 / v2.1
      - Simple custom JSON list

    Raises:
      FileNotFoundError  if the file does not exist
      ValueError         if the file format is not recognised
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Collection file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Collection file is not valid JSON: {e}")

    # Detect format and delegate
    if isinstance(data, list):
        return _parse_simple(data, filepath)

    if isinstance(data, dict):
        info = data.get("info", {})
        schema = info.get("schema", "")
        if "postman" in schema.lower() or "item" in data:
            return _parse_postman(data, filepath)

    raise ValueError(
        f"Unrecognised collection format in: {filepath}\n"
        "Expected a Postman v2.1 collection or a simple JSON list."
    )


# ─────────────────────────────────────────────────────────────
# Postman Collection v2 / v2.1 parser
# ─────────────────────────────────────────────────────────────

def _parse_postman(data: dict, filepath: str) -> list[dict]:
    """
    Parse a Postman Collection v2 / v2.1 JSON file.

    Postman collections can have nested folders (items inside items).
    We flatten everything into a single list of requests.
    """
    requests = []
    collection_name = data.get("info", {}).get("name", filepath)
    _flatten_postman_items(data.get("item", []), requests, collection_name)
    print(f"[Collection] Loaded '{collection_name}' — {len(requests)} requests")
    return requests


def _flatten_postman_items(items: list, output: list, collection_name: str):
    """
    Recursively flatten Postman items (handles nested folders).

    A Postman item is either:
      - A request  → has a 'request' key
      - A folder   → has an 'item' key (recurse into it)
    """
    for item in items:
        if "item" in item:
            # This is a folder — recurse
            _flatten_postman_items(item["item"], output, collection_name)
        elif "request" in item:
            req = _parse_postman_request(item, collection_name)
            if req:
                output.append(req)


def _parse_postman_request(item: dict, collection_name: str) -> dict | None:
    """
    Convert a single Postman request item into a request dict.

    Handles:
      - URL as string or as Postman URL object
      - Headers as list of {key, value} dicts
      - Body modes: raw (JSON), urlencoded, formdata
      - Query params embedded in the URL object
    """
    try:
        name    = item.get("name", "Unnamed")
        raw_req = item["request"]
        method  = raw_req.get("method", "GET").upper()

        # ── URL ──────────────────────────────────────────────
        url_field = raw_req.get("url", "")

        if isinstance(url_field, str):
            raw_url = url_field
        elif isinstance(url_field, dict):
            raw_url = url_field.get("raw", "")
        else:
            raw_url = ""

        if not raw_url:
            print(f"  [!] Skipping '{name}' — no URL found")
            return None

        parsed   = urlparse(raw_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params   = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # Also grab query params from Postman URL object if present
        if isinstance(url_field, dict):
            for qp in url_field.get("query", []):
                if not qp.get("disabled", False):
                    params[qp["key"]] = qp.get("value", "")

        # ── Headers ──────────────────────────────────────────
        headers = {}
        for h in raw_req.get("header", []):
            if not h.get("disabled", False):
                headers[h["key"]] = h["value"]

        # ── Body ─────────────────────────────────────────────
        body     = None
        raw_body = ""
        body_obj = raw_req.get("body", {}) or {}
        mode     = body_obj.get("mode", "")

        if mode == "raw":
            raw_body = body_obj.get("raw", "")
            # Try to parse as JSON
            try:
                body = json.loads(raw_body)
            except (json.JSONDecodeError, TypeError):
                body = raw_body

        elif mode == "urlencoded":
            body = {}
            for param in body_obj.get("urlencoded", []):
                if not param.get("disabled", False):
                    body[param["key"]] = param.get("value", "")
            raw_body = urlencode(body)

        elif mode == "formdata":
            body = {}
            for param in body_obj.get("formdata", []):
                if not param.get("disabled", False) and param.get("type") == "text":
                    body[param["key"]] = param.get("value", "")
            raw_body = urlencode(body)

        return {
            "name":      name,
            "method":    method,
            "url":       base_url,
            "headers":   headers,
            "body":      body,
            "params":    params,
            "raw_body":  raw_body,
            "source":    "postman",
            "collection": collection_name,
        }

    except Exception as e:
        print(f"  [!] Error parsing Postman request '{item.get('name','?')}': {e}")
        return None


# ─────────────────────────────────────────────────────────────
# Simple custom JSON format parser
# ─────────────────────────────────────────────────────────────

def _parse_simple(data: list, filepath: str) -> list[dict]:
    """
    Parse a simple JSON list of request objects.

    Each item in the list can have:
      name     (optional) — human label
      method   (optional, default GET)
      url      (required)
      headers  (optional) — dict
      body     (optional) — dict or string
      params   (optional) — dict of query params
    """
    requests = []

    for i, item in enumerate(data):
        if not isinstance(item, dict):
            print(f"  [!] Skipping item {i} — not a dict")
            continue

        url = item.get("url", "")
        if not url:
            print(f"  [!] Skipping item {i} — no URL")
            continue

        # Parse URL to separate base from query params
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        url_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # Merge URL params with any explicit params field
        explicit_params = item.get("params", {}) or {}
        merged_params   = {**url_params, **explicit_params}

        body = item.get("body", None)
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass

        raw_body = json.dumps(body) if isinstance(body, dict) else (body or "")

        requests.append({
            "name":      item.get("name", f"Request {i + 1}"),
            "method":    item.get("method", "GET").upper(),
            "url":       base_url,
            "headers":   item.get("headers", {}),
            "body":      body,
            "params":    merged_params,
            "raw_body":  raw_body,
            "source":    "simple",
            "collection": filepath,
        })

    print(f"[Collection] Loaded '{filepath}' — {len(requests)} requests")
    return requests


# ─────────────────────────────────────────────────────────────
# Utility — summarise a loaded collection in the terminal
# ─────────────────────────────────────────────────────────────

def summarise(requests: list[dict]):
    """Print a summary table of all requests in a collection."""
    print(f"\n{'─' * 60}")
    print(f"  {'#':<4} {'METHOD':<8} {'NAME':<25} URL")
    print(f"{'─' * 60}")
    for i, r in enumerate(requests, 1):
        name   = r.get("name", "")[:24]
        method = r.get("method", "GET")
        url    = r.get("url", "")
        print(f"  {i:<4} {method:<8} {name:<25} {url}")
    print(f"{'─' * 60}\n")


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.collection_parser)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os, json, tempfile

    # ── Test 1: Simple format ────────────────────────────────
    simple = [
        {
            "name": "Get Users",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/users?role=admin",
        },
        {
            "name": "Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "x"},
        },
        {
            "name": "NoSQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/nosql/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "admin123"},
        },
        {
            "name": "GraphQL User",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {"query": "query { sqlUser(id: \"1\") { id username } }"},
        },
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(simple, f)
        simple_path = f.name

    print("\n=== TEST 1: Simple JSON format ===")
    reqs = parse_collection(simple_path)
    summarise(reqs)
    for r in reqs:
        print(f"  {r['name']}: body={r['body']}, params={r['params']}")

    os.unlink(simple_path)

    # ── Test 2: Postman format ───────────────────────────────
    postman = {
        "info": {
            "name": "Mock API Tests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"
        },
        "item": [
            {
                "name": "Auth",
                "item": [
                    {
                        "name": "SQL Login",
                        "request": {
                            "method": "POST",
                            "header": [
                                {"key": "Content-Type", "value": "application/json"}
                            ],
                            "url": {
                                "raw": "http://127.0.0.1:5000/api/login",
                                "host": ["127.0.0.1"],
                                "path": ["api", "login"]
                            },
                            "body": {
                                "mode": "raw",
                                "raw": "{\"username\":\"admin\",\"password\":\"x\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Products Search",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": {
                        "raw": "http://127.0.0.1:5000/api/products/search?q=phone",
                        "query": [{"key": "q", "value": "phone"}]
                    }
                }
            }
        ]
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(postman, f)
        postman_path = f.name

    print("\n=== TEST 2: Postman Collection v2.1 format ===")
    reqs2 = parse_collection(postman_path)
    summarise(reqs2)
    for r in reqs2:
        print(f"  {r['name']}: method={r['method']}, params={r['params']}, body={r['body']}")

    os.unlink(postman_path)

    print("\n✅ collection_parser self-test complete")