"""
graphql_routes.py — Deliberately vulnerable GraphQL endpoint.

WHY GRAPHQL SEPARATELY?
GraphQL has a different attack surface from REST:
  - All requests go to POST /graphql  (single endpoint)
  - User input lives inside the 'query' string or 'variables' dict
  - Errors appear in a structured JSON 'errors' key, not HTTP status codes
  - Introspection can be abused to discover the schema before attacking

We implement a minimal GraphQL parser (no graphene/strawberry needed)
so there is nothing extra to install. It extracts field arguments from
the query string and passes them to the vulnerable database functions.

SUPPORTED OPERATIONS:
  SQLi  → sqlUser · sqlLogin · sqlSearch
  NoSQLi → nosqlLogin · nosqlUser · nosqlFind
"""

import re
import json
from flask import Blueprint, request, jsonify
from .database import sql_query_raw, nosql_find, nosql_find_one

graphql_bp = Blueprint("graphql", __name__, url_prefix="/graphql")


# ─────────────────────────────────────────────────────────────
# Minimal GraphQL argument parser
# ─────────────────────────────────────────────────────────────

def _parse_args(args_string: str) -> dict:
    """
    Extract key:value pairs from a GraphQL argument string.

    Example input  : 'username: "admin", password: "x"'
    Example output : {'username': 'admin', 'password': 'x'}

    Handles quoted strings, numbers, and escaped quotes.
    """
    args = {}
    pattern = r'(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"|(\w+)\s*:\s*([^\s,)]+)'
    for m in re.finditer(pattern, args_string):
        if m.group(1):
            # Quoted string value
            args[m.group(1)] = m.group(2).replace('\\"', '"')
        else:
            # Unquoted value — number or boolean
            val = m.group(4)
            try:
                args[m.group(3)] = int(val)
            except ValueError:
                args[m.group(3)] = val
    return args


def _parse_graphql_query(gql: str) -> list:
    """
    Parse a GraphQL query string into a list of operation dicts.
    Each dict has: { 'field': str, 'args': dict, 'fields': list[str] }

    FIX: First strips the outer query/mutation wrapper using a greedy
    match on the outermost braces, then parses field operations from
    the inner content. This avoids the nested-brace consumption bug
    where [^}]* would stop at the first } instead of the matching one.
    """
    gql = gql.strip()

    # Step 1 — strip outer  query { ... }  /  mutation { ... }  wrapper
    outer = re.match(
        r'(?:query|mutation|subscription)\s*\{(.*)\}\s*$',
        gql,
        re.DOTALL
    )
    inner = outer.group(1) if outer else gql

    # Step 2 — match individual field operations inside the wrapper
    operations = []
    pattern = r'(\w+)\s*(?:\(([^)]*)\))?\s*\{([^}]*)\}'
    for m in re.finditer(pattern, inner):
        field_name = m.group(1)
        if field_name in ("query", "mutation", "subscription"):
            continue
        args_str   = m.group(2) or ""
        fields_str = m.group(3) or ""
        operations.append({
            "field":  field_name,
            "args":   _parse_args(args_str),
            "fields": [f.strip() for f in fields_str.split() if f.strip()],
        })
    return operations


# ─────────────────────────────────────────────────────────────
# Resolvers — each maps to a vulnerable backend call
# ─────────────────────────────────────────────────────────────

def resolve_sql_user(args: dict) -> dict:
    """
    Fetch a user by ID.

    VULNERABILITY: id concatenated directly into SQL.
    Payload : query { sqlUser(id: "1 OR 1=1--") { id username email } }
    Effect  : returns all users.
    """
    user_id = args.get("id", "1")
    # VULNERABLE
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    result = sql_query_raw(query)
    return {"data": result["data"], "error": result["error"]}


def resolve_sql_login(args: dict) -> dict:
    """
    SQL authentication via GraphQL.

    VULNERABILITY: same auth bypass as the REST login endpoint.
    Payload : query { sqlLogin(username: "admin'--", password: "x")
                      { success username role } }
    Effect  : logs in as admin without the correct password.
    """
    username = args.get("username", "")
    password = args.get("password", "")
    # VULNERABLE
    query = (
        f"SELECT id, username, email, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    result = sql_query_raw(query)
    if result["error"]:
        return {"success": False, "error": result["error"]}
    if result["data"]:
        u = result["data"][0]
        return {"success": True, "username": u["username"], "role": u["role"]}
    return {"success": False, "message": "Invalid credentials"}


def resolve_sql_search(args: dict) -> dict:
    """
    Product search — vulnerable to UNION-based injection via GraphQL.

    Payload : query { sqlSearch(q: "' UNION SELECT
                      id,username,password,email FROM users--")
                      { id name price } }
    Effect  : leaks the users table through the products search resolver.
    """
    q = args.get("q", "")
    # VULNERABLE
    query = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{q}%'"
    result = sql_query_raw(query)
    return {"data": result["data"], "error": result["error"]}


def resolve_nosql_login(args: dict) -> dict:
    """
    NoSQL authentication via GraphQL.

    VULNERABILITY: args dict used directly as the nosql query.
    Payload : query { nosqlLogin(username: "admin",
                      password: "{\"$ne\": \"\"}") { success username } }
    Effect  : password value becomes an operator dict, bypassing auth.
    """
    username    = args.get("username", "")
    password_raw = args.get("password", "")

    # Try to parse password as JSON — allows operator injection
    try:
        password = json.loads(password_raw)
    except (json.JSONDecodeError, TypeError):
        password = password_raw

    # VULNERABLE — operator can arrive as the password value
    query = {"username": username, "password": password}
    user  = nosql_find_one("users", query)

    if user:
        return {"success": True, "username": user["username"], "role": user["role"]}
    return {"success": False, "message": "Invalid credentials"}


def resolve_nosql_user(args: dict) -> dict:
    """
    Look up a user by username — vulnerable to $regex injection.

    Payload : query { nosqlUser(username: "{\"$regex\": \".*\"}")
                      { id username role } }
    Effect  : regex matches all users, leaking the full user list.
    """
    username_raw = args.get("username", "")

    try:
        username = json.loads(username_raw)  # parses operator dicts
    except (json.JSONDecodeError, TypeError):
        username = username_raw

    # VULNERABLE — parsed value (possibly an operator dict) goes straight in
    users = nosql_find("users", {"username": username})
    safe  = [{k: v for k, v in u.items() if k != "password"} for u in users]
    return {"data": safe}


def resolve_nosql_find(args: dict) -> dict:
    """
    Raw NoSQL query via GraphQL — most dangerous resolver.

    Payload : query { nosqlFind(query: "{\"$where\":
                      \"this.role == 'admin'\"}") { id username role } }
    Effect  : returns all admin users via $where expression.
    """
    query_raw  = args.get("query", "{}")
    collection = args.get("collection", "users")

    try:
        query = json.loads(query_raw)   # VULNERABLE — user-supplied JSON
    except json.JSONDecodeError as e:
        return {"error": f"Invalid query JSON: {e}", "data": []}

    results = nosql_find(collection, query)
    safe    = [{k: v for k, v in r.items() if k != "password"} for r in results]
    return {"data": safe, "count": len(safe)}


# ─────────────────────────────────────────────────────────────
# Resolver dispatch table
# ─────────────────────────────────────────────────────────────

RESOLVERS = {
    "sqlUser":    resolve_sql_user,
    "sqlLogin":   resolve_sql_login,
    "sqlSearch":  resolve_sql_search,
    "nosqlLogin": resolve_nosql_login,
    "nosqlUser":  resolve_nosql_user,
    "nosqlFind":  resolve_nosql_find,
}


# ─────────────────────────────────────────────────────────────
# GraphQL endpoint
# ─────────────────────────────────────────────────────────────

@graphql_bp.route("", methods=["GET", "POST"])
def graphql_endpoint():
    """
    Single GraphQL endpoint — handles queries and introspection.

    Accepts:
      POST /graphql  body: {"query": "...", "variables": {...}}
      GET  /graphql  ?query=...  (quick browser/curl testing)

    Returns standard GraphQL response shape:
      {"data": {...}, "errors": [...]}
    """
    if request.method == "GET":
        gql_query = request.args.get("query", "")
        variables  = {}
    else:
        body      = request.get_json(force=True) or {}
        gql_query = body.get("query", "")
        variables  = body.get("variables") or {}

    if not gql_query.strip():
        return jsonify({"errors": [{"message": "No query provided"}]}), 400

    # Basic introspection — lets attackers discover the schema
    if "__schema" in gql_query or "__typename" in gql_query:
        return jsonify({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": f, "args": [], "type": {"name": "JSON"}}
                                for f in RESOLVERS
                            ]
                        }
                    ]
                }
            }
        })

    # Parse and resolve
    operations    = _parse_graphql_query(gql_query)
    response_data = {}
    errors        = []

    for op in operations:
        resolver = RESOLVERS.get(op["field"])
        if resolver is None:
            errors.append({"message": f"Unknown field: {op['field']}"})
            continue
        try:
            result = resolver(op["args"])
            response_data[op["field"]] = result
        except Exception as e:
            # INTENTIONALLY verbose — leaks implementation details
            errors.append({"message": str(e), "field": op["field"]})

    resp = {"data": response_data}
    if errors:
        resp["errors"] = errors

    return jsonify(resp)