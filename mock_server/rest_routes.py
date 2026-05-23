"""
rest_routes.py — Deliberately vulnerable REST API endpoints.

ENDPOINT MAP
─────────────────────────────────────────────────────────────────────
SQLi-vulnerable  (SQLite backend):
  GET  /api/users             → filter by ?role=  (string concat)
  GET  /api/users/<id>        → fetch by id       (integer SQLi)
  POST /api/login             → auth bypass       (classic SQLi)
  GET  /api/products/search   → search by ?q=     (UNION-based)
  GET  /api/orders            → filter by ?user_id=

NoSQLi-vulnerable (in-memory MongoDB-style backend):
  POST /api/nosql/login       → auth bypass via operator injection
  GET  /api/nosql/users       → user lookup via $regex / $ne
  POST /api/nosql/find        → raw query passthrough (worst case)
─────────────────────────────────────────────────────────────────────
"""

from flask import Blueprint, request, jsonify
from .database import sql_query_raw, nosql_find, nosql_find_one

rest_bp = Blueprint("rest", __name__, url_prefix="/api")


# ─────────────────────────────────────────────────────────────
# SQL-Injection-vulnerable endpoints
# ─────────────────────────────────────────────────────────────

@rest_bp.route("/users", methods=["GET"])
def get_users():
    """
    List users filtered by ?role=

    VULNERABILITY: role parameter injected directly into WHERE clause.
    Payload: ?role=' OR '1'='1
    Effect : returns ALL users regardless of role.
    """
    role = request.args.get("role", "user")
    # VULNERABLE — string concatenation, not parameterised
    query = f"SELECT id, username, email, role FROM users WHERE role = '{role}'"
    result = sql_query_raw(query)
    return jsonify(result)


@rest_bp.route("/users/<user_id>", methods=["GET"])
def get_user_by_id(user_id):
    """
    Fetch a single user by ID.

    VULNERABILITY: user_id embedded in query string directly.
    Payload: /api/users/1 OR 1=1--
    Effect : bypasses the ID filter, returns all users.
    """
    # VULNERABLE — user_id from URL path, no validation
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    result = sql_query_raw(query)
    return jsonify(result)


@rest_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user with username + password.

    VULNERABILITY: classic authentication bypass.
    Payload — username: admin'--   password: anything
    Effect : logs in as admin without knowing the password.

    Payload — username: ' OR '1'='1'--   password: anything
    Effect : returns the first user in the table.
    """
    body = request.get_json(force=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    # VULNERABLE — both fields concatenated directly
    query = (
        f"SELECT id, username, email, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    result = sql_query_raw(query)

    if result["error"]:
        return jsonify({"success": False, "error": result["error"]}), 400

    if result["data"]:
        return jsonify({"success": True, "user": result["data"][0]})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401


@rest_bp.route("/products/search", methods=["GET"])
def search_products():
    """
    Search products by name via ?q= parameter.

    VULNERABILITY: LIKE clause built with raw string concat.
    Payload: ?q=' UNION SELECT id,username,password,email FROM users--
    Effect : leaks the entire users table through the products endpoint.
    """
    q = request.args.get("q", "")
    # VULNERABLE — LIKE with concatenated user input
    query = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{q}%'"
    result = sql_query_raw(query)
    return jsonify(result)


@rest_bp.route("/orders", methods=["GET"])
def get_orders():
    """
    Get orders for a user via ?user_id= parameter.

    VULNERABILITY: user_id embedded directly in query.
    Payload: ?user_id=1 AND (SELECT COUNT(*) FROM sqlite_master)>0
    Effect : confirms SQLite is the backend (boolean blind probe).
    """
    user_id = request.args.get("user_id", "1")
    # VULNERABLE
    query = (
        f"SELECT o.id, u.username, p.name, o.quantity "
        f"FROM orders o "
        f"JOIN users u ON o.user_id = u.id "
        f"JOIN products p ON o.product_id = p.id "
        f"WHERE o.user_id = {user_id}"
    )
    result = sql_query_raw(query)
    return jsonify(result)


# ─────────────────────────────────────────────────────────────
# NoSQL-Injection-vulnerable endpoints
# ─────────────────────────────────────────────────────────────

@rest_bp.route("/nosql/login", methods=["POST"])
def nosql_login():
    """
    NoSQL authentication endpoint.

    VULNERABILITY: request body passed directly as the query dict.
    The client controls the operator, not just the value.

    Normal request:
      {"username": "admin", "password": "admin123"}

    Injection — $ne operator bypass:
      {"username": "admin", "password": {"$ne": ""}}
    Effect: matches any user named admin regardless of password.

    Injection — $gt bypass:
      {"username": {"$gt": ""}, "password": {"$gt": ""}}
    Effect: returns the first user in the collection.
    """
    body = request.get_json(force=True) or {}

    # VULNERABLE — body passed straight to nosql_find_one
    user = nosql_find_one("users", body)

    if user:
        safe = {k: v for k, v in user.items() if k != "password"}
        return jsonify({"success": True, "user": safe})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401


@rest_bp.route("/nosql/users", methods=["GET"])
def nosql_get_user():
    """
    Look up a user by username via query params.

    VULNERABILITY: $regex injection via query string.

    Normal request : ?username=alice
    Injection      : ?username[$regex]=.*
    Effect         : regex matches all users, leaking full user list.
    """
    username = request.args.get("username", "")

    # Accept operator syntax passed via query params
    if "username[$regex]" in request.args:
        query = {"username": {"$regex": request.args["username[$regex]"]}}
    elif "username[$ne]" in request.args:
        query = {"username": {"$ne": request.args["username[$ne]"]}}
    else:
        query = {"username": username}

    # VULNERABLE — query built from unsanitised user input
    users = nosql_find("users", query)
    safe = [{k: v for k, v in u.items() if k != "password"} for u in users]
    return jsonify({"data": safe})


@rest_bp.route("/nosql/find", methods=["POST"])
def nosql_find_raw():
    """
    Raw document search — most dangerous endpoint on the server.

    VULNERABILITY: entire request body treated as the MongoDB query.
    Equivalent to exposing db.collection.find(<user_input>) directly.

    $where injection:
      {"$where": "this.role == 'admin'"}
    Effect: returns all admin users.

    $regex injection:
      {"role": {"$regex": "admin"}}
    Effect: same result via regex.

    JS-style expression:
      {"$where": "this.password.length > 5"}
    Effect: returns users with passwords longer than 5 characters.
    """
    query = request.get_json(force=True) or {}
    collection = request.args.get("collection", "users")

    # VULNERABLE — zero filtering of query operators
    results = nosql_find(collection, query)
    safe = [{k: v for k, v in r.items() if k != "password"} for r in results]
    return jsonify({"data": safe, "count": len(safe)})