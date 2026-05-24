"""
app.py — Main Flask application for the mock vulnerable server.

This is the entry point. It:
  1. Creates the Flask app
  2. Initialises the SQLite database
  3. Generates all agent collection files
  4. Registers the REST and GraphQL blueprints
  5. Prints a startup banner with all available endpoints

HOW TO RUN:
  Make sure your venv is active, then from injection_agents/ folder:
    python -m mock_server.app

Server starts at http://127.0.0.1:5000
"""

import json
import os
from flask import Flask, jsonify

try:
    from flask_cors import CORS
    _cors_available = True
except ImportError:
    _cors_available = False

from .database import init_sql_db
from .rest_routes import rest_bp
from .graphql_routes import graphql_bp


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def create_app():
    app = Flask(__name__)

    if _cors_available:
        CORS(app)

    # Initialise SQLite with seed data on startup
    init_sql_db()

    # Generate all agent collection files
    _ensure_mock_collections()

    # Register blueprints
    app.register_blueprint(rest_bp)
    app.register_blueprint(graphql_bp)

    # ── Health check ──────────────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "server": "mock-vulnerable-api"})

    # ── Schema discovery ──────────────────────────────────────
    @app.route("/schema")
    def schema():
        return jsonify({
            "rest_endpoints": {
                "sqli_vulnerable": [
                    "GET  /api/users?role=<value>",
                    "GET  /api/users/<id>",
                    "POST /api/login                body: {username, password}",
                    "GET  /api/products/search?q=<value>",
                    "GET  /api/orders?user_id=<value>",
                ],
                "nosqli_vulnerable": [
                    "POST /api/nosql/login          body: {username, password}",
                    "GET  /api/nosql/users?username=<value>",
                    "POST /api/nosql/find           body: <query dict>",
                ]
            },
            "graphql_endpoint": {
                "url": "POST /graphql",
                "sqli_operations": [
                    'query { sqlUser(id: "1") { id username email role } }',
                    'query { sqlLogin(username: "admin", password: "x") { success username role } }',
                    'query { sqlSearch(q: "phone") { id name price } }',
                ],
                "nosqli_operations": [
                    'query { nosqlLogin(username: "admin", password: "x") { success username role } }',
                    'query { nosqlUser(username: "alice") { id username role email } }',
                    'query { nosqlFind(query: "{}", collection: "users") { id username role } }',
                ]
            }
        })

    return app


# ─────────────────────────────────────────────────────────────
# Collection generator
# ─────────────────────────────────────────────────────────────

def _ensure_mock_collections():
    """
    Generate all mock server collection files for the agents.

    Called on every server startup. Safe to call multiple times —
    only creates files that do not already exist.

    WHY HERE?
    The collections are tightly coupled to the mock server endpoints.
    Generating them here means they are always in sync with the server
    and available the moment the server starts, before any agent runs.

    Collections generated:
      mock_full.json          — all 14 endpoints (REST + GraphQL)
      mock_rest_sqli.json     — REST SQLi endpoints only
      mock_rest_nosql.json    — REST NoSQLi endpoints only
      mock_graphql_sqli.json  — GraphQL SQLi endpoints only
      mock_graphql_nosql.json — GraphQL NoSQLi endpoints only
    """
    # Resolve collections/ relative to the project root
    # __file__ is mock_server/app.py → parent is mock_server/ → parent is project root
    project_root    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    collections_dir = os.path.join(project_root, "collections")
    os.makedirs(collections_dir, exist_ok=True)

    def _write(filename, data):
        path = os.path.join(collections_dir, filename)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[Collections] Created: {path}")

    # ── mock_full.json — all 14 endpoints ────────────────────
    _write("mock_full.json", [
        {
            "name": "SQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "x"},
        },
        {
            "name": "SQL Get User by ID",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/users/1",
        },
        {
            "name": "SQL Users Role Filter",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/users",
            "params": {"role": "user"},
        },
        {
            "name": "SQL Product Search",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/products/search",
            "params": {"q": "phone"},
        },
        {
            "name": "SQL Orders",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/orders",
            "params": {"user_id": "1"},
        },
        {
            "name": "NoSQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/nosql/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "x"},
        },
        {
            "name": "NoSQL User Lookup",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/nosql/users",
            "params": {"username": "alice"},
        },
        {
            "name": "NoSQL Raw Find",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/nosql/find",
            "headers": {"Content-Type": "application/json"},
            "body": {"role": "user"},
        },
        {
            "name": "GraphQL SQL User",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlUser(id: "1") { id username email } }'
            },
        },
        {
            "name": "GraphQL SQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlLogin(username: "admin", password: "x") { success username role } }'
            },
        },
        {
            "name": "GraphQL SQL Search",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlSearch(q: "phone") { id name price } }'
            },
        },
        {
            "name": "GraphQL NoSQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlLogin(username: "admin", password: "x") { success username role } }'
            },
        },
        {
            "name": "GraphQL NoSQL User",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlUser(username: "alice") { id username role } }'
            },
        },
        {
            "name": "GraphQL NoSQL Find",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlFind(query: "{}", collection: "users") { id username role } }'
            },
        },
    ])

    # ── mock_rest_sqli.json ───────────────────────────────────
    _write("mock_rest_sqli.json", [
        {
            "name": "SQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "x"},
        },
        {
            "name": "SQL Get User by ID",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/users/1",
        },
        {
            "name": "SQL Product Search",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/products/search",
            "params": {"q": "phone"},
        },
    ])

    # ── mock_rest_nosql.json ──────────────────────────────────
    _write("mock_rest_nosql.json", [
        {
            "name": "NoSQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/nosql/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "password": "x"},
        },
        {
            "name": "NoSQL User Lookup",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/nosql/users",
            "params": {"username": "alice"},
        },
        {
            "name": "NoSQL Raw Find",
            "method": "POST",
            "url": "http://127.0.0.1:5000/api/nosql/find",
            "headers": {"Content-Type": "application/json"},
            "body": {"role": "user"},
        },
    ])

    # ── mock_graphql_sqli.json ────────────────────────────────
    _write("mock_graphql_sqli.json", [
        {
            "name": "GraphQL SQL User by ID",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlUser(id: "1") { id username email role } }'
            },
        },
        {
            "name": "GraphQL SQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlLogin(username: "admin", password: "x") { success username role } }'
            },
        },
        {
            "name": "GraphQL SQL Product Search",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { sqlSearch(q: "phone") { id name price } }'
            },
        },
    ])

    # ── mock_graphql_nosql.json ───────────────────────────────
    _write("mock_graphql_nosql.json", [
        {
            "name": "GraphQL NoSQL Login",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlLogin(username: "admin", password: "x") { success username role } }'
            },
        },
        {
            "name": "GraphQL NoSQL User Lookup",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlUser(username: "alice") { id username role email } }'
            },
        },
        {
            "name": "GraphQL NoSQL Raw Find",
            "method": "POST",
            "url": "http://127.0.0.1:5000/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "query": 'query { nosqlFind(query: "{}", collection: "users") { id username role } }'
            },
        },
    ])


# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────

def _print_banner(host, port):
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         MOCK VULNERABLE API SERVER — STARTED                 ║
╠══════════════════════════════════════════════════════════════╣
║  Base URL : http://{host}:{port}
║  Health   : http://{host}:{port}/health
║  Schema   : http://{host}:{port}/schema
╠══════════════════════════════════════════════════════════════╣
║  SQLi-VULNERABLE REST ENDPOINTS                              ║
║    GET  /api/users?role=                                     ║
║    GET  /api/users/<id>                                      ║
║    POST /api/login                                           ║
║    GET  /api/products/search?q=                              ║
║    GET  /api/orders?user_id=                                 ║
╠══════════════════════════════════════════════════════════════╣
║  NoSQLi-VULNERABLE REST ENDPOINTS                            ║
║    POST /api/nosql/login                                     ║
║    GET  /api/nosql/users?username=                           ║
║    POST /api/nosql/find                                      ║
╠══════════════════════════════════════════════════════════════╣
║  GRAPHQL ENDPOINT  (SQLi + NoSQLi)                           ║
║    POST /graphql                                             ║
║    Ops  : sqlUser · sqlLogin · sqlSearch                     ║
║           nosqlLogin · nosqlUser · nosqlFind                 ║
╚══════════════════════════════════════════════════════════════╝
  ⚠  FOR SECURITY TESTING ONLY — DO NOT DEPLOY
""")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 5000
    app = create_app()
    _print_banner(HOST, PORT)
    app.run(host=HOST, port=PORT, debug=False)