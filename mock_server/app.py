"""
app.py — Main Flask application for the mock vulnerable server.

This is the entry point. It:
  1. Creates the Flask app
  2. Initialises the SQLite database
  3. Registers the REST and GraphQL blueprints
  4. Prints a startup banner with all available endpoints

HOW TO RUN:
  Make sure your venv is active, then from injection_agents/ folder:
    python -m mock_server.app

Server starts at http://127.0.0.1:5000
"""

from flask import Flask, jsonify

try:
    from flask_cors import CORS
    _cors_available = True
except ImportError:
    _cors_available = False

from .database import init_sql_db
from .rest_routes import rest_bp
from .graphql_routes import graphql_bp


def create_app():
    app = Flask(__name__)

    # Allow cross-origin requests so agents can call the server freely
    if _cors_available:
        CORS(app)

    # Initialise SQLite with seed data on startup
    init_sql_db()

    # Register blueprints
    app.register_blueprint(rest_bp)
    app.register_blueprint(graphql_bp)

    # ── Health check ──────────────────────────────────────────
    # Lets the agents verify the server is up before testing begins
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "server": "mock-vulnerable-api"})

    # ── Schema discovery ──────────────────────────────────────
    # Returns all endpoints as a reference map for the agents
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


if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 5000
    app = create_app()
    _print_banner(HOST, PORT)
    app.run(host=HOST, port=PORT, debug=False)