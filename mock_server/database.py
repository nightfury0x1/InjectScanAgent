"""
database.py — Two backend stores for the mock vulnerable server.

WHY TWO STORES?
  - SQLite     → backs the SQL-injection-vulnerable endpoints
  - nosql_store → a plain Python dict that mimics MongoDB operator
                  semantics ($gt, $ne, $regex, $where) so we can
                  demonstrate NoSQL injection without installing MongoDB.

IMPORTANT: Every vulnerability here is deliberate and educational.
           Never copy these patterns into real application code.
"""

import sqlite3
import re
import os

# ─────────────────────────────────────────────────────────────
# SQLite setup
# ─────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


def get_db():
    """Return a SQLite connection. Called per-request."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    return conn


def init_sql_db():
    """
    Create tables and seed sample data.
    Called once at server startup.

    WHY STRING CONCATENATION IN QUERIES BELOW?
    We are intentionally NOT using parameterised queries so that
    the SQL injection agent can find and demonstrate the flaw.
    Real apps must always use parameterised queries (? placeholders).
    """
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS orders;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE products (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL
        );

        CREATE TABLE orders (
            id         INTEGER PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity   INTEGER NOT NULL
        );

        INSERT INTO users VALUES
            (1, 'admin',   'admin123',   'admin@corp.com',   'admin'),
            (2, 'alice',   'alice456',   'alice@corp.com',   'user'),
            (3, 'bob',     'bob789',     'bob@corp.com',     'user'),
            (4, 'charlie', 'charlie000', 'charlie@corp.com', 'user');

        INSERT INTO products VALUES
            (1, 'Laptop',      999.99, 10),
            (2, 'Phone',       499.99, 25),
            (3, 'Headphones',   79.99, 50),
            (4, 'Tablet',      329.99, 15);

        INSERT INTO orders VALUES
            (1, 2, 1, 1),
            (2, 2, 3, 2),
            (3, 3, 2, 1);
    """)

    conn.commit()
    conn.close()
    print("[DB] SQLite database initialised at:", DB_PATH)


def sql_query_raw(query: str):
    """
    Execute a raw SQL string and return all rows as dicts.

    VULNERABLE BY DESIGN — no sanitisation, no parameterisation.
    The injection agent should detect calls that reach this function.
    """
    conn = get_db()
    try:
        cur = conn.execute(query)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {"data": rows, "error": None}
    except Exception as e:
        conn.close()
        # Returning the raw exception leaks DB internals — also intentional.
        return {"data": [], "error": str(e)}


# ─────────────────────────────────────────────────────────────
# In-memory NoSQL store (MongoDB-style)
# ─────────────────────────────────────────────────────────────

nosql_store = {
    "users": [
        {"_id": "1", "username": "admin",   "password": "admin123",   "role": "admin", "email": "admin@corp.com"},
        {"_id": "2", "username": "alice",   "password": "alice456",   "role": "user",  "email": "alice@corp.com"},
        {"_id": "3", "username": "bob",     "password": "bob789",     "role": "user",  "email": "bob@corp.com"},
        {"_id": "4", "username": "charlie", "password": "charlie000", "role": "user",  "email": "charlie@corp.com"},
    ],
    "products": [
        {"_id": "1", "name": "Laptop",     "price": 999.99, "stock": 10},
        {"_id": "2", "name": "Phone",      "price": 499.99, "stock": 25},
        {"_id": "3", "name": "Headphones", "price": 79.99,  "stock": 50},
    ]
}


def _nosql_match(doc: dict, query: dict) -> bool:
    """
    Evaluate whether a document matches a query dict.

    Supports MongoDB-style operators:
      $gt, $lt, $gte, $lte  — comparison
      $ne                   — not equal
      $regex                — regex match
      $where                — expression evaluated with Python eval()
      $exists               — field existence check

    WHY IS $where DANGEROUS?
    In real MongoDB, $where executes arbitrary JavaScript server-side.
    Here we simulate it with Python eval() — equally dangerous because
    it allows arbitrary code execution.

    VULNERABLE BY DESIGN — mimics real-world NoSQL injection vectors.
    """
    for key, value in query.items():

        # Top-level $where operator
        if key == "$where":
            # Convert JS-style  this.fieldName  →  doc.get("fieldName")
            expr = re.sub(r'this\.(\w+)', r'doc.get("\1")', value)
            try:
                if not eval(expr):          # intentionally unsafe
                    return False
            except Exception:
                return False
            continue

        if not isinstance(value, dict):
            # Simple equality check
            if str(doc.get(key, "")) != str(value):
                return False
            continue

        # Operator-based sub-query  e.g. {"password": {"$ne": ""}}
        doc_val = doc.get(key, "")
        for op, op_val in value.items():
            if op == "$gt"  and not (doc_val >  op_val): return False
            if op == "$lt"  and not (doc_val <  op_val): return False
            if op == "$gte" and not (doc_val >= op_val): return False
            if op == "$lte" and not (doc_val <= op_val): return False
            if op == "$ne"  and not (doc_val != op_val): return False
            if op == "$exists":
                present = key in doc
                if op_val and not present:  return False
                if not op_val and present:  return False
            if op == "$regex":
                try:
                    if not re.search(op_val, str(doc_val)):
                        return False
                except re.error:
                    return False

    return True


def nosql_find(collection: str, query: dict) -> list:
    """
    Return all documents in `collection` matching `query`.

    VULNERABLE BY DESIGN — query dict is accepted directly from
    the request body without any sanitisation.
    """
    docs = nosql_store.get(collection, [])
    return [doc for doc in docs if _nosql_match(doc, query)]


def nosql_find_one(collection: str, query: dict):
    """Return the first matching document, or None."""
    results = nosql_find(collection, query)
    return results[0] if results else None