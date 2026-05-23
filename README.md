# Injection Detection Agents

Two autonomous Python agents for detecting **SQL Injection** and **NoSQL Injection** vulnerabilities in REST and GraphQL APIs.

- **Agent 1 — SQLi Agent**: Detects SQL injection across REST and GraphQL endpoints
- **Agent 2 — NoSQLi Agent**: Detects NoSQL injection across REST and GraphQL endpoints

Both agents accept a single cURL command or an entire API collection file and autonomously scan every endpoint and injection point, producing a colour-coded terminal report and optional JSON/HTML output files.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/injection_agents.git
cd injection_agents

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\Activate.ps1       # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run against a target
python main.py --agent sqli --curl "curl -X POST http://target.com/api/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"test\"}'"
```

---

## Installation

**Requirements:** Python 3.10 or higher

```bash
pip install -r requirements.txt
```

**Optional — mock server** (for local demo and testing):
```bash
pip install -r requirements-mock.txt
python -m mock_server.app
```

---

## Usage

```
python main.py --agent <sqli|nosqli|both>
               --curl <curl_string>       # single cURL command
               --collection <file.json>   # or a collection file
               [--output <path_prefix>]   # save JSON + HTML report
               [--format <json|html|both>]
               [--auth-type <bearer|apikey|basic|none>]
               [--auth-value <token>]
               [--auth-header <header_name>]
               [--delay <seconds>]
               [--timeout <seconds>]
               [--confirm]
```

### Examples

**Single cURL — SQLi agent (Linux):**
```bash
python main.py --agent sqli \
  --curl "curl -X POST http://127.0.0.1:5000/api/login \
  -H 'Content-Type: application/json' \
  -d '{\"username\":\"admin\",\"password\":\"x\"}'"
```

**Collection file — NoSQLi agent:**
```bash
python main.py --agent nosqli --collection collections/my_api.json
```

**Both agents with file output:**
```bash
python main.py --agent both \
  --collection collections/my_api.json \
  --output results/scan_001 \
  --format both
```

**External API with Bearer token and rate limiting:**
```bash
python main.py --agent sqli \
  --collection collections/external_api.json \
  --auth-type bearer \
  --auth-value "eyJhbGci..." \
  --delay 1.0 \
  --timeout 15 \
  --output results/external_scan
```

**GraphQL endpoint:**
```bash
python main.py --agent sqli \
  --curl "curl -X POST http://127.0.0.1:5000/graphql \
  -H 'Content-Type: application/json' \
  -d '{\"query\":\"query { sqlUser(id: \\\"1\\\") { id username } }\"}'"
```

---

## Collection File Format

Two formats are supported.

**Simple format** (recommended — easy to write by hand):
```json
[
  {
    "name": "Login",
    "method": "POST",
    "url": "http://target.com/api/login",
    "headers": {"Content-Type": "application/json"},
    "body": {"username": "admin", "password": "test"}
  },
  {
    "name": "Search",
    "method": "GET",
    "url": "http://target.com/api/products/search",
    "params": {"q": "phone"}
  }
]
```

**Postman Collection v2.1** — export directly from Postman or Thunder Client and pass the `.json` file.

---

## Detection Coverage

### SQLi Agent

| Technique | Description |
|---|---|
| `auth_bypass` | Tautology and comment-based login bypass |
| `error_based` | Forces DB errors that leak internal information |
| `boolean_blind` | True/false condition probing via response differences |
| `time_based` | Response delay detection via `SLEEP()`, `randomblob()` |
| `union` | Cross-table data extraction via UNION SELECT |
| `stacked` | Multiple statement injection via semicolons |

### NoSQLi Agent

| Technique | Description |
|---|---|
| `operator_injection` | `$ne`, `$gt`, `$exists` operator bypass |
| `auth_bypass` | Combined operator pairs for full auth bypass |
| `regex_injection` | `$regex` pattern matching to dump collections |
| `where_injection` | `$where` JavaScript expression evaluation |
| `array_abuse` | `$in`, `$nin` array operator injection |

Both agents test **REST endpoints** (query params, body fields, headers) and **GraphQL endpoints** (operation arguments, variables).

---

## Output

**Terminal** — colour-coded live report printed after each scan.

**JSON** (`--format json` or `--format both`):
```json
{
  "meta": {
    "agent_name": "SQLi Agent",
    "scan_time": "2026-05-23T10:00:00",
    "total_tested": 117,
    "total_findings": 9,
    "severity_counts": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 0}
  },
  "findings": [...]
}
```

**HTML** (`--format html` or `--format both`) — self-contained browser report with collapsible findings, severity dashboard, and auto-expanded CRITICAL items.

---

## Demo — Mock Vulnerable Server

A deliberately vulnerable Flask server is included for safe local testing.

```bash
# Install mock server dependency
pip install -r requirements-mock.txt

# Start the mock server (keep this terminal open)
python -m mock_server.app

# In a second terminal — run a full scan
python main.py --agent both \
  --collection collections/mock_full.json \
  --output results/demo_scan \
  --format both
```

The mock server exposes intentionally vulnerable REST and GraphQL endpoints backed by SQLite (for SQLi) and an in-memory NoSQL store (for NoSQLi). It is for testing and demonstration only — never deploy it publicly.

---

## Arguments Reference

| Argument | Default | Description |
|---|---|---|
| `--agent` | required | `sqli`, `nosqli`, or `both` |
| `--curl` | — | Raw cURL command string |
| `--collection` | — | Path to JSON collection file |
| `--output` | none | File path prefix for reports |
| `--format` | `both` | `json`, `html`, or `both` |
| `--auth-type` | `none` | `bearer`, `apikey`, `basic`, or `none` |
| `--auth-value` | none | Token, key, or `user:pass` |
| `--auth-header` | `X-API-Key` | Header name for `apikey` auth |
| `--delay` | `0.0` | Seconds between requests |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--confirm` | flag | Skip external API warning prompt |

---

## Legal Notice

This tool is for **authorised security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorised security testing is illegal in most jurisdictions. The authors accept no responsibility for misuse.

---

## Project Structure

```
injection_agents/
├── agents/
│   ├── base_agent.py        # Shared agentic loop (OBSERVE→THINK→ACT→UPDATE)
│   ├── sqli_agent.py        # Agent 1 — SQL injection detection
│   └── nosqli_agent.py      # Agent 2 — NoSQL injection detection
├── tools/
│   ├── curl_parser.py       # Parse cURL commands into request dicts
│   ├── collection_parser.py # Parse Postman / custom JSON collections
│   ├── endpoint_detector.py # Detect REST vs GraphQL automatically
│   ├── payload_library.py   # All SQLi and NoSQLi payloads
│   ├── injector.py          # Craft and send injection requests
│   ├── response_analyser.py # Detect vulnerability signals in responses
│   ├── reporter.py          # Colour-coded terminal report
│   └── file_reporter.py     # JSON and HTML file output
├── mock_server/             # Optional — demo vulnerable server
├── main.py                  # Entry point
├── requirements.txt         # Core dependencies
└── requirements-mock.txt    # Mock server dependency
```