"""
main.py — Entry point for the SQL and NoSQL injection detection agents.

USAGE
────────────────────────────────────────────────────────────────
Basic scan (mock server):
  python main.py --agent sqli --collection collections/mock_full.json

With file output:
  python main.py --agent both --collection collections/mock_full.json
                 --output results/my_scan --format both

Single cURL (use collection file on Windows to avoid quoting issues):
  python main.py --agent sqli --collection test_login.json

External API with authentication:
  python main.py --agent sqli --collection my_api.json
                 --auth-type bearer --auth-value "eyJhbGci..."

  python main.py --agent nosqli --collection my_api.json
                 --auth-type apikey --auth-header "X-API-Key"
                 --auth-value "my-secret-key"

With rate limiting (recommended for external APIs):
  python main.py --agent both --collection my_api.json
                 --delay 1.5 --output results/external_scan

ARGUMENTS
  --agent          sqli | nosqli | both            (required)
  --curl           raw cURL string                 (or --collection)
  --collection     path to JSON collection file    (or --curl)
  --output         output file path prefix         (optional)
                   e.g. "results/scan_001"
                   → writes scan_001.json + scan_001.html
  --format         json | html | both              (default: both)
  --auth-type      none | bearer | apikey | basic  (default: none)
  --auth-header    header name for apikey auth     (default: X-API-Key)
  --auth-value     token / key / user:pass value
  --delay          seconds between requests        (default: 0)
                   recommended: 0.5-2.0 for external APIs
  --timeout        per-request timeout seconds     (default: 10)
  --confirm        skip the external API warning   (flag, no value)
"""

import argparse
import sys
import os
import time
import datetime
# Stores the last agent's total_tested count
# Used to pass attempt counts to the combined report
_last_agent_tested = 0


# ─────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "main.py",
        description = "SQL and NoSQL Injection Detection Agents",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--agent", required=True,
        choices=["sqli", "nosqli", "both"],
        help="Which agent to run",
    )

    # Input source
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--curl", metavar="CURL_STRING",
        help="Raw cURL command string",
    )
    input_group.add_argument(
        "--collection", metavar="FILE_PATH",
        help="Path to Postman or custom JSON collection file",
    )

    # Output options
    parser.add_argument(
        "--output", metavar="PATH_PREFIX", default=None,
        help="Output file path prefix e.g. 'results/scan_001'",
    )
    parser.add_argument(
        "--format", dest="fmt",
        choices=["json", "html", "both"], default="both",
        help="Output file format (default: both)",
    )

    # Auth options
    parser.add_argument(
        "--auth-type",
        choices=["none", "bearer", "apikey", "basic"],
        default="none",
        help="Authentication type for target API",
    )
    parser.add_argument(
        "--auth-header", default="X-API-Key",
        help="Header name for apikey auth (default: X-API-Key)",
    )
    parser.add_argument(
        "--auth-value", default=None,
        help="Token, API key, or user:pass for auth",
    )

    # Request options
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Seconds to wait between requests (for external APIs)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )

    # Safety
    parser.add_argument(
        "--confirm", action="store_true",
        help="Skip the external API warning prompt",
    )

    return parser


# ─────────────────────────────────────────────────────────────
# Auth header builder
# ─────────────────────────────────────────────────────────────

def build_auth_headers(auth_type: str, auth_value: str | None,
                        auth_header: str) -> dict:
    """
    Build authentication headers based on auth-type argument.

    bearer  → Authorization: Bearer <token>
    apikey  → <auth_header>: <auth_value>
    basic   → Authorization: Basic <base64(user:pass)>
    none    → {}
    """
    if auth_type == "none" or not auth_value:
        return {}

    if auth_type == "bearer":
        return {"Authorization": f"Bearer {auth_value}"}

    if auth_type == "apikey":
        return {auth_header: auth_value}

    if auth_type == "basic":
        import base64
        encoded = base64.b64encode(auth_value.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    return {}


# ─────────────────────────────────────────────────────────────
# External API safety check
# ─────────────────────────────────────────────────────────────

def is_external_target(input_str: str) -> bool:
    """
    Return True if the target contains external URLs.
    Reads collection files to check the actual URLs inside them,
    not just the file path string.
    """
    local_hints = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "192.168.", "10.", "172.16.", "172.17."
    ]

    # If it looks like a cURL string check directly
    if input_str.strip().lower().startswith("curl"):
        check = input_str.lower()
        return not any(h in check for h in local_hints)

    # If it is a file path read the URLs inside it
    if os.path.exists(input_str):
        try:
            import json
            with open(input_str, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Extract all URLs from the collection
            urls = []
            if isinstance(data, list):
                for item in data:
                    url = item.get("url", "")
                    if url:
                        urls.append(url.lower())
            elif isinstance(data, dict):
                # Postman format — recurse into items
                def extract(items):
                    for item in items:
                        if "item" in item:
                            extract(item["item"])
                        elif "request" in item:
                            url = item["request"].get("url", "")
                            if isinstance(url, dict):
                                url = url.get("raw", "")
                            if url:
                                urls.append(url.lower())
                extract(data.get("item", []))

            if not urls:
                return False

            # External only if ALL urls are external
            # (mixed collections with some localhost are treated as local)
            external_urls = [
                u for u in urls
                if not any(h in u for h in local_hints)
            ]
            return len(external_urls) == len(urls)

        except Exception:
            return False

    # Fallback — check the string directly
    check = input_str.lower()
    return not any(h in check for h in local_hints)


def warn_external(input_str: str, confirm: bool) -> bool:
    """
    Print a responsible use warning for external API targets.
    Returns True if the user confirms they want to proceed.
    """
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        yellow = Fore.YELLOW + Style.BRIGHT
        red    = Fore.RED + Style.BRIGHT
        reset  = Style.RESET_ALL
    except ImportError:
        yellow = red = reset = ""

    print(f"""
{yellow}{'═' * 65}
  ⚠  EXTERNAL API TARGET DETECTED
{'═' * 65}{reset}

  You are about to run injection tests against what appears
  to be an EXTERNAL API (not localhost).

  Before proceeding, confirm ALL of the following:

    ✅  You own this API or have WRITTEN permission to test it
    ✅  You are NOT testing a production system with live data
    ✅  You understand this tool sends malicious payloads
    ✅  You accept full responsibility for your actions

  Unauthorised security testing is illegal in most jurisdictions.
  This tool is for authorised penetration testing ONLY.

{yellow}{'═' * 65}{reset}
""")

    if confirm:
        print("  --confirm flag set — proceeding without prompt.\n")
        return True

    try:
        answer = input("  Type YES to confirm and proceed: ").strip()
        print()
        return answer.upper() == "YES"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ─────────────────────────────────────────────────────────────
# Server health check
# ─────────────────────────────────────────────────────────────

def check_server(url: str = "http://127.0.0.1:5000/health") -> bool:
    """Ping the mock server health endpoint."""
    try:
        import httpx
        resp = httpx.get(url, timeout=3.0)
        if resp.status_code == 200:
            print(f"  [✓] Mock server reachable at {url}")
            return True
    except Exception:
        pass
    print(f"  [!] Mock server not reachable at {url}")
    print(f"  [!] If targeting an external API this is expected.")
    print(f"  [!] To start the mock server: python -m mock_server.app\n")
    return False


# ─────────────────────────────────────────────────────────────
# Output path builder
# ─────────────────────────────────────────────────────────────

def build_output_path(base_path: str | None, agent_name: str) -> str | None:
    """
    Build the output path suffix for this agent's report.

    SQLi Agent   → base_path_sqli
    NoSQLi Agent → base_path_nosqli

    FIX: Check for 'nosql' first since 'nosqli' also contains 'sqli'.
    Checking 'sqli' first caused NoSQLi to always get _sqli suffix.
    """
    if not base_path:
        return None
    # Check nosql FIRST — it is the more specific string
    suffix = "nosqli" if "nosql" in agent_name.lower() else "sqli"
    return f"{base_path}_{suffix}"


# ─────────────────────────────────────────────────────────────
# Agent runners
# ─────────────────────────────────────────────────────────────

def _apply_auth_to_requests(input_str: str,
                             auth_headers: dict) -> str:
    """
    If auth headers are provided and input is a collection file,
    write a temporary collection with auth merged into every
    request that does not already have that header.
    Returns path to use — original or temp file.
    """
    if not auth_headers or not os.path.exists(input_str):
        return input_str

    import json, tempfile
    with open(input_str, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        for item in data:
            existing = {
                k.lower(): k
                for k in (item.get("headers") or {})
            }
            for k, v in auth_headers.items():
                # Only add if header not already present
                if k.lower() not in existing:
                    item.setdefault("headers", {})[k] = v

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json",
        delete=False, encoding="utf-8"
    )
    json.dump(data, tmp, indent=2)
    tmp.close()
    return tmp.name


def run_sqli_agent(input_str: str, output_path: str | None,
                   formats: list[str], config: dict) -> list[dict]:
    """Instantiate and run the SQLi agent."""
    from agents.sqli_agent import SQLiAgent

    # Apply optional auth to collection if needed
    auth_headers    = config.get("auth_headers", {})
    effective_input = _apply_auth_to_requests(
        input_str, auth_headers
    )

    agent    = SQLiAgent()
    findings = agent.run(effective_input, config=config)

    if output_path:
        from tools.file_reporter import save_report
        save_report(
            findings     = agent.state["findings"],
            agent_name   = agent.agent_name,
            target_info  = input_str,
            total_tested = agent.state["total_tested"],
            output_path  = output_path,
            formats      = formats,
        )

    # Remove temp file if one was created
    if effective_input != input_str:
        try:
            os.unlink(effective_input)
        except OSError:
            pass

    global _last_agent_tested
    _last_agent_tested = agent.state.get("total_tested", 0)
    return findings


def run_nosqli_agent(input_str: str, output_path: str | None,
                     formats: list[str], config: dict) -> list[dict]:
    """Instantiate and run the NoSQLi agent."""
    from agents.nosqli_agent import NoSQLiAgent

    auth_headers    = config.get("auth_headers", {})
    effective_input = _apply_auth_to_requests(
        input_str, auth_headers
    )

    agent    = NoSQLiAgent()
    findings = agent.run(effective_input, config=config)

    if output_path:
        from tools.file_reporter import save_report
        save_report(
            findings     = agent.state["findings"],
            agent_name   = agent.agent_name,
            target_info  = input_str,
            total_tested = agent.state["total_tested"],
            output_path  = output_path,
            formats      = formats,
        )

    if effective_input != input_str:
        try:
            os.unlink(effective_input)
        except OSError:
            pass

    global _last_agent_tested
    _last_agent_tested = agent.state.get("total_tested", 0)
    return findings


# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────

def print_banner():
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        c1 = Fore.CYAN + Style.BRIGHT
        rs = Style.RESET_ALL
    except ImportError:
        c1 = rs = ""

    print(f"""
{c1}╔══════════════════════════════════════════════════════════════╗
║       INJECTION DETECTION AGENTS — STARTING                  ║
║       SQL Injection  +  NoSQL Injection                      ║
║       REST  +  GraphQL                                       ║
╚══════════════════════════════════════════════════════════════╝{rs}
""")

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    # ── Resolve input ─────────────────────────────────────────
    input_str  = args.curl if args.curl else args.collection
    input_type = "curl"   if args.curl else "collection"

    # ── Resolve formats ───────────────────────────────────────
    formats = (
        ["json", "html"] if args.fmt == "both"
        else [args.fmt]
    )

    # ── Build auth headers ────────────────────────────────────
    auth_headers = build_auth_headers(
        args.auth_type, args.auth_value, args.auth_header
    )

    # ── Print config summary ──────────────────────────────────
    print(f"  Agent     : {args.agent.upper()}")
    print(f"  Input     : {input_type}")
    print(f"  Source    : {input_str[:80]}")
    if auth_headers:
        header_name = list(auth_headers.keys())[0]
        print(f"  Auth      : {args.auth_type} ({header_name})")
    if args.delay > 0:
        print(f"  Delay     : {args.delay}s between requests")
    if args.output:
        print(f"  Output    : {args.output}_<agent>.json/html")
    print()

    # ── External API safety check ─────────────────────────────
    if is_external_target(input_str):
        if not warn_external(input_str, args.confirm):
            print("  Scan cancelled.")
            sys.exit(0)
    else:
        check_server()

    print()

    # ── Build runtime config ──────────────────────────────────
    config = {
        "timeout":      args.timeout,
        "delay":        args.delay,
        "auth_headers": auth_headers,
    }

    # ── Run agent(s) ──────────────────────────────────────────
    start_time = time.time()

    if args.agent == "sqli":
        out      = build_output_path(args.output, "SQLi Agent")
        findings = run_sqli_agent(
            input_str, out, formats, config
        )

    elif args.agent == "nosqli":
        out      = build_output_path(args.output, "NoSQLi Agent")
        findings = run_nosqli_agent(
            input_str, out, formats, config
        )

    elif args.agent == "both":
        print("  Running SQLi Agent first...\n")
        sqli_out      = None   # no individual file for both mode
        sqli_findings = run_sqli_agent(
            input_str, sqli_out, formats, config
        )
        sqli_tested   = 0
        # Capture tested count from agent state via a small helper
        sqli_tested   = _last_agent_tested

        print("\n  Running NoSQLi Agent next...\n")
        nosqli_out      = None
        nosqli_findings = run_nosqli_agent(
            input_str, nosqli_out, formats, config
        )
        nosqli_tested   = _last_agent_tested

        findings = sqli_findings + nosqli_findings

        # Save combined report if output path specified
        if args.output:
            from tools.file_reporter import save_combined_report
            save_combined_report(
                sqli_findings   = sqli_findings,
                nosqli_findings = nosqli_findings,
                sqli_tested     = sqli_tested,
                nosqli_tested   = nosqli_tested,
                target_info     = input_str,
                output_path     = args.output,
                formats         = formats,
            )
    
    elapsed = time.time() - start_time

    # ── Final summary ─────────────────────────────────────────
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        c = Fore.CYAN + Style.BRIGHT
        r = Style.RESET_ALL
    except ImportError:
        c = r = ""

    print(f"\n{c}{'─' * 65}{r}")
    print(f"{c}  SCAN COMPLETE{r}")
    print(f"{c}{'─' * 65}{r}")
    print(f"  Total findings : {len(findings)}")
    print(f"  Total time     : {elapsed:.1f}s")
    if args.output:
        print(f"  Reports saved  : {args.output}_*.json / *.html")
    print(f"{c}{'─' * 65}{r}\n")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()