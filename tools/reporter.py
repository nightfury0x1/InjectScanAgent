"""
reporter.py — Print vulnerability findings to the terminal.

WHY THIS EXISTS?
The analyser produces Finding dicts. The reporter turns them into
a human-readable terminal report that clearly communicates:
  - What was found
  - Where it was found
  - How severe it is
  - What payload triggered it
  - What evidence confirmed it
  - How to fix it

SEVERITY LEVELS:
  CRITICAL  — auth bypass, full data dump, RCE via $where
  HIGH      — error leak, UNION dump, time-based blind, data exposure
  MEDIUM    — boolean blind, content change, partial data leak
  LOW       — informational, weak signals, unconfirmed hints

COLOUR CODING (Windows-compatible via colorama):
  CRITICAL  → bright red
  HIGH      → red
  MEDIUM    → yellow
  LOW       → cyan
  SAFE      → green
"""

import os
import sys

# Colour support — works on Windows, Mac, Linux
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)   # resets colour after each print
    _COLOUR = True
except ImportError:
    _COLOUR = False

    # Stub out colorama constants so the rest of the code works
    class _Stub:
        def __getattr__(self, _): return ""
    Fore  = _Stub()
    Back  = _Stub()
    Style = _Stub()


# ─────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────

SEVERITY_COLOURS = {
    "CRITICAL": Fore.RED    + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


def _c(text: str, colour: str) -> str:
    """Wrap text in a colour code if colours are available."""
    if _COLOUR:
        return f"{colour}{text}{Style.RESET_ALL}"
    return text


def _severity_str(severity: str) -> str:
    colour = SEVERITY_COLOURS.get(severity, "")
    icon   = SEVERITY_ICONS.get(severity, "⚪")
    return f"{icon}  {_c(severity, colour)}"


# ─────────────────────────────────────────────────────────────
# Main report functions
# ─────────────────────────────────────────────────────────────

def print_report(findings: list[dict], agent_name: str,
                 target_info: str = "", total_tested: int = 0):
    """
    Print a full vulnerability report to the terminal.

    Parameters:
      findings      — list of Finding dicts from response_analyser
      agent_name    — "SQLi Agent" or "NoSQLi Agent"
      target_info   — human label e.g. cURL or collection filename
      total_tested  — total number of injection attempts made
    """
    _print_header(agent_name, target_info, total_tested, len(findings))

    if not findings:
        _print_safe()
        _print_footer(findings)
        return

    # Sort by severity order
    order    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(findings, key=lambda f: order.get(f["severity"], 9))

    # Print each finding
    for i, finding in enumerate(sorted_f, 1):
        _print_finding(finding, i)

    # Summary table at the bottom
    _print_summary_table(sorted_f)
    _print_footer(findings)


def print_scan_start(agent_name: str, target: str,
                     endpoint_type: str, payload_count: int):
    """
    Print a brief scan-start notice before injection begins.
    Gives the user live feedback that the agent is working.
    """
    w = 65
    print()
    print(_c("─" * w, Fore.CYAN))
    print(_c(f"  ▶  {agent_name} — Scan Starting", Fore.CYAN + Style.BRIGHT))
    print(_c("─" * w, Fore.CYAN))
    print(f"  Target       : {target}")
    print(f"  Endpoint type: {endpoint_type.upper()}")
    print(f"  Payloads     : {payload_count}")
    print(_c("─" * w, Fore.CYAN))
    print()


def print_progress(current: int, total: int,
                   inject_point: str, payload_value: str):
    """
    Print a single-line progress update during scanning.
    Overwrites the same line each time using carriage return.
    """
    pct   = int((current / total) * 100) if total else 0
    val   = str(payload_value)[:35]
    line  = f"  [{pct:>3}%] {inject_point:<25} {val}"
    # \r returns to start of line without newline — live progress
    print(f"\r{line:<70}", end="", flush=True)


def print_progress_done():
    """Move to a new line after progress updates finish."""
    print()


# ─────────────────────────────────────────────────────────────
# Internal print helpers
# ─────────────────────────────────────────────────────────────

def _print_header(agent_name: str, target_info: str,
                  total_tested: int, finding_count: int):
    w = 65
    print()
    print(_c("═" * w, Fore.WHITE + Style.BRIGHT))
    print(_c(f"  {agent_name} — SCAN REPORT", Fore.WHITE + Style.BRIGHT))
    print(_c("═" * w, Fore.WHITE + Style.BRIGHT))
    if target_info:
        print(f"  Target  : {target_info}")
    print(f"  Tested  : {total_tested} injection attempt(s)")
    count_colour = Fore.RED + Style.BRIGHT if finding_count else Fore.GREEN
    print(f"  Found   : {_c(str(finding_count), count_colour)} "
          f"vulnerability finding(s)")
    print(_c("─" * w, Fore.WHITE))
    print()


def _print_safe():
    w = 65
    print(_c("  ✅  No vulnerabilities detected.", Fore.GREEN + Style.BRIGHT))
    print()
    print(_c("  The tested endpoint(s) did not respond to any of the", Fore.GREEN))
    print(_c("  injection payloads in a way that indicates vulnerability.", Fore.GREEN))
    print(_c("  This does not guarantee the endpoint is secure — consider", Fore.GREEN))
    print(_c("  expanding the payload set or testing manually.", Fore.GREEN))
    print()
    print(_c("─" * w, Fore.WHITE))


def _print_finding(finding: dict, index: int):
    w = 65
    severity = finding.get("severity", "LOW")
    colour   = SEVERITY_COLOURS.get(severity, "")

    print(_c(f"  ┌─ Finding #{index} ", colour) +
          _c("─" * (w - 14), colour))

    print(_c(f"  │  Severity   : ", colour) +
          _severity_str(severity))

    print(_c(f"  │  Title      : ", colour) +
          _c(finding.get("title", ""), Style.BRIGHT))

    print(_c(f"  │  Signal     : ", colour) +
          finding.get("signal", ""))

    print(_c(f"  │  URL        : ", colour) +
          finding.get("url", ""))

    print(_c(f"  │  Method     : ", colour) +
          finding.get("method", ""))

    print(_c(f"  │  Inj. Point : ", colour) +
          finding.get("inject_point", ""))

    # Payload value
    payload     = finding.get("payload", {})
    payload_val = str(payload.get("value", ""))
    technique   = payload.get("technique", "")
    print(_c(f"  │  Technique  : ", colour) + technique)
    print(_c(f"  │  Payload    : ", colour) +
          _c(payload_val[:80], Fore.YELLOW))

    # Evidence
    evidence = finding.get("evidence", "")
    # Wrap long evidence lines
    if len(evidence) > 60:
        words   = evidence.split()
        lines   = []
        current = ""
        for w_word in words:
            if len(current) + len(w_word) + 1 > 58:
                lines.append(current)
                current = w_word
            else:
                current = f"{current} {w_word}".strip()
        if current:
            lines.append(current)
        print(_c(f"  │  Evidence   : ", colour) + lines[0])
        for line in lines[1:]:
            print(_c(f"  │             : ", colour) + line)
    else:
        print(_c(f"  │  Evidence   : ", colour) + evidence)

    # Recommendation
    rec = finding.get("recommendation", "")
    if len(rec) > 60:
        words   = rec.split()
        lines   = []
        current = ""
        for w_word in words:
            if len(current) + len(w_word) + 1 > 58:
                lines.append(current)
                current = w_word
            else:
                current = f"{current} {w_word}".strip()
        if current:
            lines.append(current)
        print(_c(f"  │  Fix        : ", colour) +
              _c(lines[0], Fore.GREEN))
        for line in lines[1:]:
            print(_c(f"  │             : ", colour) +
                  _c(line, Fore.GREEN))
    else:
        print(_c(f"  │  Fix        : ", colour) +
              _c(rec, Fore.GREEN))

    # Response info
    print(_c(f"  │  Status     : ", colour) +
          str(finding.get("status_code", "")))
    print(_c(f"  │  Resp. time : ", colour) +
          f"{finding.get('response_time', 0):.3f}s")

    print(_c(f"  └" + "─" * (w - 4), colour))
    print()


def _print_summary_table(findings: list[dict]):
    w = 65
    print(_c("─" * w, Fore.WHITE))
    print(_c("  SUMMARY", Fore.WHITE + Style.BRIGHT))
    print(_c("─" * w, Fore.WHITE))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.get("severity", "LOW")] += 1

    for severity, count in counts.items():
        if count > 0:
            bar    = "█" * count
            colour = SEVERITY_COLOURS.get(severity, "")
            print(f"  {_severity_str(severity):<35} "
                  f"{_c(bar, colour)}  {count}")

    print()
    print(_c("  TECHNIQUES DETECTED", Fore.WHITE + Style.BRIGHT))
    print(_c("─" * w, Fore.WHITE))

    techniques = {}
    for f in findings:
        tech = f.get("payload", {}).get("technique", "unknown")
        url  = f.get("url", "")
        if tech not in techniques:
            techniques[tech] = []
        if url not in techniques[tech]:
            techniques[tech].append(url)

    for tech, urls in techniques.items():
        print(f"  • {tech}")
        for url in urls:
            print(f"      {url}")

    print()


def _print_footer(findings: list[dict]):
    w = 65
    overall = "VULNERABLE" if findings else "CLEAN"
    colour  = (Fore.RED + Style.BRIGHT) if findings else (Fore.GREEN + Style.BRIGHT)
    print(_c("═" * w, Fore.WHITE + Style.BRIGHT))
    print(f"  Overall status : {_c(overall, colour)}")
    print(_c("═" * w, Fore.WHITE + Style.BRIGHT))
    print()


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python -m tools.reporter)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    sample_findings = [
        {
            "vulnerable":     True,
            "signal":         "auth",
            "severity":       "CRITICAL",
            "title":          "SQL Injection — Authentication Bypass",
            "evidence":       "Login succeeded with injected credentials. Payload: admin'--",
            "inject_point":   "body.username",
            "payload":        {
                "value":     "admin'--",
                "category":  "sqli",
                "technique": "auth_bypass",
                "detect_in": ["auth"],
            },
            "request_name":   "SQL Login",
            "url":            "http://127.0.0.1:5000/api/login",
            "method":         "POST",
            "status_code":    200,
            "response_time":  0.023,
            "recommendation": "Use parameterised queries for all authentication logic.",
        },
        {
            "vulnerable":     True,
            "signal":         "data",
            "severity":       "HIGH",
            "title":          "SQL Injection — Unauthorised Data Exposure",
            "evidence":       "Baseline returned 1 row. Injection returned 4 rows.",
            "inject_point":   "params.q",
            "payload":        {
                "value":     "' UNION SELECT id,username,password,email FROM users--",
                "category":  "sqli",
                "technique": "union",
                "detect_in": ["data"],
            },
            "request_name":   "Product Search",
            "url":            "http://127.0.0.1:5000/api/products/search",
            "method":         "GET",
            "status_code":    200,
            "response_time":  0.018,
            "recommendation": "Use parameterised queries. Apply row-level access controls.",
        },
        {
            "vulnerable":     True,
            "signal":         "auth",
            "severity":       "CRITICAL",
            "title":          "NoSQL Injection — Authentication Bypass",
            "evidence":       "Login succeeded with injected credentials. Payload: {'$ne': ''}",
            "inject_point":   "body.password",
            "payload":        {
                "value":     {"$ne": ""},
                "category":  "nosqli",
                "technique": "operator_injection",
                "detect_in": ["auth"],
            },
            "request_name":   "NoSQL Login",
            "url":            "http://127.0.0.1:5000/api/nosql/login",
            "method":         "POST",
            "status_code":    200,
            "response_time":  0.011,
            "recommendation": "Validate and sanitise all query operators.",
        },
        {
            "vulnerable":     True,
            "signal":         "content_change",
            "severity":       "MEDIUM",
            "title":          "Boolean Blind SQL Injection — Content Change Detected",
            "evidence":       "Baseline returned 1 row, injection returned 4 rows.",
            "inject_point":   "params.user_id",
            "payload":        {
                "value":     "1 AND 1=1",
                "category":  "sqli",
                "technique": "boolean_blind",
                "detect_in": ["content_change"],
            },
            "request_name":   "Get Orders",
            "url":            "http://127.0.0.1:5000/api/orders",
            "method":         "GET",
            "status_code":    200,
            "response_time":  0.009,
            "recommendation": "Use parameterised queries.",
        },
    ]

    print_report(
        findings     = sample_findings,
        agent_name   = "SQLi Agent",
        target_info  = "http://127.0.0.1:5000  (mock server)",
        total_tested = 247,
    )