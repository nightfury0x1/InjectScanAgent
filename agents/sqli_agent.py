"""
sqli_agent.py — SQL Injection detection agent.

HOW THIS AGENT THINKS
────────────────────────────────────────────────────────────────
The agent's reasoning lives entirely in decide_next_tool().
After every tool call it looks at its current state and answers
one question: "What do I still need to do?"

Decision tree:
  1. No requests parsed yet?
     → call parse_input

  2. Requests parsed but no endpoint detection yet?
     → call detect_endpoints

  3. Endpoints detected but no payloads loaded?
     → call load_payloads

  4. Payloads loaded and there are still requests to scan?
     → call inject_and_analyse
       (called once per request — agent loops back here
        until all requests are processed)

  5. All requests scanned but report not printed yet?
     → call report

  6. Report printed?
     → return None (agent is done)

WHAT THIS AGENT TESTS
────────────────────────────────────────────────────────────────
  REST endpoints:
    → query params    (?role=, ?q=, ?user_id=, ?id=)
    → body fields     (username, password, any JSON field)
    → suspicious headers

  GraphQL endpoints:
    → operation arguments  (id, username, password, q)
    → variables dict

PAYLOAD CATEGORIES USED
  auth_bypass    — comment-based and tautology bypasses
  error_based    — triggers DB error messages
  boolean_blind  — true/false condition probing
  time_based     — response delay detection
  union          — cross-table data extraction
  stacked        — multiple statement injection
"""

from agents.base_agent import BaseAgent
from tools.payload_library import get_sqli_payloads


class SQLiAgent(BaseAgent):
    """
    Agent 1 — Detects SQL injection vulnerabilities in both
    REST and GraphQL endpoints.
    """

    # ── Identity ──────────────────────────────────────────────

    @property
    def agent_name(self) -> str:
        return "SQLi Agent"


    # ── Tool registration ─────────────────────────────────────

    def register_tools(self):
        """
        Register all tools this agent can call.
        Names must match what decide_next_tool() returns.
        """
        self.tools["parse_input"]        = self._tool_parse_input
        self.tools["detect_endpoints"]   = self._tool_detect_endpoints
        self.tools["load_payloads"]      = self._tool_load_payloads
        self.tools["inject_and_analyse"] = self._tool_inject_and_analyse
        self.tools["report"]             = self._tool_report


    # ── Payload selection ─────────────────────────────────────

    def load_payloads(self) -> list[dict]:
        """
        Return ALL SQL injection payloads from the library.
        The agent tests every technique against every endpoint.

        Techniques included:
          auth_bypass, error_based, boolean_blind,
          time_based, union, stacked
        """
        payloads = get_sqli_payloads()
        self._log(
            f"Payload breakdown: "
            f"auth_bypass={self._count(payloads,'auth_bypass')}  "
            f"error_based={self._count(payloads,'error_based')}  "
            f"boolean_blind={self._count(payloads,'boolean_blind')}  "
            f"time_based={self._count(payloads,'time_based')}  "
            f"union={self._count(payloads,'union')}  "
            f"stacked={self._count(payloads,'stacked')}"
        )
        return payloads


    # ── Core reasoning — the THINK step ──────────────────────

    def decide_next_tool(self) -> str | None:
        """
        Inspect current state and decide the next tool to call.

        This function is the agent's brain. It is called after
        every single tool invocation and must return either a
        tool name or None to signal completion.

        The logic follows a strict priority order so the agent
        always knows exactly where it is in the scan lifecycle.
        """
        state = self.state

        # ── Priority 1: Handle errors immediately ─────────────
        if state.get("error"):
            self._log(f"Error in state: {state['error']} — stopping")
            return None

        # ── Priority 2: Parse the input ───────────────────────
        # No requests yet means we haven't parsed anything
        if not state["requests"]:
            self._log("Deciding: no requests yet → parse_input")
            return "parse_input"

        # ── Priority 3: Detect endpoint types ────────────────
        # We have requests but haven't classified them yet
        if not state["endpoint_info"]:
            self._log("Deciding: requests parsed → detect_endpoints")
            return "detect_endpoints"

        # ── Priority 4: Load payloads ─────────────────────────
        # We know what we're targeting but have no payloads yet
        if not state["payloads"]:
            self._log("Deciding: endpoints detected → load_payloads")
            return "load_payloads"

        # ── Priority 5: Scan remaining requests ───────────────
        # Payloads ready — work through requests one at a time.
        # current_request is an index that increments after each
        # inject_and_analyse call so the agent loops here until
        # all requests are processed.
        current = state["current_request"]
        total   = len(state["requests"])

        if current < total:
            self._log(
                f"Deciding: scanning request "
                f"{current + 1}/{total} → inject_and_analyse"
            )
            return "inject_and_analyse"

        # ── Priority 6: Print the report ──────────────────────
        # All requests scanned — report unless already done
        if not state["done"]:
            self._log("Deciding: all requests scanned → report")
            return "report"

        # ── Done ──────────────────────────────────────────────
        return None


    # ── Private helper ────────────────────────────────────────

    def _count(self, payloads: list, technique: str) -> int:
        """Count payloads matching a specific technique name."""
        return sum(1 for p in payloads if p["technique"] == technique)