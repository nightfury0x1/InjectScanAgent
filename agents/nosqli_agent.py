"""
nosqli_agent.py — NoSQL Injection detection agent.

HOW THIS AGENT THINKS
────────────────────────────────────────────────────────────────
Identical decision structure to the SQLi agent but with a
completely different payload set and detection focus.

Decision tree:
  1. No requests parsed yet?
     → call parse_input

  2. Requests parsed but no endpoint detection yet?
     → call detect_endpoints

  3. Endpoints detected but no payloads loaded?
     → call load_payloads

  4. Payloads loaded and there are still requests to scan?
     → call inject_and_analyse
       (called once per request — loops until all done)

  5. All requests scanned but report not printed yet?
     → call report

  6. Report printed?
     → return None (agent is done)

WHY THE SAME STRUCTURE AS SQLi AGENT?
────────────────────────────────────────────────────────────────
The scanning lifecycle is identical — only the payloads and
the signals we look for are different. Having the same
decision structure means:
  - Both agents are easy to reason about
  - New techniques can be added to either agent independently
  - The base_agent loop handles all the orchestration

WHAT THIS AGENT TESTS
────────────────────────────────────────────────────────────────
  REST endpoints:
    → JSON body fields  (username, password, any field)
    → query params      (?username=, ?collection=)
    → full body replacement for auth-bypass payloads

  GraphQL endpoints:
    → operation arguments  (username, password, query)
    → variables dict

PAYLOAD CATEGORIES USED
────────────────────────────────────────────────────────────────
  operator_injection — $ne, $gt, $gte, $lt, $exists, $ne null
  auth_bypass        — combined operator pairs for full bypass
  regex_injection    — $regex .*, ^pattern, case-insensitive
  where_injection    — $where JS expression evaluation
  array_abuse        — $in, $nin, array with operator element
"""

from agents.base_agent import BaseAgent
from tools.payload_library import get_nosqli_payloads


class NoSQLiAgent(BaseAgent):
    """
    Agent 2 — Detects NoSQL injection vulnerabilities in both
    REST and GraphQL endpoints.
    """

    # ── Identity ──────────────────────────────────────────────

    @property
    def agent_name(self) -> str:
        return "NoSQLi Agent"


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
        Return ALL NoSQL injection payloads from the library.

        Techniques included:
          operator_injection, auth_bypass, regex_injection,
          where_injection, array_abuse
        """
        payloads = get_nosqli_payloads()
        self._log(
            f"Payload breakdown: "
            f"operator_injection={self._count(payloads,'operator_injection')}  "
            f"auth_bypass={self._count(payloads,'auth_bypass')}  "
            f"regex_injection={self._count(payloads,'regex_injection')}  "
            f"where_injection={self._count(payloads,'where_injection')}  "
            f"array_abuse={self._count(payloads,'array_abuse')}"
        )
        return payloads


    # ── Core reasoning — the THINK step ──────────────────────

    def decide_next_tool(self) -> str | None:
        """
        Inspect current state and decide the next tool to call.

        Same priority structure as the SQLi agent. The separation
        between the two agents is entirely in load_payloads() —
        everything else in the loop is identical by design.

        Priority order:
          error → parse → detect → load → scan → report → done
        """
        state = self.state

        # ── Priority 1: Handle errors immediately ─────────────
        if state.get("error"):
            self._log(f"Error in state: {state['error']} — stopping")
            return None

        # ── Priority 2: Parse the input ───────────────────────
        if not state["requests"]:
            self._log("Deciding: no requests yet → parse_input")
            return "parse_input"

        # ── Priority 3: Detect endpoint types ────────────────
        if not state["endpoint_info"]:
            self._log("Deciding: requests parsed → detect_endpoints")
            return "detect_endpoints"

        # ── Priority 4: Load payloads ─────────────────────────
        if not state["payloads"]:
            self._log("Deciding: endpoints detected → load_payloads")
            return "load_payloads"

        # ── Priority 5: Scan remaining requests ───────────────
        # Loops here — one inject_and_analyse call per request
        # until current_request reaches len(requests)
        current = state["current_request"]
        total   = len(state["requests"])

        if current < total:
            self._log(
                f"Deciding: scanning request "
                f"{current + 1}/{total} → inject_and_analyse"
            )
            return "inject_and_analyse"

        # ── Priority 6: Print the report ──────────────────────
        if not state["done"]:
            self._log("Deciding: all requests scanned → report")
            return "report"

        # ── Done ──────────────────────────────────────────────
        return None


    # ── Private helper ────────────────────────────────────────

    def _count(self, payloads: list, technique: str) -> int:
        """Count payloads matching a specific technique name."""
        return sum(1 for p in payloads if p["technique"] == technique)