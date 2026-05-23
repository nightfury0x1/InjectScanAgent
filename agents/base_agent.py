"""
base_agent.py — Shared agentic loop used by both SQLi and NoSQLi agents.

AGENTIC FLOW DESIGN
────────────────────────────────────────────────────────────────
The agent operates as a OBSERVE → THINK → ACT → UPDATE loop.

  OBSERVE  : agent receives input and initialises its state
  THINK    : _decide_next_tool() looks at current state and
             returns the name of the next tool to call
  ACT      : the tool is called, producing an observation
  UPDATE   : the observation is stored in state
  REPEAT   : until state["done"] is True

WHY THIS IS AGENTIC (not just a pipeline):
  - The agent maintains state across all tool calls
  - _decide_next_tool() makes a fresh decision after every
    observation — it does not follow a hardcoded sequence
  - If parsing fails, the agent records the error and stops
    gracefully rather than crashing
  - If an endpoint has no injectable fields, the agent skips
    injection entirely and reports "nothing to test"
  - The agent tracks progress and emits live updates

TOOL REGISTRY
  Each subclass registers its tools in self.tools as a dict:
    { "tool_name": callable }
  The base loop calls tools by name — subclasses decide which
  tools exist and what they do.

STATE SCHEMA
  {
    "input":           str | None,   raw cURL or collection path
    "requests":        list[dict],   parsed request dicts
    "endpoint_info":   list[dict],   one detection result per request
    "payloads":        list[dict],   payloads to test
    "inject_results":  list[dict],   raw InjectionResult dicts
    "findings":        list[dict],   confirmed vulnerability findings
    "total_tested":    int,          total injection attempts
    "current_request": int,          index into requests list
    "done":            bool,
    "error":           str | None,
    "phase":           str,          current phase label for logging
  }
"""

import time
from abc import ABC, abstractmethod
from tools.reporter import print_scan_start, print_progress
from tools.reporter import print_progress_done, print_report


# ─────────────────────────────────────────────────────────────
# Base Agent
# ─────────────────────────────────────────────────────────────

class BaseAgent(ABC):
    """
    Abstract base class for the SQLi and NoSQLi agents.

    Subclasses must implement:
      - agent_name      : str property
      - register_tools  : populate self.tools dict
      - load_payloads   : return the right payload list
      - decide_next_tool: return next tool name given state
    """

    def __init__(self):
        self.tools = {}          # tool_name → callable
        self.state = {}          # current agent state
        self.register_tools()    # subclass fills self.tools


    # ── Abstract interface ────────────────────────────────────

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Human-readable agent name e.g. 'SQLi Agent'"""
        pass

    @abstractmethod
    def register_tools(self):
        """
        Populate self.tools with all tools this agent can call.
        Called once at __init__ time.

        Example:
          self.tools["parse_input"]     = self._tool_parse_input
          self.tools["detect_endpoint"] = self._tool_detect_endpoint
          ...
        """
        pass

    @abstractmethod
    def load_payloads(self) -> list[dict]:
        """
        Return the payload list for this agent.
        SQLi agent  → get_sqli_payloads()
        NoSQLi agent → get_nosqli_payloads()
        """
        pass

    @abstractmethod
    def decide_next_tool(self) -> str | None:
        """
        THINK step — inspect current state and return the name
        of the next tool to call, or None if the agent is done.

        This is the core reasoning function. It is called after
        every tool invocation and must base its decision purely
        on self.state.

        Return values:
          "tool_name"  → call that tool next
          None         → agent is finished
        """
        pass


    # ── Core agent loop ───────────────────────────────────────

    def run(self, input_str: str,
            config: dict | None = None) -> list[dict]:
        """
        Main entry point. Run the full agentic loop.

        Parameters:
          input_str — either a raw cURL string
                      or a path to a collection JSON file

        Returns list of Finding dicts (may be empty if nothing found).
        """
        cfg = config or {}
        # ── OBSERVE: initialise state ─────────────────────────
        self.state = {
            "input":           input_str,
            "requests":        [],
            "endpoint_info":   [],
            "payloads":        [],
            "inject_results":  [],
            "findings":        [],
            "total_tested":    0,
            "current_request": 0,
            "done":            False,
            "error":           None,
            "phase":           "init",
            "output_path":     None,
            "output_formats":  ["json", "html"],
            "output_files":    [],
            # Runtime config — carried through all tool calls
            "timeout":         cfg.get("timeout", 10.0),
            "delay":           cfg.get("delay", 0.0),
            "auth_headers":    cfg.get("auth_headers", {}),
        }

        self._log(f"Agent started. Input: {input_str[:80]}")
        step = 0
        max_steps = 1000   # safety ceiling — prevents infinite loops

        # ── THINK → ACT → UPDATE loop ─────────────────────────
        while not self.state["done"] and step < max_steps:
            step += 1

            # THINK — decide what to do next
            tool_name = self.decide_next_tool()

            if tool_name is None:
                self.state["done"] = True
                break

            if tool_name not in self.tools:
                self._log(f"Unknown tool requested: '{tool_name}' — stopping")
                self.state["error"] = f"Unknown tool: {tool_name}"
                self.state["done"]  = True
                break

            # ACT — call the tool
            self._log(f"[Step {step:>3}] Calling tool: {tool_name}")
            tool_fn = self.tools[tool_name]

            try:
                observation = tool_fn()
            except Exception as e:
                self._log(f"Tool '{tool_name}' raised an exception: {e}")
                self.state["error"] = str(e)
                self.state["done"]  = True
                break

            # UPDATE — store observation in state
            if isinstance(observation, dict):
                for key, value in observation.items():
                    self.state[key] = value

        if step >= max_steps:
            self._log("Max steps reached — stopping agent")

        self._log(
            f"Agent finished. "
            f"Findings: {len(self.state['findings'])}  "
            f"Tested: {self.state['total_tested']}"
        )

        return self.state["findings"]


    # ── Shared tool implementations ───────────────────────────
    # These are used by both SQLi and NoSQLi agents.
    # Each tool returns a dict that gets merged into self.state.

    def _tool_parse_input(self) -> dict:
        """
        TOOL: parse_input
        Parses the raw input (cURL string or collection file path)
        into a list of request dicts.

        Updates state keys: requests, phase
        """
        from tools.curl_parser import parse_curl
        from tools.collection_parser import parse_collection

        inp = self.state["input"]

        # Detect whether input is a file path or a cURL string
        if self._looks_like_file(inp):
            self._log("Input looks like a file path — parsing as collection")
            try:
                requests = parse_collection(inp)
                return {"requests": requests, "phase": "parsed_collection"}
            except (FileNotFoundError, ValueError) as e:
                return {
                    "error": str(e),
                    "done":  True,
                    "phase": "error",
                }
        else:
            self._log("Input looks like a cURL command — parsing as curl")
            try:
                request = parse_curl(inp)
                return {"requests": [request], "phase": "parsed_curl"}
            except ValueError as e:
                return {
                    "error": str(e),
                    "done":  True,
                    "phase": "error",
                }


    def _tool_detect_endpoints(self) -> dict:
        """
        TOOL: detect_endpoints
        Runs endpoint detection on every parsed request.

        Updates state keys: endpoint_info, phase
        """
        from tools.endpoint_detector import detect_endpoint_type

        info_list = []
        for req in self.state["requests"]:
            info = detect_endpoint_type(req)
            info_list.append(info)
            self._log(
                f"  Detected: {req.get('url','')} "
                f"→ {info['type'].upper()} "
                f"(confidence: {info['confidence']})"
            )

        return {"endpoint_info": info_list, "phase": "endpoints_detected"}


    def _tool_load_payloads(self) -> dict:
        """
        TOOL: load_payloads
        Calls the subclass load_payloads() to get the right
        payload list for this agent.

        Updates state keys: payloads, phase
        """
        payloads = self.load_payloads()
        self._log(f"Loaded {len(payloads)} payloads")
        return {"payloads": payloads, "phase": "payloads_loaded"}


    def _tool_inject_and_analyse(self) -> dict:
        """
        TOOL: inject_and_analyse
        Core scanning tool. Fires every payload at every injection
        point for one request, then analyses each response.

        Reads timeout, delay, and auth_headers from self.state
        so no global variables or patching needed.
        """
        import time as _time
        from tools.injector import inject_all
        from tools.response_analyser import analyse_all, get_baseline

        idx          = self.state["current_request"]
        requests     = self.state["requests"]
        request      = dict(requests[idx])
        endpoint     = self.state["endpoint_info"][idx]
        payloads     = self.state["payloads"]
        timeout      = self.state["timeout"]
        delay        = self.state["delay"]
        auth_headers = self.state["auth_headers"]

        # Merge auth headers if provided — only adds missing headers,
        # never overrides headers already in the request
        if auth_headers:
            merged = dict(request.get("headers", {}))
            for k, v in auth_headers.items():
                if k not in merged and k.lower() not in {
                    h.lower() for h in merged
                }:
                    merged[k] = v
            request["headers"] = merged

        name = request.get("name") or request.get("url", "")
        self._log(f"Scanning request {idx+1}/{len(requests)}: {name}")

        print_scan_start(
            agent_name    = self.agent_name,
            target        = request.get("url", ""),
            endpoint_type = endpoint["type"],
            payload_count = len(payloads),
        )

        # Baseline uses same timeout
        baseline = get_baseline(request, timeout=timeout)

        # Fire all payloads
        results = inject_all(
            request, payloads, endpoint, timeout=timeout
        )

        # Progress output + optional delay between requests
        total = len(results)
        for i, result in enumerate(results, 1):
            print_progress(
                current       = i,
                total         = total,
                inject_point  = result.get("inject_point", ""),
                payload_value = result.get("payload", {}).get("value", ""),
            )
            if delay > 0:
                _time.sleep(delay)

        print_progress_done()

        new_findings = analyse_all(results, baseline)
        self._log(
            f"  → {len(results)} attempts, "
            f"{len(new_findings)} finding(s)"
        )

        all_results  = self.state["inject_results"] + results
        all_findings = self.state["findings"] + new_findings
        total_tested = self.state["total_tested"] + len(results)

        return {
            "inject_results":  all_results,
            "findings":        all_findings,
            "total_tested":    total_tested,
            "current_request": idx + 1,
            "phase":           "scanning",
        }


    def _tool_report(self) -> dict:
        """
        TOOL: report
        Prints the final terminal report, then saves to files
        if an output path was configured in state.

        Updates state keys: done, phase
        """
        print_report(
            findings     = self.state["findings"],
            agent_name   = self.agent_name,
            target_info  = self.state["input"],
            total_tested = self.state["total_tested"],
        )

        # Save to files if output_path was set by main.py
        output_path = self.state.get("output_path")
        formats     = self.state.get("output_formats", ["json", "html"])

        if output_path:
            from tools.file_reporter import save_report
            written = save_report(
                findings     = self.state["findings"],
                agent_name   = self.agent_name,
                target_info  = self.state["input"],
                total_tested = self.state["total_tested"],
                output_path  = output_path,
                formats      = formats,
            )
            self.state["output_files"] = written

        return {"done": True, "phase": "complete"}


    # ── Helpers ───────────────────────────────────────────────

    def _looks_like_file(self, s: str) -> bool:
        """
        Return True if the input string looks like a file path
        rather than a cURL command.

        Heuristics:
          - ends with .json
          - contains a path separator and does not start with curl
          - is an existing file path
        """
        import os
        s = s.strip()
        if s.lower().startswith("curl"):
            return False
        if s.endswith(".json"):
            return True
        if os.path.exists(s):
            return True
        return False


    def _log(self, message: str):
        """Print a timestamped agent log line."""
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}] {self.agent_name} | {message}")