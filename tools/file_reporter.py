"""
file_reporter.py — Save scan findings to JSON and HTML files.

FORMATS:
  JSON  — structured machine-readable output, easy to parse
          or feed into other security tools
  HTML  — self-contained browser report with colour coding,
          collapsible findings, and a summary dashboard

USAGE (called automatically by the agent after scanning):
  from tools.file_reporter import save_report
  save_report(
      findings     = [...],
      agent_name   = "SQLi Agent",
      target_info  = "collections/mock_full.json",
      total_tested = 702,
      output_path  = "results/scan_001",   # no extension
      formats      = ["json", "html"],
  )
  → writes results/scan_001.json
  → writes results/scan_001.html
"""

import json
import os
import datetime


# ─────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────

def save_report(findings: list[dict], agent_name: str,
                target_info: str, total_tested: int,
                output_path: str,
                formats: list[str] | None = None) -> list[str]:
    """
    Save findings to one or more file formats.

    Parameters:
      findings      — list of Finding dicts from response_analyser
      agent_name    — "SQLi Agent" or "NoSQLi Agent"
      target_info   — cURL string or collection file path
      total_tested  — total injection attempts made
      output_path   — file path WITHOUT extension
                      e.g. "results/scan_001"
      formats       — list of formats: ["json"], ["html"], or
                      ["json", "html"] (default: both)

    Returns list of file paths written.
    """
    if formats is None:
        formats = ["json", "html"]

    # Ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    written = []
    meta    = _build_meta(agent_name, target_info, total_tested, findings)

    if "json" in formats:
        path = _save_json(findings, meta, output_path)
        written.append(path)

    if "html" in formats:
        path = _save_html(findings, meta, output_path)
        written.append(path)

    return written


# ─────────────────────────────────────────────────────────────
# Metadata builder
# ─────────────────────────────────────────────────────────────

def _build_meta(agent_name: str, target_info: str,
                total_tested: int, findings: list[dict]) -> dict:
    """Build a metadata dict summarising the scan."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    techniques = {}
    urls = set()

    for f in findings:
        sev  = f.get("severity", "LOW")
        tech = f.get("payload", {}).get("technique", "unknown")
        url  = f.get("url", "")
        counts[sev] = counts.get(sev, 0) + 1
        techniques[tech] = techniques.get(tech, 0) + 1
        urls.add(url)

    return {
        "agent_name":    agent_name,
        "target":        target_info,
        "scan_time":     datetime.datetime.now().isoformat(),
        "total_tested":  total_tested,
        "total_findings": len(findings),
        "severity_counts": counts,
        "techniques":    techniques,
        "urls_scanned":  sorted(urls),
        "overall_status": "VULNERABLE" if findings else "CLEAN",
    }


# ─────────────────────────────────────────────────────────────
# JSON output
# ─────────────────────────────────────────────────────────────

def _save_json(findings: list[dict], meta: dict,
               output_path: str) -> str:
    """Write findings and metadata to a JSON file."""
    path = f"{output_path}.json"

    # Make findings JSON-serialisable
    # (payload values may be dicts with non-string keys)
    clean_findings = []
    for f in findings:
        cf = dict(f)
        payload = dict(cf.get("payload", {}))
        payload["value"] = str(payload.get("value", ""))
        cf["payload"] = payload
        clean_findings.append(cf)

    output = {
        "meta":     meta,
        "findings": clean_findings,
    }

    with open(path, "w", encoding="utf-8") as fp:
        json.dump(output, fp, indent=2, default=str)

    print(f"  [✓] JSON report saved : {path}")
    return path


# ─────────────────────────────────────────────────────────────
# HTML output
# ─────────────────────────────────────────────────────────────

def _save_html(findings: list[dict], meta: dict,
               output_path: str) -> str:
    """Write a self-contained HTML report."""
    path = f"{output_path}.html"

    with open(path, "w", encoding="utf-8") as fp:
        fp.write(_render_html(findings, meta))

    print(f"  [✓] HTML report saved : {path}")
    return path


def _severity_colour(severity: str) -> str:
    return {
        "CRITICAL": "#e53e3e",
        "HIGH":     "#dd6b20",
        "MEDIUM":   "#d69e2e",
        "LOW":      "#3182ce",
    }.get(severity, "#718096")


def _severity_bg(severity: str) -> str:
    return {
        "CRITICAL": "#fff5f5",
        "HIGH":     "#fffaf0",
        "MEDIUM":   "#fffff0",
        "LOW":      "#ebf8ff",
    }.get(severity, "#f7fafc")


def _render_html(findings: list[dict], meta: dict) -> str:
    """Render the full HTML report as a string."""

    scan_time  = meta["scan_time"].replace("T", " ")[:19]
    status_col = "#e53e3e" if findings else "#38a169"
    status_txt = meta["overall_status"]

    # ── Summary cards ────────────────────────────────────────
    counts   = meta["severity_counts"]
    cards_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = counts.get(sev, 0)
        col   = _severity_colour(sev)
        cards_html += f"""
        <div class="card" style="border-left:4px solid {col}">
            <div class="card-count" style="color:{col}">{count}</div>
            <div class="card-label">{sev}</div>
        </div>"""

    # ── Techniques table ─────────────────────────────────────
    tech_rows = ""
    for tech, count in sorted(meta["techniques"].items()):
        tech_rows += f"""
        <tr>
            <td>{tech}</td>
            <td><strong>{count}</strong></td>
        </tr>"""

    # ── Findings ─────────────────────────────────────────────
    findings_html = ""
    if not findings:
        findings_html = """
        <div style="text-align:center;padding:40px;color:#38a169;font-size:1.2em">
            ✅ No vulnerabilities detected.
        </div>"""
    else:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_f = sorted(findings,
                          key=lambda f: order.get(f.get("severity", "LOW"), 9))

        for i, f in enumerate(sorted_f, 1):
            sev      = f.get("severity", "LOW")
            col      = _severity_colour(sev)
            bg       = _severity_bg(sev)
            payload  = f.get("payload", {})
            pay_val  = str(payload.get("value", ""))[:200]
            tech     = payload.get("technique", "")
            evidence = f.get("evidence", "")
            fix      = f.get("recommendation", "")

            findings_html += f"""
        <div class="finding" style="border-left:4px solid {col};
             background:{bg}">
            <div class="finding-header" onclick="toggle(this)">
                <span class="finding-sev" style="color:{col}">
                    ● {sev}
                </span>
                <span class="finding-title">
                    #{i} — {f.get('title', '')}
                </span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="finding-body">
                <table class="detail-table">
                    <tr><td>URL</td>
                        <td><code>{f.get('url','')}</code></td></tr>
                    <tr><td>Method</td>
                        <td>{f.get('method','')}</td></tr>
                    <tr><td>Injection Point</td>
                        <td><code>{f.get('inject_point','')}</code></td></tr>
                    <tr><td>Technique</td>
                        <td>{tech}</td></tr>
                    <tr><td>Signal</td>
                        <td>{f.get('signal','')}</td></tr>
                    <tr><td>Payload</td>
                        <td><code class="payload">{pay_val}</code></td></tr>
                    <tr><td>Evidence</td>
                        <td>{evidence}</td></tr>
                    <tr><td>Status Code</td>
                        <td>{f.get('status_code','')}</td></tr>
                    <tr><td>Response Time</td>
                        <td>{f.get('response_time', 0):.3f}s</td></tr>
                    <tr><td>Fix</td>
                        <td class="fix-cell">{fix}</td></tr>
                </table>
            </div>
        </div>"""

    # ── Full HTML ─────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{meta['agent_name']} — Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7fafc; color: #2d3748; font-size: 14px;
  }}
  .header {{
    background: #1a202c; color: white;
    padding: 24px 32px;
  }}
  .header h1 {{ font-size: 1.5em; font-weight: 700; }}
  .header .subtitle {{ color: #a0aec0; margin-top: 4px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .meta-bar {{
    background: white; border-radius: 8px;
    padding: 16px 24px; margin-bottom: 20px;
    border: 1px solid #e2e8f0;
    display: flex; flex-wrap: wrap; gap: 24px;
  }}
  .meta-item {{ display: flex; flex-direction: column; }}
  .meta-label {{ font-size: 11px; color: #718096;
                 text-transform: uppercase; letter-spacing: 0.05em; }}
  .meta-value {{ font-weight: 600; margin-top: 2px; }}
  .status-badge {{
    display: inline-block; padding: 4px 12px;
    border-radius: 12px; font-weight: 700;
    font-size: 0.85em; color: white;
    background: {status_col};
  }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 20px;
            flex-wrap: wrap; }}
  .card {{
    background: white; border-radius: 8px;
    padding: 16px 20px; flex: 1; min-width: 120px;
    border: 1px solid #e2e8f0;
  }}
  .card-count {{ font-size: 2em; font-weight: 700; }}
  .card-label {{ color: #718096; font-size: 0.85em;
                 text-transform: uppercase; }}
  .section-title {{
    font-size: 1em; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: #4a5568; margin: 24px 0 12px;
  }}
  .techniques-table {{
    width: 100%; border-collapse: collapse;
    background: white; border-radius: 8px;
    overflow: hidden; border: 1px solid #e2e8f0;
    margin-bottom: 20px;
  }}
  .techniques-table th {{
    background: #edf2f7; padding: 10px 16px;
    text-align: left; font-size: 0.85em;
    text-transform: uppercase; color: #4a5568;
  }}
  .techniques-table td {{
    padding: 10px 16px; border-top: 1px solid #e2e8f0;
  }}
  .finding {{
    border-radius: 8px; margin-bottom: 12px;
    border: 1px solid #e2e8f0; overflow: hidden;
  }}
  .finding-header {{
    padding: 14px 18px; cursor: pointer;
    display: flex; align-items: center; gap: 12px;
    user-select: none;
  }}
  .finding-header:hover {{ background: rgba(0,0,0,0.03); }}
  .finding-sev {{ font-weight: 700; font-size: 0.85em;
                  min-width: 80px; }}
  .finding-title {{ flex: 1; font-weight: 600; }}
  .toggle-icon {{ color: #a0aec0; transition: transform 0.2s; }}
  .finding-body {{
    padding: 0 18px 18px; display: none;
  }}
  .detail-table {{ width: 100%; border-collapse: collapse; }}
  .detail-table td {{
    padding: 6px 12px; border-bottom: 1px solid #edf2f7;
    vertical-align: top;
  }}
  .detail-table td:first-child {{
    font-weight: 600; color: #4a5568; width: 140px;
    white-space: nowrap;
  }}
  code {{
    background: #edf2f7; padding: 2px 6px;
    border-radius: 4px; font-size: 0.85em;
    word-break: break-all;
  }}
  .payload {{
    background: #fef3c7; color: #92400e;
  }}
  .fix-cell {{ color: #276749; }}
  footer {{
    text-align: center; color: #a0aec0;
    padding: 24px; font-size: 0.85em;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 {meta['agent_name']} — Scan Report</h1>
  <div class="subtitle">Generated: {scan_time}</div>
</div>

<div class="container">

  <div class="meta-bar">
    <div class="meta-item">
      <span class="meta-label">Target</span>
      <span class="meta-value">{meta['target'][:80]}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Attempts</span>
      <span class="meta-value">{meta['total_tested']}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Findings</span>
      <span class="meta-value">{meta['total_findings']}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Status</span>
      <span class="meta-value">
        <span class="status-badge">{status_txt}</span>
      </span>
    </div>
  </div>

  <div class="cards">{cards_html}</div>

  <div class="section-title">Techniques Detected</div>
  <table class="techniques-table">
    <thead>
      <tr><th>Technique</th><th>Findings</th></tr>
    </thead>
    <tbody>{tech_rows if tech_rows else
            '<tr><td colspan="2">None detected</td></tr>'}
    </tbody>
  </table>

  <div class="section-title">
    Findings ({meta['total_findings']})
  </div>
  {findings_html}

</div>

<footer>
  Injection Detection Agents — For authorised security testing only
</footer>

<script>
function toggle(header) {{
  var body = header.nextElementSibling;
  var icon = header.querySelector('.toggle-icon');
  if (body.style.display === 'block') {{
    body.style.display = 'none';
    icon.style.transform = 'rotate(0deg)';
  }} else {{
    body.style.display = 'block';
    icon.style.transform = 'rotate(180deg)';
  }}
}}
// Auto-expand CRITICAL findings
document.querySelectorAll('.finding').forEach(function(f) {{
  if (f.querySelector('.finding-sev').textContent.includes('CRITICAL')) {{
    var body = f.querySelector('.finding-body');
    var icon = f.querySelector('.toggle-icon');
    body.style.display = 'block';
    icon.style.transform = 'rotate(180deg)';
  }}
}});
</script>
</body>
</html>"""