#!/usr/bin/env python3
"""
CVE Report Generator
Fetches CVE data from RHEL, OSV, and BDU FSTEC databases
and generates a parameterized HTML report.

Usage:
    python cve_report.py CVE-2021-44228 CVE-2022-0847
    python cve_report.py --output report.html CVE-2021-44228
    python cve_report.py --timeout 30 --no-rhel CVE-2021-44228
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Install it: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── API endpoints ─────────────────────────────────────────────────────────────

RHEL_CVE_URL  = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{vuln_id}"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
BDU_SEARCH_URL = "https://bdu.fstec.ru/web-api/vulnerabilities"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# ── Source fetchers ───────────────────────────────────────────────────────────

def fetch_rhel(cve_id: str, session: requests.Session, timeout: int) -> dict:
    result = {"source": "RHEL", "cve_id": cve_id, "found": False, "error": None, "data": {}}
    try:
        resp = session.get(RHEL_CVE_URL.format(cve_id=cve_id), timeout=timeout)
        if resp.status_code == 404:
            result["error"] = "Not found in RHEL database"
            return result
        resp.raise_for_status()
        raw = resp.json()
        result["found"] = True
        result["data"] = {
            "severity":    raw.get("threat_severity", "UNKNOWN").upper(),
            "cvss3_score": raw.get("cvss3", {}).get("cvss3_base_score", "N/A"),
            "cvss3_vector":raw.get("cvss3", {}).get("cvss3_scoring_vector", "N/A"),
            "cvss2_score": raw.get("cvss", {}).get("cvss_base_score", "N/A"),
            "summary":     raw.get("details", raw.get("bugzilla", {}).get("description", "N/A")),
            "public_date": raw.get("public_date", "N/A"),
            "cwe":         raw.get("cwe", "N/A"),
            "affected_packages": [
                p.get("package", p.get("name", ""))
                for p in raw.get("affected_release", [])
            ][:20],
            "references":  [r.get("url", r) if isinstance(r, dict) else r
                            for r in raw.get("references", [])][:10],
            "raw_url":     f"https://access.redhat.com/security/cve/{cve_id}",
        }
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except (ValueError, KeyError) as e:
        result["error"] = f"Parse error: {e}"
    return result


def fetch_osv(cve_id: str, session: requests.Session, timeout: int) -> dict:
    result = {"source": "OSV", "cve_id": cve_id, "found": False, "error": None, "data": {}}
    try:
        # Try direct lookup first (OSV uses the CVE id directly)
        resp = session.get(OSV_VULN_URL.format(vuln_id=cve_id), timeout=timeout)
        if resp.status_code == 200:
            raw = resp.json()
        else:
            # Fall back to query endpoint
            payload = {"query": {"id": cve_id}}
            resp2 = session.post(OSV_QUERY_URL, json=payload, timeout=timeout)
            resp2.raise_for_status()
            vulns = resp2.json().get("vulns", [])
            if not vulns:
                result["error"] = "Not found in OSV database"
                return result
            raw = vulns[0]

        result["found"] = True
        severity_list = raw.get("severity", [])
        cvss_score, cvss_vector, severity_label = "N/A", "N/A", "UNKNOWN"
        for s in severity_list:
            if s.get("type") == "CVSS_V3":
                cvss_vector = s.get("score", "N/A")
                cvss_score  = _parse_cvss_score(cvss_vector)
                severity_label = _cvss_score_to_severity(cvss_score)
            elif s.get("type") == "CVSS_V2" and cvss_score == "N/A":
                cvss_vector = s.get("score", "N/A")
                cvss_score  = _parse_cvss_score(cvss_vector)
                severity_label = _cvss_score_to_severity(cvss_score)

        aliases  = raw.get("aliases", [])
        refs     = [r.get("url", "") for r in raw.get("references", [])][:10]
        affected = []
        for pkg_info in raw.get("affected", [])[:10]:
            pkg = pkg_info.get("package", {})
            name = pkg.get("name", "")
            eco  = pkg.get("ecosystem", "")
            if name:
                affected.append(f"{eco}/{name}" if eco else name)

        result["data"] = {
            "severity":    severity_label,
            "cvss3_score": cvss_score,
            "cvss3_vector":cvss_vector,
            "summary":     raw.get("summary", raw.get("details", "N/A")),
            "published":   raw.get("published", "N/A"),
            "modified":    raw.get("modified", "N/A"),
            "aliases":     aliases,
            "affected_packages": affected,
            "references":  refs,
            "raw_url":     f"https://osv.dev/vulnerability/{cve_id}",
        }
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except (ValueError, KeyError) as e:
        result["error"] = f"Parse error: {e}"
    return result


def fetch_bdu(cve_id: str, session: requests.Session, timeout: int) -> dict:
    result = {"source": "BDU FSTEC", "cve_id": cve_id, "found": False, "error": None, "data": {}}
    try:
        params = {"identcve": cve_id, "page": 1, "size": 5}
        resp = session.get(BDU_SEARCH_URL, params=params, timeout=timeout)
        resp.raise_for_status()
        body = resp.json()

        # BDU may return list or dict with "content"/"data" field
        items = []
        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = body.get("content", body.get("data", body.get("items", [])))

        # Filter to exact CVE match by aliases / identifiers
        matched = []
        for item in items:
            idents = _bdu_identifiers(item)
            if cve_id.upper() in idents:
                matched.append(item)

        if not matched:
            # Try broader: any item that mentions cve_id somewhere
            matched = items[:1] if items else []

        if not matched:
            result["error"] = "Not found in BDU FSTEC database"
            return result

        raw = matched[0]
        bdu_id   = raw.get("id", raw.get("identifier", raw.get("bduId", "N/A")))
        cvss3    = raw.get("cvss3", raw.get("cvssVector3", {}))
        cvss2    = raw.get("cvss2", raw.get("cvssVector2", {}))
        score3   = _extract_bdu_score(cvss3)
        score2   = _extract_bdu_score(cvss2)
        score    = score3 if score3 != "N/A" else score2
        severity = _cvss_score_to_severity(score)

        result["found"] = True
        result["data"] = {
            "bdu_id":      f"BDU:{bdu_id}" if bdu_id != "N/A" and not str(bdu_id).startswith("BDU") else str(bdu_id),
            "severity":    raw.get("severity", severity),
            "cvss3_score": score3,
            "cvss2_score": score2,
            "summary":     raw.get("description", raw.get("name", raw.get("shortDescription", "N/A"))),
            "published":   raw.get("identifyDate", raw.get("publishDate", raw.get("created", "N/A"))),
            "updated":     raw.get("updateDate", raw.get("modified", "N/A")),
            "affected_software": raw.get("affectedSoftware", raw.get("software", [])),
            "identifiers": list(_bdu_identifiers(raw)),
            "remediation": raw.get("solution", raw.get("remediation", raw.get("fix", "N/A"))),
            "raw_url":     f"https://bdu.fstec.ru/vul/{bdu_id}" if bdu_id != "N/A" else "https://bdu.fstec.ru/",
        }
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except (ValueError, KeyError) as e:
        result["error"] = f"Parse error: {e}"
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bdu_identifiers(item: dict) -> set:
    ids = set()
    for key in ("cveId", "cve_id", "identCVE", "identifiers", "aliases"):
        val = item.get(key)
        if isinstance(val, str):
            ids.add(val.upper())
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    ids.add(v.upper())
                elif isinstance(v, dict):
                    ids.add(v.get("identifier", v.get("value", "")).upper())
    return ids


def _extract_bdu_score(cvss) -> str:
    if isinstance(cvss, dict):
        for key in ("score", "baseScore", "base_score", "vector"):
            val = cvss.get(key)
            if val is not None:
                return str(val)
    if isinstance(cvss, (int, float)):
        return str(cvss)
    return "N/A"


def _parse_cvss_score(vector: str) -> str:
    """Extract base score from CVSS vector string or return it if already numeric."""
    if not vector or vector == "N/A":
        return "N/A"
    try:
        score = float(vector)
        return f"{score:.1f}"
    except ValueError:
        pass
    # Some OSV entries embed score as "CVSS:3.1/AV:N/..."
    parts = vector.split("/")
    for part in parts:
        if part.startswith("BS:") or part.startswith("baseScore:"):
            return part.split(":")[1]
    return "N/A"


def _cvss_score_to_severity(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return "UNKNOWN"


def _overall_severity(results: list[dict]) -> str:
    best = "UNKNOWN"
    for r in results:
        if not r["found"]:
            continue
        sev = r["data"].get("severity", "UNKNOWN").upper()
        if SEVERITY_ORDER.get(sev, 99) < SEVERITY_ORDER.get(best, 99):
            best = sev
    return best


# ── HTML generation ───────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": ("#7b0000", "#ff4444"),
    "HIGH":     ("#5c2700", "#ff8c00"),
    "MEDIUM":   ("#4a3800", "#ffc107"),
    "LOW":      ("#1a3a00", "#4caf50"),
    "UNKNOWN":  ("#2a2a2a", "#9e9e9e"),
}

CSS = """
:root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Consolas', 'SFMono-Regular', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font);
       font-size: 14px; line-height: 1.6; padding: 24px; }
h1   { font-size: 1.6rem; color: #e6edf3; margin-bottom: 4px; }
h2   { font-size: 1.1rem; color: var(--accent); margin: 20px 0 10px; }
h3   { font-size: 1rem; color: #e6edf3; margin-bottom: 8px; }
a    { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
.meta   { color: var(--text-dim); font-size: 0.85rem; margin-top: 4px; }

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
}
.stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
}
.stat-card .label { color: var(--text-dim); font-size: 0.78rem; text-transform: uppercase;
                    letter-spacing: .05em; margin-bottom: 4px; }
.stat-card .value { font-size: 1.5rem; font-weight: 700; color: #e6edf3; }

.cve-block {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 24px;
    overflow: hidden;
}
.cve-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    background: #1c2128;
}
.cve-id   { font-size: 1.1rem; font-weight: 700; font-family: var(--mono); color: #e6edf3; }
.sev-badge {
    font-size: 0.75rem; font-weight: 700; letter-spacing: .06em;
    padding: 3px 10px; border-radius: 12px; text-transform: uppercase;
}
.sources-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 0;
}
.source-panel {
    padding: 16px 20px;
    border-right: 1px solid var(--border);
}
.source-panel:last-child { border-right: none; }
.source-name {
    font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em;
    color: var(--text-dim); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;
}
.dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.dot-ok  { background: #3fb950; }
.dot-err { background: #f85149; }
.dot-na  { background: #6e7681; }
.kv-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
.kv-table td { padding: 3px 0; vertical-align: top; }
.kv-table td:first-child { color: var(--text-dim); width: 42%; padding-right: 8px;
                            white-space: nowrap; }
.tag-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
.tag { background: #21262d; border: 1px solid var(--border); border-radius: 4px;
       font-size: 0.75rem; padding: 1px 7px; font-family: var(--mono); color: var(--text-dim); }
.ref-list { list-style: none; margin-top: 4px; }
.ref-list li { word-break: break-all; font-size: 0.8rem; padding: 1px 0; }
.error-msg { color: #f85149; font-size: 0.82rem; font-style: italic; }
.not-found { color: var(--text-dim); font-size: 0.82rem; }

.footer { border-top: 1px solid var(--border); margin-top: 32px; padding-top: 14px;
          color: var(--text-dim); font-size: 0.8rem; }
"""

def _sev_badge(sev: str) -> str:
    bg, fg = SEV_COLORS.get(sev.upper(), SEV_COLORS["UNKNOWN"])
    return f'<span class="sev-badge" style="background:{bg};color:{fg}">{sev}</span>'


def _tags(items) -> str:
    if not items:
        return '<span class="not-found">—</span>'
    return '<div class="tag-list">' + "".join(f'<span class="tag">{i}</span>' for i in items[:15]) + "</div>"


def _refs(urls) -> str:
    if not urls:
        return '<span class="not-found">—</span>'
    items = "".join(f'<li><a href="{u}" target="_blank" rel="noopener">{u}</a></li>' for u in urls)
    return f'<ul class="ref-list">{items}</ul>'


def _kv(label: str, value, raw: bool = False) -> str:
    if value is None or value == "N/A" or value == [] or value == "":
        value_html = '<span class="not-found">N/A</span>'
    elif raw:
        value_html = str(value)
    else:
        value_html = str(value)
    return f"<tr><td>{label}</td><td>{value_html}</td></tr>"


def _render_rhel_panel(r: dict) -> str:
    if r["error"]:
        return f'<span class="dot dot-err"></span>RHEL</div><p class="error-msg">{r["error"]}</p>'
    d = r["data"]
    rows = (
        _kv("Severity",   _sev_badge(d.get("severity","UNKNOWN")), raw=True) +
        _kv("CVSS3 Score", d.get("cvss3_score")) +
        _kv("CVSS2 Score", d.get("cvss2_score")) +
        _kv("CWE",         d.get("cwe")) +
        _kv("Public date", d.get("public_date")) +
        _kv("Summary",     (d.get("summary","") or "")[:300]) +
        _kv("Affected",    _tags(d.get("affected_packages", [])), raw=True) +
        _kv("References",  _refs(d.get("references", [])), raw=True)
    )
    link = d.get("raw_url","")
    return (f'<span class="dot dot-ok"></span>'
            f'RHEL &nbsp;<a href="{link}" target="_blank" rel="noopener">↗</a>'
            f'</div><table class="kv-table">{rows}</table>')


def _render_osv_panel(r: dict) -> str:
    if r["error"]:
        return f'<span class="dot dot-err"></span>OSV</div><p class="error-msg">{r["error"]}</p>'
    d = r["data"]
    rows = (
        _kv("Severity",    _sev_badge(d.get("severity","UNKNOWN")), raw=True) +
        _kv("CVSS3 Score", d.get("cvss3_score")) +
        _kv("CVSS Vector", (d.get("cvss3_vector","") or "")[:80]) +
        _kv("Published",   d.get("published")) +
        _kv("Modified",    d.get("modified")) +
        _kv("Summary",     (d.get("summary","") or "")[:300]) +
        _kv("Aliases",     _tags(d.get("aliases", [])), raw=True) +
        _kv("Affected",    _tags(d.get("affected_packages", [])), raw=True) +
        _kv("References",  _refs(d.get("references", [])), raw=True)
    )
    link = d.get("raw_url","")
    return (f'<span class="dot dot-ok"></span>'
            f'OSV &nbsp;<a href="{link}" target="_blank" rel="noopener">↗</a>'
            f'</div><table class="kv-table">{rows}</table>')


def _render_bdu_panel(r: dict) -> str:
    if r["error"]:
        return f'<span class="dot dot-err"></span>BDU FSTEC</div><p class="error-msg">{r["error"]}</p>'
    d = r["data"]
    sw = d.get("affected_software", [])
    if isinstance(sw, list):
        sw_tags = _tags([s if isinstance(s, str) else s.get("name", str(s)) for s in sw])
    else:
        sw_tags = str(sw)[:200]
    rows = (
        _kv("BDU ID",      d.get("bdu_id")) +
        _kv("Severity",    _sev_badge(d.get("severity","UNKNOWN")), raw=True) +
        _kv("CVSS3 Score", d.get("cvss3_score")) +
        _kv("CVSS2 Score", d.get("cvss2_score")) +
        _kv("Published",   d.get("published")) +
        _kv("Updated",     d.get("updated")) +
        _kv("Summary",     (d.get("summary","") or "")[:300]) +
        _kv("Identifiers", _tags(d.get("identifiers", [])), raw=True) +
        _kv("Affected SW", sw_tags, raw=True) +
        _kv("Remediation", (d.get("remediation","") or "")[:300])
    )
    link = d.get("raw_url","")
    return (f'<span class="dot dot-ok"></span>'
            f'BDU FSTEC &nbsp;<a href="{link}" target="_blank" rel="noopener">↗</a>'
            f'</div><table class="kv-table">{rows}</table>')


_PANEL_RENDERERS = {
    "RHEL":      _render_rhel_panel,
    "OSV":       _render_osv_panel,
    "BDU FSTEC": _render_bdu_panel,
}


def generate_html(all_results: dict, args) -> str:
    cve_ids  = list(all_results.keys())
    total    = len(cve_ids)
    found_any = sum(1 for cve in all_results.values() if any(r["found"] for r in cve))
    now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sources_used = []
    if not args.no_rhel:
        sources_used.append("RHEL")
    if not args.no_osv:
        sources_used.append("OSV")
    if not args.no_bdu:
        sources_used.append("BDU FSTEC")

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cve, results in all_results.items():
        sev = _overall_severity(results)
        if sev in sev_counts:
            sev_counts[sev] += 1

    stat_cards = "".join(
        f'<div class="stat-card"><div class="label">{label}</div>'
        f'<div class="value" style="color:{color}">{val}</div></div>'
        for label, val, color in [
            ("Total CVEs",  total,                  "#e6edf3"),
            ("Found",       found_any,              "#3fb950"),
            ("Critical",    sev_counts["CRITICAL"], "#ff4444"),
            ("High",        sev_counts["HIGH"],     "#ff8c00"),
            ("Medium",      sev_counts["MEDIUM"],   "#ffc107"),
            ("Low",         sev_counts["LOW"],      "#4caf50"),
        ]
    )

    cve_blocks = ""
    for cve_id, results in all_results.items():
        overall_sev = _overall_severity(results)
        bg, fg = SEV_COLORS.get(overall_sev, SEV_COLORS["UNKNOWN"])
        badge   = _sev_badge(overall_sev)
        panels  = ""
        for r in results:
            renderer = _PANEL_RENDERERS.get(r["source"])
            if not renderer:
                continue
            inner = renderer(r)
            panels += f'<div class="source-panel"><div class="source-name">{inner}</div>'
        cve_blocks += f"""
<div class="cve-block">
  <div class="cve-header">
    <span class="cve-id">{cve_id}</span>
    {badge}
  </div>
  <div class="sources-grid">{panels}</div>
</div>"""

    sources_str = ", ".join(sources_used)
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVE Report — {now_str}</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
  <h1>CVE Security Report</h1>
  <div class="meta">Generated: {now_str} &nbsp;|&nbsp; Sources: {sources_str}</div>
</div>
<div class="summary-grid">{stat_cards}</div>
{cve_blocks}
<div class="footer">
  CVE Report Generator &nbsp;|&nbsp; Data from RHEL Security Data API, OSV.dev, BDU FSTEC
</div>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────

def build_session(timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "cve-report-generator/1.0 (+https://github.com)",
        "Accept": "application/json",
    })
    return s


def main():
    parser = argparse.ArgumentParser(
        description="Fetch CVE data from RHEL, OSV and BDU FSTEC; output an HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("cve_ids", nargs="+", metavar="CVE-XXXX-XXXXX",
                        help="One or more CVE identifiers, e.g. CVE-2021-44228")
    parser.add_argument("-o", "--output", default="cve_report.html",
                        help="Output HTML file path (default: cve_report.html)")
    parser.add_argument("--timeout", type=int, default=20,
                        help="HTTP request timeout in seconds (default: 20)")
    parser.add_argument("--no-rhel", action="store_true",
                        help="Skip Red Hat security data")
    parser.add_argument("--no-osv",  action="store_true",
                        help="Skip OSV database")
    parser.add_argument("--no-bdu",  action="store_true",
                        help="Skip BDU FSTEC database")
    parser.add_argument("--delay",  type=float, default=0.5,
                        help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print progress to stderr")
    args = parser.parse_args()

    # Normalise IDs
    cve_ids = [c.strip().upper() for c in args.cve_ids]
    for cid in cve_ids:
        if not cid.startswith("CVE-"):
            parser.error(f"Invalid CVE identifier: {cid!r}  (expected CVE-YYYY-NNNNN)")

    session = build_session(args.timeout)
    all_results: dict[str, list[dict]] = {}

    def log(msg):
        if args.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    fetchers = []
    if not args.no_rhel:
        fetchers.append(("RHEL",      fetch_rhel))
    if not args.no_osv:
        fetchers.append(("OSV",       fetch_osv))
    if not args.no_bdu:
        fetchers.append(("BDU FSTEC", fetch_bdu))

    if not fetchers:
        parser.error("All sources disabled — nothing to fetch.")

    total = len(cve_ids) * len(fetchers)
    done  = 0
    for cve_id in cve_ids:
        all_results[cve_id] = []
        for name, fn in fetchers:
            log(f"[{done+1}/{total}] {cve_id} → {name}")
            result = fn(cve_id, session, args.timeout)
            all_results[cve_id].append(result)
            done += 1
            if args.delay > 0 and done < total:
                time.sleep(args.delay)

    html = generate_html(all_results, args)
    out  = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"Report saved → {out.resolve()}")
    if args.verbose:
        found = sum(1 for results in all_results.values() if any(r["found"] for r in results))
        print(f"  CVEs queried : {len(cve_ids)}", file=sys.stderr)
        print(f"  CVEs found   : {found}", file=sys.stderr)


if __name__ == "__main__":
    main()
