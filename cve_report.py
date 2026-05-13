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
import xml.etree.ElementTree as ET
import zipfile
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
# BDU FSTEC has no search API — provides a full XML dump updated several times/week
BDU_XML_URL   = "https://bdu.fstec.ru/files/documents/vulxml.zip"
BDU_CACHE_DIR  = Path.home() / ".cache" / "cve_report" / "bdu"
BDU_CACHE_FILE = BDU_CACHE_DIR / "vulxml.zip"
BDU_CACHE_TTL  = 86400  # seconds (24 h)

BDU_SEVERITY_MAP = {
    "критическая": "CRITICAL",
    "высокая":     "HIGH",
    "средняя":     "MEDIUM",
    "низкая":      "LOW",
}

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


def _bdu_ensure_cache(session: requests.Session, timeout: int,
                      force_refresh: bool = False, verbose: bool = False) -> None:
    """Download vulxml.zip if missing or older than BDU_CACHE_TTL."""
    BDU_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not force_refresh and BDU_CACHE_FILE.exists():
        age = time.time() - BDU_CACHE_FILE.stat().st_mtime
        if age < BDU_CACHE_TTL:
            return
    if verbose:
        print("[*] Downloading BDU FSTEC XML dump (may take a while)…", file=sys.stderr)
    resp = session.get(BDU_XML_URL, timeout=max(timeout, 120), stream=True)
    resp.raise_for_status()
    tmp = BDU_CACHE_FILE.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
    tmp.replace(BDU_CACHE_FILE)


def _bdu_find_cve(cve_id: str) -> Optional[dict]:
    """
    Parse the cached XML with iterparse to find the first vulnerability
    whose <identifiers> contains a CVE-type entry matching cve_id.
    Returns a dict of extracted fields, or None if not found.
    Uses iterparse to avoid loading the full multi-MB XML into memory.
    """
    target = cve_id.upper()

    with zipfile.ZipFile(BDU_CACHE_FILE) as z:
        xml_names = [n for n in z.namelist() if n.endswith(".xml")]
        if not xml_names:
            raise ValueError("No XML file found inside BDU zip")
        with z.open(xml_names[0]) as raw_stream:
            # Stream-parse element by element; accumulate one <vul> at a time
            vul: Optional[dict] = None
            found: Optional[dict] = None
            context = ET.iterparse(raw_stream, events=("start", "end"))
            depth = 0  # nesting depth inside a <vul> element
            current_tag = []  # path stack inside vul

            for event, elem in context:
                if event == "start":
                    if depth == 0 and elem.tag not in ("export", "vulnerabilities"):
                        # Every direct child of root is a vulnerability record
                        vul = {
                            "identifier": None, "name": None, "description": None,
                            "severity": None, "solution": None, "identify_date": None,
                            "exploit_status": None, "vul_incident": None,
                            "cvss": {}, "cvss3": {}, "cwe": [], "soft": [],
                            "identifiers": [],
                        }
                        depth = 1
                    elif depth >= 1:
                        depth += 1
                elif event == "end":
                    if vul is None:
                        continue

                    tag = elem.tag
                    text = (elem.text or "").strip()

                    if depth == 2:  # direct children of <vul>
                        if tag == "identifier":
                            vul["identifier"] = text
                        elif tag == "name":
                            vul["name"] = text
                        elif tag == "description":
                            vul["description"] = text
                        elif tag == "severity":
                            vul["severity"] = text
                        elif tag == "solution":
                            vul["solution"] = text
                        elif tag == "identify_date":
                            vul["identify_date"] = text
                        elif tag == "exploit_status":
                            vul["exploit_status"] = text
                        elif tag == "vul_incident":
                            vul["vul_incident"] = text
                        elif tag == "identifiers":
                            for ident in elem:
                                vul["identifiers"].append({
                                    "type":  ident.attrib.get("type", ""),
                                    "value": (ident.text or "").strip(),
                                })
                        elif tag == "vulnerable_software":
                            for soft in elem:
                                sd = {sp.tag: (sp.text or "").strip() for sp in soft}
                                vul["soft"].append(sd)
                        elif tag == "cvss":
                            for cp in elem:
                                if cp.tag == "vector":
                                    vul["cvss"] = {
                                        "vector": (cp.text or "").strip(),
                                        "score":  cp.attrib.get("score", "N/A"),
                                    }
                        elif tag == "cvss3":
                            for cp in elem:
                                if cp.tag == "vector":
                                    vul["cvss3"] = {
                                        "vector": (cp.text or "").strip(),
                                        "score":  cp.attrib.get("score", "N/A"),
                                    }
                        elif tag == "cwe":
                            vul["cwe"] = [(c.text or "").strip() for c in elem if c.text]

                    if depth == 1:
                        # Closing tag of the vulnerability record itself
                        elem.clear()  # free memory
                        depth = 0
                        if vul is not None:
                            cve_ids_in_vul = {
                                i["value"].upper()
                                for i in vul["identifiers"]
                                if i["type"].upper() == "CVE"
                            }
                            if target in cve_ids_in_vul:
                                found = vul
                                break  # stop parsing — we found it
                        vul = None
                    else:
                        depth -= 1

            return found


def fetch_bdu(cve_id: str, session: requests.Session, timeout: int,
              force_refresh: bool = False, verbose: bool = False) -> dict:
    result = {"source": "BDU FSTEC", "cve_id": cve_id, "found": False, "error": None, "data": {}}
    try:
        _bdu_ensure_cache(session, timeout, force_refresh=force_refresh, verbose=verbose)
        raw = _bdu_find_cve(cve_id)
        if raw is None:
            result["error"] = "Not found in BDU FSTEC database"
            return result

        bdu_id  = raw.get("identifier") or "N/A"
        score3  = raw.get("cvss3", {}).get("score", "N/A") or "N/A"
        score2  = raw.get("cvss",  {}).get("score", "N/A") or "N/A"
        score   = score3 if score3 not in ("N/A", "") else score2
        sev_raw = (raw.get("severity") or "").strip().lower()
        severity = BDU_SEVERITY_MAP.get(sev_raw, _cvss_score_to_severity(score))

        cve_aliases = [
            i["value"] for i in raw.get("identifiers", [])
            if i["type"].upper() == "CVE" and i["value"]
        ]
        soft_list = [
            " ".join(filter(None, [s.get("vendor", ""), s.get("name", ""), s.get("version", "")]))
            for s in raw.get("soft", [])
        ]
        num_id = bdu_id.split(":")[-1] if ":" in bdu_id else bdu_id

        result["found"] = True
        result["data"] = {
            "bdu_id":         bdu_id,
            "severity":       severity,
            "cvss3_score":    score3,
            "cvss3_vector":   raw.get("cvss3", {}).get("vector", "N/A"),
            "cvss2_score":    score2,
            "cvss2_vector":   raw.get("cvss", {}).get("vector", "N/A"),
            "summary":        raw.get("description") or raw.get("name") or "N/A",
            "published":      raw.get("identify_date") or "N/A",
            "exploit_status": raw.get("exploit_status") or "N/A",
            "wild_exploited": raw.get("vul_incident") == "1",
            "cwe":            raw.get("cwe", []),
            "cve_aliases":    cve_aliases,
            "affected_software": soft_list,
            "remediation":    raw.get("solution") or "N/A",
            "raw_url":        f"https://bdu.fstec.ru/vul/{num_id}",
        }
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out (BDU ZIP download)"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except (ValueError, KeyError, OSError) as e:
        result["error"] = f"Parse error: {e}"
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _overall_severity(results: "list[dict]") -> str:
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
       font-size: 14px; line-height: 1.6; padding: 24px; min-width: 0; }
h1   { font-size: 1.6rem; color: #e6edf3; margin-bottom: 4px; }
h2   { font-size: 1.1rem; color: var(--accent); margin: 20px 0 10px; }
h3   { font-size: 1rem; color: #e6edf3; margin-bottom: 8px; }
a    { color: var(--accent); text-decoration: none; word-break: break-all; }
a:hover { text-decoration: underline; }

.header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
.meta   { color: var(--text-dim); font-size: 0.85rem; margin-top: 4px; }

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
}
.stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    min-width: 0;
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
    min-width: 0;
}
.cve-header {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    background: #1c2128;
}
.cve-id   { font-size: 1.1rem; font-weight: 700; font-family: var(--mono); color: #e6edf3; }
.sev-badge {
    font-size: 0.75rem; font-weight: 700; letter-spacing: .06em;
    padding: 3px 10px; border-radius: 12px; text-transform: uppercase;
    white-space: nowrap;
}

/* Панели источников — вертикальный стек, каждая на всю ширину */
.sources-grid {
    display: flex;
    flex-direction: column;
}
.source-panel {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    min-width: 0;
}
.source-panel:last-child { border-bottom: none; }

.source-name {
    font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em;
    color: var(--text-dim); margin-bottom: 10px;
    display: flex; align-items: center; gap: 6px;
}
.dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.dot-ok  { background: #3fb950; }
.dot-err { background: #f85149; }
.dot-na  { background: #6e7681; }

/* Таблица ключ-значение */
.kv-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; table-layout: fixed; }
.kv-table td { padding: 4px 0; vertical-align: top; word-break: break-word; overflow-wrap: break-word; }
.kv-table td:first-child {
    color: var(--text-dim);
    width: 130px;
    min-width: 130px;
    max-width: 130px;
    padding-right: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.kv-table td:last-child { min-width: 0; }

.tag-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 2px; }
.tag { background: #21262d; border: 1px solid var(--border); border-radius: 4px;
       font-size: 0.75rem; padding: 1px 7px; font-family: var(--mono); color: var(--text-dim);
       word-break: break-all; max-width: 100%; }
.ref-list { list-style: none; margin-top: 2px; }
.ref-list li { word-break: break-all; overflow-wrap: break-word; font-size: 0.8rem; padding: 2px 0; }
.error-msg { color: #f85149; font-size: 0.82rem; font-style: italic; }
.not-found { color: var(--text-dim); font-size: 0.82rem; }

.footer { border-top: 1px solid var(--border); margin-top: 32px; padding-top: 14px;
          color: var(--text-dim); font-size: 0.8rem; }

@media (min-width: 900px) {
    /* На широких экранах — три колонки рядом */
    .sources-grid {
        flex-direction: row;
        align-items: stretch;
    }
    .source-panel {
        flex: 1 1 0;
        min-width: 0;
        border-bottom: none;
        border-right: 1px solid var(--border);
    }
    .source-panel:last-child { border-right: none; }
}
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
    exploit_html = d.get("exploit_status") or "N/A"
    if d.get("wild_exploited"):
        exploit_html = f'<span style="color:#ff4444;font-weight:700">{exploit_html} ⚠ exploited in wild</span>'
    rows = (
        _kv("BDU ID",        d.get("bdu_id")) +
        _kv("Severity",      _sev_badge(d.get("severity", "UNKNOWN")), raw=True) +
        _kv("CVSS3 Score",   d.get("cvss3_score")) +
        _kv("CVSS3 Vector",  (d.get("cvss3_vector") or "")[:80]) +
        _kv("CVSS2 Score",   d.get("cvss2_score")) +
        _kv("Published",     d.get("published")) +
        _kv("Exploit",       exploit_html, raw=True) +
        _kv("CWE",           _tags(d.get("cwe", [])), raw=True) +
        _kv("Summary",       (d.get("summary") or "")[:300]) +
        _kv("CVE aliases",   _tags(d.get("cve_aliases", [])), raw=True) +
        _kv("Affected SW",   _tags(d.get("affected_software", [])), raw=True) +
        _kv("Remediation",   (d.get("remediation") or "")[:300])
    )
    link = d.get("raw_url", "")
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
    parser.add_argument("--bdu-refresh", action="store_true",
                        help="Force re-download of BDU FSTEC XML dump (ignores 24h cache)")
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
    all_results = {}  # type: dict[str, list[dict]]

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

    # Pre-download BDU cache once before the per-CVE loop (avoids repeated downloads)
    if not args.no_bdu:
        try:
            _bdu_ensure_cache(session, args.timeout,
                              force_refresh=args.bdu_refresh, verbose=args.verbose)
        except Exception as e:
            print(f"[!] BDU cache download failed: {e}", file=sys.stderr)

    total = len(cve_ids) * len(fetchers)
    done  = 0
    for cve_id in cve_ids:
        all_results[cve_id] = []
        for name, fn in fetchers:
            log(f"[{done+1}/{total}] {cve_id} → {name}")
            if name == "BDU FSTEC":
                # cache already warmed; pass force_refresh=False to skip re-download
                result = fn(cve_id, session, args.timeout,
                            force_refresh=False, verbose=args.verbose)
            else:
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
