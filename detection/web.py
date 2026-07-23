"""Local browser workbench: daily threat digest, header analysis, OSINT, and package watchlist."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from analysis.email_header import analyze_message
from analysis.osint import run_osint_lookup
from detection.package_watch import (
    add_manual_package,
    load_watchlist,
    remove_package,
    scan_for_new_packages,
)
from detection.analyst_tools import build_investigation_summary, build_siem_query, extract_indicators
from detection.generator import latest_digest_path
from shared.actor_tracking import load_tracking_data, update_actor_tracking
from shared.mitre_data import get_all_groups, get_all_techniques, get_group_by_name, get_technique_by_id


_GENERATION_LOCK = threading.Lock()

DIGEST_HTML_PATH = Path("output/threat_digest/index.html")


def _load_known_domains() -> list[str]:
    """Best-effort load of `known_domains` from the configured company profile."""
    try:
        from threat_digest.profile import load_known_domains

        return load_known_domains()
    except Exception:
        return []


def _workbench_html(known_domains: list[str] | None = None) -> str:
    html_doc = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecOps Workbench</title>
  <style>
    :root { color-scheme: dark; --bg: #07111f; --panel: #102038; --panel2: #0c182b; --line: #294263; --text: #e7f1ff; --muted: #a8b8d2; --accent: #5eead4; --warn: #f6c66b; --bad: #fb7185; }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at top left, rgba(94,234,212,.14), transparent 28%), linear-gradient(135deg, #06101d 0%, #07111f 50%, #0d1b2d 100%); color: var(--text); font-family: Segoe UI, Arial, sans-serif; }
    main { max-width: 1440px; margin: 0 auto; padding: 28px 18px 60px; }
    header { display: grid; gap: 18px; align-items: end; margin-bottom: 18px; }
    .hero { border: 1px solid rgba(94,234,212,.22); border-radius: 16px; padding: 22px; background: linear-gradient(135deg, rgba(16,32,56,.95), rgba(10,22,38,.92)); box-shadow: 0 18px 45px rgba(7,12,21,.35); }
    h1 { margin: 0; font-size: clamp(30px, 4vw, 52px); letter-spacing: 0; }
    h2 { margin: 0 0 10px; font-size: 18px; }
    p { color: var(--muted); line-height: 1.5; }
    button, select, input, textarea { font: inherit; }
    button, a.button { border: 1px solid var(--line); background: #142944; color: var(--text); border-radius: 8px; padding: 9px 11px; cursor: pointer; text-decoration: none; transition: transform .15s ease, border-color .15s ease, box-shadow .15s ease; }
    button:hover, a.button:hover { border-color: var(--accent); transform: translateY(-1px); box-shadow: 0 8px 20px rgba(7,12,21,.22); }
    button.primary { background: linear-gradient(135deg, #0f766e, #14b8a6); border-color: #2dd4bf; color: #ecfeff; }
    button:disabled { opacity: .55; cursor: wait; transform: none; box-shadow: none; }
    .status { border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; background: var(--panel2); min-height: 48px; color: var(--muted); }
    .control-grid { display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 10px; align-items: end; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; }
    select { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    .check-label { grid-template-columns: auto minmax(0, 1fr); align-items: center; padding-bottom: 9px; }
    .check-label input { width: auto; }
    .panel { border: 1px solid rgba(94,234,212,.16); border-radius: 16px; background: linear-gradient(145deg, rgba(16,32,56,.95), rgba(8,21,37,.94)); padding: 18px; min-width: 0; box-shadow: 0 14px 36px rgba(7,12,21,.24); }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
    .chip { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 5px 10px; border: 1px solid rgba(94,234,212,.22); background: rgba(94,234,212,.1); color: var(--accent); font-size: 12px; font-weight: 600; }
    .hero-stats { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
    .stat-pill { border: 1px solid rgba(94,234,212,.16); border-radius: 10px; padding: 8px 12px; background: rgba(8,21,37,.7); min-width: 110px; }
    .stat-pill strong { display: block; font-size: 18px; color: var(--text); }
    .stat-pill span { display: block; font-size: 12px; color: var(--muted); margin-top: 2px; }
    .tool-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 14px; }
    .card { border: 1px solid rgba(94,234,212,.14); border-radius: 14px; padding: 14px; background: rgba(10,20,36,.9); }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; }
    .table-shell { overflow-x: auto; }
    .compact { display: grid; gap: 8px; grid-template-columns: 1fr auto; }
    .tab-panel--digest { display: none; margin: 0 -18px; }
    .tab-panel--digest.is-active { display: flex; flex-direction: column; }
    .tab-panel--embed { display: none; }
    .tab-panel--embed.is-active { display: flex; flex-direction: column; min-height: calc(100vh - 260px); }
    .embed-toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
    .embed-frame { width: 100%; flex: 1 1 auto; min-height: 720px; border: 0; background: var(--bg); display: block; border-radius: 10px; border: 1px solid var(--line); }
    .digest-toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 10px 18px; border-bottom: 1px solid var(--line); background: var(--panel2); }
    .digest-overview { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); padding: 12px 18px 0; }
    .digest-overview .summary-pill { min-height: 84px; }
    .digest-toolbar label { display: flex; flex-direction: row; gap: 6px; align-items: center; color: var(--muted); font-size: 13px; margin: 0; }
    .digest-toolbar select { width: auto; padding: 6px 8px; }
    .digest-toolbar .check-label input { width: auto; }
    .status-inline { color: var(--muted); font-size: 13px; margin-left: auto; }
    .digest-frame { width: 100%; flex: 1 1 auto; border: 0; background: var(--bg); display: block; }
    .digest-empty { margin: 40px 18px; border: 1px dashed var(--line); border-radius: 8px; padding: 40px 16px; text-align: center; color: var(--muted); }
    .manual { display: grid; gap: 8px; margin-top: 12px; }
    input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    textarea { min-height: 110px; resize: vertical; }
    .workspace-shell { display: grid; grid-template-columns: 260px minmax(0, 1fr); gap: 16px; align-items: start; }
    .side-nav { position: sticky; top: 16px; border: 1px solid rgba(94,234,212,.16); border-radius: 14px; background: rgba(10,20,36,.9); padding: 14px; box-shadow: 0 10px 24px rgba(7,12,21,.2); }
    .nav-heading { font-size: 12px; letter-spacing: .16em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }
    .tabs { display: flex; flex-direction: column; gap: 8px; margin-bottom: 14px; }
    .tab-btn { border: 1px solid transparent; background: rgba(8,21,37,.7); border-radius: 10px; padding: 10px 12px; color: var(--muted); font-weight: 600; text-align: left; width: 100%; }
    .tab-btn:hover { border-color: var(--line); color: var(--text); }
    .tab-btn.is-active { color: var(--text); border-color: rgba(94,234,212,.35); background: rgba(94,234,212,.12); }
    .quick-actions { display: grid; gap: 8px; padding-top: 6px; border-top: 1px solid var(--line); }
    .quick-actions button { width: 100%; justify-content: center; font-size: 13px; }
    .mini-action { border: 1px solid rgba(94,234,212,.16); background: rgba(16,32,56,.92); color: var(--text); border-radius: 8px; padding: 8px 10px; cursor: pointer; }
    .mini-action:hover { border-color: var(--accent); }
    .workspace-content { min-width: 0; }
    .tab-panel { display: none; }
    .tab-panel.is-active { display: block; }
    .tab-panel--digest.is-active { display: flex; flex-direction: column; min-height: calc(100vh - 260px); }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; }
    .badge-pass { background: rgba(94,234,212,.15); color: var(--accent); }
    .badge-fail { background: rgba(251,113,133,.18); color: var(--bad); }
    .badge-none, .badge-neutral { background: rgba(168,184,210,.15); color: var(--muted); }
    .badge-warn { background: rgba(246,198,107,.18); color: var(--warn); }
    .risk-banner { border-radius: 8px; padding: 12px 14px; margin: 12px 0; font-weight: 600; }
    .risk-informational, .risk-low { background: rgba(94,234,212,.12); border: 1px solid rgba(94,234,212,.3); color: var(--accent); }
    .risk-medium { background: rgba(246,198,107,.12); border: 1px solid rgba(246,198,107,.3); color: var(--warn); }
    .risk-high { background: rgba(251,113,133,.15); border: 1px solid rgba(251,113,133,.35); color: var(--bad); }
    .hop-list { display: grid; gap: 8px; margin: 8px 0; }
    .hop-row { border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; background: var(--panel2); font-size: 13px; }
    .hop-row .meta { display: block; margin-top: 4px; }
    .ioc-chip { border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px; color: var(--text); font-size: 12px; background: #142944; cursor: pointer; }
    .ioc-chip:hover { border-color: var(--accent); }
    .result-block { margin-top: 12px; border-top: 1px solid rgba(94,234,212,.12); padding-top: 10px; }
    .investigation-summary { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin-bottom: 12px; }
    .summary-pill { border: 1px solid rgba(94,234,212,.16); border-radius: 10px; padding: 10px 12px; background: rgba(8,21,37,.8); }
    .summary-pill strong { display: block; font-size: 18px; }
    .summary-pill span { font-size: 12px; color: var(--muted); }
    .indicator-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .indicator-pill { border: 1px solid var(--line); border-radius: 999px; padding: 6px 10px; background: rgba(20,41,68,.7); color: var(--text); font-size: 12px; }
    .indicator-pill strong { color: var(--accent); }
    pre { white-space: pre-wrap; word-break: break-word; background: rgba(8,21,37,.8); border: 1px solid var(--line); border-radius: 10px; padding: 10px; font-size: 12px; line-height: 1.45; }
    .result-block h3 { font-size: 14px; margin: 14px 0 6px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
    .actor-grid { display: grid; gap: 12px; }
    .actor-card { border: 1px solid rgba(94,234,212,.14); border-radius: 12px; padding: 12px; background: rgba(8,21,37,.76); }
    .actor-card h3 { margin: 0 0 4px; font-size: 15px; }
    .actor-card p { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
    .actor-metrics { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .metric-pill { border: 1px solid rgba(94,234,212,.16); border-radius: 999px; padding: 4px 8px; background: rgba(20,41,68,.72); color: var(--muted); font-size: 12px; }
    .context-list { display: grid; gap: 8px; margin-top: 10px; }
    .context-item { border-left: 2px solid rgba(94,234,212,.3); padding-left: 8px; color: var(--muted); font-size: 12px; }
    .mitre-grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-top: 10px; }
    .mitre-card { border: 1px solid rgba(94,234,212,.14); border-radius: 12px; padding: 12px; background: rgba(8,21,37,.76); }
    .mitre-card h3 { margin: 0 0 6px; font-size: 15px; }
    .mitre-card p { margin: 6px 0 0; color: var(--muted); font-size: 13px; line-height: 1.5; }
    .inline-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .inline-chip { border: 1px solid rgba(94,234,212,.16); border-radius: 999px; padding: 4px 8px; font-size: 11px; color: var(--muted); background: rgba(20,41,68,.72); }
    .muted { color: var(--muted); }
    table.pkg-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    table.pkg-table th, table.pkg-table td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    table.pkg-table th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .03em; }
    table.pkg-table td a { color: var(--accent); }
    button.pkg-remove { padding: 4px 8px; font-size: 12px; border-color: var(--bad); color: var(--bad); }
    button.pkg-remove:hover { background: rgba(251,113,133,.12); }
    @media (max-width: 980px) { header, .digest-controls, .control-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <div class="hero">
      <h1>SecOps Workbench</h1>
      <p>The threat digest is the default landing view. Use the tabs below to switch between investigations, actor intelligence, and analyst tooling.</p>
    </div>
  </header>
  <div class="workspace-shell">
    <aside class="side-nav" aria-label="Operational shortcuts">
      <div class="nav-heading">Operator board</div>
      <nav class="tabs" role="tablist" aria-label="Workbench sections">
        <button type="button" class="tab-btn is-active" data-tab="digest" role="tab" aria-selected="true">Threat Digest</button>
        <button type="button" class="tab-btn" data-tab="header" role="tab" aria-selected="false">Header Analysis</button>
        <button type="button" class="tab-btn" data-tab="osint" role="tab" aria-selected="false">OSINT Lookup</button>
        <button type="button" class="tab-btn" data-tab="packages" role="tab" aria-selected="false">Package Watchlist</button>
        <button type="button" class="tab-btn" data-tab="actor-watch" role="tab" aria-selected="false">Actor Watch</button>
        <button type="button" class="tab-btn" data-tab="actor-tracker" role="tab" aria-selected="false">Actor Tracker</button>
        <button type="button" class="tab-btn" data-tab="mitre" role="tab" aria-selected="false">MITRE Lookup</button>
        <button type="button" class="tab-btn" data-tab="indicators" role="tab" aria-selected="false">Indicator Extractor</button>
        <button type="button" class="tab-btn" data-tab="siem" role="tab" aria-selected="false">SIEM Query Builder</button>
      </nav>
      <div class="quick-actions">
        <button type="button" class="mini-action" id="quick-generate-digest">Generate digest</button>
        <button type="button" class="mini-action" id="quick-refresh-actors">Refresh actors</button>
        <button type="button" class="mini-action" id="quick-refresh-watch">Refresh watch</button>
      </div>
    </aside>
    <div class="workspace-content">
  <div id="tab-digest" class="tab-panel is-active tab-panel--digest">
  <div class="digest-toolbar">
    <label>Look-back
      <select id="digest-days">
        <option value="1">1 day</option>
        <option value="3">3 days</option>
        <option value="7" selected>7 days</option>
        <option value="14">14 days</option>
        <option value="30">30 days</option>
      </select>
    </label>
    <label class="check-label">
      <input id="digest-no-llm" type="checkbox">
      <span>Feed-only</span>
    </label>
    <label class="check-label">
      <input id="digest-pdf" type="checkbox">
      <span>Also generate PDF</span>
    </label>
    <button type="button" id="generate-digest" class="primary">Generate Digest</button>
    <a class="button" id="digest-open-new" href="/output/threat_digest/index.html" target="_blank" rel="noopener">Open In New Tab</a>
    <span id="status" class="status-inline"></span>
  </div>
  <div id="digest-overview" class="digest-overview"></div>
  <div id="digest-empty" class="digest-empty">No digest generated yet. Choose a look-back window above and press <strong>Generate Digest</strong>.</div>
  <iframe id="digest-frame" class="digest-frame" style="display:none" title="Threat digest report"></iframe>
  </div>
  <div id="tab-header" class="tab-panel">
    <section class="panel" aria-label="Email/message header analysis">
      <h2>Header Analysis</h2>
      <p>Paste raw email headers (or a full .eml). Heuristic screening only — always confirm with the mailbox provider's own tooling before acting.</p>
      <div class="manual">
        <textarea id="header-raw" placeholder="Paste raw headers or a full .eml here..." style="min-height:220px"></textarea>
        <label>Known organisation domains (comma-separated, used for lookalike detection)
          <input id="header-known-domains" placeholder="yourcompany.com, yourcompany.co.uk">
        </label>
        <button type="button" id="header-analyze" class="primary">Analyze Headers</button>
      </div>
      <div id="header-results"></div>
    </section>
  </div>
  <div id="tab-osint" class="tab-panel">
    <section class="panel" aria-label="OSINT lookup">
      <h2>OSINT Lookup</h2>
      <p>Domain / IP: free RDAP lookup, no key needed. File hash: requires <code>VIRUSTOTAL_API_KEY</code> in <code>.env</code>. VirusTotal free tier is rate-limited to 4 lookups/minute.</p>
      <div class="manual" style="grid-template-columns: 1fr auto; display: grid; gap: 8px;">
        <input id="osint-query" placeholder="Domain, IP address, or file hash (md5/sha1/sha256)">
        <button type="button" id="osint-lookup" class="primary">Lookup</button>
      </div>
      <div id="osint-results"></div>
    </section>
  </div>
  <div id="tab-packages" class="tab-panel">
    <section class="panel" aria-label="Breached NPM and PyPI package watchlist">
      <h2>Breached Package Watchlist</h2>
      <p>Tracks NPM and Python (PyPI) packages flagged in threat-intel feeds as compromised, malicious, or typosquatted. Updated automatically whenever a digest runs, or on demand below.</p>
      <div class="toolbar">
        <button type="button" id="packages-scan" class="primary">Scan Recent Feeds Now</button>
        <button type="button" id="packages-refresh">Refresh List</button>
      </div>
      <div id="packages-status" class="status">Loading watchlist...</div>
      <div class="manual">
        <h2>Add Manually</h2>
        <div class="control-grid">
          <label>Ecosystem
            <select id="pkg-ecosystem">
              <option value="npm">npm</option>
              <option value="python">Python (PyPI)</option>
            </select>
          </label>
          <label>Package name
            <input id="pkg-name" placeholder="e.g. left-pad">
          </label>
          <label>Reason
            <input id="pkg-reason" placeholder="e.g. malicious postinstall script">
          </label>
        </div>
        <input id="pkg-source" placeholder="Source link (optional)">
        <button type="button" id="pkg-add">Add To Watchlist</button>
      </div>
      <div class="result-block">
        <h3>npm</h3>
        <div id="packages-npm"></div>
      </div>
      <div class="result-block">
        <h3>Python (PyPI)</h3>
        <div id="packages-python"></div>
      </div>
    </section>
  </div>
  <div id="tab-actor-watch" class="tab-panel tab-panel--embed">
    <section class="panel" aria-label="Actor watch dashboard">
      <div class="embed-toolbar">
        <h2 style="margin: 0;">Actor Watch</h2>
        <button type="button" id="actor-watch-refresh" class="primary">Refresh</button>
        <a class="button" href="/output/actor_watch/index.html" target="_blank" rel="noopener">Open In New Tab</a>
      </div>
      <p>Browse the generated actor catalogue without leaving the workbench.</p>
      <iframe id="actor-watch-frame" class="embed-frame" title="Actor watch dashboard" src="/output/actor_watch/index.html"></iframe>
    </section>
  </div>
  <div id="tab-actor-tracker" class="tab-panel">
    <section class="panel" aria-label="Actor tracker">
      <h2>Actor Tracker</h2>
      <p>Spot actor trends across the latest digests and see where they reappear.</p>
      <div class="hero-stats" id="analyst-summary"></div>
      <div class="toolbar">
        <input id="actor-search" placeholder="Filter actors by name or alias">
        <button type="button" id="actor-filter-btn">Filter</button>
        <button type="button" id="actors-refresh" class="primary">Refresh Actor Tracking</button>
      </div>
      <div id="actor-tracker-results" class="table-shell"></div>
    </section>
  </div>
  <div id="tab-mitre" class="tab-panel">
    <section class="panel" aria-label="MITRE ATT&CK lookup">
      <h2>MITRE ATT&CK Lookup</h2>
      <p>Search groups, aliases, and techniques to map suspicious activity to ATT&CK.</p>
      <div class="compact">
        <input id="mitre-query" placeholder="Search group, alias, or technique ID">
        <button type="button" id="mitre-search" class="primary">Search</button>
      </div>
      <div class="chips" style="margin-top:10px">
        <button type="button" class="chip mitre-example" data-query="APT29">APT29</button>
        <button type="button" class="chip mitre-example" data-query="Wizard Spider">Wizard Spider</button>
        <button type="button" class="chip mitre-example" data-query="T1566">T1566</button>
        <button type="button" class="chip mitre-example" data-query="Credential Access">Credential Access</button>
      </div>
      <div id="mitre-results" class="result-block"></div>
    </section>
  </div>
  <div id="tab-indicators" class="tab-panel">
    <section class="panel" aria-label="Indicator extractor">
      <h2>Indicator Extractor</h2>
      <p>Paste an email, report excerpt, or chat message to turn it into structured IOCs.</p>
      <textarea id="investigation-text" placeholder="Paste an email, report excerpt, or chat message..." style="min-height:140px"></textarea>
      <div class="toolbar" style="margin-top:10px">
        <button type="button" id="extract-indicators" class="primary">Extract Indicators</button>
      </div>
      <div id="indicator-results" class="result-block"></div>
      <div id="investigation-summary" class="result-block"></div>
    </section>
  </div>
  <div id="tab-siem" class="tab-panel">
    <section class="panel" aria-label="SIEM query builder">
      <h2>SIEM Query Builder</h2>
      <p>Turn extracted indicators into ready-to-use hunting queries for common SIEM platforms.</p>
      <div id="query-results" class="result-block"></div>
    </section>
  </div>
    </div>
  </div>
</main>
<script>
var statusEl = document.getElementById("status");
var digestBtn = document.getElementById("generate-digest");
var digestFrame = document.getElementById("digest-frame");
var digestEmpty = document.getElementById("digest-empty");
var digestOverview = document.getElementById("digest-overview");

function setStatus(text) { statusEl.textContent = text; }
function renderDigestOverview(data) {
  if (!digestOverview) return;
  var lookback = document.getElementById("digest-days").value;
  var feedOnly = document.getElementById("digest-no-llm").checked ? "Feed-only" : "Full feed";
  var statusText = data && data.html_available ? "Ready" : "Pending";
  var updatedText = data && data.generated_at ? new Date(data.generated_at).toLocaleString() : "Not generated yet";
  digestOverview.innerHTML = [
    "<div class='summary-pill'><strong>" + escapeHtml(statusText) + "</strong><span>Digest status</span></div>",
    "<div class='summary-pill'><strong>" + escapeHtml(lookback + "d") + "</strong><span>Current look-back</span></div>",
    "<div class='summary-pill'><strong>" + escapeHtml(feedOnly) + "</strong><span>Generation mode</span></div>",
    "<div class='summary-pill'><strong>" + escapeHtml(updatedText) + "</strong><span>Last update</span></div>"
  ].join("");
}
function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function(c) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c];
  });
}
async function api(path, options) {
  var res = await fetch(path, options || {});
  var data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || res.statusText);
  return data;
}
function showDigestFrame() {
  digestEmpty.style.display = "none";
  digestFrame.style.display = "block";
  digestFrame.src = "/output/threat_digest/index.html?t=" + Date.now();
}
async function loadDigestStatus() {
  setStatus("Loading latest digest...");
  try {
    var data = await api("/api/digest-status");
    renderDigestOverview(data);
    if (data.html_available) {
      showDigestFrame();
      setStatus("Loaded existing digest" + (data.digest_path ? " (" + data.digest_path + ")" : "") + ".");
    } else {
      setStatus("No digest generated yet.");
    }
  } catch (e) {
    setStatus(e.message);
  }
}
async function generateDigest() {
  var days = parseInt(document.getElementById("digest-days").value || "7", 10);
  var noLlm = document.getElementById("digest-no-llm").checked;
  var pdf = document.getElementById("digest-pdf").checked;
  setStatus("Generating threat digest for the last " + days + " day(s). This can take a few minutes...");
  digestBtn.disabled = true;
  try {
    var data = await api("/api/generate-digest", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({days: days, no_llm: noLlm, pdf: pdf})
    });
    showDigestFrame();
    renderDigestOverview({html_available: true, generated_at: new Date().toISOString(), digest_path: data.latest_digest || null});
    setStatus("Digest generated. Latest report: " + data.latest_html);
  } finally {
    digestBtn.disabled = false;
  }
}
digestBtn.addEventListener("click", function() { generateDigest().catch(function(e) { setStatus(e.message); digestBtn.disabled = false; }); });
document.getElementById("quick-generate-digest").addEventListener("click", function() {
  activateTab("digest");
  generateDigest().catch(function(e) { setStatus(e.message); digestBtn.disabled = false; });
});
document.getElementById("quick-refresh-actors").addEventListener("click", function() {
  activateTab("actor-tracker");
  refreshActorTracker();
});
document.getElementById("quick-refresh-watch").addEventListener("click", function() {
  activateTab("actor-watch");
  refreshActorWatch();
});
loadDigestStatus();

// --- Tabs -------------------------------------------------------------
document.querySelectorAll(".tab-btn").forEach(function(btn) {
  btn.addEventListener("click", function() {
    var tab = btn.getAttribute("data-tab");
    document.querySelectorAll(".tab-btn").forEach(function(b) {
      b.classList.toggle("is-active", b === btn);
      b.setAttribute("aria-selected", b === btn ? "true" : "false");
    });
    document.querySelectorAll(".tab-panel").forEach(function(p) {
      p.classList.toggle("is-active", p.id === "tab-" + tab);
    });
  });
});
function activateTab(tab) {
  var btn = document.querySelector(".tab-btn[data-tab='" + tab + "']");
  if (btn) btn.click();
}
activateTab("digest");

// --- Header Analysis ----------------------------------------------------
var KNOWN_DOMAINS = __KNOWN_DOMAINS_JSON__;
document.getElementById("header-known-domains").value = KNOWN_DOMAINS.join(", ");

function sevBadgeClass(v) {
  v = (v || "").toLowerCase();
  if (v === "pass") return "badge-pass";
  if (v === "fail") return "badge-fail";
  if (v === "none" || v === "neutral") return "badge-none";
  return "badge-warn";
}
function riskClass(level) { return "risk-" + (level || "informational").toLowerCase(); }

function renderIocChips(list, containerEl) {
  containerEl.innerHTML = "";
  (list || []).forEach(function(value) {
    var chip = document.createElement("button");
    chip.type = "button";
    chip.className = "ioc-chip";
    chip.textContent = value;
    chip.addEventListener("click", function() {
      activateTab("osint");
      runOsintLookup(value);
    });
    containerEl.appendChild(chip);
  });
}

function renderHeaderResults(result) {
  var el = document.getElementById("header-results");
  el.innerHTML = "";

  var risk = result.risk || {};
  var banner = document.createElement("div");
  banner.className = "risk-banner " + riskClass(risk.level);
  banner.textContent = "Heuristic risk: " + (risk.level || "Informational") + " (score " + (risk.score || 0) + ")";
  el.appendChild(banner);

  (result.warnings || []).forEach(function(w) {
    var p = document.createElement("p");
    p.textContent = "Note: " + w;
    el.appendChild(p);
  });

  var auth = result.authentication || {};
  var authBlock = document.createElement("div");
  authBlock.className = "result-block";
  authBlock.innerHTML = "<h3>Authentication</h3>" +
    "<span class='badge " + sevBadgeClass(auth.spf) + "'>SPF: " + escapeHtml(auth.spf || "none") + "</span> " +
    "<span class='badge " + sevBadgeClass(auth.dkim) + "'>DKIM: " + escapeHtml(auth.dkim || "none") + "</span> " +
    "<span class='badge " + sevBadgeClass(auth.dmarc) + "'>DMARC: " + escapeHtml(auth.dmarc || "none") + "</span>";
  el.appendChild(authBlock);

  var h = result.headers || {};
  var fromDisplay = h.from ? ((h.from.name ? h.from.name + " " : "") + "<" + (h.from.address || "") + ">") : "-";
  var headersBlock = document.createElement("div");
  headersBlock.className = "result-block";
  headersBlock.innerHTML = "<h3>Headers</h3>" +
    "<p><strong>From:</strong> " + escapeHtml(fromDisplay) + "</p>" +
    "<p><strong>Reply-To:</strong> " + escapeHtml((h.reply_to && h.reply_to.address) || "-") + "</p>" +
    "<p><strong>Return-Path:</strong> " + escapeHtml(h.return_path || "-") + "</p>" +
    "<p><strong>Subject:</strong> " + escapeHtml(h.subject || "-") + "</p>" +
    "<p><strong>Date:</strong> " + escapeHtml(h.date || "-") + "</p>";
  el.appendChild(headersBlock);

  if ((result.spoofing_signals || []).length) {
    var spoofBlock = document.createElement("div");
    spoofBlock.className = "result-block";
    var lis = result.spoofing_signals.map(function(s) {
      return "<li><span class='badge " + (s.severity === "high" ? "badge-fail" : "badge-warn") + "'>" + escapeHtml(s.severity) + "</span> " + escapeHtml(s.detail) + "</li>";
    }).join("");
    spoofBlock.innerHTML = "<h3>Spoofing signals</h3><ul>" + lis + "</ul>";
    el.appendChild(spoofBlock);
  }

  if ((result.hops || []).length) {
    var hopsBlock = document.createElement("div");
    hopsBlock.className = "result-block";
    var hopRows = result.hops.map(function(hop) {
      var flagText = (hop.flags || []).length ? " &mdash; " + hop.flags.join("; ") : "";
      return "<div class='hop-row'>#" + hop.index + " from <strong>" + escapeHtml(hop.from || "?") + "</strong> by <strong>" + escapeHtml(hop.by || "?") + "</strong>" +
        "<span class='meta'>" + escapeHtml(hop.date || "unknown date") + flagText + "</span></div>";
    }).join("");
    hopsBlock.innerHTML = "<h3>Hop timeline</h3><div class='hop-list'>" + hopRows + "</div>";
    el.appendChild(hopsBlock);
  }

  var iocs = result.iocs || {};
  var iocBlock = document.createElement("div");
  iocBlock.className = "result-block";
  iocBlock.innerHTML = "<h3>Extracted indicators (click to look up)</h3>";
  var chipWrap = document.createElement("div");
  chipWrap.className = "chips";
  iocBlock.appendChild(chipWrap);
  el.appendChild(iocBlock);
  var allIocs = [].concat(iocs.domains || [], (iocs.ips || []).map(function(i) { return i.value; }));
  renderIocChips(allIocs, chipWrap);
}

document.getElementById("header-analyze").addEventListener("click", function() {
  var raw = document.getElementById("header-raw").value;
  var resultsEl = document.getElementById("header-results");
  if (!raw.trim()) { resultsEl.innerHTML = "<p>Paste headers first.</p>"; return; }
  var domains = document.getElementById("header-known-domains").value.split(",").map(function(d) { return d.trim(); }).filter(Boolean);
  var btn = this;
  btn.disabled = true;
  resultsEl.innerHTML = "<p>Analyzing...</p>";
  api("/api/header-analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({raw: raw, known_domains: domains})
  }).then(renderHeaderResults).catch(function(e) {
    resultsEl.innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
  }).finally(function() { btn.disabled = false; });
});

// --- OSINT Lookup --------------------------------------------------------
function renderOsintResults(result) {
  var el = document.getElementById("osint-results");
  el.innerHTML = "";

  var header = document.createElement("p");
  header.innerHTML = "<strong>" + escapeHtml(result.query) + "</strong> (" + escapeHtml(result.type) + ")";
  el.appendChild(header);

  var rdap = result.rdap || {};
  var rdapBlock = document.createElement("div");
  rdapBlock.className = "result-block";
  if (rdap.available) {
    var rows = Object.keys(rdap).filter(function(k) { return k !== "available" && k !== "events"; })
      .map(function(k) {
        var v = rdap[k];
        var text = Array.isArray(v) ? v.join(", ") : (v == null || v === "" ? "-" : String(v));
        return "<p><strong>" + escapeHtml(k) + ":</strong> " + escapeHtml(text) + "</p>";
      }).join("");
    rdapBlock.innerHTML = "<h3>RDAP</h3>" + rows;
  } else {
    rdapBlock.innerHTML = "<h3>RDAP</h3><p>" + escapeHtml(rdap.error || "Not available.") + "</p>";
  }
  el.appendChild(rdapBlock);

  var vt = result.virustotal || {};
  var vtBlock = document.createElement("div");
  vtBlock.className = "result-block";
  if (vt.available) {
    vtBlock.innerHTML = "<h3>VirusTotal</h3>" +
      "<p><span class='badge " + (vt.malicious > 0 ? "badge-fail" : "badge-pass") + "'>Malicious: " + vt.malicious + "</span> " +
      "<span class='badge badge-warn'>Suspicious: " + vt.suspicious + "</span> " +
      "<span class='badge badge-pass'>Harmless: " + vt.harmless + "</span></p>" +
      "<p><a href='" + escapeHtml(vt.link || "#") + "' target='_blank' rel='noopener'>Open in VirusTotal</a></p>";
  } else {
    vtBlock.innerHTML = "<h3>VirusTotal</h3><p>" + escapeHtml(vt.error || "Not available.") + "</p>";
  }
  el.appendChild(vtBlock);
}
function runOsintLookup(query) {
  document.getElementById("osint-query").value = query;
  var el = document.getElementById("osint-results");
  el.innerHTML = "<p>Looking up " + escapeHtml(query) + "...</p>";
  return api("/api/osint-lookup", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({query: query})
  }).then(renderOsintResults).catch(function(e) {
    el.innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
  });
}
document.getElementById("osint-lookup").addEventListener("click", function() {
  var q = document.getElementById("osint-query").value.trim();
  if (q) runOsintLookup(q);
});

// --- Package Watchlist --------------------------------------------------
function renderPackageTable(ecosystem, packages) {
  var el = document.getElementById("packages-" + ecosystem);
  if (!packages || !packages.length) {
    el.innerHTML = "<p>No " + ecosystem + " packages on the watchlist yet.</p>";
    return;
  }
  var rows = packages.map(function(p) {
    var link = p.source_link ? "<a href='" + escapeHtml(p.source_link) + "' target='_blank' rel='noopener'>source</a>" : "-";
    return "<tr><td><strong>" + escapeHtml(p.name) + "</strong></td>" +
      "<td>" + escapeHtml(p.reason || "-") + "</td>" +
      "<td>" + escapeHtml(p.date_added || "-") + "</td>" +
      "<td>" + link + "</td>" +
      "<td><button type='button' class='pkg-remove' data-ecosystem='" + ecosystem + "' data-name='" + escapeHtml(p.name) + "'>Remove</button></td></tr>";
  }).join("");
  el.innerHTML = "<table class='pkg-table'><thead><tr><th>Name</th><th>Reason</th><th>Date added</th><th>Source</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>";
  el.querySelectorAll(".pkg-remove").forEach(function(btn) {
    btn.addEventListener("click", function() {
      removePackage(btn.getAttribute("data-ecosystem"), btn.getAttribute("data-name"));
    });
  });
}
function renderWatchlist(watchlist) {
  renderPackageTable("npm", watchlist.npm || []);
  renderPackageTable("python", watchlist.python || []);
}
function setPackagesStatus(text) { document.getElementById("packages-status").textContent = text; }
async function loadWatchlist() {
  setPackagesStatus("Loading watchlist...");
  var data = await api("/api/package-watchlist");
  renderWatchlist(data.watchlist || {npm: [], python: []});
  var total = (data.watchlist.npm || []).length + (data.watchlist.python || []).length;
  setPackagesStatus(total + " package(s) on the watchlist.");
}
async function scanForPackages() {
  var btn = document.getElementById("packages-scan");
  btn.disabled = true;
  setPackagesStatus("Scanning recent feeds for newly breached packages. This can take a minute...");
  try {
    var data = await api("/api/package-watchlist/scan", {method: "POST"});
    renderWatchlist(data.watchlist || {npm: [], python: []});
    var added = data.newly_added || [];
    setPackagesStatus("Scanned " + data.articles_scanned + " article(s). " +
      (added.length ? "Added " + added.length + " new package(s): " + added.map(function(p) { return p.name; }).join(", ") + "." : "No new packages found."));
  } catch (e) {
    setPackagesStatus(e.message);
  } finally {
    btn.disabled = false;
  }
}
async function addPackageManually() {
  var ecosystem = document.getElementById("pkg-ecosystem").value;
  var name = document.getElementById("pkg-name").value.trim();
  var reason = document.getElementById("pkg-reason").value.trim();
  var source = document.getElementById("pkg-source").value.trim();
  if (!name) { setPackagesStatus("Enter a package name first."); return; }
  try {
    var data = await api("/api/package-watchlist/add", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ecosystem: ecosystem, name: name, reason: reason, source_link: source})
    });
    renderWatchlist(data.watchlist || {npm: [], python: []});
    document.getElementById("pkg-name").value = "";
    document.getElementById("pkg-reason").value = "";
    document.getElementById("pkg-source").value = "";
    setPackagesStatus("Added " + name + " to the " + ecosystem + " watchlist.");
  } catch (e) {
    setPackagesStatus(e.message);
  }
}
async function removePackage(ecosystem, name) {
  try {
    var data = await api("/api/package-watchlist/remove", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ecosystem: ecosystem, name: name})
    });
    renderWatchlist(data.watchlist || {npm: [], python: []});
    setPackagesStatus("Removed " + name + " from the " + ecosystem + " watchlist.");
  } catch (e) {
    setPackagesStatus(e.message);
  }
}
document.getElementById("packages-scan").addEventListener("click", function() { scanForPackages(); });
document.getElementById("packages-refresh").addEventListener("click", function() { loadWatchlist().catch(function(e) { setPackagesStatus(e.message); }); });
document.getElementById("pkg-add").addEventListener("click", function() { addPackageManually(); });
loadWatchlist().catch(function(e) { setPackagesStatus(e.message); });

// --- Analyst Toolkit ----------------------------------------------------
var actorWatchFrame = document.getElementById("actor-watch-frame");
function refreshActorWatch() {
  if (actorWatchFrame) {
    actorWatchFrame.src = "/output/actor_watch/index.html?t=" + Date.now();
  }
}
if (document.getElementById("actor-watch-refresh")) {
  document.getElementById("actor-watch-refresh").addEventListener("click", function() { refreshActorWatch(); });
}
function renderAnalystSummary(data) {
  var el = document.getElementById("analyst-summary");
  var totalActors = data.total_actors || 0;
  var totalMentions = data.total_mentions || 0;
  var totalDigests = data.total_digests || 0;
  el.innerHTML = "<div class='stat-pill'><strong>" + totalActors + "</strong><span>actors seen</span></div>" +
    "<div class='stat-pill'><strong>" + totalMentions + "</strong><span>mentions</span></div>" +
    "<div class='stat-pill'><strong>" + totalDigests + "</strong><span>digests scanned</span></div>";
}
function renderActorTracker(data) {
  var el = document.getElementById("actor-tracker-results");
  var searchTerm = (document.getElementById("actor-search")?.value || "").trim().toLowerCase();
  var actors = Object.values(data.actors || {}).filter(function(actor) { return (actor.total_mentions || 0) > 0; })
    .filter(function(actor) {
      if (!searchTerm) return true;
      var haystack = [actor.name, actor.id, ...(actor.aliases || [])].join(" ").toLowerCase();
      return haystack.indexOf(searchTerm) !== -1;
    })
    .sort(function(a, b) { return (b.total_mentions || 0) - (a.total_mentions || 0); })
    .slice(0, 12);
  renderAnalystSummary({
    total_actors: actors.length,
    total_mentions: actors.reduce(function(sum, actor) { return sum + (actor.total_mentions || 0); }, 0),
    total_digests: data.total_digests_scanned || 0
  });
  if (!actors.length) {
    el.innerHTML = "<p>No actor mentions found yet. Generate a digest to populate the tracker.</p>";
    return;
  }
  var cards = actors.map(function(actor) {
    var recentContexts = (actor.recent_contexts || []).slice(0, 2);
    return "<article class='actor-card'><div class='card-header' style='margin-bottom: 6px;'><h3>" + escapeHtml(actor.name) + "</h3><span class='chip'>" + escapeHtml(actor.type || "Actor") + "</span></div>" +
      (actor.id ? "<div class='muted'>" + escapeHtml(actor.id) + "</div>" : "") +
      "<div class='actor-metrics'><span class='metric-pill'>Mentions: " + (actor.total_mentions || 0) + "</span><span class='metric-pill'>Digests: " + (actor.digest_appearances || 0) + "</span><span class='metric-pill'>Last seen: " + escapeHtml(actor.last_seen || "-") + "</span></div>" +
      (recentContexts.length ? "<div class='context-list'>" + recentContexts.map(function(item) {
        return "<div class='context-item'><strong>" + escapeHtml(item.alias_used || "Mention") + "</strong> — " + escapeHtml((item.context || "").slice(0, 140)) + "</div>";
      }).join("") + "</div>" : "") +
      "</article>";
  }).join("");
  el.innerHTML = "<div class='actor-grid'>" + cards + "</div>";
}
async function loadActorTracker() {
  try {
    var data = await api("/api/actor-tracking-data");
    renderActorTracker(data);
  } catch (e) {
    document.getElementById("actor-tracker-results").innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
  }
}
async function refreshActorTracker() {
  try {
    var data = await api("/api/actor-tracking/refresh", {method: "POST"});
    renderActorTracker(data);
  } catch (e) {
    document.getElementById("actor-tracker-results").innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
  }
}
function renderInvestigationSummary(summary) {
  var el = document.getElementById("investigation-summary");
  if (!summary || !summary.total_indicators) {
    el.innerHTML = "";
    return;
  }
  var byType = summary.by_type || {};
  var cards = [
    "<div class='summary-pill'><strong>" + summary.total_indicators + "</strong><span>Total indicators</span></div>",
    "<div class='summary-pill'><strong>" + (byType.domain || 0) + "</strong><span>Domains</span></div>",
    "<div class='summary-pill'><strong>" + (byType.ip || 0) + "</strong><span>IPs</span></div>",
    "<div class='summary-pill'><strong>" + (byType.hash || 0) + "</strong><span>Hashes</span></div>"
  ].join("");
  el.innerHTML = "<div class='investigation-summary'>" + cards + "</div>" +
    "<div class='result-block'><h3>Recommended actions</h3><ul>" +
    (summary.recommended_actions || []).map(function(action) { return "<li>" + escapeHtml(action) + "</li>"; }).join("") +
    "</ul></div>";
}
function renderMitreResults(result) {
  var el = document.getElementById("mitre-results");
  el.innerHTML = "";
  if (result.error) {
    el.innerHTML = "<p>" + escapeHtml(result.error) + "</p>";
    return;
  }
  var groups = result.groups || [];
  var techniques = result.techniques || [];
  if (!groups.length && !techniques.length) {
    el.innerHTML = "<p>No matching ATT&CK data found.</p>";
    return;
  }
  var html = [];
  html.push("<div class='investigation-summary'><div class='summary-pill'><strong>" + groups.length + "</strong><span>Groups</span></div><div class='summary-pill'><strong>" + techniques.length + "</strong><span>Techniques</span></div></div>");
  if (groups.length) {
    html.push("<div class='mitre-grid'>");
    groups.forEach(function(group) {
      var aliases = (group.aliases || []).slice(0, 4);
      html.push("<article class='mitre-card'><h3>" + escapeHtml(group.name) + "</h3><div class='muted'>" + escapeHtml(group.id || "No ATT&CK ID") + "</div><p>" + escapeHtml((group.description || "No description available.").slice(0, 180)) + "</p>" + (aliases.length ? "<div class='inline-list'>" + aliases.map(function(alias) { return "<span class='inline-chip'>" + escapeHtml(alias) + "</span>"; }).join("") + "</div>" : "") + "</article>");
    });
    html.push("</div>");
  }
  if (techniques.length) {
    html.push("<div class='mitre-grid'>");
    techniques.forEach(function(tech) {
      var tactics = (tech.tactics || []).slice(0, 4);
      html.push("<article class='mitre-card'><h3>" + escapeHtml(tech.id) + " " + escapeHtml(tech.name) + "</h3><p>" + escapeHtml((tech.description || "No description available.").slice(0, 180)) + "</p>" + (tactics.length ? "<div class='inline-list'>" + tactics.map(function(tactic) { return "<span class='inline-chip'>" + escapeHtml(tactic) + "</span>"; }).join("") + "</div>" : "") + "</article>");
    });
    html.push("</div>");
  }
  el.innerHTML = html.join("");
}
async function runMitreSearch(query) {
  var el = document.getElementById("mitre-results");
  el.innerHTML = "<p>Searching ATT&CK...</p>";
  try {
    var data = await api("/api/mitre-search", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({query: query})
    });
    renderMitreResults(data);
  } catch (e) {
    el.innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
  }
}
document.getElementById("actors-refresh").addEventListener("click", function() { refreshActorTracker(); });
document.getElementById("actor-filter-btn").addEventListener("click", function() { loadActorTracker().catch(function(e) { document.getElementById("actor-tracker-results").innerHTML = "<p>" + escapeHtml(e.message) + "</p>"; }); });
document.getElementById("actor-search").addEventListener("keydown", function(e) {
  if (e.key === "Enter") {
    e.preventDefault();
    loadActorTracker().catch(function(err) { document.getElementById("actor-tracker-results").innerHTML = "<p>" + escapeHtml(err.message) + "</p>"; });
  }
});
document.getElementById("mitre-search").addEventListener("click", function() {
  var q = document.getElementById("mitre-query").value.trim();
  if (q) runMitreSearch(q);
});
document.getElementById("mitre-query").addEventListener("keydown", function(e) {
  if (e.key === "Enter") {
    e.preventDefault();
    var q = document.getElementById("mitre-query").value.trim();
    if (q) runMitreSearch(q);
  }
});
document.querySelectorAll(".mitre-example").forEach(function(btn) {
  btn.addEventListener("click", function() {
    var q = btn.getAttribute("data-query");
    document.getElementById("mitre-query").value = q;
    runMitreSearch(q);
  });
});
document.getElementById("extract-indicators").addEventListener("click", function() {
  var text = document.getElementById("investigation-text").value;
  var indicatorEl = document.getElementById("indicator-results");
  var queryEl = document.getElementById("query-results");
  if (!text.trim()) { indicatorEl.innerHTML = "<p>Paste some evidence first.</p>"; queryEl.innerHTML = ""; return; }
  indicatorEl.innerHTML = "<p>Extracting indicators...</p>";
  queryEl.innerHTML = "<p>Building query templates...</p>";
  api("/api/analyst-tools", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({text: text})
  }).then(function(data) {
    var indicators = data.indicators || [];
    var summary = data.summary || {};
    if (!indicators.length) {
      indicatorEl.innerHTML = "<p>No obvious indicators were found.</p>";
      renderInvestigationSummary({});
      queryEl.innerHTML = "";
      return;
    }
    var items = indicators.map(function(item) {
      return "<span class='indicator-pill'><strong>" + escapeHtml(item.type) + "</strong> " + escapeHtml(item.value) + "</span>";
    }).join("");
    indicatorEl.innerHTML = "<div class='indicator-list'>" + items + "</div>";
    renderInvestigationSummary(summary);
    var queries = data.queries || {};
    queryEl.innerHTML = "<div class='result-block'><h3>Splunk</h3><pre>" + escapeHtml(queries.splunk || "") + "</pre></div>" +
      "<div class='result-block'><h3>Elastic</h3><pre>" + escapeHtml(queries.elastic || "") + "</pre></div>" +
      "<div class='result-block'><h3>Microsoft Sentinel</h3><pre>" + escapeHtml(queries.sentinel || "") + "</pre></div>";
  }).catch(function(e) {
    indicatorEl.innerHTML = "<p>" + escapeHtml(e.message) + "</p>";
    renderInvestigationSummary({});
    queryEl.innerHTML = "";
  });
});
loadActorTracker().catch(function(e) { document.getElementById("actor-tracker-results").innerHTML = "<p>" + escapeHtml(e.message) + "</p>"; });
</script>
</body>
</html>
"""
    return html_doc.replace("__KNOWN_DOMAINS_JSON__", json.dumps(known_domains or []))


class DetectionWorkbenchHandler(BaseHTTPRequestHandler):
    server_version = "DetectionWorkbench/1.0"

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(status, json.dumps(payload, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        self._json({"error": message}, status)

    def do_GET(self) -> None:
        try:
            path = urlsplit(self.path).path
            if path in ("/", "/detections", "/detections/"):
                self._send(HTTPStatus.OK, _workbench_html(_load_known_domains()).encode("utf-8"), "text/html; charset=utf-8")
                return
            if path == "/api/health":
                self._json({"status": "ok", "service": "secops-workbench"})
                return
            if path == "/api/digest-status":
                digest = latest_digest_path()
                generated_at = None
                if DIGEST_HTML_PATH.is_file():
                    generated_at = datetime.fromtimestamp(DIGEST_HTML_PATH.stat().st_mtime, tz=timezone.utc).isoformat()
                self._json({
                    "digest_path": str(digest) if digest else None,
                    "html_available": DIGEST_HTML_PATH.is_file(),
                    "generated_at": generated_at,
                })
                return
            if path == "/api/package-watchlist":
                self._json({"watchlist": load_watchlist()})
                return
            if path == "/api/actor-tracking-data":
                self._json(load_tracking_data())
                return
            if path == "/api/analyst-tools":
                self._json(self._handle_analyst_tools())
                return
            if path.startswith("/output/"):
                self._serve_output_file(path.lstrip("/"))
                return
            self._error("Not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        try:
            path = urlsplit(self.path).path
            if path == "/api/generate-digest":
                self._handle_generate_digest()
                return
            if path == "/api/header-analyze":
                self._handle_header_analyze()
                return
            if path == "/api/osint-lookup":
                self._handle_osint_lookup()
                return
            if path == "/api/package-watchlist/scan":
                self._handle_package_scan()
                return
            if path == "/api/package-watchlist/add":
                self._handle_package_add()
                return
            if path == "/api/package-watchlist/remove":
                self._handle_package_remove()
                return
            if path == "/api/actor-tracking/refresh":
                self._handle_actor_tracking_refresh()
                return
            if path == "/api/mitre-search":
                self._handle_mitre_search()
                return
            if path == "/api/analyst-tools":
                self._handle_analyst_tools_post()
                return
            self._error("Not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_header_analyze(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        raw = str(payload.get("raw") or "")
        if not raw.strip():
            self._error("No header/message text provided.")
            return
        known_domains = payload.get("known_domains")
        if not isinstance(known_domains, list) or not known_domains:
            known_domains = _load_known_domains()
        result = analyze_message(raw, known_domains=known_domains)
        self._json(result)

    def _handle_osint_lookup(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        query = str(payload.get("query") or "").strip()
        if not query:
            self._error("No query provided.")
            return
        self._json(run_osint_lookup(query))

    def _handle_package_scan(self) -> None:
        if not _GENERATION_LOCK.acquire(blocking=False):
            self._error("A generation job is already running. Wait for it to finish.", HTTPStatus.CONFLICT)
            return
        try:
            result = scan_for_new_packages()
            self._json(result)
        finally:
            _GENERATION_LOCK.release()

    def _handle_package_add(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        try:
            watchlist = add_manual_package(
                ecosystem=str(payload.get("ecosystem") or ""),
                name=str(payload.get("name") or ""),
                reason=str(payload.get("reason") or ""),
                source_link=str(payload.get("source_link") or ""),
            )
        except ValueError as exc:
            self._error(str(exc))
            return
        self._json({"watchlist": watchlist})

    def _handle_package_remove(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        try:
            watchlist = remove_package(
                ecosystem=str(payload.get("ecosystem") or ""),
                name=str(payload.get("name") or ""),
            )
        except ValueError as exc:
            self._error(str(exc))
            return
        self._json({"watchlist": watchlist})

    def _handle_actor_tracking_refresh(self) -> None:
        data = update_actor_tracking()
        self._json(data)

    def _handle_mitre_search(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        query = str(payload.get("query") or "").strip()
        if not query:
            self._error("No MITRE query provided.")
            return
        q = query.lower()
        groups = [g for g in get_all_groups() if q in g["name"].lower() or any(q in alias.lower() for alias in g.get("aliases", [])) or q in g.get("id", "").lower()]
        techniques = [t for t in get_all_techniques() if q in t["name"].lower() or q in t["id"].lower() or any(q in item.lower() for item in t.get("tactics", []))]
        self._json({"groups": groups[:8], "techniques": techniques[:8]})

    def _handle_analyst_tools(self) -> dict[str, Any]:
        return {"status": "ok"}

    def _handle_analyst_tools_post(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        text = str(payload.get("text") or "").strip()
        if not text:
            self._error("No evidence text provided.")
            return
        indicators = extract_indicators(text)
        query = build_siem_query(indicators)
        summary = build_investigation_summary(indicators)
        self._json({"indicators": indicators, "queries": query, "summary": summary})

    def _handle_generate_digest(self) -> None:
        if not _GENERATION_LOCK.acquire(blocking=False):
            self._error("A generation job is already running. Wait for it to finish.", HTTPStatus.CONFLICT)
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            days = int(payload.get("days") or 7)
            days = max(1, min(days, 30))
            no_llm = bool(payload.get("no_llm"))
            pdf = bool(payload.get("pdf"))

            from threat_digest.__main__ import main as digest_main

            args = ["--days", str(days), "--output-dir", "output/threat_digest"]
            if no_llm:
                args.append("--no-llm")
            if pdf:
                args.append("--pdf")
            exit_code = digest_main(args)
            if exit_code != 0:
                raise RuntimeError(f"Digest generation failed with exit code {exit_code}.")
            digest = latest_digest_path()
            self._json(
                {
                    "days": days,
                    "latest_digest": str(digest) if digest else None,
                    "latest_html": "output/threat_digest/index.html",
                }
            )
        finally:
            _GENERATION_LOCK.release()

    def _serve_output_file(self, requested: str) -> None:
        path = Path(requested).resolve()
        output_root = Path("output").resolve()
        if output_root not in path.parents and path != output_root:
            self._error("Invalid output path", HTTPStatus.FORBIDDEN)
            return
        if not path.is_file():
            self._error("File not found", HTTPStatus.NOT_FOUND)
            return
        suffix = path.suffix.lower()
        content_type = "text/html; charset=utf-8" if suffix == ".html" else "text/plain; charset=utf-8"
        self._send(HTTPStatus.OK, path.read_bytes(), content_type)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[detection-web] " + fmt % args + "\n")


def run_server(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), DetectionWorkbenchHandler)
    url = f"http://{host}:{port}/"
    print(f"Detection Workbench running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Detection Workbench.")
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local Detection Workbench web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8765, help="Bind port")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_server(host=args.host, port=args.port, open_browser=not args.no_open)
    return 0
