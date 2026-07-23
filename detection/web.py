"""Local browser workbench: daily threat digest, header analysis, OSINT, and package watchlist."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import webbrowser
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
from detection.generator import latest_digest_path


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
    body { margin: 0; background: var(--bg); color: var(--text); font-family: Segoe UI, Arial, sans-serif; }
    main { max-width: 1440px; margin: 0 auto; padding: 28px 18px 60px; }
    header { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: end; margin-bottom: 18px; }
    h1 { margin: 0; font-size: clamp(30px, 4vw, 52px); letter-spacing: 0; }
    h2 { margin: 0 0 10px; font-size: 18px; }
    p { color: var(--muted); line-height: 1.5; }
    button, select, input, textarea { font: inherit; }
    button, a.button { border: 1px solid var(--line); background: #142944; color: var(--text); border-radius: 6px; padding: 9px 11px; cursor: pointer; text-decoration: none; }
    button:hover, a.button:hover { border-color: var(--accent); }
    button.primary { background: #0f766e; border-color: #2dd4bf; color: #ecfeff; }
    button:disabled { opacity: .55; cursor: wait; }
    .status { border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; background: var(--panel2); min-height: 48px; color: var(--muted); }
    .control-grid { display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 10px; align-items: end; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; }
    select { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    .check-label { grid-template-columns: auto minmax(0, 1fr); align-items: center; padding-bottom: 9px; }
    .check-label input { width: auto; }
    .panel { border: 1px solid var(--line); border-radius: 8px; background: var(--panel); padding: 16px; min-width: 0; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
    .tab-panel--digest { display: none; margin: 0 -18px; }
    .tab-panel--digest.is-active { display: flex; flex-direction: column; }
    .digest-toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 10px 18px; border-bottom: 1px solid var(--line); background: var(--panel2); }
    .digest-toolbar label { display: flex; flex-direction: row; gap: 6px; align-items: center; color: var(--muted); font-size: 13px; margin: 0; }
    .digest-toolbar select { width: auto; padding: 6px 8px; }
    .digest-toolbar .check-label input { width: auto; }
    .status-inline { color: var(--muted); font-size: 13px; margin-left: auto; }
    .digest-frame { width: 100%; flex: 1 1 auto; border: 0; background: var(--bg); display: block; }
    .digest-empty { margin: 40px 18px; border: 1px dashed var(--line); border-radius: 8px; padding: 40px 16px; text-align: center; color: var(--muted); }
    .manual { display: grid; gap: 8px; margin-top: 12px; }
    input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    textarea { min-height: 110px; resize: vertical; }
    .tabs { display: flex; gap: 6px; margin-bottom: 16px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
    .tab-btn { border: none; border-bottom: 2px solid transparent; background: transparent; border-radius: 0; padding: 10px 4px; margin-right: 14px; color: var(--muted); font-weight: 600; }
    .tab-btn:hover { border-color: var(--line); color: var(--text); }
    .tab-btn.is-active { color: var(--text); border-bottom-color: var(--accent); }
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
    .result-block { margin-top: 10px; }
    .result-block h3 { font-size: 14px; margin: 14px 0 6px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
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
    <div>
      <h1>SecOps Workbench</h1>
      <p>The threat digest is the default landing view. Use the tabs below to switch to header analysis, OSINT lookups, or the package watchlist.</p>
    </div>
  </header>
  <nav class="tabs" role="tablist" aria-label="Workbench sections">
    <button type="button" class="tab-btn is-active" data-tab="digest" role="tab" aria-selected="true">Threat Digest</button>
    <button type="button" class="tab-btn" data-tab="header" role="tab" aria-selected="false">Header Analysis</button>
    <button type="button" class="tab-btn" data-tab="osint" role="tab" aria-selected="false">OSINT Lookup</button>
    <button type="button" class="tab-btn" data-tab="packages" role="tab" aria-selected="false">Package Watchlist</button>
  </nav>
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
</main>
<script>
var statusEl = document.getElementById("status");
var digestBtn = document.getElementById("generate-digest");
var digestFrame = document.getElementById("digest-frame");
var digestEmpty = document.getElementById("digest-empty");

function setStatus(text) { statusEl.textContent = text; }
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
    setStatus("Digest generated. Latest report: " + data.latest_html);
  } finally {
    digestBtn.disabled = false;
  }
}
digestBtn.addEventListener("click", function() { generateDigest().catch(function(e) { setStatus(e.message); digestBtn.disabled = false; }); });
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
                self._json({
                    "digest_path": str(digest) if digest else None,
                    "html_available": DIGEST_HTML_PATH.is_file(),
                })
                return
            if path == "/api/package-watchlist":
                self._json({"watchlist": load_watchlist()})
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
