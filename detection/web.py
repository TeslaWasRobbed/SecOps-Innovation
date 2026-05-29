"""Local browser workbench for detection draft generation."""

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

from detection.generator import (
    DEFAULT_GUIDE,
    DEFAULT_MAX_TOKENS,
    DEFAULT_OUTPUT_DIR,
    DetectionItem,
    extract_digest_items,
    generate_rule_draft,
    latest_digest_path,
    list_detection_drafts,
)


_GENERATION_LOCK = threading.Lock()


def _item_to_dict(item: DetectionItem) -> dict[str, Any]:
    return {
        "index": item.index,
        "section": item.section,
        "title": item.title,
        "context": item.context,
        "source_path": str(item.source_path) if item.source_path else None,
    }


def _workbench_html() -> str:
    return """<!doctype html>
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
    .digest-controls { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 16px; align-items: end; margin: 16px 0; }
    .control-grid { display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 10px; align-items: end; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; }
    select { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    .check-label { grid-template-columns: auto minmax(0, 1fr); align-items: center; padding-bottom: 9px; }
    .check-label input { width: auto; }
    .layout { display: grid; grid-template-columns: minmax(280px, .95fr) minmax(0, 1.5fr); gap: 16px; align-items: start; }
    .panel { border: 1px solid var(--line); border-radius: 8px; background: var(--panel); padding: 16px; }
    .layout > *, .panel, .draft-card { min-width: 0; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
    .items { display: grid; gap: 10px; max-height: 72vh; overflow: auto; padding-right: 4px; }
    .item { text-align: left; width: 100%; background: var(--panel2); }
    .item.is-active { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(94,234,212,.25) inset; }
    .item strong { display: block; margin-bottom: 6px; }
    .item span, .meta { color: var(--muted); font-size: 13px; }
    .drafts { display: grid; gap: 12px; }
    .draft-card { border: 1px solid var(--line); background: var(--panel2); border-radius: 8px; padding: 14px; }
    .draft-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; align-items: start; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
    .chip { border: 1px solid var(--line); border-radius: 999px; padding: 3px 8px; color: var(--muted); font-size: 12px; }
    pre { width: 100%; max-width: 100%; overflow: auto; max-height: min(520px, 62vh); margin: 12px 0 0; padding: 14px; background: #06101d; border: 1px solid var(--line); border-radius: 6px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
    .manual { display: grid; gap: 8px; margin-top: 12px; }
    input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #081525; color: var(--text); padding: 9px 10px; }
    textarea { min-height: 110px; resize: vertical; }
    @media (max-width: 980px) { header, .layout, .draft-head, .digest-controls, .control-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>SecOps Workbench</h1>
      <p>Generate the latest threat digest, select items, draft disabled Sentinel analytics, then review and copy YAML.</p>
    </div>
    <div class="toolbar">
      <a class="button" href="/output/threat_digest/index.html">Digest</a>
      <a class="button" href="/output/actor_watch/index.html">Actor Watch</a>
      <a class="button" href="/output/detections/index.html">Detection Drafts</a>
    </div>
  </header>
  <div id="status" class="status">Loading latest digest items...</div>
  <section class="panel digest-controls" aria-label="Digest generation">
    <div>
      <h2>Threat Digest</h2>
      <div class="control-grid">
        <label>Look-back window
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
          <span>Feed-only mode</span>
        </label>
        <label class="check-label">
          <input id="digest-pdf" type="checkbox">
          <span>Also generate PDF</span>
        </label>
      </div>
    </div>
    <div class="toolbar">
      <button type="button" id="generate-digest" class="primary">Generate Digest</button>
      <a class="button" href="/output/threat_digest/history.html">History</a>
    </div>
  </section>
  <section class="layout" aria-label="Detection drafting workspace">
    <aside class="panel">
      <div class="toolbar">
        <button type="button" id="refresh">Refresh</button>
        <button type="button" id="generate" class="primary" disabled>Generate Draft</button>
      </div>
      <h2>Digest Items</h2>
      <div id="items" class="items"></div>
      <div class="manual">
        <h2>Manual Request</h2>
        <input id="manual-title" placeholder="Threat title">
        <textarea id="manual-context" placeholder="Context, indicators, behaviour, or source notes"></textarea>
        <button type="button" id="manual-generate">Generate Manual Draft</button>
      </div>
    </aside>
    <section class="panel">
      <div class="toolbar">
        <button type="button" id="reload-drafts">Reload Drafts</button>
      </div>
      <h2>Generated Drafts</h2>
      <div id="drafts" class="drafts"></div>
    </section>
  </section>
</main>
<script>
var state = { items: [], selected: null };
var statusEl = document.getElementById("status");
var itemsEl = document.getElementById("items");
var draftsEl = document.getElementById("drafts");
var generateBtn = document.getElementById("generate");
var digestBtn = document.getElementById("generate-digest");

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
function renderItems() {
  itemsEl.innerHTML = "";
  if (!state.items.length) {
    itemsEl.innerHTML = "<p>No detection-ready digest items found. Generate a digest first.</p>";
    return;
  }
  state.items.forEach(function(item) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "item" + (state.selected === item.index ? " is-active" : "");
    btn.innerHTML = "<strong>" + escapeHtml(item.title) + "</strong><span>" + escapeHtml(item.section) + "</span>";
    btn.addEventListener("click", function() {
      state.selected = item.index;
      generateBtn.disabled = false;
      renderItems();
    });
    itemsEl.appendChild(btn);
  });
}
function renderDrafts(drafts) {
  draftsEl.innerHTML = "";
  if (!drafts.length) {
    draftsEl.innerHTML = "<p>No drafts generated yet.</p>";
    return;
  }
  drafts.forEach(function(draft) {
    var card = document.createElement("article");
    card.className = "draft-card";
    card.innerHTML =
      "<div class='draft-head'><div><h2>" + escapeHtml(draft.name) + "</h2>" +
      "<div class='chips'><span class='chip'>" + escapeHtml(draft.status) + "</span>" +
      "<span class='chip'>" + escapeHtml(draft.severity) + "</span>" +
      "<span class='chip'>enabled: " + escapeHtml(String(draft.enabled)) + "</span>" +
      "<span class='chip'>" + escapeHtml(draft.date) + "</span></div>" +
      "<p class='meta'>" + escapeHtml(draft.path) + "</p></div>" +
      "<div><button type='button' class='copy'>Copy YAML</button></div></div>" +
      "<pre>" + escapeHtml(draft.yaml) + "</pre>";
    card.querySelector(".copy").addEventListener("click", function() {
      navigator.clipboard.writeText(draft.yaml || "");
      this.textContent = "Copied";
      var btn = this;
      setTimeout(function() { btn.textContent = "Copy YAML"; }, 1200);
    });
    draftsEl.appendChild(card);
  });
}
async function loadItems() {
  setStatus("Loading latest digest items...");
  var data = await api("/api/digest-items");
  state.items = data.items || [];
  state.selected = null;
  generateBtn.disabled = true;
  renderItems();
  setStatus(data.digest_path ? "Loaded " + state.items.length + " items from " + data.digest_path : "No digest found.");
}
async function loadDrafts() {
  var data = await api("/api/drafts");
  renderDrafts(data.drafts || []);
}
async function generate(payload) {
  setStatus("Generating detection draft. This can take a minute or two...");
  generateBtn.disabled = true;
  document.getElementById("manual-generate").disabled = true;
  try {
    var data = await api("/api/generate", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    setStatus("Saved " + data.path + " - " + data.validation_message);
    await loadDrafts();
  } finally {
    generateBtn.disabled = !state.selected;
    document.getElementById("manual-generate").disabled = false;
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
    setStatus("Digest generated. Latest report: " + data.latest_html);
    await loadItems();
  } finally {
    digestBtn.disabled = false;
  }
}
document.getElementById("refresh").addEventListener("click", function() { loadItems().catch(function(e) { setStatus(e.message); }); });
document.getElementById("reload-drafts").addEventListener("click", function() { loadDrafts().catch(function(e) { setStatus(e.message); }); });
digestBtn.addEventListener("click", function() { generateDigest().catch(function(e) { setStatus(e.message); digestBtn.disabled = false; }); });
generateBtn.addEventListener("click", function() { if (state.selected) generate({item_index: state.selected}).catch(function(e) { setStatus(e.message); }); });
document.getElementById("manual-generate").addEventListener("click", function() {
  var title = document.getElementById("manual-title").value.trim();
  var context = document.getElementById("manual-context").value.trim();
  if (!title && !context) { setStatus("Add a title or context for the manual draft."); return; }
  generate({title: title || "Manual detection request", context: context || title}).catch(function(e) { setStatus(e.message); });
});
loadItems().catch(function(e) { setStatus(e.message); });
loadDrafts().catch(function(e) { setStatus(e.message); });
</script>
</body>
</html>
"""


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
            if self.path in ("/", "/detections", "/detections/"):
                self._send(HTTPStatus.OK, _workbench_html().encode("utf-8"), "text/html; charset=utf-8")
                return
            if self.path == "/api/health":
                self._json({"status": "ok", "service": "secops-workbench"})
                return
            if self.path == "/api/digest-items":
                digest = latest_digest_path()
                items = extract_digest_items(digest) if digest else []
                self._json({"digest_path": str(digest) if digest else None, "items": [_item_to_dict(i) for i in items]})
                return
            if self.path == "/api/drafts":
                self._json({"drafts": list_detection_drafts()})
                return
            if self.path.startswith("/output/"):
                self._serve_output_file(self.path.lstrip("/"))
                return
            self._error("Not found", HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        try:
            if self.path == "/api/generate-digest":
                self._handle_generate_digest()
                return
            if self.path != "/api/generate":
                self._error("Not found", HTTPStatus.NOT_FOUND)
                return
            length = int(self.headers.get("Content-Length") or "0")
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            item = self._resolve_generation_item(payload)
            path, validation_message, yaml_text = generate_rule_draft(
                item,
                guide_path=DEFAULT_GUIDE,
                output_dir=DEFAULT_OUTPUT_DIR,
                max_tokens=DEFAULT_MAX_TOKENS,
            )
            self._json(
                {
                    "path": str(path),
                    "validation_message": validation_message,
                    "yaml": yaml_text,
                    "drafts": list_detection_drafts(),
                }
            )
        except Exception as exc:
            self._error(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

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
            items = extract_digest_items(digest) if digest else []
            self._json(
                {
                    "days": days,
                    "latest_digest": str(digest) if digest else None,
                    "latest_html": "output/threat_digest/index.html",
                    "items": [_item_to_dict(i) for i in items],
                }
            )
        finally:
            _GENERATION_LOCK.release()

    def _resolve_generation_item(self, payload: dict[str, Any]) -> DetectionItem:
        if payload.get("title") or payload.get("context"):
            title = str(payload.get("title") or "Manual detection request").strip()
            context = str(payload.get("context") or title).strip()
            return DetectionItem(index=1, section="Manual request", title=title, context=context)
        digest = latest_digest_path()
        if not digest:
            raise ValueError("No digest Markdown found. Generate a digest first.")
        items = extract_digest_items(digest)
        requested = int(payload.get("item_index") or 0)
        for item in items:
            if item.index == requested:
                return item
        raise ValueError(f"No digest item #{requested}")

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
