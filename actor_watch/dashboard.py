"""Static Actor Watch dashboard generation."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actor_watch.enhanced_watch import list_all_enhanced_actors
from shared.actor_tracking import load_tracking_data
from shared.mitre_data import get_software_used_by_group, get_techniques_used_by_group


SECTOR_KEYWORDS = {
    "Financial Services": ("financial", "bank", "payment", "fintech", "insurance"),
    "Government": ("government", "diplomatic", "election", "public sector"),
    "Healthcare": ("healthcare", "hospital", "medical", "pharma"),
    "Technology": ("technology", "software", "telecom", "cloud", "it "),
    "Energy": ("energy", "oil", "gas", "electric"),
    "Defense": ("defense", "military", "aerospace"),
    "Retail": ("retail", "hospitality", "restaurant", "pos", "e-commerce"),
    "Education": ("education", "university", "research"),
    "Critical Infrastructure": ("critical infrastructure", "water", "transport"),
}

ATTACK_KEYWORDS = {
    "Phishing": ("phishing", "spearphishing", "malicious attachment", "malicious link"),
    "Credential Theft": ("credential", "password", "token theft", "mfa", "lsass"),
    "Ransomware": ("ransomware", "extortion", "encrypted for impact"),
    "Lateral Movement": ("lateral", "remote desktop", "rdp", "wmi", "smb"),
    "Persistence": ("persistence", "registry run", "startup", "scheduled task"),
    "Exfiltration": ("exfiltration", "collection", "data theft", "steal"),
    "Supply Chain": ("supply chain", "dependency", "package", "vendor"),
    "Exploit Public-Facing App": ("public-facing", "web shell", "exploit", "rce"),
    "Living off the Land": ("living off", "powershell", "built-in windows", "lolbin"),
}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "actor"


def _source_label(source: str) -> str:
    if source == "mitre_attack":
        return "MITRE ATT&CK"
    if source == "microsoft":
        return "Microsoft Threat Intel"
    return source.replace("_", " ").title() if source else "Open Source"


def _tracking_for(actor: dict[str, Any], tracking: dict[str, Any]) -> dict[str, Any] | None:
    actors = tracking.get("actors", {})
    names = {
        str(actor.get("name", "")).lower(),
        str(actor.get("id", "")).lower(),
        *(str(alias).lower() for alias in actor.get("aliases", []) or []),
    }
    names.discard("")
    for tracked in actors.values():
        tracked_names = {
            str(tracked.get("name", "")).lower(),
            str(tracked.get("id", "")).lower(),
            *(str(alias).lower() for alias in tracked.get("aliases", []) or []),
        }
        if names.intersection(tracked_names):
            return tracked
    return None


def _text_blob(actor: dict[str, Any]) -> str:
    parts: list[str] = [
        str(actor.get("name", "")),
        str(actor.get("id", "")),
        str(actor.get("description", "")),
        str(actor.get("type", "")),
        " ".join(str(alias) for alias in actor.get("aliases", []) or []),
        " ".join(str(sector) for sector in actor.get("sectors", []) or []),
    ]
    for technique in actor.get("techniques", []) or []:
        if isinstance(technique, dict):
            parts.extend(str(technique.get(k, "")) for k in ("id", "name", "tactic"))
        else:
            parts.append(str(technique))
    return " ".join(parts).lower()


def _clean_description(text: str) -> str:
    """Convert ATT&CK markdown-ish descriptions into readable plain text."""
    cleaned = str(text or "")
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"\(Citation:[^)]+\)", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _hydrate_actor(actor: dict[str, Any]) -> dict[str, Any]:
    """Add full MITRE relationship data when the list view only has counts."""
    if actor.get("source") != "mitre_attack" or not actor.get("stix_id"):
        return actor
    hydrated = dict(actor)
    hydrated["techniques"] = get_techniques_used_by_group(str(actor["stix_id"]))
    hydrated["software"] = get_software_used_by_group(str(actor["stix_id"]))
    return hydrated


def _derive_motivation(actor: dict[str, Any]) -> str:
    actor_type = str(actor.get("type", "")).replace("_", " ").lower()
    blob = _text_blob(actor)
    if "financial" in actor_type or "financial" in blob or "ransomware" in blob:
        return "Financial"
    if "nation" in actor_type or "espionage" in blob or "sponsored" in blob:
        return "Nation State"
    if "hacktiv" in blob:
        return "Hacktivist"
    if "crime" in blob or "criminal" in blob:
        return "Cybercrime"
    return "Unknown"


def _derive_sectors(actor: dict[str, Any]) -> list[str]:
    explicit = [
        str(sector).replace("_", " ").title()
        for sector in actor.get("sectors", []) or []
        if str(sector).strip()
    ]
    found = set(explicit)
    blob = _text_blob(actor)
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(keyword in blob for keyword in keywords):
            found.add(sector)
    return sorted(found) or ["Unknown"]


def _derive_attack_types(actor: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    blob = _text_blob(actor)
    for attack_type, keywords in ATTACK_KEYWORDS.items():
        if any(keyword in blob for keyword in keywords):
            found.add(attack_type)
    if not found and actor.get("technique_count"):
        found.add("Mapped TTPs")
    return sorted(found) or ["Unknown"]


def _technique_summary(actor: dict[str, Any]) -> tuple[int, list[str]]:
    techniques = actor.get("techniques") or []
    if isinstance(techniques, list) and techniques:
        labels: list[str] = []
        for technique in techniques[:80]:
            if isinstance(technique, dict):
                tech_id = str(technique.get("id") or "").strip()
                name = str(technique.get("name") or "").strip()
                labels.append(f"{tech_id} {name}".strip())
            else:
                labels.append(str(technique).replace("_", " ").title())
        return len(techniques), labels
    count = actor.get("technique_count")
    try:
        return int(count or 0), []
    except (TypeError, ValueError):
        return 0, []


def _actor_records(actors: list[dict[str, Any]], tracking: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_actor in actors:
        actor = _hydrate_actor(raw_actor)
        tracked = _tracking_for(actor, tracking) or {}
        technique_count, technique_labels = _technique_summary(actor)
        aliases = [str(alias) for alias in actor.get("aliases", []) or [] if str(alias).strip()]
        sectors = _derive_sectors(actor)
        attack_types = _derive_attack_types(actor)
        source_key = str(actor.get("source", "unknown") or "unknown")
        name = str(actor.get("name") or "Unknown Actor")
        actor_id = str(actor.get("id") or actor.get("microsoft_id") or "")
        actor_type = str(actor.get("type") or "unknown").replace("_", " ").title()
        description = _clean_description(str(actor.get("description") or ""))
        mentions = int(tracked.get("total_mentions", 0) or 0)
        appearances = int(tracked.get("digest_appearances", 0) or 0)
        recent_contexts = tracked.get("recent_contexts") or []

        records.append(
            {
                "key": _slug(actor_id or name),
                "name": name,
                "id": actor_id,
                "aliases": aliases,
                "source": _source_label(source_key),
                "sourceKey": source_key,
                "type": actor_type,
                "motivation": _derive_motivation(actor),
                "sectors": sectors,
                "attackTypes": attack_types,
                "description": description,
                "techniqueCount": technique_count,
                "techniques": technique_labels,
                "tools": [
                    f"{tool.get('id', '')} {tool.get('name', '')}".strip()
                    if isinstance(tool, dict)
                    else str(tool)
                    for tool in actor.get("tools", []) or actor.get("software", []) or []
                ],
                "mentions": mentions,
                "reports": appearances,
                "firstSeen": tracked.get("first_seen") or "",
                "lastSeen": tracked.get("last_seen") or "",
                "recentContexts": recent_contexts[:5],
                "search": " ".join(
                    [
                        name,
                        actor_id,
                        actor_type,
                        _source_label(source_key),
                        " ".join(aliases),
                        " ".join(sectors),
                        " ".join(attack_types),
                        description,
                    ]
                ).lower(),
            }
        )
    return sorted(records, key=lambda item: item["name"].lower())


def _json_for_script(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def generate_actor_dashboard(output_path: str | Path = "output/actor_watch/index.html", days: int = 30) -> Path:
    """Generate an interactive static actor catalogue."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    tracking = load_tracking_data()
    records = _actor_records(list_all_enhanced_actors(), tracking)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tracked_mentions = sum(record["mentions"] for record in records)
    tracked_actors = sum(1 for record in records if record["mentions"] > 0)
    source_count = len({record["source"] for record in records})
    sectors = sorted({sector for record in records for sector in record["sectors"]})
    motivations = sorted({record["motivation"] for record in records})
    attack_types = sorted({attack for record in records for attack in record["attackTypes"]})
    sources = sorted({record["source"] for record in records})

    payload = {
        "actors": records,
        "filters": {
            "sources": sources,
            "motivations": motivations,
            "sectors": sectors,
            "attackTypes": attack_types,
        },
        "summary": {
            "actors": len(records),
            "sources": source_count,
            "trackedActors": tracked_actors,
            "mentions": tracked_mentions,
            "digests": tracking.get("total_digests_scanned", 0),
            "generated": generated,
        },
    }

    template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Actor Watch</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07101d;
      --panel: #101b2d;
      --panel-2: #17243a;
      --panel-3: #1d2c45;
      --border: rgba(164, 181, 206, 0.18);
      --border-strong: rgba(164, 181, 206, 0.34);
      --text: #edf4ff;
      --muted: #b8c7dc;
      --soft: #d8e6f8;
      --accent: #5eead4;
      --accent-2: #93c5fd;
      --warn: #fbbf24;
      --danger: #fb7185;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 15% 0%, rgba(94, 234, 212, 0.12), transparent 28rem),
        radial-gradient(circle at 85% 12%, rgba(147, 197, 253, 0.10), transparent 26rem),
        var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main { width: min(1500px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 56px; }
    header { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: end; margin-bottom: 22px; }
    h1 { margin: 0; font-size: clamp(1.8rem, 4vw, 3.1rem); line-height: 1.05; }
    .lede { margin: 10px 0 0; color: var(--muted); max-width: 880px; line-height: 1.55; }
    .nav { display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
    .nav a, button, select, input {
      font: inherit;
    }
    .nav a {
      color: var(--text);
      border: 1px solid var(--border);
      background: rgba(16, 27, 45, 0.9);
      text-decoration: none;
      padding: 10px 13px;
      border-radius: 6px;
      font-weight: 700;
    }
    .summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin: 22px 0; }
    .stat, .filters, .actor-card, .drawer {
      border: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(16, 27, 45, 0.96), rgba(13, 24, 40, 0.96));
      border-radius: 8px;
    }
    .stat { padding: 16px; }
    .stat strong { display: block; font-size: 1.7rem; overflow-wrap: anywhere; }
    .stat span { color: var(--muted); font-size: 0.86rem; }
    .filters { padding: 14px; margin-bottom: 16px; position: sticky; top: 0; z-index: 5; backdrop-filter: blur(16px); }
    .filter-grid { display: grid; grid-template-columns: minmax(220px, 1.7fr) repeat(5, minmax(150px, 1fr)); gap: 10px; }
    input, select {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      border-radius: 6px;
      padding: 0 12px;
    }
    .filter-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; color: var(--muted); }
    .clear-btn {
      border: 1px solid var(--border);
      color: var(--text);
      background: var(--panel-2);
      border-radius: 6px;
      min-height: 38px;
      padding: 0 12px;
      cursor: pointer;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 14px; }
    .actor-card { padding: 18px; cursor: pointer; transition: border-color 0.15s, transform 0.15s, background 0.15s; scroll-margin-top: 96px; }
    .actor-card:hover { border-color: var(--border-strong); transform: translateY(-2px); background: var(--panel); }
    .actor-card__top { display: flex; justify-content: space-between; gap: 14px; align-items: start; }
    .actor-card h2 { margin: 0 0 5px; font-size: 1.15rem; }
    .muted { color: var(--muted); }
    .aliases { margin: 0; color: var(--soft); line-height: 1.45; min-height: 40px; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border-radius: 999px;
      background: var(--panel-3);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 0.74rem;
      font-weight: 750;
      white-space: nowrap;
    }
    .pill-source { color: #05211d; background: var(--accent); border-color: transparent; }
    .pill-hot { color: #2a1600; background: var(--warn); border-color: transparent; }
    .description { margin: 13px 0 0; color: var(--soft); line-height: 1.6; min-height: 78px; }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 14px 0; }
    .metrics span { background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 9px; min-width: 0; }
    .metrics strong { display: block; font-size: 1rem; overflow-wrap: anywhere; }
    .metrics small { color: var(--muted); font-size: 0.72rem; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
    .empty { display: none; border: 1px dashed var(--border); border-radius: 8px; padding: 28px; color: var(--muted); text-align: center; }
    .drawer-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.42);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.18s;
      z-index: 20;
    }
    .drawer {
      position: fixed;
      top: 0;
      right: 0;
      width: min(620px, 100vw);
      height: 100vh;
      overflow: auto;
      border-radius: 0;
      border-top: 0;
      border-right: 0;
      border-bottom: 0;
      transform: translateX(100%);
      transition: transform 0.22s;
      z-index: 21;
      padding: 22px;
      background: #0d1828;
      box-shadow: -28px 0 80px rgba(0, 0, 0, 0.45);
    }
    body.drawer-open .drawer-backdrop { opacity: 1; pointer-events: auto; }
    body.drawer-open .drawer { transform: translateX(0); }
    .drawer-header { display: flex; align-items: start; justify-content: space-between; gap: 14px; margin-bottom: 18px; }
    .drawer h2 { margin: 0 0 6px; font-size: 1.55rem; }
    .close-btn {
      border: 1px solid var(--border);
      background: var(--panel-2);
      color: var(--text);
      border-radius: 6px;
      min-width: 40px;
      min-height: 40px;
      cursor: pointer;
    }
    .drawer-section { margin-top: 18px; }
    .drawer-section h3 { margin: 0 0 8px; font-size: 0.92rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.06em; }
    .list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
    .list li { background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 10px; color: var(--soft); line-height: 1.45; }
    @media (max-width: 1100px) {
      .filter-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      header { grid-template-columns: 1fr; }
      .nav { justify-content: start; }
    }
    @media (max-width: 720px) {
      main { width: min(100vw - 20px, 1500px); padding-top: 18px; }
      .filter-grid, .summary, .grid { grid-template-columns: 1fr; }
      .filters { position: static; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Actor Watch</h1>
        <p class="lede">Interactive threat actor catalogue from MITRE ATT&CK and Microsoft threat intelligence, overlaid with actor mentions found across generated digest reports.</p>
      </div>
      <nav class="nav">
        <a href="../threat_digest/index.html">Latest Digest</a>
        <a href="../threat_digest/history.html">Digest History</a>
        <a href="../detections/index.html">Detection Drafts</a>
      </nav>
    </header>

    <section class="summary">
      <div class="stat"><strong id="stat-visible">0</strong><span>Visible actors</span></div>
      <div class="stat"><strong id="stat-total">0</strong><span>Total indexed</span></div>
      <div class="stat"><strong id="stat-sources">0</strong><span>Sources</span></div>
      <div class="stat"><strong id="stat-tracked">0</strong><span>Actors in digests</span></div>
      <div class="stat"><strong id="stat-mentions">0</strong><span>Total mentions</span></div>
    </section>

    <section class="filters" aria-label="Actor filters">
      <div class="filter-grid">
        <input id="search" type="search" placeholder="Search actor, alias, TTP, sector, source">
        <select id="source-filter"><option value="">All sources</option></select>
        <select id="motivation-filter"><option value="">All motivations</option></select>
        <select id="sector-filter"><option value="">All sectors</option></select>
        <select id="attack-filter"><option value="">All attack types</option></select>
        <select id="sort-mode">
          <option value="name">Sort: name</option>
          <option value="mentions">Sort: digest mentions</option>
          <option value="ttps">Sort: TTP count</option>
          <option value="lastSeen">Sort: last seen</option>
        </select>
      </div>
      <div class="filter-footer">
        <span id="result-count">0 actors</span>
        <button class="clear-btn" id="clear-filters" type="button">Clear filters</button>
      </div>
    </section>

    <section class="grid" id="actor-grid"></section>
    <div class="empty" id="empty-state">No actors match the current filters.</div>
  </main>

  <div class="drawer-backdrop" id="drawer-backdrop"></div>
  <aside class="drawer" id="drawer" aria-label="Actor details"></aside>

  <script id="actor-data" type="application/json">__ACTOR_DATA__</script>
  <script>
    const payload = JSON.parse(document.getElementById('actor-data').textContent);
    const actors = payload.actors;
    const filters = payload.filters;
    const summary = payload.summary;
    const grid = document.getElementById('actor-grid');
    const emptyState = document.getElementById('empty-state');
    const resultCount = document.getElementById('result-count');
    const controls = {
      search: document.getElementById('search'),
      source: document.getElementById('source-filter'),
      motivation: document.getElementById('motivation-filter'),
      sector: document.getElementById('sector-filter'),
      attack: document.getElementById('attack-filter'),
      sort: document.getElementById('sort-mode')
    };

    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      })[ch]);
    }

    function populateSelect(select, values) {
      values.forEach(value => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      });
    }

    populateSelect(controls.source, filters.sources);
    populateSelect(controls.motivation, filters.motivations);
    populateSelect(controls.sector, filters.sectors);
    populateSelect(controls.attack, filters.attackTypes);

    document.getElementById('stat-total').textContent = summary.actors;
    document.getElementById('stat-sources').textContent = summary.sources;
    document.getElementById('stat-tracked').textContent = summary.trackedActors;
    document.getElementById('stat-mentions').textContent = summary.mentions;

    function actorMatches(actor) {
      const q = controls.search.value.trim().toLowerCase();
      if (q && !actor.search.includes(q)) return false;
      if (controls.source.value && actor.source !== controls.source.value) return false;
      if (controls.motivation.value && actor.motivation !== controls.motivation.value) return false;
      if (controls.sector.value && !actor.sectors.includes(controls.sector.value)) return false;
      if (controls.attack.value && !actor.attackTypes.includes(controls.attack.value)) return false;
      return true;
    }

    function sortedActors(items) {
      const mode = controls.sort.value;
      return [...items].sort((a, b) => {
        if (mode === 'mentions') return (b.mentions - a.mentions) || a.name.localeCompare(b.name);
        if (mode === 'ttps') return (b.techniqueCount - a.techniqueCount) || a.name.localeCompare(b.name);
        if (mode === 'lastSeen') return String(b.lastSeen).localeCompare(String(a.lastSeen)) || a.name.localeCompare(b.name);
        return a.name.localeCompare(b.name);
      });
    }

    function chips(values, limit = 4) {
      return values.slice(0, limit).map(value => `<span class="pill">${esc(value)}</span>`).join('');
    }

    function renderCard(actor) {
      const hot = actor.mentions > 0 ? `<span class="pill pill-hot">${actor.mentions} digest mentions</span>` : '';
      const aliases = actor.aliases.length ? actor.aliases.slice(0, 4).join(', ') : 'No aliases listed';
      const desc = actor.description || 'No description available.';
      return `
        <article class="actor-card" id="${esc(actor.key)}" data-key="${esc(actor.key)}" tabindex="0">
          <div class="actor-card__top">
            <div>
              <h2>${esc(actor.name)}</h2>
              <p class="aliases">${esc(aliases)}</p>
            </div>
            <span class="pill pill-source">${esc(actor.source)}</span>
          </div>
          <p class="description">${esc(desc.length > 230 ? desc.slice(0, 227).trim() + '...' : desc)}</p>
          <div class="metrics">
            <span><strong>${actor.techniqueCount}</strong><small>TTPs</small></span>
            <span><strong>${actor.mentions}</strong><small>Mentions</small></span>
            <span><strong>${actor.reports}</strong><small>Reports</small></span>
            <span><strong>${esc(actor.lastSeen || '-')}</strong><small>Last seen</small></span>
          </div>
          <div class="chips">
            <span class="pill">${esc(actor.motivation)}</span>
            ${hot}
            ${chips(actor.sectors, 2)}
            ${chips(actor.attackTypes, 2)}
          </div>
        </article>
      `;
    }

    function applyFilters() {
      const visible = sortedActors(actors.filter(actorMatches));
      grid.innerHTML = visible.map(renderCard).join('');
      emptyState.style.display = visible.length ? 'none' : 'block';
      resultCount.textContent = `${visible.length} actor${visible.length === 1 ? '' : 's'}`;
      document.getElementById('stat-visible').textContent = visible.length;
    }

    Object.values(controls).forEach(control => control.addEventListener('input', applyFilters));
    document.getElementById('clear-filters').addEventListener('click', () => {
      controls.search.value = '';
      controls.source.value = '';
      controls.motivation.value = '';
      controls.sector.value = '';
      controls.attack.value = '';
      controls.sort.value = 'name';
      applyFilters();
    });

    function renderList(values) {
      if (!values || !values.length) return '<li>No data recorded.</li>';
      return values.map(value => `<li>${esc(value)}</li>`).join('');
    }

    function openDrawer(actor) {
      const drawer = document.getElementById('drawer');
      drawer.innerHTML = `
        <div class="drawer-header">
          <div>
            <h2>${esc(actor.name)}</h2>
            <div class="chips">
              <span class="pill pill-source">${esc(actor.source)}</span>
              <span class="pill">${esc(actor.motivation)}</span>
              <span class="pill">${esc(actor.type)}</span>
            </div>
          </div>
          <button class="close-btn" type="button" id="drawer-close">x</button>
        </div>
        <p class="description">${esc(actor.description || 'No description available.')}</p>
        <div class="metrics">
          <span><strong>${actor.techniqueCount}</strong><small>TTPs</small></span>
          <span><strong>${actor.mentions}</strong><small>Mentions</small></span>
          <span><strong>${actor.reports}</strong><small>Reports</small></span>
          <span><strong>${esc(actor.lastSeen || '-')}</strong><small>Last seen</small></span>
        </div>
        <section class="drawer-section"><h3>Aliases</h3><ul class="list">${renderList(actor.aliases)}</ul></section>
        <section class="drawer-section"><h3>Sectors</h3><div class="chips">${chips(actor.sectors, 20)}</div></section>
        <section class="drawer-section"><h3>Attack Types</h3><div class="chips">${chips(actor.attackTypes, 20)}</div></section>
        <section class="drawer-section"><h3>Techniques</h3><ul class="list">${renderList(actor.techniques)}</ul></section>
        <section class="drawer-section"><h3>Tools</h3><ul class="list">${renderList(actor.tools)}</ul></section>
        <section class="drawer-section"><h3>Digest Context</h3><ul class="list">${
          actor.recentContexts.length
            ? actor.recentContexts.map(ctx => `<li><strong>${esc(ctx.date || '')}</strong>: ${esc(ctx.context || '')}</li>`).join('')
            : '<li>No mentions in generated digests yet.</li>'
        }</ul></section>
      `;
      document.body.classList.add('drawer-open');
      document.getElementById('drawer-close').addEventListener('click', closeDrawer);
    }

    function closeDrawer() {
      document.body.classList.remove('drawer-open');
    }

    grid.addEventListener('click', event => {
      const card = event.target.closest('.actor-card');
      if (!card) return;
      const actor = actors.find(item => item.key === card.dataset.key);
      if (actor) openDrawer(actor);
    });
    grid.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const card = event.target.closest('.actor-card');
      if (!card) return;
      event.preventDefault();
      const actor = actors.find(item => item.key === card.dataset.key);
      if (actor) openDrawer(actor);
    });
    document.getElementById('drawer-backdrop').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') closeDrawer();
    });

    applyFilters();

    if (location.hash) {
      const wanted = location.hash.slice(1).toLowerCase();
      const match = actors.find(actor => actor.key === wanted || actor.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') === wanted);
      if (match) {
        controls.search.value = match.name;
        applyFilters();
        setTimeout(() => document.getElementById(match.key)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50);
      }
    }
  </script>
</body>
</html>
"""

    html_doc = template.replace("__ACTOR_DATA__", _json_for_script(payload))
    output.write_text(html_doc, encoding="utf-8")
    return output
