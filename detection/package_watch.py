"""Watchlist for breached NPM and Python packages."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.llm import complete

logger = logging.getLogger(__name__)

WATCHLIST_PATH = Path("output/breached_packages.json")
ECOSYSTEMS = ("npm", "python")

def load_watchlist() -> dict[str, list[dict[str, str]]]:
    """Load the current watchlist of breached packages."""
    if not WATCHLIST_PATH.exists():
        return {"npm": [], "python": []}
    try:
        with WATCHLIST_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if "npm" not in data:
                data["npm"] = []
            if "python" not in data:
                data["python"] = []
            return data
    except Exception as exc:
        logger.error(f"Failed to load package watchlist: {exc}")
        return {"npm": [], "python": []}

def save_watchlist(watchlist: dict[str, list[dict[str, str]]]) -> None:
    """Save the watchlist to disk."""
    WATCHLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with WATCHLIST_PATH.open("w", encoding="utf-8") as f:
            json.dump(watchlist, f, indent=2)
    except Exception as exc:
        logger.error(f"Failed to save package watchlist: {exc}")

def extract_breached_packages(articles: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Use LLM to extract newly breached NPM and Python packages from RSS articles."""
    if not articles:
        return {"npm": [], "python": []}

    # Combine article summaries for the prompt
    articles_text = ""
    for a in articles:
        articles_text += f"- Title: {a.get('title', '')}\n  Summary: {a.get('summary', '')}\n  Link: {a.get('link', '')}\n  Date: {a.get('published', '')}\n\n"

    prompt = f"""
Analyze the following recent threat intelligence articles and identify any newly breached, malicious, or compromised NPM or Python packages mentioned.

Articles:
{articles_text}

Return a JSON object with two keys: "npm" and "python". Each key should map to a list of objects containing:
- "name": The exact name of the compromised package.
- "reason": A brief explanation of why it was flagged (e.g., "malware", "typosquatting", "compromised maintainer").
- "date_added": The date from the article (YYYY-MM-DD).
- "source_link": The link to the article.

If no packages are mentioned, return empty lists.
Respond ONLY with the JSON object. Do not include markdown formatting like ```json.
"""
    try:
        response = complete(
            prompt,
            system="You are a security analyst extracting compromised package names from threat intelligence.",
            max_tokens=2000
        )
        
        # Clean up potential markdown formatting if the LLM included it anyway
        text = response.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
            
        data = json.loads(text.strip())
        
        result = {
            "npm": data.get("npm", []),
            "python": data.get("python", [])
        }
        return result
    except Exception as exc:
        logger.error(f"Failed to extract breached packages using LLM: {exc}")
        return {"npm": [], "python": []}

def update_watchlist_from_articles(articles: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Update the persistent watchlist with newly found breached packages."""
    logger.info("Checking articles for breached NPM/Python packages...")
    new_packages = extract_breached_packages(articles)
    
    if not new_packages["npm"] and not new_packages["python"]:
        logger.info("No new breached packages found in recent articles.")
        return load_watchlist()
        
    watchlist = load_watchlist()
    added_count = 0
    
    for ecosystem in ["npm", "python"]:
        existing_names = {p["name"].lower() for p in watchlist[ecosystem]}
        for pkg in new_packages[ecosystem]:
            if pkg["name"].lower() not in existing_names:
                watchlist[ecosystem].append(pkg)
                added_count += 1
                logger.info(f"Added new breached {ecosystem} package to watchlist: {pkg['name']}")
                
    if added_count > 0:
        save_watchlist(watchlist)
        logger.info(f"Watchlist updated with {added_count} new packages.")
        
    return watchlist

def scan_for_new_packages(*, days: int = 3, limit: int = 40) -> dict[str, Any]:
    """Fetch recent RSS articles and check them for newly breached packages.

    Lighter-weight than a full digest run: no LLM digest/report generation,
    just the feed fetch + package extraction step. Intended for on-demand use
    from the workbench UI.
    """
    from shared.feeds import fetch_rss

    articles = fetch_rss(limit=limit, days=days)
    before = load_watchlist()
    before_names = {
        (eco, p["name"].lower()) for eco in ECOSYSTEMS for p in before.get(eco, [])
    }

    watchlist = update_watchlist_from_articles(articles)

    added = [
        {**p, "ecosystem": eco}
        for eco in ECOSYSTEMS
        for p in watchlist.get(eco, [])
        if (eco, p["name"].lower()) not in before_names
    ]

    return {
        "watchlist": watchlist,
        "articles_scanned": len(articles),
        "newly_added": added,
    }

def add_manual_package(
    ecosystem: str,
    name: str,
    reason: str = "",
    source_link: str = "",
) -> dict[str, list[dict[str, str]]]:
    """Manually add a package to the watchlist (e.g. from analyst knowledge)."""
    ecosystem = ecosystem.strip().lower()
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"ecosystem must be one of {ECOSYSTEMS}")
    name = name.strip()
    if not name:
        raise ValueError("name is required")

    watchlist = load_watchlist()
    existing_names = {p["name"].lower() for p in watchlist[ecosystem]}
    if name.lower() not in existing_names:
        watchlist[ecosystem].append({
            "name": name,
            "reason": reason.strip() or "Manually added",
            "date_added": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "source_link": source_link.strip(),
        })
        save_watchlist(watchlist)
        logger.info(f"Manually added {ecosystem} package to watchlist: {name}")
    return watchlist

def remove_package(ecosystem: str, name: str) -> dict[str, list[dict[str, str]]]:
    """Remove a package from the watchlist (e.g. a false positive)."""
    ecosystem = ecosystem.strip().lower()
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"ecosystem must be one of {ECOSYSTEMS}")

    watchlist = load_watchlist()
    remaining = [p for p in watchlist[ecosystem] if p["name"].lower() != name.strip().lower()]
    if len(remaining) != len(watchlist[ecosystem]):
        watchlist[ecosystem] = remaining
        save_watchlist(watchlist)
        logger.info(f"Removed {ecosystem} package from watchlist: {name}")
    return watchlist
