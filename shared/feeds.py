"""Fetch threat-intelligence data from CISA KEV and RSS feeds."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import feedparser
import requests

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_RSS_FEEDS: list[dict[str, str]] = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
]


def fetch_cisa_kev(*, limit: int = 10, days: int = 30) -> list[dict[str, Any]]:
    """Return the most recent CISA KEV entries within *days*, capped at *limit*."""
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("Failed to fetch CISA KEV: %s", exc)
        return []

    data = resp.json()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    vulns = [
        v for v in data.get("vulnerabilities", [])
        if v.get("dateAdded", "") >= cutoff
    ]
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return vulns[:limit]


def fetch_rss(
    feeds: list[dict[str, str]] | None = None,
    *,
    limit: int = 15,
    days: int = 7,
) -> list[dict[str, str]]:
    """Aggregate articles from RSS feeds, most recent first."""
    feeds = feeds or DEFAULT_RSS_FEEDS
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    articles: list[dict[str, str]] = []

    for feed_info in feeds:
        name = feed_info["name"]
        url = feed_info["url"]
        try:
            parsed = feedparser.parse(url)
        except Exception as exc:
            logger.warning("Failed to parse feed %s: %s", name, exc)
            continue

        for entry in parsed.entries:
            published = None
            for attr in ("published_parsed", "updated_parsed"):
                ts = getattr(entry, attr, None)
                if ts:
                    try:
                        published = datetime(*ts[:6], tzinfo=timezone.utc)
                    except Exception:
                        pass
                    break

            if published and published < cutoff:
                continue

            articles.append({
                "source": name,
                "title": getattr(entry, "title", "(no title)"),
                "link": getattr(entry, "link", ""),
                "published": published.strftime("%Y-%m-%d") if published else "unknown",
                "summary": getattr(entry, "summary", "")[:300],
            })

    articles.sort(key=lambda a: a["published"], reverse=True)
    return articles[:limit]
