"""Fetch threat-intelligence data from CISA KEV and RSS feeds."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import feedparser
import requests
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_RSS_FEEDS: list[dict[str, str]] = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
]

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 1.0  # Base delay in seconds
SIMILARITY_THRESHOLD = 0.8  # For duplicate detection

# Cache configuration
CACHE_DIR = Path(".cache/feeds")
CACHE_DURATION_HOURS = 1  # Cache feeds for 1 hour in development


def _retry_request(url: str, timeout: int = 30, max_retries: int = MAX_RETRIES) -> requests.Response:
    """Make HTTP request with exponential backoff retry logic."""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            logger.debug(f"Fetching {url} (attempt {attempt + 1}/{max_retries})")
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout as exc:
            last_exception = exc
            logger.warning(f"Timeout fetching {url} (attempt {attempt + 1}/{max_retries}): {exc}")
        except requests.exceptions.ConnectionError as exc:
            last_exception = exc
            logger.warning(f"Connection error fetching {url} (attempt {attempt + 1}/{max_retries}): {exc}")
        except requests.exceptions.HTTPError as exc:
            # Don't retry on client errors (4xx), only server errors (5xx)
            if exc.response and 400 <= exc.response.status_code < 500:
                logger.error(f"Client error fetching {url}: {exc}")
                raise
            last_exception = exc
            logger.warning(f"HTTP error fetching {url} (attempt {attempt + 1}/{max_retries}): {exc}")
        except requests.RequestException as exc:
            last_exception = exc
            logger.warning(f"Request error fetching {url} (attempt {attempt + 1}/{max_retries}): {exc}")
        
        if attempt < max_retries - 1:
            delay = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
            logger.debug(f"Retrying in {delay:.1f} seconds...")
            time.sleep(delay)
    
    # All retries failed
    raise last_exception or requests.RequestException(f"Failed to fetch {url} after {max_retries} attempts")


def _is_similar(title1: str, title2: str, threshold: float = SIMILARITY_THRESHOLD) -> bool:
    """Check if two article titles are similar enough to be considered duplicates."""
    if not title1 or not title2:
        return False
    
    # Normalize titles for comparison
    t1 = title1.lower().strip()
    t2 = title2.lower().strip()
    
    # Exact match
    if t1 == t2:
        return True
    
    # Use sequence matcher for fuzzy comparison
    similarity = SequenceMatcher(None, t1, t2).ratio()
    return similarity >= threshold


def _get_cache_enabled() -> bool:
    """Check if caching is enabled via environment variable."""
    return os.environ.get("FEEDS_CACHE_ENABLED", "").lower() in ("1", "true", "yes", "on")


def _get_cache_path(cache_key: str) -> Path:
    """Get cache file path for a given key."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{cache_key}.json"


def _is_cache_valid(cache_path: Path) -> bool:
    """Check if cache file exists and is within the cache duration."""
    if not cache_path.exists():
        return False
    
    try:
        mtime = cache_path.stat().st_mtime
        cache_age_hours = (time.time() - mtime) / 3600
        return cache_age_hours < CACHE_DURATION_HOURS
    except OSError:
        return False


def _load_from_cache(cache_key: str) -> Any | None:
    """Load data from cache if valid."""
    if not _get_cache_enabled():
        return None
    
    cache_path = _get_cache_path(cache_key)
    if not _is_cache_valid(cache_path):
        return None
    
    try:
        with cache_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Loaded {cache_key} from cache")
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug(f"Failed to load cache {cache_key}: {exc}")
        return None


def _save_to_cache(cache_key: str, data: Any) -> None:
    """Save data to cache."""
    if not _get_cache_enabled():
        return
    
    try:
        cache_path = _get_cache_path(cache_key)
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.debug(f"Saved {cache_key} to cache")
    except (OSError, TypeError) as exc:
        logger.debug(f"Failed to save cache {cache_key}: {exc}")


def _deduplicate_articles(articles: list[dict[str, str]]) -> list[dict[str, str]]:
    """Remove duplicate articles based on title similarity."""
    if not articles:
        return articles
    
    unique_articles = []
    seen_titles = []
    duplicates_removed = 0
    
    for article in articles:
        title = article.get("title", "")
        is_duplicate = False
        
        for seen_title in seen_titles:
            if _is_similar(title, seen_title):
                is_duplicate = True
                duplicates_removed += 1
                logger.debug(f"Removing duplicate article: '{title}' (similar to '{seen_title}')")
                break
        
        if not is_duplicate:
            unique_articles.append(article)
            seen_titles.append(title)
    
    if duplicates_removed > 0:
        logger.info(f"Removed {duplicates_removed} duplicate articles from {len(articles)} total")
    
    return unique_articles


def fetch_cisa_kev(*, limit: int = 10, days: int = 30) -> list[dict[str, Any]]:
    """Return the most recent CISA KEV entries within *days*, capped at *limit*."""
    cache_key = f"cisa_kev_{limit}_{days}"
    
    # Try cache first
    cached_data = _load_from_cache(cache_key)
    if cached_data is not None:
        logger.info(f"Using cached CISA KEV data ({len(cached_data)} entries)")
        return cached_data
    
    try:
        resp = _retry_request(CISA_KEV_URL, timeout=30)
        data = resp.json()
    except requests.RequestException as exc:
        logger.error(f"Failed to fetch CISA KEV after retries: {exc}")
        return []
    except ValueError as exc:
        logger.error(f"Failed to parse CISA KEV JSON: {exc}")
        return []

    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        vulns = [
            v for v in data.get("vulnerabilities", [])
            if v.get("dateAdded", "") >= cutoff
        ]
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        result = vulns[:limit]
        
        # Cache the result
        _save_to_cache(cache_key, result)
        
        logger.info(f"Successfully fetched {len(result)} CISA KEV entries (from {len(vulns)} within {days} days)")
        return result
        
    except Exception as exc:
        logger.error(f"Error processing CISA KEV data: {exc}")
        return []


def fetch_rss(
    feeds: list[dict[str, str]] | None = None,
    *,
    limit: int = 15,
    days: int = 7,
) -> list[dict[str, str]]:
    """Aggregate articles from RSS feeds, most recent first."""
    feeds = feeds or DEFAULT_RSS_FEEDS
    
    # Create cache key based on feed URLs and parameters
    feed_urls = sorted([f["url"] for f in feeds])
    cache_key = f"rss_{hash(str(feed_urls))}_{limit}_{days}"
    
    # Try cache first
    cached_data = _load_from_cache(cache_key)
    if cached_data is not None:
        logger.info(f"Using cached RSS data ({len(cached_data)} articles)")
        return cached_data
    
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    articles: list[dict[str, str]] = []
    successful_feeds = 0
    failed_feeds = 0

    for feed_info in feeds:
        name = feed_info["name"]
        url = feed_info["url"]
        feed_articles = []
        
        try:
            # Use feedparser with timeout and retry logic
            logger.debug(f"Parsing RSS feed: {name}")
            parsed = feedparser.parse(url)
            
            # Check if feedparser encountered errors
            if hasattr(parsed, 'bozo') and parsed.bozo:
                logger.warning(f"Feed parser warnings for {name}: {getattr(parsed, 'bozo_exception', 'Unknown')}")
            
            # Process entries
            for entry in parsed.entries:
                published = None
                for attr in ("published_parsed", "updated_parsed"):
                    ts = getattr(entry, attr, None)
                    if ts:
                        try:
                            published = datetime(*ts[:6], tzinfo=timezone.utc)
                        except Exception as exc:
                            logger.debug(f"Failed to parse timestamp for {name}: {exc}")
                        break

                # Skip old articles
                if published and published < cutoff:
                    continue

                # Extract article data
                title = getattr(entry, "title", "(no title)").strip()
                link = getattr(entry, "link", "").strip()
                summary = getattr(entry, "summary", "")[:300].strip()
                
                if not title or title == "(no title)":
                    logger.debug(f"Skipping article with no title from {name}")
                    continue

                feed_articles.append({
                    "source": name,
                    "title": title,
                    "link": link,
                    "published": published.strftime("%Y-%m-%d") if published else "unknown",
                    "summary": summary,
                })

            articles.extend(feed_articles)
            successful_feeds += 1
            logger.info(f"Successfully parsed {len(feed_articles)} articles from {name}")
            
        except Exception as exc:
            failed_feeds += 1
            logger.warning(f"Failed to parse feed {name} ({url}): {exc}")
            continue

    logger.info(f"RSS feed summary: {successful_feeds} successful, {failed_feeds} failed")
    
    # Remove duplicates before sorting and limiting
    articles = _deduplicate_articles(articles)
    
    # Sort by publication date and limit results
    articles.sort(key=lambda a: a["published"], reverse=True)
    result = articles[:limit]
    
    # Cache the result
    _save_to_cache(cache_key, result)
    
    logger.info(f"Returning {len(result)} unique articles from {len(articles)} total")
    return result
