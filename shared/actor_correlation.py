"""Correlate free-text (RSS headlines/summaries, digest Markdown) against the
full known threat-actor roster (MITRE ATT&CK + Microsoft Threat Intelligence).

This supersedes ad-hoc small hardcoded actor lists — every actor/alias in the
combined roster (100+) is eligible for a match, not just a handful of
financially-motivated groups.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)

# Aliases shorter than this are too likely to collide with ordinary words/acronyms
# when matched against free-text headlines, so they are dropped from the index.
_MIN_ALIAS_LEN = 4

# Real MITRE/Microsoft aliases that are still too generic for safe free-text matching
# (common English phrases, or names that overlap heavily with unrelated security terms).
_ALIAS_STOPWORDS = {
    "cutting edge",
    "money taker",
    "the shadow brokers",  # "shadow" alone is fine to exclude, this phrase stays deliberately
}


def actor_key(name: str) -> str:
    """Stable dict/slug key for an actor name (e.g. 'FIN7' -> 'fin7')."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "actor"


@lru_cache(maxsize=1)
def get_actor_alias_index() -> list[dict[str, Any]]:
    """Build a flat, de-duplicated actor/alias index from all available sources.

    Cached for the life of the process. MITRE ATT&CK data involves a one-time
    (network-fetched, then disk-cached) STIX bundle load; this index is built
    at most once per run regardless of how many articles are scanned.
    """
    actors: list[dict[str, Any]] = []
    try:
        from actor_watch.enhanced_watch import list_all_enhanced_actors

        actors = list_all_enhanced_actors()
    except Exception as exc:
        logger.warning(
            f"Could not load full MITRE+Microsoft actor list for correlation ({exc}); "
            "falling back to Microsoft threat intel only."
        )
        try:
            from shared.microsoft_intel import list_microsoft_actors

            actors = list_microsoft_actors()
        except Exception as exc2:
            logger.error(f"Actor correlation unavailable: {exc2}")
            return []

    index: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for actor in actors:
        name = str(actor.get("name") or "").strip()
        if not name or name.lower() in seen_names:
            continue
        seen_names.add(name.lower())

        raw_aliases = {name, *[str(a).strip() for a in (actor.get("aliases") or []) if str(a).strip()]}
        usable_aliases = sorted(
            (
                a
                for a in raw_aliases
                if len(a) >= _MIN_ALIAS_LEN and a.lower() not in _ALIAS_STOPWORDS
            ),
            key=len,
            reverse=True,
        )
        if not usable_aliases:
            continue

        index.append(
            {
                "name": name,
                "id": str(actor.get("id") or "").strip(),
                "source": str(actor.get("source") or "unknown"),
                "type": str(actor.get("type") or "unknown"),
                "aliases": usable_aliases,
            }
        )

    logger.info(f"Actor correlation index built: {len(index)} actors")
    return index


def find_actor_matches(text: str) -> list[dict[str, str]]:
    """Return actors whose name/alias appears as a whole word in *text* (case-insensitive)."""
    if not text:
        return []
    matches: list[dict[str, str]] = []
    for actor in get_actor_alias_index():
        for alias in actor["aliases"]:
            pattern = r"\b" + re.escape(alias) + r"\b"
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(
                    {
                        "name": actor["name"],
                        "id": actor["id"],
                        "source": actor["source"],
                        "matched_alias": alias,
                    }
                )
                break
    return matches


def correlate_articles(articles: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Attach a `related_actors` list (actor names only, deduped) to each article dict."""
    enriched: list[dict[str, Any]] = []
    for article in articles:
        text = f"{article.get('title', '')} {article.get('summary', '')}"
        matches = find_actor_matches(text)
        item = dict(article)
        item["related_actors"] = [m["name"] for m in matches]
        enriched.append(item)
    return enriched
