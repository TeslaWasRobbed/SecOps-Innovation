"""Core logic for building and summarising a threat digest."""

from __future__ import annotations

import logging
import os
from typing import Any

from shared.feeds import fetch_cisa_kev, fetch_rss
from shared.llm import complete
from threat_digest.digest_payload import (
    DIGEST_JSON_SCHEMA_INSTRUCTIONS,
    normalize_digest_payload,
    parse_digest_json,
    payload_to_markdown,
)
from threat_digest.profile import profile_to_prompt_block

logger = logging.getLogger(__name__)

# Reasoning-style Azure deployments often need a large budget; profile text increases prompt size.
_DEFAULT_DIGEST_COMPLETION_TOKENS = 16384


def _format_kevs(kevs: list[dict[str, Any]]) -> str:
    if not kevs:
        return "No new CISA KEV entries in the selected period."
    lines = []
    for v in kevs:
        lines.append(
            f"- **{v.get('cveID', 'N/A')}** — {v.get('vendorProject', '?')} "
            f"{v.get('product', '?')}: {v.get('vulnerabilityName', '')} "
            f"(added {v.get('dateAdded', '?')}, due {v.get('dueDate', '?')})"
        )
    return "\n".join(lines)


def _format_articles(articles: list[dict[str, str]]) -> str:
    if not articles:
        return "No recent articles from RSS feeds."
    lines = []
    for a in articles:
        actor_note = ""
        related = a.get("related_actors")
        if related:
            actor_note = f" — **Related actor(s): {', '.join(related)}**"
        lines.append(f"- [{a['title']}]({a['link']}) — *{a['source']}*, {a['published']}{actor_note}")
    return "\n".join(lines)


DIGEST_SYSTEM_BASE = (
    "You are a threat-intelligence analyst writing a weekly digest for a CISO and "
    "non-technical leadership. Be concise, use bullet points, and highlight actions."
)

DIGEST_SYSTEM_TAILORED = (
    "You are given an organisation profile (sector, tooling, priorities). "
    "Explicitly relate KEV entries and headlines to their environment where credible — "
    "e.g. call out products they use, sector-relevant regulation, or themes they care about. "
    "Do not invent facts about their estate; stay grounded in the feeds. "
    "When relevance is weak, say so briefly and give general best practice."
)

DIGEST_SYSTEM_JSON = (
    DIGEST_SYSTEM_BASE
    + " Respond with one JSON object only, as specified in the user message — no preamble or markdown outside the JSON."
)

# Assembled with string concatenation so feed text with "{" / "}" cannot break formatting.
DIGEST_PROMPT_PREFIX = """\
Summarise the following raw intelligence into a stakeholder-friendly threat digest.
Your entire reply must be the JSON object specified below (no prose before or after it).

## Organisation context (use this to tailor tone and priorities)

"""

DIGEST_PROMPT_MIDDLE = """

Structure your response as Markdown with these sections.
Use **scannable bullets** and short paragraphs under each heading (avoid long unbroken prose).

For each vulnerability in **Key Vulnerabilities** and each story cluster in **Notable Campaigns & Incidents**, use **three separate list items** (not one bullet with everything run together):
1) Title / one-line summary.
2) A line starting with **Why it matters:** (bold label) and the explanation.
3) **Actions** as either ``- **Actions:**`` followed by **indented** sub-bullets (two spaces before each ``-``) so steps nest under Actions, **or** a line that is only **Actions** with the next bullets each on their own top-level list line (the HTML exporter can merge those).

Never emit action steps as separate top-level bullets **without** nesting or an **Actions** header line directly above them — that breaks the briefing layout.

Include **severity** where relevant (**Critical** / **High** / **Medium**) in the title or first sentence so badges render.

Some headlines below are annotated with **Related actor(s): Name** — this was matched against the MITRE ATT&CK / Microsoft Threat Intelligence roster, not guessed by you. When a cluster includes this annotation, name the actor explicitly in the title or Why-it-matters line. Do not attribute an actor unless it is annotated or explicitly named in the source text.

## Key Vulnerabilities to Act On
(From the CISA KEV list — highlight the most critical, recommend patching priorities; tie to org context where relevant)

## Notable Campaigns & Incidents
(From the RSS headlines — group related stories, call out trends; note sector/tool relevance where clear)

## Recommended Actions
(3-5 concrete actions the security team should take this week — align with their stack and priorities when sensible)

---
### CISA Known Exploited Vulnerabilities (recent)

"""

DIGEST_PROMPT_SUFFIX = """

### Recent Threat Headlines

"""

DIGEST_PROMPT_JSON = (
    DIGEST_JSON_SCHEMA_INSTRUCTIONS
    + """
---
### CISA Known Exploited Vulnerabilities (recent)

"""
)


def _raw_digest_markdown(kevs_md: str, articles_md: str, profile_block: str) -> str:
    """Stakeholder-style structure using only fetched data (no LLM API call)."""
    profile_note = ""
    if profile_block and "No organisation profile" not in profile_block:
        profile_note = (
            "\nThis digest is generated from public feeds and framed against the configured "
            "organisation profile. Items still require analyst validation before action.\n"
        )

    return f"""## Executive Summary

Public threat intelligence was collected from CISA KEV and curated RSS feeds for analyst triage.{profile_note}

## Key Vulnerabilities to Act On

{kevs_md}

## Notable Campaigns & Incidents

{articles_md}

## Recommended Actions

- Review CISA KEV entries against the asset inventory and prioritise patching or mitigation by CISA due dates.
- Triage RSS headlines for relevance to the organisation's sector, regions, public-facing services, and third-party dependencies.
- Share high-relevance items with incident response, vulnerability management, and service owners for validation.
- Use the AI-generated digest mode when available for richer grouping, relevance scoring, and executive wording.
"""


def build_digest(
    *,
    days: int = 7,
    kev_limit: int = 10,
    rss_limit: int = 15,
    use_llm: bool = True,
    company_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch feeds; optionally summarise with the configured LLM."""
    logger.info(f"Building digest: {days} days lookback, KEV limit={kev_limit}, RSS limit={rss_limit}, LLM={use_llm}")
    
    profile = company_profile or {}
    profile_block = profile_to_prompt_block(profile)
    
    if profile:
        logger.info(f"Using company profile: {profile.get('company_name', 'Unknown')}")
    else:
        logger.info("No company profile provided")

    # Fetch data with error tracking
    logger.info("Fetching CISA KEV data...")
    kevs = fetch_cisa_kev(limit=kev_limit, days=days)
    
    logger.info("Fetching RSS feeds...")
    articles = fetch_rss(limit=rss_limit, days=days)

    # Correlate headlines against the full known threat-actor roster (MITRE ATT&CK +
    # Microsoft Threat Intel) so campaigns can be tied to a named actor automatically.
    try:
        from shared.actor_correlation import correlate_articles

        articles = correlate_articles(articles)
        actor_hits = sum(1 for a in articles if a.get("related_actors"))
        if actor_hits:
            logger.info(f"Actor correlation matched {actor_hits} article(s) to known threat actors")
    except Exception as exc:
        logger.warning(f"Actor correlation failed, continuing without it: {exc}")

    # Update breached packages watchlist from the fetched articles
    try:
        from detection.package_watch import update_watchlist_from_articles, load_watchlist
        update_watchlist_from_articles(articles)
        watchlist = load_watchlist()
    except Exception as exc:
        logger.error(f"Failed to update package watchlist: {exc}")
        watchlist = {"npm": [], "python": []}

    # Check if we have any data to work with
    if not kevs and not articles:
        logger.error("No data retrieved from any feeds - cannot generate digest")
        raise RuntimeError("Failed to fetch any threat intelligence data. Check network connectivity and feed URLs.")
    
    if not kevs:
        logger.warning("No CISA KEV data retrieved")
    if not articles:
        logger.warning("No RSS articles retrieved")

    kevs_md = _format_kevs(kevs)
    articles_md = _format_articles(articles)

    system_json = DIGEST_SYSTEM_JSON
    if profile:
        system_json = DIGEST_SYSTEM_JSON + " " + DIGEST_SYSTEM_TAILORED

    used_llm_effective = use_llm
    digest_payload: dict[str, Any] | None = None
    if use_llm:
        prompt = (
            DIGEST_PROMPT_PREFIX
            + profile_block
            + DIGEST_PROMPT_JSON
            + kevs_md
            + DIGEST_PROMPT_SUFFIX
            + articles_md
        )
        raw_budget = (os.environ.get("DIGEST_MAX_COMPLETION_TOKENS") or "").strip()
        try:
            max_out = int(raw_budget) if raw_budget else _DEFAULT_DIGEST_COMPLETION_TOKENS
        except ValueError:
            max_out = _DEFAULT_DIGEST_COMPLETION_TOKENS
        try:
            logger.info(f"Calling LLM with max_tokens={max_out}")
            summary_raw = complete(prompt, system=system_json, max_tokens=max_out)
            
            if not (summary_raw or "").strip():
                raise RuntimeError("LLM returned empty text after completion.")
            
            logger.debug(f"LLM returned {len(summary_raw)} characters")
            
            # Try to parse structured JSON response
            parsed = parse_digest_json(summary_raw)
            if parsed:
                logger.info("Successfully parsed structured JSON response from LLM")
                digest_payload = normalize_digest_payload(parsed)
                summary = payload_to_markdown(digest_payload)
                
                # Log structure info
                kv_count = len(digest_payload.get("key_vulnerabilities", []))
                nc_count = len(digest_payload.get("notable_campaigns", []))
                ra_count = len(digest_payload.get("recommended_actions", []))
                logger.info(f"Structured digest: {kv_count} vulnerabilities, {nc_count} campaigns, {ra_count} actions")
            else:
                logger.warning(
                    "LLM output was not valid digest JSON; using raw response as Markdown "
                    "and legacy HTML pipeline. Check model follows the JSON schema."
                )
                logger.debug(f"Raw LLM response preview: {summary_raw[:200]}...")
                summary = summary_raw
                
        except RuntimeError as exc:
            logger.error(f"LLM completion failed: {exc}")
            logger.warning(
                "Threat digest LLM step failed (%s); using feed-only export. "
                "If you use a reasoning model, raise DIGEST_MAX_COMPLETION_TOKENS (default %s).",
                exc,
                _DEFAULT_DIGEST_COMPLETION_TOKENS,
            )
            summary = _raw_digest_markdown(kevs_md, articles_md, profile_block)
            used_llm_effective = False
        except Exception as exc:
            logger.error(f"Unexpected error during LLM processing: {exc}")
            logger.warning("Falling back to feed-only digest due to unexpected error")
            summary = _raw_digest_markdown(kevs_md, articles_md, profile_block)
            used_llm_effective = False
    else:
        summary = _raw_digest_markdown(kevs_md, articles_md, profile_block)

    # Append breached packages to summary
    if watchlist and (watchlist.get("npm") or watchlist.get("python")):
        packages_md = "\n\n## Breached Packages Watchlist\n\n"
        
        if watchlist.get("npm"):
            packages_md += "### NPM Packages\n"
            for pkg in watchlist["npm"]:
                packages_md += f"- **{pkg['name']}** (Added {pkg.get('date_added', 'Unknown')})\n"
                packages_md += f"  - Reason: {pkg.get('reason', 'Unknown')}\n"
                if pkg.get('source_link'):
                    packages_md += f"  - Source: [Link]({pkg['source_link']})\n"
            packages_md += "\n"
            
        if watchlist.get("python"):
            packages_md += "### Python Packages\n"
            for pkg in watchlist["python"]:
                packages_md += f"- **{pkg['name']}** (Added {pkg.get('date_added', 'Unknown')})\n"
                packages_md += f"  - Reason: {pkg.get('reason', 'Unknown')}\n"
                if pkg.get('source_link'):
                    packages_md += f"  - Source: [Link]({pkg['source_link']})\n"
            packages_md += "\n"
            
        summary += packages_md

    result = {
        "summary": summary,
        "digest_payload": digest_payload,
        "kevs_raw": kevs_md,
        "articles_raw": articles_md,
        "kev_count": str(len(kevs)),
        "article_count": str(len(articles)),
        "used_llm": "true" if used_llm_effective else "false",
        "profile_loaded": "true" if profile else "false",
        "watchlist": watchlist,
    }
    
    logger.info(f"Digest generation complete: {result['kev_count']} KEVs, {result['article_count']} articles, LLM={result['used_llm']}")
    return result
