"""Core logic for building and summarising a threat digest."""

from __future__ import annotations

import logging
from typing import Any

from shared.feeds import fetch_cisa_kev, fetch_rss
from shared.llm import ask_claude

logger = logging.getLogger(__name__)


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
        lines.append(f"- [{a['title']}]({a['link']}) — *{a['source']}*, {a['published']}")
    return "\n".join(lines)


DIGEST_SYSTEM = (
    "You are a threat-intelligence analyst writing a weekly digest for a CISO and "
    "non-technical leadership. Be concise, use bullet points, and highlight actions."
)

DIGEST_PROMPT = """\
Summarise the following raw intelligence into a stakeholder-friendly threat digest.

Structure your response as Markdown with these sections:
## Key Vulnerabilities to Act On
(From the CISA KEV list — highlight the most critical, recommend patching priorities)

## Notable Campaigns & Incidents
(From the RSS headlines — group related stories, call out trends)

## Recommended Actions
(3-5 concrete actions the security team should take this week)

---
### CISA Known Exploited Vulnerabilities (recent)
{kevs}

### Recent Threat Headlines
{articles}
"""


def _raw_digest_markdown(kevs_md: str, articles_md: str) -> str:
    """Stakeholder-style structure using only fetched data (no LLM)."""
    return f"""## Key vulnerabilities (CISA KEV)

{kevs_md}

## Recent threat headlines (RSS)

{articles_md}

## Recommended actions

- Review KEV entries above against your asset inventory and patch or mitigate per CISA due dates.
- Triage RSS items relevant to your sector and share links with incident-response and leadership.
- Re-run with AI summarisation after Anthropic billing has credits: `python -m threat_digest` (omit `--no-llm`).
"""


def build_digest(
    *,
    days: int = 7,
    kev_limit: int = 10,
    rss_limit: int = 15,
    use_llm: bool = True,
) -> dict[str, str]:
    """Fetch feeds; optionally summarise with Claude."""
    kevs = fetch_cisa_kev(limit=kev_limit, days=days)
    articles = fetch_rss(limit=rss_limit, days=days)

    kevs_md = _format_kevs(kevs)
    articles_md = _format_articles(articles)

    if use_llm:
        prompt = DIGEST_PROMPT.format(kevs=kevs_md, articles=articles_md)
        summary = ask_claude(prompt, system=DIGEST_SYSTEM)
    else:
        summary = _raw_digest_markdown(kevs_md, articles_md)

    return {
        "summary": summary,
        "kevs_raw": kevs_md,
        "articles_raw": articles_md,
        "kev_count": str(len(kevs)),
        "article_count": str(len(articles)),
        "used_llm": str(use_llm),
    }
