"""Core logic for building and summarising a threat digest."""

from __future__ import annotations

import logging
from typing import Any

from shared.feeds import fetch_cisa_kev, fetch_rss
from shared.llm import complete

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
    """Stakeholder-style structure using only fetched data (no LLM API call).

    Leading lines are a copy-paste prompt for Cursor Chat (or similar) to turn feeds into a webpage.
    """
    return f"""Please create a stakeholder digest webpage.

Use the raw intelligence below. Write in clear, executive-friendly language; structure it like a simple single-page brief (headings, bullets, short paragraphs). Include: key vulnerabilities to prioritise, notable campaigns or headlines, and concrete recommended actions.

---

## Source data (automated feeds)

### Key vulnerabilities (CISA KEV)

{kevs_md}

### Recent threat headlines (RSS)

{articles_md}

### Suggested manual triage (optional)

- Review KEV entries against your asset inventory and patch or mitigate per CISA due dates.
- Triage RSS items relevant to your sector and share with incident-response and leadership.
- For an API-generated summary instead of pasting this file into chat, run `python -m threat_digest` without `--no-claude` / `--no-llm` (requires LLM API key and credits).
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
        summary = complete(prompt, system=DIGEST_SYSTEM)
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
