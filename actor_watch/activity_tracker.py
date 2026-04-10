"""Track recent threat actor activity from multiple intelligence sources."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from shared.feeds import fetch_rss, DEFAULT_RSS_FEEDS

logger = logging.getLogger(__name__)

# Additional RSS feeds focused on threat intelligence
THREAT_INTEL_FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "US-CERT", "url": "https://us-cert.cisa.gov/ncas/alerts.xml"},
    {"name": "Microsoft Security", "url": "https://www.microsoft.com/security/blog/feed/"},
    {"name": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/feed/"},
    {"name": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/_jcr_content.feed"},
]


def search_actor_mentions(actor_name: str, days: int = 30) -> list[dict[str, Any]]:
    """Search for recent mentions of a threat actor in security feeds."""
    # Get actor aliases for comprehensive search
    from actor_watch.enhanced_watch import get_enhanced_actor_profile
    
    profile = get_enhanced_actor_profile(actor_name)
    if not profile:
        return []
    
    # Build search terms
    search_terms = [actor_name.lower()]
    if profile.get("aliases"):
        search_terms.extend([alias.lower() for alias in profile["aliases"]])
    
    # Add Microsoft ID if available
    if profile.get("microsoft_id"):
        search_terms.append(profile["microsoft_id"].lower())
    
    # Search in threat intelligence feeds
    all_feeds = DEFAULT_RSS_FEEDS + THREAT_INTEL_FEEDS
    articles = fetch_rss(all_feeds, limit=100, days=days)
    
    mentions = []
    for article in articles:
        title_lower = article.get("title", "").lower()
        summary_lower = article.get("summary", "").lower()
        
        # Check if any search term appears in title or summary
        for term in search_terms:
            if term in title_lower or term in summary_lower:
                mentions.append({
                    **article,
                    "matched_term": term,
                    "actor_name": actor_name,
                    "relevance_score": calculate_relevance_score(article, search_terms)
                })
                break  # Avoid duplicate entries for same article
    
    # Sort by relevance and recency
    mentions.sort(key=lambda x: (x["relevance_score"], x["published"]), reverse=True)
    
    return mentions


def calculate_relevance_score(article: dict[str, Any], search_terms: list[str]) -> float:
    """Calculate relevance score for an article based on search terms."""
    title = article.get("title", "").lower()
    summary = article.get("summary", "").lower()
    source = article.get("source", "").lower()
    
    score = 0.0
    
    # Title matches are more important
    for term in search_terms:
        if term in title:
            score += 3.0
        if term in summary:
            score += 1.0
    
    # Boost score for authoritative sources
    authoritative_sources = ["cisa", "microsoft", "mandiant", "crowdstrike", "fireeye"]
    for auth_source in authoritative_sources:
        if auth_source in source:
            score += 2.0
            break
    
    # Boost for security-related keywords
    security_keywords = ["ransomware", "apt", "malware", "breach", "attack", "vulnerability", "exploit"]
    for keyword in security_keywords:
        if keyword in title or keyword in summary:
            score += 0.5
    
    return score


def get_actor_timeline(actor_name: str, days: int = 90) -> dict[str, Any]:
    """Get a timeline of recent actor activity."""
    mentions = search_actor_mentions(actor_name, days)
    
    if not mentions:
        return {
            "actor_name": actor_name,
            "timeline": [],
            "summary": f"No recent mentions found for {actor_name} in the last {days} days."
        }
    
    # Group mentions by date
    timeline = {}
    for mention in mentions:
        date = mention["published"]
        if date not in timeline:
            timeline[date] = []
        timeline[date].append(mention)
    
    # Sort timeline by date (most recent first)
    sorted_timeline = []
    for date in sorted(timeline.keys(), reverse=True):
        sorted_timeline.append({
            "date": date,
            "mentions": timeline[date],
            "count": len(timeline[date])
        })
    
    # Generate summary
    total_mentions = len(mentions)
    unique_sources = len(set(m["source"] for m in mentions))
    recent_activity = len([m for m in mentions if is_recent_activity(m["published"])])
    
    summary = f"Found {total_mentions} mentions across {unique_sources} sources in the last {days} days."
    if recent_activity > 0:
        summary += f" {recent_activity} mentions in the last 7 days indicate recent activity."
    
    return {
        "actor_name": actor_name,
        "timeline": sorted_timeline,
        "summary": summary,
        "stats": {
            "total_mentions": total_mentions,
            "unique_sources": unique_sources,
            "recent_activity": recent_activity,
            "top_sources": get_top_sources(mentions)
        }
    }


def is_recent_activity(date_str: str) -> bool:
    """Check if a date represents recent activity (within 7 days)."""
    try:
        # Parse the date string (assuming YYYY-MM-DD format)
        if date_str == "unknown":
            return False
        
        article_date = datetime.strptime(date_str, "%Y-%m-%d")
        cutoff = datetime.now() - timedelta(days=7)
        return article_date.date() >= cutoff.date()
    except (ValueError, TypeError):
        return False


def get_top_sources(mentions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Get top sources by mention count."""
    source_counts = {}
    for mention in mentions:
        source = mention["source"]
        source_counts[source] = source_counts.get(source, 0) + 1
    
    top_sources = []
    for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        top_sources.append({"source": source, "count": count})
    
    return top_sources


def format_activity_timeline_markdown(timeline_data: dict[str, Any]) -> str:
    """Format activity timeline as Markdown."""
    lines = [f"# {timeline_data['actor_name']} - Recent Activity Timeline\n"]
    
    lines.append(f"**Summary:** {timeline_data['summary']}\n")
    
    stats = timeline_data.get("stats", {})
    if stats:
        lines.append("## Activity Statistics\n")
        lines.append(f"- **Total Mentions:** {stats['total_mentions']}")
        lines.append(f"- **Unique Sources:** {stats['unique_sources']}")
        lines.append(f"- **Recent Activity (7 days):** {stats['recent_activity']}")
        
        if stats.get("top_sources"):
            lines.append("\n### Top Sources")
            for source_info in stats["top_sources"]:
                lines.append(f"- **{source_info['source']}**: {source_info['count']} mentions")
        
        lines.append("")
    
    timeline = timeline_data.get("timeline", [])
    if timeline:
        lines.append("## Timeline\n")
        
        for entry in timeline[:20]:  # Limit to top 20 dates
            date = entry["date"]
            count = entry["count"]
            mentions = entry["mentions"]
            
            lines.append(f"### {date} ({count} mentions)\n")
            
            for mention in mentions[:5]:  # Limit to top 5 mentions per date
                title = mention.get("title", "No title")
                source = mention.get("source", "Unknown source")
                link = mention.get("link", "")
                relevance = mention.get("relevance_score", 0)
                
                if link:
                    lines.append(f"- [{title}]({link}) - *{source}* (relevance: {relevance:.1f})")
                else:
                    lines.append(f"- {title} - *{source}* (relevance: {relevance:.1f})")
            
            if len(mentions) > 5:
                lines.append(f"- *... and {len(mentions) - 5} more mentions*")
            
            lines.append("")
    
    lines.append("---")
    lines.append(f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}*")
    
    return "\n".join(lines)