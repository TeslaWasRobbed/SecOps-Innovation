"""Generate HTML dashboard for threat actor monitoring."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actor_watch.enhanced_watch import list_all_enhanced_actors, get_enhanced_actor_profile
from actor_watch.activity_tracker import get_actor_timeline


def generate_actor_dashboard(output_path: Path | str, days: int = 30) -> str:
    """Generate HTML dashboard for threat actor monitoring."""
    output_path = Path(output_path)
    
    # Get all actors
    all_actors = list_all_enhanced_actors()
    
    # Separate by source
    microsoft_actors = [a for a in all_actors if a["source"] == "microsoft"]
    mitre_actors = [a for a in all_actors if a["source"] == "mitre_attack"]
    
    # Get recent activity for top Microsoft actors
    top_microsoft = microsoft_actors[:10]  # Top 10 Microsoft actors
    activity_data = []
    
    for actor in top_microsoft:
        timeline = get_actor_timeline(actor["name"], days=days)
        activity_data.append({
            "actor": actor,
            "timeline": timeline,
            "recent_mentions": timeline.get("stats", {}).get("recent_activity", 0)
        })
    
    # Sort by recent activity
    activity_data.sort(key=lambda x: x["recent_mentions"], reverse=True)
    
    # Generate HTML
    html_content = _build_dashboard_html(microsoft_actors, mitre_actors, activity_data, days)
    
    # Save to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    
    return str(output_path)


def _build_dashboard_html(microsoft_actors: list[dict], mitre_actors: list[dict], 
                         activity_data: list[dict], days: int) -> str:
    """Build the HTML dashboard."""
    
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    
    # Build actor cards
    microsoft_cards = ""
    for actor_data in activity_data[:6]:  # Top 6 with activity
        actor = actor_data["actor"]
        timeline = actor_data["timeline"]
        recent_mentions = actor_data["recent_mentions"]
        
        activity_indicator = "🔴" if recent_mentions > 5 else "🟡" if recent_mentions > 0 else "🟢"
        activity_class = "high" if recent_mentions > 5 else "medium" if recent_mentions > 0 else "low"
        
        microsoft_cards += f"""
        <div class="actor-card" data-activity="{activity_class}">
            <div class="actor-header">
                <h3>{html.escape(actor['name'])}</h3>
                <div class="activity-indicator {activity_class}" title="{recent_mentions} recent mentions">
                    {activity_indicator}
                </div>
            </div>
            <div class="actor-meta">
                <span class="actor-type">{html.escape(actor.get('type', '').replace('_', ' ').title())}</span>
                {f'<span class="actor-attribution">{html.escape(actor.get("attribution", ""))}</span>' if actor.get("attribution") else ""}
            </div>
            <div class="actor-stats">
                <div class="stat">
                    <span class="stat-value">{timeline.get('stats', {}).get('total_mentions', 0)}</span>
                    <span class="stat-label">mentions ({days}d)</span>
                </div>
                <div class="stat">
                    <span class="stat-value">{recent_mentions}</span>
                    <span class="stat-label">recent (7d)</span>
                </div>
            </div>
            <div class="actor-sectors">
                {', '.join(actor.get('sectors', [])[:3])}
            </div>
        </div>
        """
    
    # Build summary stats
    total_actors = len(microsoft_actors) + len(mitre_actors)
    active_actors = len([a for a in activity_data if a["recent_mentions"] > 0])
    total_mentions = sum(a["timeline"].get("stats", {}).get("total_mentions", 0) for a in activity_data)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Threat Actor Dashboard</title>
    <style>
        :root {{
            --bg-primary: #0a0c14;
            --bg-secondary: #12162a;
            --bg-card: rgba(18, 22, 36, 0.8);
            --border: rgba(120, 140, 200, 0.12);
            --text: #f0f3fa;
            --text-muted: #6b7a99;
            --accent: #00e5c8;
            --danger: #fb7185;
            --warning: #fbbf24;
            --success: #22c55e;
        }}
        
        * {{ box-sizing: border-box; }}
        
        body {{
            margin: 0;
            font-family: system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text);
            line-height: 1.6;
        }}
        
        .header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 1.5rem 2rem;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
        }}
        
        .header .subtitle {{
            margin: 0.5rem 0 0;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        
        .dashboard {{
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        
        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
            display: block;
        }}
        
        .stat-card .label {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}
        
        .section {{
            margin-bottom: 2rem;
        }}
        
        .section h2 {{
            margin: 0 0 1rem;
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text);
        }}
        
        .actors-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }}
        
        .actor-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            transition: all 0.2s ease;
        }}
        
        .actor-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}
        
        .actor-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}
        
        .actor-header h3 {{
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
        }}
        
        .activity-indicator {{
            font-size: 1.2rem;
            cursor: help;
        }}
        
        .activity-indicator.high {{
            color: var(--danger);
        }}
        
        .activity-indicator.medium {{
            color: var(--warning);
        }}
        
        .activity-indicator.low {{
            color: var(--success);
        }}
        
        .actor-meta {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}
        
        .actor-type, .actor-attribution {{
            background: rgba(0, 229, 200, 0.1);
            color: var(--accent);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        
        .actor-attribution {{
            background: rgba(251, 113, 133, 0.1);
            color: var(--danger);
        }}
        
        .actor-stats {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat-value {{
            display: block;
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--accent);
        }}
        
        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        
        .actor-sectors {{
            color: var(--text-muted);
            font-size: 0.9rem;
            font-style: italic;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }}
        
        @media (max-width: 768px) {{
            .dashboard {{
                padding: 1rem;
            }}
            
            .actors-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Threat Actor Dashboard</h1>
        <p class="subtitle">Real-time monitoring of threat actor activity and intelligence</p>
    </div>
    
    <div class="dashboard">
        <div class="stats-grid">
            <div class="stat-card">
                <span class="value">{total_actors}</span>
                <div class="label">Total Actors Tracked</div>
            </div>
            <div class="stat-card">
                <span class="value">{active_actors}</span>
                <div class="label">Recently Active</div>
            </div>
            <div class="stat-card">
                <span class="value">{total_mentions}</span>
                <div class="label">Total Mentions ({days}d)</div>
            </div>
            <div class="stat-card">
                <span class="value">{len(microsoft_actors)}</span>
                <div class="label">Microsoft Intel</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔥 Recently Active Threat Actors</h2>
            <div class="actors-grid">
                {microsoft_cards}
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>Generated on {generated} | Data from Microsoft Threat Intelligence & MITRE ATT&CK</p>
        <p>🔴 High Activity (5+ mentions) | 🟡 Medium Activity (1-4 mentions) | 🟢 Low Activity (0 mentions)</p>
    </div>
    
    <script>
        // Auto-refresh every 5 minutes
        setTimeout(() => location.reload(), 5 * 60 * 1000);
        
        // Add click handlers for actor cards
        document.querySelectorAll('.actor-card').forEach(card => {{
            card.addEventListener('click', () => {{
                const actorName = card.querySelector('h3').textContent;
                console.log('Clicked actor:', actorName);
                // Could integrate with actor watch CLI here
            }});
        }});
    </script>
</body>
</html>"""


def create_dashboard_cli_command() -> None:
    """Add dashboard generation to the main CLI."""
    import argparse
    import sys
    from pathlib import Path
    
    parser = argparse.ArgumentParser(description="Generate threat actor dashboard")
    parser.add_argument("--output", default="output/actor_watch/dashboard.html", 
                       help="Output path for HTML dashboard")
    parser.add_argument("--days", type=int, default=30,
                       help="Days to look back for activity")
    
    args = parser.parse_args()
    
    print("Generating threat actor dashboard...")
    dashboard_path = generate_actor_dashboard(args.output, args.days)
    print(f"Dashboard saved to: {dashboard_path}")
    print(f"Open in browser: file://{Path(dashboard_path).absolute()}")


if __name__ == "__main__":
    create_dashboard_cli_command()