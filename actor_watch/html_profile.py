"""Generate beautiful HTML profiles for threat actors."""

from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_actor_html_profile(
    actor_data: dict[str, Any],
    markdown_content: str,
    output_path: Path | str,
    *,
    include_timeline: bool = False,
    timeline_data: dict[str, Any] | None = None
) -> str:
    """Generate HTML profile for a threat actor."""
    output_path = Path(output_path)
    
    # Extract key information
    actor_name = actor_data.get("name", "Unknown Actor")
    actor_id = actor_data.get("id", "")
    aliases = actor_data.get("aliases", [])
    description = actor_data.get("description", "")
    source = actor_data.get("source", "mitre_attack")
    
    # Build HTML content
    html_content = _build_actor_html(
        actor_name=actor_name,
        actor_id=actor_id,
        aliases=aliases,
        description=description,
        source=source,
        actor_data=actor_data,
        markdown_content=markdown_content,
        include_timeline=include_timeline,
        timeline_data=timeline_data
    )
    
    # Save to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    
    return str(output_path)


def _build_actor_html(
    actor_name: str,
    actor_id: str,
    aliases: list[str],
    description: str,
    source: str,
    actor_data: dict[str, Any],
    markdown_content: str,
    include_timeline: bool = False,
    timeline_data: dict[str, Any] | None = None
) -> str:
    """Build the complete HTML for an actor profile."""
    
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    
    # Extract techniques and tactics
    techniques = actor_data.get("techniques", [])
    tactics = actor_data.get("tactic_coverage", {})
    software = actor_data.get("software", [])
    
    # Build technique cards
    technique_cards = ""
    if techniques:
        for i, technique in enumerate(techniques[:20]):  # Show top 20
            tech_id = technique.get("id", "")
            tech_name = technique.get("name", "Unknown Technique")
            tech_tactic = technique.get("tactic", "unknown")
            
            technique_cards += f"""
            <div class="technique-card" data-tactic="{tech_tactic}">
                <div class="technique-header">
                    <span class="technique-id">{html.escape(tech_id)}</span>
                    <span class="tactic-badge tactic-{tech_tactic.replace('-', '_')}">{html.escape(tech_tactic.replace('-', ' ').title())}</span>
                </div>
                <div class="technique-name">{html.escape(tech_name)}</div>
            </div>
            """
    
    # Build tactic coverage chart
    tactic_chart = ""
    if tactics:
        max_count = max(tactics.values()) if tactics else 1
        for tactic, count in sorted(tactics.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / max_count) * 100
            tactic_chart += f"""
            <div class="tactic-bar">
                <div class="tactic-label">{html.escape(tactic.replace('-', ' ').title())}</div>
                <div class="tactic-progress">
                    <div class="tactic-fill" style="width: {percentage}%"></div>
                    <span class="tactic-count">{count}</span>
                </div>
            </div>
            """
    
    # Build software list
    software_list = ""
    if software:
        for tool in software[:10]:  # Show top 10
            tool_name = tool.get("name", "Unknown Tool")
            tool_id = tool.get("id", "")
            software_list += f"""
            <div class="software-item">
                <span class="software-name">{html.escape(tool_name)}</span>
                {f'<span class="software-id">{html.escape(tool_id)}</span>' if tool_id else ''}
            </div>
            """
    
    # Build timeline section if provided
    timeline_section = ""
    if include_timeline and timeline_data:
        timeline_entries = timeline_data.get("timeline", [])[:10]  # Show last 10 days
        timeline_html = ""
        
        for entry in timeline_entries:
            date = entry.get("date", "")
            mentions = entry.get("mentions", [])
            
            if mentions:
                timeline_html += f"""
                <div class="timeline-entry">
                    <div class="timeline-date">{html.escape(date)}</div>
                    <div class="timeline-mentions">
                        {len(mentions)} mentions
                    </div>
                    <div class="timeline-items">
                """
                
                for mention in mentions[:3]:  # Top 3 per day
                    title = mention.get("title", "No title")[:100]
                    source_name = mention.get("source", "Unknown")
                    relevance = mention.get("relevance_score", 0)
                    
                    timeline_html += f"""
                        <div class="timeline-item">
                            <div class="timeline-title">{html.escape(title)}</div>
                            <div class="timeline-meta">{html.escape(source_name)} • Score: {relevance:.1f}</div>
                        </div>
                    """
                
                timeline_html += "</div></div>"
        
        if timeline_html:
            timeline_section = f"""
            <section class="profile-section">
                <h2 class="section-title">
                    <span class="section-icon">📈</span>
                    Recent Activity Timeline
                </h2>
                <div class="timeline-container">
                    {timeline_html}
                </div>
            </section>
            """
    
    # Source badge
    source_info = {
        "mitre_attack": {"name": "MITRE ATT&CK", "color": "#e11d48"},
        "microsoft": {"name": "Microsoft Threat Intelligence", "color": "#0ea5e9"}
    }
    source_details = source_info.get(source, {"name": "Unknown", "color": "#6b7280"})
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Threat Actor Profile: {html.escape(actor_name)} - Comprehensive intelligence and analysis">
    <title>{html.escape(actor_name)} - Threat Actor Profile | SecOps Innovation</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0d16;
            --bg-secondary: #0f1419;
            --bg-tertiary: #1a1f2e;
            --bg-card: rgba(26, 31, 46, 0.8);
            --bg-card-hover: rgba(26, 31, 46, 0.95);
            --border: rgba(100, 116, 139, 0.12);
            --border-bright: rgba(100, 116, 139, 0.3);
            --text: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-muted: #64748b;
            --accent: #06b6d4;
            --accent-hover: #0891b2;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --gradient-primary: linear-gradient(135deg, #06b6d4 0%, #3b82f6 50%, #8b5cf6 100%);
            --gradient-secondary: linear-gradient(135deg, #10b981 0%, #06b6d4 100%);
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}
        
        * {{ box-sizing: border-box; }}
        
        body {{
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        /* Header */
        .header {{
            background: rgba(15, 20, 25, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            padding: 1.5rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .actor-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .actor-icon {{
            width: 48px;
            height: 48px;
            background: var(--gradient-primary);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            box-shadow: var(--shadow-lg);
        }}
        
        .actor-title h1 {{
            margin: 0;
            font-size: 1.5rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }}
        
        .actor-title p {{
            margin: 0;
            font-size: 0.875rem;
            color: var(--text-muted);
            font-weight: 500;
        }}
        
        .header-actions {{
            display: flex;
            gap: 1rem;
            align-items: center;
        }}
        
        .source-badge {{
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: white;
            background: {source_details['color']};
        }}
        
        .btn {{
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .btn-secondary {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }}
        
        .btn-secondary:hover {{
            background: var(--bg-card);
            border-color: var(--border-bright);
        }}
        
        /* Main content */
        .main {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .profile-overview {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(20px);
        }}
        
        .actor-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            color: var(--accent);
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        
        .aliases {{
            margin-bottom: 1.5rem;
        }}
        
        .aliases-label {{
            font-size: 0.875rem;
            color: var(--text-muted);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}
        
        .alias-tag {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .description {{
            font-size: 1rem;
            line-height: 1.7;
            color: var(--text-secondary);
        }}
        
        /* Profile sections */
        .profile-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(20px);
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text);
            margin: 0 0 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .section-icon {{
            font-size: 1.25rem;
        }}
        
        /* Tactic coverage chart */
        .tactic-chart {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}
        
        .tactic-bar {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .tactic-label {{
            min-width: 150px;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
        }}
        
        .tactic-progress {{
            flex: 1;
            height: 24px;
            background: var(--bg-tertiary);
            border-radius: 12px;
            position: relative;
            overflow: hidden;
        }}
        
        .tactic-fill {{
            height: 100%;
            background: var(--gradient-secondary);
            border-radius: 12px;
            transition: width 0.5s ease;
        }}
        
        .tactic-count {{
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text);
        }}
        
        /* Technique grid */
        .technique-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }}
        
        .technique-card {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            transition: all 0.2s ease;
        }}
        
        .technique-card:hover {{
            border-color: var(--border-bright);
            transform: translateY(-2px);
        }}
        
        .technique-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }}
        
        .technique-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--accent);
            font-weight: 600;
        }}
        
        .tactic-badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.625rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .tactic-initial_access {{ background: #ef4444; color: white; }}
        .tactic-execution {{ background: #f97316; color: white; }}
        .tactic-persistence {{ background: #eab308; color: white; }}
        .tactic-privilege_escalation {{ background: #84cc16; color: white; }}
        .tactic-defense_evasion {{ background: #22c55e; color: white; }}
        .tactic-credential_access {{ background: #06b6d4; color: white; }}
        .tactic-discovery {{ background: #3b82f6; color: white; }}
        .tactic-lateral_movement {{ background: #6366f1; color: white; }}
        .tactic-collection {{ background: #8b5cf6; color: white; }}
        .tactic-command_and_control {{ background: #a855f7; color: white; }}
        .tactic-exfiltration {{ background: #ec4899; color: white; }}
        .tactic-impact {{ background: #f43f5e; color: white; }}
        
        .technique-name {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text);
        }}
        
        /* Software list */
        .software-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
        }}
        
        .software-item {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .software-name {{
            font-weight: 600;
            color: var(--text);
        }}
        
        .software-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        
        /* Timeline */
        .timeline-container {{
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}
        
        .timeline-entry {{
            border-left: 3px solid var(--accent);
            padding-left: 1.5rem;
            position: relative;
        }}
        
        .timeline-entry::before {{
            content: '';
            position: absolute;
            left: -6px;
            top: 0;
            width: 9px;
            height: 9px;
            background: var(--accent);
            border-radius: 50%;
        }}
        
        .timeline-date {{
            font-weight: 700;
            color: var(--text);
            margin-bottom: 0.5rem;
        }}
        
        .timeline-mentions {{
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-bottom: 1rem;
        }}
        
        .timeline-items {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        
        .timeline-item {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
        }}
        
        .timeline-title {{
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.25rem;
        }}
        
        .timeline-meta {{
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        
        /* Generated info */
        .generated-info {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .main {{
                padding: 1rem;
            }}
            
            .header {{
                padding: 1rem;
            }}
            
            .header-content {{
                flex-direction: column;
                gap: 1rem;
                align-items: flex-start;
            }}
            
            .technique-grid {{
                grid-template-columns: 1fr;
            }}
            
            .software-grid {{
                grid-template-columns: 1fr;
            }}
            
            .tactic-bar {{
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }}
            
            .tactic-label {{
                min-width: auto;
            }}
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="actor-header">
                <div class="actor-icon">🎯</div>
                <div class="actor-title">
                    <h1>{html.escape(actor_name)}</h1>
                    <p>Threat Actor Profile</p>
                </div>
            </div>
            <div class="header-actions">
                <div class="source-badge">{source_details['name']}</div>
                <button class="btn btn-secondary" onclick="window.history.back()">
                    <span>←</span> Back to Platform
                </button>
            </div>
        </div>
    </header>
    
    <main class="main">
        <div class="profile-overview">
            {f'<div class="actor-id">ID: {html.escape(actor_id)}</div>' if actor_id else ''}
            
            {f'''<div class="aliases">
                <div class="aliases-label">Known Aliases:</div>
                {''.join(f'<span class="alias-tag">{html.escape(alias)}</span>' for alias in aliases)}
            </div>''' if aliases else ''}
            
            <div class="description">
                {html.escape(description)}
            </div>
        </div>
        
        {f'''<section class="profile-section">
            <h2 class="section-title">
                <span class="section-icon">📊</span>
                Tactic Coverage
            </h2>
            <div class="tactic-chart">
                {tactic_chart}
            </div>
        </section>''' if tactic_chart else ''}
        
        {f'''<section class="profile-section">
            <h2 class="section-title">
                <span class="section-icon">⚔️</span>
                Attack Techniques ({len(techniques)})
            </h2>
            <div class="technique-grid">
                {technique_cards}
            </div>
        </section>''' if technique_cards else ''}
        
        {f'''<section class="profile-section">
            <h2 class="section-title">
                <span class="section-icon">🛠️</span>
                Associated Software
            </h2>
            <div class="software-grid">
                {software_list}
            </div>
        </section>''' if software_list else ''}
        
        {timeline_section}
    </main>
    
    <div class="generated-info">
        Generated on {generated} by SecOps Innovation Platform
    </div>
</body>
</html>"""