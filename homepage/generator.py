"""Generate the main SecOps Innovation homepage with dynamic content."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actor_watch.enhanced_watch import list_all_enhanced_actors
from shared.microsoft_intel import list_microsoft_actors


def scan_project_content() -> dict[str, Any]:
    """Scan the project for existing content to display on homepage."""
    content = {
        "threat_digests": [],
        "actor_profiles": [],
        "recent_activity": [],
        "stats": {
            "total_actors": 0,
            "total_digests": 0,
            "microsoft_actors": 0,
            "mitre_actors": 0
        }
    }
    
    # Scan for threat digests
    digest_dir = Path("output/threat_digest")
    if digest_dir.exists():
        for digest_file in digest_dir.glob("digest_*.html"):
            date_str = digest_file.stem.replace("digest_", "")
            content["threat_digests"].append({
                "date": date_str,
                "filename": digest_file.name,
                "path": str(digest_file),
                "size": digest_file.stat().st_size if digest_file.exists() else 0
            })
    
    # Sort digests by date (newest first)
    content["threat_digests"].sort(key=lambda x: x["date"], reverse=True)
    
    # Scan for actor profiles (prioritize HTML over markdown)
    actor_dir = Path("output/actor_watch")
    if actor_dir.exists():
        processed_actors = set()
        
        # First, check for HTML profiles
        for html_file in actor_dir.glob("*.html"):
            if html_file.name != "dashboard.html":
                actor_name = html_file.stem.replace("_", " ")
                if actor_name not in processed_actors:
                    content["actor_profiles"].append({
                        "name": actor_name,
                        "filename": html_file.name,
                        "path": str(html_file),
                        "type": "html",
                        "modified": datetime.fromtimestamp(html_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    })
                    processed_actors.add(actor_name)
        
        # Then, check for markdown profiles (only if no HTML exists)
        for md_file in actor_dir.glob("*.md"):
            if not md_file.name.endswith("_timeline.md"):
                actor_name = md_file.stem.replace("_", " ")
                if actor_name not in processed_actors:
                    content["actor_profiles"].append({
                        "name": actor_name,
                        "filename": md_file.name,
                        "path": str(md_file),
                        "type": "markdown",
                        "modified": datetime.fromtimestamp(md_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                    })
    
    # Sort profiles by modification date (newest first)
    content["actor_profiles"].sort(key=lambda x: x["modified"], reverse=True)
    
    # Get actor statistics
    all_actors = list_all_enhanced_actors()
    microsoft_actors = [a for a in all_actors if a["source"] == "microsoft"]
    mitre_actors = [a for a in all_actors if a["source"] == "mitre_attack"]
    
    content["stats"] = {
        "total_actors": len(all_actors),
        "total_digests": len(content["threat_digests"]),
        "microsoft_actors": len(microsoft_actors),
        "mitre_actors": len(mitre_actors)
    }
    
    # Recent activity (last 5 items)
    recent_items = []
    
    # Add recent digests
    for digest in content["threat_digests"][:3]:
        recent_items.append({
            "type": "digest",
            "title": f"Threat Digest - {digest['date']}",
            "date": digest["date"],
            "link": f"output/threat_digest/{digest['filename']}"
        })
    
    # Add recent actor profiles
    for profile in content["actor_profiles"][:3]:
        profile_type = profile.get("type", "markdown")
        type_indicator = " (Interactive)" if profile_type == "html" else ""
        
        recent_items.append({
            "type": "actor",
            "title": f"Actor Profile - {profile['name']}{type_indicator}",
            "date": profile["modified"].split()[0],  # Just the date part
            "link": f"output/actor_watch/{profile['filename']}"
        })
    
    # Sort by date and take top 5
    recent_items.sort(key=lambda x: x["date"], reverse=True)
    content["recent_activity"] = recent_items[:5]
    
    return content


def generate_homepage(output_path: Path | str) -> str:
    """Generate the main SecOps Innovation homepage."""
    output_path = Path(output_path)
    
    # Scan project content
    content = scan_project_content()
    
    # Generate HTML
    html_content = _build_homepage_html(content)
    
    # Save to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    
    return str(output_path)


def _build_homepage_html(content: dict[str, Any]) -> str:
    """Build the homepage HTML."""
    
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    stats = content["stats"]
    
    # Build threat digest cards
    digest_cards = ""
    for digest in content["threat_digests"][:6]:  # Show top 6
        digest_cards += f"""
        <div class="content-card" data-type="digest" onclick="openContent('threat_digest', '{digest['filename']}')">
            <div class="card-header">
                <div class="card-icon">📊</div>
                <div class="card-date">{digest['date']}</div>
            </div>
            <h3>Threat Intelligence Digest</h3>
            <p>Comprehensive threat landscape analysis with CISA KEV and curated intelligence feeds</p>
            <div class="card-footer">
                <span class="file-size">{_format_file_size(digest['size'])}</span>
                <span class="card-type">HTML Report</span>
            </div>
        </div>
        """
    
    # Build actor profile cards
    actor_cards = ""
    for profile in content["actor_profiles"][:6]:  # Show top 6
        profile_type = profile.get("type", "markdown")
        type_display = "Interactive Report" if profile_type == "html" else "Markdown"
        type_icon = "🌐" if profile_type == "html" else "📝"
        
        actor_cards += f"""
        <div class="content-card" data-type="actor" onclick="openContent('actor_watch', '{profile['filename']}')">
            <div class="card-header">
                <div class="card-icon">🎯</div>
                <div class="card-date">{profile['modified'].split()[0]}</div>
            </div>
            <h3>{html.escape(profile['name'])}</h3>
            <p>Comprehensive threat actor profile with TTPs, tools, and defensive recommendations</p>
            <div class="card-footer">
                <span class="file-size">{type_icon} Profile</span>
                <span class="card-type">{type_display}</span>
            </div>
        </div>
        """
    
    # Build recent activity list
    recent_activity_html = ""
    for item in content["recent_activity"]:
        icon = "📊" if item["type"] == "digest" else "🎯"
        type_label = "Digest" if item["type"] == "digest" else "Actor"
        recent_activity_html += f"""
        <div class="activity-item" onclick="openContent('{item['type']}', '{item['link'].split('/')[-1]}')">
            <div class="activity-icon">{icon}</div>
            <div class="activity-content">
                <div class="activity-title">{html.escape(item['title'])}</div>
                <div class="activity-meta">{item['date']} • {type_label}</div>
            </div>
        </div>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="SecOps Innovation - Advanced threat intelligence and actor monitoring platform">
    <title>SecOps Innovation - Threat Intelligence Platform</title>
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
            overflow-x: hidden;
        }}
        
        /* Animated background */
        .bg-animation {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.4;
        }}
        
        .bg-animation::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 20%, rgba(6, 182, 212, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 60%, rgba(16, 185, 129, 0.1) 0%, transparent 50%);
            animation: float 20s ease-in-out infinite;
        }}
        
        @keyframes float {{
            0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
            33% {{ transform: translate(30px, -30px) rotate(120deg); }}
            66% {{ transform: translate(-20px, 20px) rotate(240deg); }}
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
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .logo-icon {{
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
        
        .logo-text h1 {{
            margin: 0;
            font-size: 1.5rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }}
        
        .logo-text p {{
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
        
        .btn-primary {{
            background: var(--gradient-primary);
            color: white;
            box-shadow: var(--shadow-md);
        }}
        
        .btn-primary:hover {{
            transform: translateY(-1px);
            box-shadow: var(--shadow-lg);
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
            max-width: 1400px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }}
        
        .hero {{
            text-align: center;
            margin-bottom: 4rem;
        }}
        
        .hero h2 {{
            font-size: 3rem;
            font-weight: 800;
            margin: 0 0 1rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            line-height: 1.2;
        }}
        
        .hero p {{
            font-size: 1.25rem;
            color: var(--text-secondary);
            margin: 0 0 2rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }}
        
        /* Stats grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            text-align: center;
            backdrop-filter: blur(20px);
            transition: all 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
            border-color: var(--border-bright);
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            display: block;
            margin-bottom: 0.5rem;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        /* Navigation pills */
        .nav-pills {{
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin-bottom: 3rem;
            flex-wrap: wrap;
        }}
        
        .nav-pill {{
            padding: 1rem 2rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 50px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.875rem;
        }}
        
        .nav-pill:hover, .nav-pill.active {{
            background: var(--gradient-primary);
            color: white;
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }}
        
        .nav-pill-icon {{
            font-size: 1.25rem;
        }}
        
        /* Content sections */
        .content-section {{
            margin-bottom: 3rem;
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
        }}
        
        .section-title {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text);
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .section-icon {{
            font-size: 1.25rem;
        }}
        
        .view-all {{
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .view-all:hover {{
            color: var(--accent-hover);
        }}
        
        /* Content grid */
        .content-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 1.5rem;
        }}
        
        .content-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            cursor: pointer;
            transition: all 0.3s ease;
            backdrop-filter: blur(20px);
        }}
        
        .content-card:hover {{
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
            border-color: var(--border-bright);
            background: var(--bg-card-hover);
        }}
        
        .card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}
        
        .card-icon {{
            font-size: 1.5rem;
        }}
        
        .card-date {{
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 600;
            background: var(--bg-tertiary);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
        }}
        
        .content-card h3 {{
            margin: 0 0 0.75rem;
            font-size: 1.125rem;
            font-weight: 700;
            color: var(--text);
        }}
        
        .content-card p {{
            margin: 0 0 1rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            line-height: 1.5;
        }}
        
        .card-footer {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 600;
        }}
        
        .card-type {{
            background: var(--gradient-secondary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.625rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        /* Recent activity sidebar */
        .sidebar {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(20px);
        }}
        
        .sidebar h3 {{
            margin: 0 0 1.5rem;
            font-size: 1.125rem;
            font-weight: 700;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .activity-item {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-bottom: 0.5rem;
        }}
        
        .activity-item:hover {{
            background: var(--bg-tertiary);
        }}
        
        .activity-icon {{
            font-size: 1.25rem;
            flex-shrink: 0;
        }}
        
        .activity-content {{
            flex: 1;
        }}
        
        .activity-title {{
            font-weight: 600;
            color: var(--text);
            font-size: 0.875rem;
            margin-bottom: 0.25rem;
        }}
        
        .activity-meta {{
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        
        /* Layout */
        .main-layout {{
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 2rem;
            align-items: start;
        }}
        
        @media (max-width: 1024px) {{
            .main-layout {{
                grid-template-columns: 1fr;
            }}
            
            .hero h2 {{
                font-size: 2rem;
            }}
            
            .main {{
                padding: 2rem 1rem;
            }}
            
            .header {{
                padding: 1rem;
            }}
            
            .content-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        /* Hidden sections */
        .content-section.hidden {{
            display: none;
        }}
        
        /* Loading states */
        .loading {{
            opacity: 0.6;
            pointer-events: none;
        }}
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>SecOps Innovation</h1>
                    <p>Advanced Threat Intelligence Platform</p>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn btn-secondary" onclick="refreshContent()">
                    <span>🔄</span> Refresh
                </button>
                <button class="btn btn-primary" onclick="generateNewContent()">
                    <span>⚡</span> Generate
                </button>
            </div>
        </div>
    </header>
    
    <main class="main">
        <section class="hero">
            <h2>Threat Intelligence at Scale</h2>
            <p>Comprehensive threat actor monitoring, intelligence digests, and actionable security insights powered by MITRE ATT&CK and Microsoft threat intelligence.</p>
        </section>
        
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value">{stats['total_actors']}</span>
                <div class="stat-label">Threat Actors Tracked</div>
            </div>
            <div class="stat-card">
                <span class="stat-value">{stats['total_digests']}</span>
                <div class="stat-label">Intelligence Digests</div>
            </div>
            <div class="stat-card">
                <span class="stat-value">{stats['microsoft_actors']}</span>
                <div class="stat-label">Microsoft Intel</div>
            </div>
            <div class="stat-card">
                <span class="stat-value">{stats['mitre_actors']}</span>
                <div class="stat-label">MITRE ATT&CK Groups</div>
            </div>
        </div>
        
        <div class="nav-pills">
            <div class="nav-pill active" data-section="all" onclick="showSection('all')">
                <span class="nav-pill-icon">🌐</span>
                All Content
            </div>
            <div class="nav-pill" data-section="digests" onclick="showSection('digests')">
                <span class="nav-pill-icon">📊</span>
                Threat Digests
            </div>
            <div class="nav-pill" data-section="actors" onclick="showSection('actors')">
                <span class="nav-pill-icon">🎯</span>
                Actor Profiles
            </div>
            <div class="nav-pill" onclick="openDashboard()">
                <span class="nav-pill-icon">📈</span>
                Live Dashboard
            </div>
        </div>
        
        <div class="main-layout">
            <div class="main-content">
                <section class="content-section" id="digests-section">
                    <div class="section-header">
                        <h2 class="section-title">
                            <span class="section-icon">📊</span>
                            Latest Threat Digests
                        </h2>
                        <a href="#" class="view-all" onclick="generateThreatDigest()">
                            Generate New →
                        </a>
                    </div>
                    <div class="content-grid" id="digests-grid">
                        {digest_cards}
                    </div>
                </section>
                
                <section class="content-section" id="actors-section">
                    <div class="section-header">
                        <h2 class="section-title">
                            <span class="section-icon">🎯</span>
                            Actor Profiles
                        </h2>
                        <a href="#" class="view-all" onclick="showActorWatch()">
                            Browse All →
                        </a>
                    </div>
                    <div class="content-grid" id="actors-grid">
                        {actor_cards}
                    </div>
                </section>
            </div>
            
            <aside class="sidebar">
                <h3>
                    <span>⚡</span>
                    Recent Activity
                </h3>
                <div id="recent-activity">
                    {recent_activity_html}
                </div>
            </aside>
        </div>
    </main>
    
    <script>
        // Global state
        let currentSection = 'all';
        
        // Navigation functions
        function showSection(section) {{
            currentSection = section;
            
            // Update nav pills
            document.querySelectorAll('.nav-pill').forEach(pill => {{
                pill.classList.remove('active');
            }});
            document.querySelector(`[data-section="${{section}}"]`).classList.add('active');
            
            // Show/hide sections
            const digestsSection = document.getElementById('digests-section');
            const actorsSection = document.getElementById('actors-section');
            
            if (section === 'all') {{
                digestsSection.classList.remove('hidden');
                actorsSection.classList.remove('hidden');
            }} else if (section === 'digests') {{
                digestsSection.classList.remove('hidden');
                actorsSection.classList.add('hidden');
            }} else if (section === 'actors') {{
                digestsSection.classList.add('hidden');
                actorsSection.classList.remove('hidden');
            }}
        }}
        
        // Content interaction functions
        function openContent(type, filename) {{
            if (type === 'threat_digest') {{
                window.open(`output/threat_digest/${{filename}}`, '_blank');
            }} else if (type === 'actor_watch') {{
                // For actor profiles, prefer HTML if available
                if (filename.endsWith('.html') || filename.endsWith('.md')) {{
                    window.open(`output/actor_watch/${{filename}}`, '_blank');
                }} else {{
                    // Fallback for older links
                    window.open(`output/actor_watch/${{filename}}`, '_blank');
                }}
            }}
        }}
        
        function openDashboard() {{
            window.open('output/actor_watch/dashboard.html', '_blank');
        }}
        
        function generateThreatDigest() {{
            showNotification('Generating new threat digest...', 'info');
            // In a real implementation, this would trigger the digest generation
            setTimeout(() => {{
                showNotification('Threat digest generation started! Check back in a few minutes.', 'success');
            }}, 1000);
        }}
        
        function showActorWatch() {{
            showNotification('Opening actor watch interface...', 'info');
            // In a real implementation, this would open the actor watch interface
        }}
        
        function generateNewContent() {{
            showNotification('Generating new content...', 'info');
            // Simulate content generation
            setTimeout(() => {{
                refreshContent();
                showNotification('Content updated successfully!', 'success');
            }}, 2000);
        }}
        
        function refreshContent() {{
            // Add loading state
            document.body.classList.add('loading');
            
            // Simulate refresh
            setTimeout(() => {{
                document.body.classList.remove('loading');
                showNotification('Content refreshed!', 'success');
                // In a real implementation, this would reload the page data
            }}, 1000);
        }}
        
        // Notification system
        function showNotification(message, type = 'info') {{
            const notification = document.createElement('div');
            notification.className = `notification notification-${{type}}`;
            notification.textContent = message;
            
            // Style the notification
            Object.assign(notification.style, {{
                position: 'fixed',
                top: '20px',
                right: '20px',
                padding: '1rem 1.5rem',
                borderRadius: '8px',
                color: 'white',
                fontWeight: '600',
                fontSize: '0.875rem',
                zIndex: '1000',
                transform: 'translateX(400px)',
                transition: 'transform 0.3s ease',
                background: type === 'success' ? 'var(--success)' : 
                           type === 'error' ? 'var(--danger)' : 'var(--accent)',
                boxShadow: 'var(--shadow-lg)'
            }});
            
            document.body.appendChild(notification);
            
            // Animate in
            setTimeout(() => {{
                notification.style.transform = 'translateX(0)';
            }}, 100);
            
            // Remove after 3 seconds
            setTimeout(() => {{
                notification.style.transform = 'translateX(400px)';
                setTimeout(() => {{
                    document.body.removeChild(notification);
                }}, 300);
            }}, 3000);
        }}
        
        // Auto-refresh every 5 minutes
        setInterval(() => {{
            refreshContent();
        }}, 5 * 60 * 1000);
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {{
            showNotification('SecOps Innovation Platform loaded successfully!', 'success');
        }});
    </script>
</body>
</html>"""


def _format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"