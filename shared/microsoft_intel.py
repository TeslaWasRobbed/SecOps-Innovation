"""Microsoft threat intelligence data - Storm groups, Volt Typhoon, etc."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Microsoft threat actor naming patterns and known groups
MICROSOFT_THREAT_ACTORS = {
    # Storm groups (financially motivated)
    "storm-0324": {
        "name": "Storm-0324",
        "aliases": ["Storm-0324", "TA505"],
        "type": "financially_motivated",
        "description": "Financially motivated threat actor known for ransomware operations and credential theft campaigns.",
        "sectors": ["financial", "healthcare", "retail"],
        "techniques": ["phishing", "credential_theft", "ransomware", "lateral_movement"],
        "tools": ["Clop", "FlawedAmmyy", "SDBbot"],
        "active_since": "2019",
        "microsoft_id": "storm-0324"
    },
    "storm-0558": {
        "name": "Storm-0558",
        "aliases": ["Storm-0558"],
        "type": "nation_state",
        "attribution": "China",
        "description": "China-based threat actor targeting email systems for espionage, particularly focused on government and diplomatic entities.",
        "sectors": ["government", "diplomatic", "defense"],
        "techniques": ["email_compromise", "token_theft", "persistence", "espionage"],
        "tools": ["Outlook Web Access exploitation", "Azure AD token manipulation"],
        "active_since": "2021",
        "microsoft_id": "storm-0558",
        "recent_activity": [
            "2023: Major campaign targeting US government email systems",
            "2023: Azure AD authentication bypass techniques"
        ]
    },
    # Typhoon groups (nation-state, typically China)
    "volt-typhoon": {
        "name": "Volt Typhoon",
        "aliases": ["Volt Typhoon", "Bronze Silhouette", "Dev-0391"],
        "type": "nation_state", 
        "attribution": "China",
        "description": "China-based nation-state actor focused on critical infrastructure espionage and pre-positioning for potential disruption.",
        "sectors": ["critical_infrastructure", "communications", "energy", "water"],
        "techniques": ["living_off_the_land", "credential_theft", "lateral_movement", "persistence"],
        "tools": ["Built-in Windows tools", "PowerShell", "WMI", "Netsh"],
        "active_since": "2021",
        "microsoft_id": "volt-typhoon",
        "recent_activity": [
            "2024: Continued targeting of US critical infrastructure",
            "2023: Major campaign against Guam infrastructure",
            "2023: Living-off-the-land techniques in telecom sector"
        ]
    },
    # Flax Typhoon
    "flax-typhoon": {
        "name": "Flax Typhoon",
        "aliases": ["Flax Typhoon"],
        "type": "nation_state",
        "attribution": "China", 
        "description": "China-based threat actor conducting espionage operations against government and critical infrastructure.",
        "sectors": ["government", "critical_infrastructure", "telecommunications"],
        "techniques": ["supply_chain", "persistence", "lateral_movement", "data_collection"],
        "tools": ["China Chopper", "SoftEther VPN", "Custom malware"],
        "active_since": "2022",
        "microsoft_id": "flax-typhoon"
    },
    
    "storm-1175": {
        "name": "Storm-1175",
        "aliases": ["Storm-1175", "DEV-1175"],
        "type": "financially_motivated",
        "description": "Financially motivated cybercriminal group conducting ransomware and extortion operations targeting various industries with sophisticated attack chains.",
        "sectors": ["healthcare", "manufacturing", "education", "government", "financial_services"],
        "techniques": ["initial_access_broker", "ransomware", "data_exfiltration", "double_extortion", "living_off_the_land"],
        "tools": ["BlackCat", "ALPHV", "Cobalt Strike", "Mimikatz", "PowerShell", "WMI"],
        "active_since": "2022",
        "microsoft_id": "storm-1175",
        "recent_activity": [
            "2024-Q1: Targeting healthcare organizations with BlackCat ransomware variants",
            "2023-Q4: Double extortion campaigns against manufacturing sector using data theft",
            "2023-Q3: Initial access broker activities selling network access to other threat actors",
            "2023-Q2: Deployment of custom PowerShell frameworks for persistence"
        ]
    }
}

# Mapping patterns for flexible lookup
THREAT_ACTOR_PATTERNS = {
    r"storm[-\s]?(\d+)": "storm-{}",
    r"volt[-\s]?typhoon": "volt-typhoon", 
    r"flax[-\s]?typhoon": "flax-typhoon"
}


def normalize_actor_name(name: str) -> str:
    """Normalize threat actor name for consistent lookup."""
    name_lower = name.lower().strip()
    
    # Check exact matches first
    if name_lower in MICROSOFT_THREAT_ACTORS:
        return name_lower
    
    # Check pattern matches
    for pattern, template in THREAT_ACTOR_PATTERNS.items():
        match = re.match(pattern, name_lower)
        if match:
            if "{}" in template:
                return template.format(match.group(1))
            else:
                return template
    
    return name_lower


def get_microsoft_actor(name: str) -> dict[str, Any] | None:
    """Get Microsoft threat actor data by name or alias."""
    normalized = normalize_actor_name(name)
    
    # Direct lookup
    if normalized in MICROSOFT_THREAT_ACTORS:
        return MICROSOFT_THREAT_ACTORS[normalized]
    
    # Search by alias
    for actor_id, actor_data in MICROSOFT_THREAT_ACTORS.items():
        for alias in actor_data.get("aliases", []):
            if alias.lower() == normalized:
                return actor_data
    
    return None


def list_microsoft_actors() -> list[dict[str, Any]]:
    """List all Microsoft threat actors."""
    actors = []
    for actor_id, actor_data in MICROSOFT_THREAT_ACTORS.items():
        actors.append({
            "id": actor_id,
            **actor_data,
            "source": "microsoft"
        })
    
    return sorted(actors, key=lambda x: x["name"])


def search_microsoft_actors(query: str) -> list[dict[str, Any]]:
    """Search Microsoft threat actors by name, alias, or description."""
    query_lower = query.lower()
    results = []
    
    for actor_id, actor_data in MICROSOFT_THREAT_ACTORS.items():
        # Check name and aliases
        if (query_lower in actor_data["name"].lower() or 
            any(query_lower in alias.lower() for alias in actor_data.get("aliases", []))):
            results.append({"id": actor_id, **actor_data, "source": "microsoft"})
            continue
            
        # Check description
        if query_lower in actor_data.get("description", "").lower():
            results.append({"id": actor_id, **actor_data, "source": "microsoft"})
    
    return results


def format_microsoft_actor_markdown(actor: dict[str, Any]) -> str:
    """Format Microsoft threat actor data as Markdown."""
    lines = [f"**Microsoft ID:** {actor.get('microsoft_id', 'N/A')}"]
    
    if actor.get("aliases"):
        lines.append(f"**Aliases:** {', '.join(actor['aliases'])}")
    
    if actor.get("type"):
        actor_type = actor["type"].replace("_", " ").title()
        lines.append(f"**Type:** {actor_type}")
    
    if actor.get("attribution"):
        lines.append(f"**Attribution:** {actor['attribution']}")
    
    if actor.get("active_since"):
        lines.append(f"**Active Since:** {actor['active_since']}")
    
    lines.append("")
    
    # Description
    if actor.get("description"):
        lines.append(actor["description"])
        lines.append("")
    
    # Targeted sectors
    if actor.get("sectors"):
        lines.append("## Targeted Sectors")
        for sector in actor["sectors"]:
            lines.append(f"- {sector.replace('_', ' ').title()}")
        lines.append("")
    
    # Techniques
    if actor.get("techniques"):
        lines.append("## Known Techniques")
        for technique in actor["techniques"]:
            lines.append(f"- {technique.replace('_', ' ').title()}")
        lines.append("")
    
    # Tools
    if actor.get("tools"):
        lines.append("## Associated Tools")
        for tool in actor["tools"]:
            lines.append(f"- {tool}")
        lines.append("")
    
    # Recent activity
    if actor.get("recent_activity"):
        lines.append("## Recent Activity")
        for activity in actor["recent_activity"]:
            lines.append(f"- {activity}")
        lines.append("")
    
    lines.append("---")
    lines.append("*Source: Microsoft Threat Intelligence*")
    
    return "\n".join(lines)