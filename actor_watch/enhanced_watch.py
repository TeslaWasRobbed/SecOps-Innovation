"""Enhanced actor watch supporting multiple threat intelligence sources."""

from __future__ import annotations

import logging
from typing import Any

from shared.microsoft_intel import (
    get_microsoft_actor,
    list_microsoft_actors, 
    search_microsoft_actors,
    format_microsoft_actor_markdown
)
from actor_watch.watch import get_actor_profile, format_actor_markdown, list_all_groups

logger = logging.getLogger(__name__)


def search_all_actors(query: str) -> list[dict[str, Any]]:
    """Search across all threat intelligence sources."""
    results = []
    
    # Search MITRE ATT&CK groups
    mitre_groups = list_all_groups()
    query_lower = query.lower()
    
    for group in mitre_groups:
        if (query_lower in group["name"].lower() or 
            any(query_lower in alias.lower() for alias in group.get("aliases", []))):
            results.append({
                **group,
                "source": "mitre_attack",
                "match_type": "name_alias"
            })
    
    # Search Microsoft threat actors
    microsoft_results = search_microsoft_actors(query)
    for actor in microsoft_results:
        results.append({
            **actor,
            "source": "microsoft",
            "match_type": "name_alias"
        })
    
    return results


def get_enhanced_actor_profile(name: str) -> dict[str, Any] | None:
    """Get actor profile from any supported source."""
    # Try Microsoft first (more specific naming)
    microsoft_actor = get_microsoft_actor(name)
    if microsoft_actor:
        return {
            **microsoft_actor,
            "source": "microsoft"
        }
    
    # Try MITRE ATT&CK
    mitre_profile = get_actor_profile(name)
    if mitre_profile:
        return {
            **mitre_profile,
            "source": "mitre_attack"
        }
    
    return None


def format_enhanced_actor_markdown(profile: dict[str, Any]) -> str:
    """Format actor profile based on source."""
    source = profile.get("source", "unknown")
    
    if source == "microsoft":
        return format_microsoft_actor_markdown(profile)
    elif source == "mitre_attack":
        return format_actor_markdown(profile)
    else:
        return f"Unknown source: {source}"


def list_all_enhanced_actors() -> list[dict[str, Any]]:
    """List actors from all sources."""
    actors = []
    
    # Add MITRE ATT&CK groups
    mitre_groups = list_all_groups()
    for group in mitre_groups:
        actors.append({
            **group,
            "source": "mitre_attack",
            "type": "apt_group"
        })
    
    # Add Microsoft threat actors
    microsoft_actors = list_microsoft_actors()
    actors.extend(microsoft_actors)
    
    return sorted(actors, key=lambda x: x["name"])


def get_actor_recommendations(actor_name: str) -> list[str]:
    """Get defensive recommendations based on actor profile."""
    profile = get_enhanced_actor_profile(actor_name)
    if not profile:
        return []
    
    recommendations = []
    source = profile.get("source", "")
    
    if source == "microsoft":
        # Microsoft-specific recommendations
        actor_type = profile.get("type", "")
        techniques = profile.get("techniques", [])
        sectors = profile.get("sectors", [])
        
        if "ransomware" in techniques:
            recommendations.extend([
                "Implement robust backup and recovery procedures",
                "Deploy endpoint detection and response (EDR) solutions",
                "Conduct regular ransomware tabletop exercises"
            ])
        
        if "credential_theft" in techniques:
            recommendations.extend([
                "Enforce multi-factor authentication (MFA)",
                "Implement privileged access management (PAM)",
                "Monitor for suspicious authentication patterns"
            ])
        
        if "phishing" in techniques:
            recommendations.extend([
                "Deploy advanced email security solutions",
                "Conduct regular phishing awareness training",
                "Implement email authentication (SPF, DKIM, DMARC)"
            ])
        
        if actor_type == "nation_state":
            recommendations.extend([
                "Implement network segmentation",
                "Deploy advanced threat hunting capabilities",
                "Establish threat intelligence sharing partnerships"
            ])
    
    elif source == "mitre_attack":
        # MITRE ATT&CK based recommendations
        techniques = profile.get("techniques", [])
        tactic_breakdown = profile.get("tactic_breakdown", {})
        
        if "initial-access" in tactic_breakdown:
            recommendations.append("Focus on initial access prevention controls")
        
        if "persistence" in tactic_breakdown:
            recommendations.append("Implement persistence detection mechanisms")
        
        if "lateral-movement" in tactic_breakdown:
            recommendations.append("Deploy network monitoring and segmentation")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)
    
    return unique_recommendations[:10]  # Limit to top 10


def generate_actor_watch_report(actor_name: str) -> dict[str, Any]:
    """Generate comprehensive actor watch report."""
    profile = get_enhanced_actor_profile(actor_name)
    if not profile:
        return {"error": f"No threat actor found matching '{actor_name}'"}
    
    recommendations = get_actor_recommendations(actor_name)
    markdown_content = format_enhanced_actor_markdown(profile)
    
    return {
        "actor_name": actor_name,
        "profile": profile,
        "recommendations": recommendations,
        "markdown": markdown_content,
        "source": profile.get("source", "unknown")
    }