"""Core logic for querying ATT&CK threat actor data."""

from __future__ import annotations

from collections import Counter
from typing import Any

from shared.mitre_data import (
    get_all_groups,
    get_group_by_name,
    get_software_used_by_group,
    get_techniques_used_by_group,
)


def list_all_groups() -> list[dict[str, Any]]:
    """Return all groups with a technique count appended."""
    groups = get_all_groups()
    for g in groups:
        techs = get_techniques_used_by_group(g["stix_id"])
        g["technique_count"] = len(techs)
    return groups


def get_actor_profile(name: str) -> dict[str, Any] | None:
    """Build a full profile for a named group/alias."""
    group = get_group_by_name(name)
    if group is None:
        return None

    techniques = get_techniques_used_by_group(group["stix_id"])
    software = get_software_used_by_group(group["stix_id"])

    tactic_counts: Counter[str] = Counter()
    for tech in techniques:
        from shared.mitre_data import get_technique_by_id

        full = get_technique_by_id(tech["id"])
        if full:
            for tac in full["tactics"]:
                tactic_counts[tac] += 1

    return {
        **group,
        "techniques": techniques,
        "software": software,
        "tactic_breakdown": dict(tactic_counts.most_common()),
    }


def format_actor_markdown(profile: dict[str, Any]) -> str:
    """Render an actor profile as Markdown."""
    lines = [f"**ID:** {profile['id']}"]
    if profile["aliases"]:
        lines.append(f"**Aliases:** {', '.join(profile['aliases'])}")
    lines.append("")

    desc = profile.get("description", "").strip()
    if desc:
        lines.append(desc[:1500])
        lines.append("")

    if profile["tactic_breakdown"]:
        lines.append("## Tactic Coverage")
        for tac, count in profile["tactic_breakdown"].items():
            lines.append(f"- **{tac}**: {count} techniques")
        lines.append("")

    if profile["techniques"]:
        lines.append(f"## Techniques ({len(profile['techniques'])})")
        for t in profile["techniques"]:
            lines.append(f"- `{t['id']}` — {t['name']}")
        lines.append("")

    if profile["software"]:
        lines.append(f"## Software ({len(profile['software'])})")
        for s in profile["software"]:
            lines.append(f"- `{s['id']}` — {s['name']}")

    return "\n".join(lines)
