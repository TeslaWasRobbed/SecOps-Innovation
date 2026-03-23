"""Core logic for generating Sentinel detection rules with Claude."""

from __future__ import annotations

import re
from typing import Any

from shared.llm import complete
from shared.mitre_data import get_technique_by_id

SYSTEM = (
    "You are a senior Microsoft Sentinel detection engineer. "
    "You write production-quality KQL analytics rules with YAML frontmatter."
)

PROMPT = """\
Write a Microsoft Sentinel scheduled analytics rule for the following ATT&CK technique.

**Technique:** {tid} — {name}
**Description:** {description}
**Tactics:** {tactics}
**Relevant data sources:** {data_sources}
{severity_hint}

The output MUST be a single fenced code block containing:
1. YAML frontmatter between --- markers with these fields:
   name, description, severity, enabled (true), tactics (list), techniques (list), entity_mappings (list)
2. A KQL query body after the closing --- that uses realistic Sentinel table names
   (e.g. SigninLogs, SecurityEvent, DeviceProcessEvents, IdentityDirectoryEvents, etc.)

Make the rule realistic, opinionated, and immediately usable. Include summarize/project
operators and meaningful entity mappings (Account, Host, IP as appropriate).
Do NOT include any text outside the fenced code block.
"""


def generate_rule(
    technique_id: str,
    *,
    severity: str | None = None,
    data_sources: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a KQL detection rule for a technique. Returns metadata + rule text."""
    tech = get_technique_by_id(technique_id)
    if tech is None:
        raise ValueError(f"Technique {technique_id} not found in ATT&CK Enterprise matrix.")

    sources = data_sources or tech.get("data_sources") or ["(not specified — use best judgement)"]
    severity_hint = f"**Suggested severity:** {severity}" if severity else ""

    prompt = PROMPT.format(
        tid=technique_id,
        name=tech["name"],
        description=tech["description"][:800],
        tactics=", ".join(tech["tactics"]) or "unknown",
        data_sources=", ".join(sources),
        severity_hint=severity_hint,
    )

    raw = complete(prompt, system=SYSTEM)
    rule_text = _extract_code_block(raw)

    return {
        "technique_id": technique_id,
        "technique_name": tech["name"],
        "tactics": tech["tactics"],
        "rule_text": rule_text,
    }


def _extract_code_block(text: str) -> str:
    """Pull the first fenced code block out of Claude's response, or return as-is."""
    match = re.search(r"```[\w]*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If the response itself starts with --- (no wrapping fence), use it directly
    stripped = text.strip()
    if stripped.startswith("---"):
        return stripped
    return stripped
