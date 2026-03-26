"""Core logic for generating Sentinel detection rules following ScheduledRuleTemplate.yaml structure."""

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

The output MUST be a single fenced code block containing a YAML rule that follows this EXACT structure:

```yaml
id: 00000000-0000-0000-0000-000000000000
name: "[{primary_tactic}] <Alert Name>"
description: |
  DO NOT EDIT IN PORTAL - MANAGED VIA GIT REPO.
  
  <Describe what the detection finds>
  <Explain why it matters (risk/behavior/attacker intent)>
  <Add expected SOC analyst action or playbook if applicable>

enabled: true
status: Available
severity: {severity_level}

requiredDataConnectors:
  - connectorId: <ConnectorId>
    dataTypes:
      - <DataType>

queryFrequency: PT1H
queryPeriod: PT2H

query: |
  // <KQL query here using realistic Sentinel table names>
  // Ensure all columns referenced in entityMappings, customDetails exist in output

triggerOperator: gt
triggerThreshold: 0

tactics:
  - {primary_tactic}
relevantTechniques:
  - {tid}

tags:
  - ManagedBy:Repository
  - Owner:SOC
  - Category:<Category>
  - Version:1.0.0

entityMappings:
  - entityType: <EntityType>
    fieldMappings:
      - identifier: <Identifier>
        columnName: <ColumnName>

alertDetailsOverride:
  alertDisplayNameFormat: "<Dynamic alert title>"
  alertDescriptionFormat: "<Dynamic alert description>"

customDetails:
  <Key>: <ColumnName>

eventGroupingSettings:
  aggregationKind: SingleAlert

incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false
    lookbackDuration: PT5H
    matchingMethod: AllEntities

suppressionEnabled: false
suppressionDuration: PT1H

version: 1.0.0
kind: Scheduled
```

Make the rule realistic, production-ready, and immediately usable. Use appropriate connector IDs, data types, and entity mappings for the technique.
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
    severity_level = severity or "Medium"
    primary_tactic = tech["tactics"][0] if tech["tactics"] else "Unknown"
    severity_hint = f"**Suggested severity:** {severity_level}"

    prompt = PROMPT.format(
        tid=technique_id,
        name=tech["name"],
        description=tech["description"][:800],
        tactics=", ".join(tech["tactics"]) or "unknown",
        data_sources=", ".join(sources),
        severity_hint=severity_hint,
        primary_tactic=primary_tactic,
        severity_level=severity_level,
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
