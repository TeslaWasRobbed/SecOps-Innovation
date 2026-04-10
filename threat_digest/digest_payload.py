"""Structured digest payload (JSON from LLM) — parse, normalise, Markdown export."""

from __future__ import annotations

import json
import re
from typing import Any

# Included in the user prompt so the model knows the exact contract.
DIGEST_JSON_SCHEMA_INSTRUCTIONS = """
## Output format (required)

Respond with **only** a single JSON object (valid UTF-8). You may wrap it in a ```json code fence if you prefer; no other prose before or after.

Use **exactly** these top-level keys (arrays may be empty but keys must exist):

```json
{
  "key_vulnerabilities": [
    {
      "title": "One-line headline (include CVE id when from KEV)",
      "severity": "critical|high|medium|low|informational|null",
      "impact": "Plain text: why this matters for leadership and org context",
      "actions": ["Concrete step 1", "Concrete step 2"]
    }
  ],
  "notable_campaigns": [
    {
      "title": "Story cluster headline",
      "severity": "high|null",
      "impact": "Relevance and risk in plain text",
      "actions": ["Tactical step"]
    }
  ],
  "recommended_actions": [
    "Cross-cutting priority for the security team this week"
  ]
}
```

Rules:
- `severity` may be `null` if unknown; use lowercase enum values when set.
- `actions` is always an array of strings (use `[]` if none).
- Ground every item in the CISA KEV and RSS data below; do not invent CVEs or vendors.
- Keep text concise; no HTML inside strings.
"""


def extract_json_object(text: str) -> str | None:
    """Strip fences and isolate the outermost `{...}` if needed."""
    t = (text or "").strip()
    if not t:
        return None
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", t, re.IGNORECASE)
    if m:
        t = m.group(1).strip()
    if not t.startswith("{"):
        start, end = t.find("{"), t.rfind("}")
        if start >= 0 and end > start:
            t = t[start : end + 1]
    return t if t.startswith("{") else None


def parse_digest_json(text: str) -> dict[str, Any] | None:
    raw = extract_json_object(text)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _norm_threat_list(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title") or "").strip() or "Untitled"
        impact = str(it.get("impact") or "").strip()
        sev = it.get("severity")
        severity = None if sev is None else str(sev).strip().lower()
        if severity in ("", "null", "none"):
            severity = None
        actions_raw = it.get("actions")
        actions: list[str] = []
        if isinstance(actions_raw, list):
            actions = [str(a).strip() for a in actions_raw if str(a).strip()]
        elif isinstance(actions_raw, str) and actions_raw.strip():
            actions = [actions_raw.strip()]
        out.append(
            {
                "title": title,
                "severity": severity,
                "impact": impact,
                "actions": actions,
            }
        )
    return out


def _norm_recommended(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    return [str(x).strip() for x in items if str(x).strip()]


def normalize_digest_payload(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_vulnerabilities": _norm_threat_list(data.get("key_vulnerabilities")),
        "notable_campaigns": _norm_threat_list(data.get("notable_campaigns")),
        "recommended_actions": _norm_recommended(data.get("recommended_actions")),
    }


def payload_to_markdown(payload: dict[str, Any]) -> str:
    """Human-readable Markdown for `digest_*.md` when using structured mode."""
    p = normalize_digest_payload(payload)
    lines: list[str] = []

    lines.append("## Key Vulnerabilities to Act On\n")
    for v in p["key_vulnerabilities"]:
        sev = f" (**{v['severity']}**)" if v.get("severity") else ""
        lines.append(f"- **{v['title']}**{sev}\n")
        if v["impact"]:
            lines.append(f"  - **Why it matters:** {v['impact']}\n")
        if v["actions"]:
            lines.append("  - **Actions:**\n")
            for a in v["actions"]:
                lines.append(f"    - {a}\n")
        lines.append("\n")

    lines.append("## Notable Campaigns & Incidents\n")
    for v in p["notable_campaigns"]:
        sev = f" (**{v['severity']}**)" if v.get("severity") else ""
        lines.append(f"- **{v['title']}**{sev}\n")
        if v["impact"]:
            lines.append(f"  - **Why it matters:** {v['impact']}\n")
        if v["actions"]:
            lines.append("  - **Actions:**\n")
            for a in v["actions"]:
                lines.append(f"    - {a}\n")
        lines.append("\n")

    lines.append("## Recommended Actions\n")
    for a in p["recommended_actions"]:
        lines.append(f"- {a}\n")

    return "".join(lines).strip() + "\n"
