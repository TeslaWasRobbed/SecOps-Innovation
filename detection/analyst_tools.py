"""Investigation helpers for SOC analysts."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)


def extract_indicators(text: str) -> list[dict[str, Any]]:
    """Extract simple indicators from free text."""
    indicators: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for match in _URL_RE.finditer(text or ""):
        value = match.group(0).rstrip(".,;:)")
        key = ("url", value)
        if key not in seen:
            indicators.append({"type": "url", "value": value})
            seen.add(key)

    for match in _HASH_RE.finditer(text or ""):
        value = match.group(0).lower()
        key = ("hash", value)
        if key not in seen:
            indicators.append({"type": "hash", "value": value})
            seen.add(key)

    for match in _DOMAIN_RE.finditer(text or ""):
        value = match.group(0).lower().rstrip(".,;:)")
        if not value.startswith("http"):
            key = ("domain", value)
            if key not in seen:
                indicators.append({"type": "domain", "value": value})
                seen.add(key)

    for match in _IP_RE.finditer(text or ""):
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        key = ("ip", value)
        if key not in seen:
            indicators.append({"type": "ip", "value": value})
            seen.add(key)

    return indicators


def build_siem_query(indicators: list[dict[str, Any]]) -> dict[str, str]:
    """Create simple SIEM query templates from extracted indicators."""
    if not indicators:
        return {"splunk": "index=* | head", "elastic": "*", "sentinel": "SecurityEvent | where TimeGenerated > ago(1d)"}

    terms = []
    for indicator in indicators:
        value = indicator.get("value", "")
        if not value:
            continue
        indicator_type = indicator.get("type", "")
        if indicator_type == "ip":
            terms.append(f'ipAddress == "{value}"')
        elif indicator_type == "domain":
            terms.append(f'dnsQuestion.name == "{value}"')
        elif indicator_type == "url":
            terms.append(f'urlContains "{value}"')
        elif indicator_type == "hash":
            terms.append(f'fileHash == "{value}"')

    if not terms:
        return {"splunk": "index=* | head", "elastic": "*", "sentinel": "SecurityEvent | where TimeGenerated > ago(1d)"}

    splunk = "index=* | search " + " OR ".join(terms)
    elastic = '{"query":{"bool":{"should":[{"match_phrase":{"dns.question.name":"' + terms[0].split(" == ")[1].strip('"') + '"}}]}}}'
    sentinel = "SecurityEvent | where TimeGenerated > ago(1d) | where " + " or ".join(terms)
    return {"splunk": splunk, "elastic": elastic, "sentinel": sentinel}
