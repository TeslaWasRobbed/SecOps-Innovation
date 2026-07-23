"""Investigation helpers for SOC analysts."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)


def _clean_value(value: str) -> str:
    return value.strip().rstrip(".,;:)")


def extract_indicators(text: str) -> list[dict[str, Any]]:
    """Extract indicators and contextual artifacts from free text."""
    indicators: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    normalized_text = text or ""

    for match in _URL_RE.finditer(normalized_text):
        value = _clean_value(match.group(0))
        key = ("url", value)
        if key not in seen:
            indicators.append({"type": "url", "value": value})
            seen.add(key)

    for match in _HASH_RE.finditer(normalized_text):
        value = match.group(0).lower()
        key = ("hash", value)
        if key not in seen:
            indicators.append({"type": "hash", "value": value})
            seen.add(key)

    for match in _DOMAIN_RE.finditer(normalized_text):
        value = _clean_value(match.group(0).lower())
        if not value.startswith("http"):
            key = ("domain", value)
            if key not in seen:
                indicators.append({"type": "domain", "value": value})
                seen.add(key)

    for match in _IP_RE.finditer(normalized_text):
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        key = ("ip", value)
        if key not in seen:
            indicators.append({"type": "ip", "value": value})
            seen.add(key)

    for match in _EMAIL_RE.finditer(normalized_text):
        value = _clean_value(match.group(0).lower())
        key = ("email", value)
        if key not in seen:
            indicators.append({"type": "email", "value": value})
            seen.add(key)

    return indicators


def build_siem_query(indicators: list[dict[str, Any]]) -> dict[str, str]:
    """Create richer SIEM query templates from extracted indicators."""
    if not indicators:
        return {"splunk": "index=* | head", "elastic": "*", "sentinel": "SecurityEvent | where TimeGenerated > ago(1d)"}

    terms: list[tuple[str, str]] = []
    for indicator in indicators:
        value = str(indicator.get("value", "") or "").strip()
        if not value:
            continue
        indicator_type = str(indicator.get("type", "") or "")
        if indicator_type == "ip":
            terms.append(("ip", f'ipAddress == "{value}"'))
        elif indicator_type == "domain":
            terms.append(("domain", f'dnsQuestion.name == "{value}"'))
        elif indicator_type == "url":
            terms.append(("url", f'urlContains "{value}"'))
        elif indicator_type == "hash":
            terms.append(("hash", f'fileHash == "{value}"'))
        elif indicator_type == "email":
            terms.append(("email", f'emailAddress == "{value}"'))

    if not terms:
        return {"splunk": "index=* | head", "elastic": "*", "sentinel": "SecurityEvent | where TimeGenerated > ago(1d)"}

    splunk_terms = [expr for _, expr in terms]
    splunk = "index=* | search " + " OR ".join(splunk_terms)
    elastic_should = []
    for indicator_type, expr in terms:
        if indicator_type == "domain":
            elastic_should.append('{"match_phrase":{"dns.question.name":"' + expr.split(' == ')[1].strip('"') + '"}}')
        elif indicator_type == "ip":
            elastic_should.append('{"match_phrase":{"source.ip":"' + expr.split(' == ')[1].strip('"') + '"}}')
        elif indicator_type == "email":
            elastic_should.append('{"match_phrase":{"user.email":"' + expr.split(' == ')[1].strip('"') + '"}}')
        else:
            elastic_should.append('{"wildcard":{"url.full":"*' + expr.split(' == ')[1].strip('"') + '*"}}')
    elastic = '{"query":{"bool":{"should":[' + ",".join(elastic_should) + ']}}}'
    sentinel = "SecurityEvent | where TimeGenerated > ago(1d) | where " + " or ".join(splunk_terms)
    return {"splunk": splunk, "elastic": elastic, "sentinel": sentinel}


def build_investigation_summary(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a compact, analyst-friendly summary for extracted indicators."""
    by_type = Counter(str(indicator.get("type", "unknown")) for indicator in indicators)
    recommended_actions = []
    if by_type.get("domain"):
        recommended_actions.append("Review domain activity and pivot to DNS/Proxy telemetry for the extracted domain(s).")
    if by_type.get("ip"):
        recommended_actions.append("Check IP reputation, firewall, and authentication logs for the extracted IP(s).")
    if by_type.get("hash"):
        recommended_actions.append("Search endpoint and email telemetry for the extracted file hash(es).")
    if by_type.get("email"):
        recommended_actions.append("Review sender reputation and mailbox delivery logs associated with the extracted email address(es).")
    if not recommended_actions:
        recommended_actions.append("Review the extracted indicators in your primary telemetry sources.")
    return {
        "total_indicators": len(indicators),
        "by_type": dict(by_type),
        "recommended_actions": recommended_actions,
    }
