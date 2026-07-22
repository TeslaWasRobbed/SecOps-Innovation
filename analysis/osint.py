"""OSINT lookups for domains, IPs, and file hashes.

Two sources, both optional/independent:

- RDAP (``rdap.org`` bootstrap) — free, no API key, works for most domains/IPs.
- VirusTotal API v3 — needs ``VIRUSTOTAL_API_KEY`` in ``.env``; degrades gracefully
  (clear message, no crash) when the key is absent, and self-throttles to stay
  within the free-tier rate limit (4 requests/minute).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Literal

import requests
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_PATH)

logger = logging.getLogger(__name__)

_RDAP_BASE = "https://rdap.org"
_VT_BASE = "https://www.virustotal.com/api/v3"

QueryType = Literal["domain", "ip", "hash", "unknown"]

# Free-tier VirusTotal: 4 requests/minute, 500/day. We only self-limit the per-minute
# burst here — daily quota errors are surfaced from the API response itself.
_VT_MAX_CALLS_PER_WINDOW = 4
_VT_WINDOW_SECONDS = 60
_vt_call_times: deque[float] = deque(maxlen=_VT_MAX_CALLS_PER_WINDOW)

_HASH_RE = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}


def detect_query_type(query: str) -> QueryType:
    """Best-effort classification of a free-text OSINT query."""
    q = (query or "").strip()
    if not q:
        return "unknown"
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", q):
        return "hash"
    if re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", q):
        return "domain"
    return "unknown"


def _rdap_get(path: str) -> dict[str, Any]:
    url = f"{_RDAP_BASE}/{path}"
    try:
        resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=15)
    except requests.RequestException as exc:
        return {"available": False, "error": f"RDAP request failed: {exc}"}

    if resp.status_code == 404:
        return {"available": False, "error": "No RDAP record found (not registered, or registry does not support RDAP)."}
    if not resp.ok:
        return {"available": False, "error": f"RDAP lookup failed (HTTP {resp.status_code})."}

    try:
        data = resp.json()
    except ValueError:
        return {"available": False, "error": "RDAP response was not valid JSON."}

    return {"available": True, "raw": data}


def _rdap_events(data: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"action": e.get("eventAction", ""), "date": e.get("eventDate", "")}
        for e in data.get("events", []) or []
        if e.get("eventAction")
    ]


def lookup_domain_rdap(domain: str) -> dict[str, Any]:
    """RDAP lookup for a domain — registrar, status, nameservers, key dates."""
    result = _rdap_get(f"domain/{domain}")
    if not result.get("available"):
        return result

    data = result["raw"]
    registrar = None
    for entity in data.get("entities", []) or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[-1]
                        break
            registrar = registrar or entity.get("handle")
            break

    return {
        "available": True,
        "domain": data.get("ldhName", domain),
        "status": data.get("status", []),
        "registrar": registrar,
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) or [] if ns.get("ldhName")],
        "events": _rdap_events(data),
    }


def lookup_ip_rdap(ip: str) -> dict[str, Any]:
    """RDAP lookup for an IP — allocation range, network name, org/country."""
    result = _rdap_get(f"ip/{ip}")
    if not result.get("available"):
        return result

    data = result["raw"]
    org = None
    for entity in data.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if field[0] == "fn":
                    org = field[-1]
                    break
        if org:
            break

    return {
        "available": True,
        "network_name": data.get("name"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "country": data.get("country"),
        "org": org,
        "type": data.get("type"),
        "events": _rdap_events(data),
    }


def _vt_headroom() -> float:
    """Seconds to wait before another VirusTotal call is safely within the free-tier burst limit."""
    now = time.monotonic()
    while _vt_call_times and now - _vt_call_times[0] > _VT_WINDOW_SECONDS:
        _vt_call_times.popleft()
    if len(_vt_call_times) < _VT_MAX_CALLS_PER_WINDOW:
        return 0.0
    return max(0.0, _VT_WINDOW_SECONDS - (now - _vt_call_times[0]))


def _vt_api_key() -> str | None:
    key = (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
    return key or None


def lookup_virustotal(query: str, qtype: QueryType) -> dict[str, Any]:
    """VirusTotal v3 lookup for a domain, IP, or file hash."""
    api_key = _vt_api_key()
    if not api_key:
        return {"available": False, "configured": False, "error": "VIRUSTOTAL_API_KEY is not set in .env."}

    endpoint_by_type = {"domain": "domains", "ip": "ip_addresses", "hash": "files"}
    endpoint = endpoint_by_type.get(qtype)
    if endpoint is None:
        return {"available": False, "configured": True, "error": f"VirusTotal lookup not supported for query type '{qtype}'."}

    wait = _vt_headroom()
    if wait > 0:
        return {
            "available": False,
            "configured": True,
            "rate_limited": True,
            "error": f"VirusTotal free-tier burst limit reached — retry in ~{int(wait) + 1}s.",
        }

    url = f"{_VT_BASE}/{endpoint}/{query}"
    try:
        _vt_call_times.append(time.monotonic())
        resp = requests.get(url, headers={"x-apikey": api_key}, timeout=15)
    except requests.RequestException as exc:
        return {"available": False, "configured": True, "error": f"VirusTotal request failed: {exc}"}

    if resp.status_code == 401:
        return {"available": False, "configured": True, "error": "VirusTotal rejected the API key (401 Unauthorized)."}
    if resp.status_code == 404:
        return {"available": False, "configured": True, "error": "Not found in VirusTotal (no analysis on file/observable)."}
    if resp.status_code == 429:
        return {"available": False, "configured": True, "rate_limited": True, "error": "VirusTotal rate limit (429) — try again shortly."}
    if not resp.ok:
        return {"available": False, "configured": True, "error": f"VirusTotal lookup failed (HTTP {resp.status_code})."}

    try:
        payload = resp.json()
    except ValueError:
        return {"available": False, "configured": True, "error": "VirusTotal response was not valid JSON."}

    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}

    return {
        "available": True,
        "configured": True,
        "reputation": attrs.get("reputation"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "categories": attrs.get("categories"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "link": f"https://www.virustotal.com/gui/{endpoint}/{query}",
    }


def run_osint_lookup(query: str) -> dict[str, Any]:
    """Combined RDAP + VirusTotal lookup for one query, with type auto-detection."""
    query = (query or "").strip()
    qtype = detect_query_type(query)

    result: dict[str, Any] = {"query": query, "type": qtype}

    if qtype == "unknown":
        result["error"] = "Could not classify input as a domain, IP address, or file hash (md5/sha1/sha256)."
        return result

    if qtype == "domain":
        result["rdap"] = lookup_domain_rdap(query)
    elif qtype == "ip":
        result["rdap"] = lookup_ip_rdap(query)
    else:
        result["rdap"] = {"available": False, "error": "RDAP does not apply to file hashes."}

    result["virustotal"] = lookup_virustotal(query, qtype)
    return result
