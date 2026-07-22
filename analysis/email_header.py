"""Email / message header analysis: authentication results, hop timeline,
spoofing heuristics, and IOC extraction.

This is a heuristic *screening* aid for analysts pasting raw headers (or a
full .eml) — it does not replace deep forensic email analysis, and every
flag is worded as "worth checking" rather than a definitive verdict.

Stdlib-only (``email``, ``re``, ``ipaddress``) — no network calls here;
OSINT lookups for extracted IOCs live in ``analysis.osint``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from email import message_from_string
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

logger = logging.getLogger(__name__)

# Brands/services commonly impersonated in phishing display names.
_COMMON_IMPERSONATION_BRANDS = (
    "paypal", "microsoft", "office365", "docusign", "amazon", "apple",
    "netflix", "linkedin", "dhl", "fedex", "ups", "hmrc", "irs", "bank",
    "google", "outlook", "adobe", "dropbox", "zoom", "americanexpress",
    "wellsfargo", "chase", "hsbc", "barclays",
)

# Narrower brand -> official domain map, used to catch "paypal-secure-login.com"-style
# lookalikes where the brand name is baked into an unofficial sending domain.
_BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "outlook.com"),
    "office365": ("microsoft.com", "office.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "amazon": ("amazon.com",),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "google": ("google.com", "gmail.com"),
    "adobe": ("adobe.com",),
    "dropbox": ("dropbox.com",),
    "zoom": ("zoom.us",),
}

_URL_RE = re.compile(r"https?://[^\s<>\"'()\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
# Dotted syntax tokens from headers like Authentication-Results (header.from=, smtp.mailfrom=)
# that match the domain regex shape but are not real domains/IOCs.
_NON_TLD_LAST_LABELS = {"from", "to", "by", "with", "for", "mailfrom", "helo", "source", "envelope", "of", "reply", "d", "i"}

_HOP_FROM_RE = re.compile(r"\bfrom\s+([^\s;]+(?:\s+\([^)]*\))?)", re.IGNORECASE)
_HOP_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
_HOP_WITH_RE = re.compile(r"\bwith\s+([^\s;]+)", re.IGNORECASE)

_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">").strip() or None


def _first_address(msg: Message, header: str) -> tuple[str, str] | None:
    """Return (display_name, email_address) for the first address in *header*."""
    raw = msg.get(header)
    if not raw:
        return None
    parsed = getaddresses([raw])
    return parsed[0] if parsed else None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def parse_headers(raw_text: str) -> Message:
    """Parse raw header text (or a full .eml) into an ``email.message.Message``."""
    return message_from_string(raw_text or "")


def analyze_authentication(msg: Message) -> dict[str, Any]:
    """Parse SPF/DKIM/DMARC results from Authentication-Results / Received-SPF."""
    results: dict[str, str] = {"spf": "none", "dkim": "none", "dmarc": "none"}
    sources: list[str] = []

    for header_name in ("Authentication-Results", "Received-SPF"):
        for raw in msg.get_all(header_name) or []:
            sources.append(f"{header_name}: {raw}")
            for match in _AUTH_RESULT_RE.finditer(raw):
                mechanism, verdict = match.group(1).lower(), match.group(2).lower()
                # First (most recent / outermost) result wins if multiple are present.
                if results.get(mechanism) in (None, "none"):
                    results[mechanism] = verdict
            if header_name == "Received-SPF" and "spf" not in raw.lower():
                # Legacy header format: "pass (reason) client-ip=..."
                first_word = raw.strip().split(" ", 1)[0].lower()
                if first_word and results["spf"] == "none":
                    results["spf"] = first_word

    return {"spf": results["spf"], "dkim": results["dkim"], "dmarc": results["dmarc"], "sources": sources}


def analyze_hops(msg: Message) -> list[dict[str, Any]]:
    """Parse Received headers into a chronological hop timeline with inter-hop deltas."""
    raw_hops = msg.get_all("Received") or []
    # Received headers are prepended by each relay, so the raw order is newest-first.
    chronological = list(reversed(raw_hops))

    hops: list[dict[str, Any]] = []
    prev_dt = None
    for idx, raw in enumerate(chronological, start=1):
        from_m = _HOP_FROM_RE.search(raw)
        by_m = _HOP_BY_RE.search(raw)
        with_m = _HOP_WITH_RE.search(raw)

        date_part = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
        dt = None
        if date_part:
            try:
                dt = parsedate_to_datetime(date_part)
            except (TypeError, ValueError):
                dt = None

        delta_seconds = None
        flags: list[str] = []
        if dt is not None and prev_dt is not None:
            delta_seconds = int((dt - prev_dt).total_seconds())
            if delta_seconds < 0:
                flags.append("Timestamp moved backwards vs. previous hop — possible clock skew or tampering")
            elif delta_seconds > 3600:
                flags.append(f"Large gap since previous hop (~{delta_seconds // 60} min) — worth checking")
        if dt is not None:
            prev_dt = dt

        hops.append(
            {
                "index": idx,
                "from": from_m.group(1) if from_m else None,
                "by": by_m.group(1) if by_m else None,
                "with": with_m.group(1) if with_m else None,
                "date": dt.isoformat() if dt else None,
                "delta_seconds": delta_seconds,
                "flags": flags,
                "raw": raw.strip(),
            }
        )
    return hops


def detect_spoofing_signals(msg: Message, known_domains: list[str] | None = None) -> list[dict[str, str]]:
    """Heuristic checks for From/Reply-To/Return-Path mismatch, brand impersonation, and lookalike domains."""
    signals: list[dict[str, str]] = []
    known_domains = [d.strip().lower() for d in (known_domains or []) if d.strip()]

    from_pair = _first_address(msg, "From")
    reply_pair = _first_address(msg, "Reply-To")
    return_path_raw = (msg.get("Return-Path") or "").strip().strip("<>")

    from_name, from_addr = from_pair if from_pair else ("", "")
    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_pair[1]) if reply_pair else None
    return_domain = _domain_of(return_path_raw) if return_path_raw else None

    if from_domain and reply_domain and reply_domain != from_domain:
        signals.append(
            {
                "type": "reply_to_mismatch",
                "severity": "medium",
                "detail": f"Reply-To domain ('{reply_domain}') differs from From domain ('{from_domain}') — "
                "common in mailing lists, but also a classic BEC/phishing pattern. Worth checking.",
            }
        )
    if from_domain and return_domain and return_domain != from_domain:
        signals.append(
            {
                "type": "return_path_mismatch",
                "severity": "medium",
                "detail": f"Return-Path domain ('{return_domain}') differs from From domain ('{from_domain}'). "
                "Worth checking — legitimate for some bulk-mail senders, suspicious otherwise.",
            }
        )

    if from_name and from_domain:
        name_lower = from_name.lower()
        for brand in _COMMON_IMPERSONATION_BRANDS:
            if brand in name_lower and brand not in from_domain.replace("-", "").replace(".", ""):
                signals.append(
                    {
                        "type": "brand_impersonation",
                        "severity": "high",
                        "detail": f"Display name references '{brand}' but the From domain ('{from_domain}') "
                        "does not — classic display-name spoofing pattern.",
                    }
                )
                break

    if from_domain:
        for brand, official_domains in _BRAND_OFFICIAL_DOMAINS.items():
            if brand not in from_domain.replace("-", ""):
                continue
            is_official = any(
                from_domain == official or from_domain.endswith("." + official) for official in official_domains
            )
            if not is_official:
                signals.append(
                    {
                        "type": "brand_domain_mismatch",
                        "severity": "high",
                        "detail": f"'{brand}' appears in the sending domain ('{from_domain}') but it is not an "
                        f"official {brand} domain ({', '.join(official_domains)}) — classic lookalike/typosquat pattern.",
                    }
                )
            break

    candidate_domains = {d for d in (from_domain, reply_domain, return_domain) if d}
    for candidate in candidate_domains:
        if candidate in known_domains:
            continue
        for known in known_domains:
            if candidate == known:
                continue
            distance = _levenshtein(candidate, known)
            if 0 < distance <= 2 and abs(len(candidate) - len(known)) <= 2:
                signals.append(
                    {
                        "type": "lookalike_domain",
                        "severity": "high",
                        "detail": f"'{candidate}' closely resembles your known domain '{known}' "
                        f"(edit distance {distance}) — possible typosquat/lookalike.",
                    }
                )
                break

    return signals


def extract_iocs(raw_text: str) -> dict[str, list[dict[str, str]]]:
    """Extract candidate IPs, domains, and URLs from raw header/body text."""
    if not raw_text:
        return {"ips": [], "domains": [], "urls": []}

    urls = sorted(set(_URL_RE.findall(raw_text)))

    ips: list[dict[str, str]] = []
    seen_ips: set[str] = set()
    for candidate in _IPV4_RE.findall(raw_text):
        if candidate in seen_ips:
            continue
        seen_ips.add(candidate)
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        kind = "private" if (addr.is_private or addr.is_loopback or addr.is_link_local) else "public"
        ips.append({"value": candidate, "type": kind})

    domains: set[str] = set()
    for url in urls:
        m = re.match(r"https?://([^/\s:]+)", url, re.IGNORECASE)
        if m:
            domains.add(m.group(1).lower())
    for m in _DOMAIN_RE.finditer(raw_text):
        candidate = m.group(0).lower()
        # Skip things that are really IPs matched loosely, or version-like numeric tokens.
        if _IPV4_RE.fullmatch(candidate):
            continue
        # Skip Authentication-Results-style syntax tokens (header.from=, smtp.mailfrom=) that
        # match the domain shape but are not real domains/IOCs.
        if candidate.rsplit(".", 1)[-1] in _NON_TLD_LAST_LABELS:
            continue
        domains.add(candidate)

    return {
        "ips": ips,
        "domains": sorted(domains),
        "urls": urls,
    }


def score_risk(auth: dict[str, Any], spoofing_signals: list[dict[str, str]], hops: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine signals into a coarse Low/Medium/High heuristic risk score."""
    score = 0
    reasons: list[str] = []

    if auth.get("dmarc") == "fail":
        score += 3
        reasons.append("DMARC failed")
    if auth.get("spf") == "fail":
        score += 2
        reasons.append("SPF failed")
    if auth.get("dkim") in ("fail", "none"):
        score += 1
        reasons.append(f"DKIM {auth.get('dkim')}")

    for sig in spoofing_signals:
        weight = {"low": 1, "medium": 2, "high": 3}.get(sig.get("severity", "low"), 1)
        score += weight
        reasons.append(sig["detail"])

    for hop in hops:
        if hop.get("flags"):
            score += 1
            reasons.extend(hop["flags"])

    if score >= 6:
        level = "High"
    elif score >= 3:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Informational"

    return {"score": score, "level": level, "reasons": reasons}


def analyze_message(raw_text: str, known_domains: list[str] | None = None) -> dict[str, Any]:
    """Top-level orchestrator: parse headers, auth, hops, spoofing, IOCs, and a risk verdict."""
    msg = parse_headers(raw_text)

    from_pair = _first_address(msg, "From")
    to_addrs = getaddresses(msg.get_all("To") or [])
    reply_pair = _first_address(msg, "Reply-To")

    headers_summary = {
        "from": {"name": from_pair[0], "address": from_pair[1]} if from_pair else None,
        "to": [{"name": n, "address": a} for n, a in to_addrs] or None,
        "reply_to": {"name": reply_pair[0], "address": reply_pair[1]} if reply_pair else None,
        "return_path": (msg.get("Return-Path") or "").strip().strip("<>") or None,
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
    }

    auth = analyze_authentication(msg)
    hops = analyze_hops(msg)
    spoofing_signals = detect_spoofing_signals(msg, known_domains)
    iocs = extract_iocs(raw_text)
    risk = score_risk(auth, spoofing_signals, hops)

    warnings: list[str] = []
    if not auth["sources"]:
        warnings.append("No Authentication-Results/Received-SPF header found — SPF/DKIM/DMARC could not be verified.")
    if not hops:
        warnings.append("No Received headers found — hop/relay path could not be analysed.")

    return {
        "headers": headers_summary,
        "authentication": auth,
        "hops": hops,
        "spoofing_signals": spoofing_signals,
        "iocs": iocs,
        "risk": risk,
        "warnings": warnings,
    }
