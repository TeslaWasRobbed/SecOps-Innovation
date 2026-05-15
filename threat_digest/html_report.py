"""Stakeholder HTML report — cyber intelligence briefing (editorial layout, executive / SecOps view modes)."""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import markdown

logger = logging.getLogger(__name__)


def _markdown_to_html(md_text: str) -> str:
    md = markdown.Markdown(extensions=["extra", "nl2br"])
    return md.convert(md_text)


_SEVERITY_CLASS: dict[str, str] = {
    "critical": "sev-critical",
    "severe": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "informational": "sev-info",
    "info": "sev-info",
}

# Longest keys first so "Informational" wins over "Info"
_SEVERITY_WORDS_ORDERED = (
    "Informational",
    "Critical",
    "Severe",
    "Medium",
    "High",
    "Low",
    "Info",
)


def _sev_class_for_word(word: str) -> str:
    return _SEVERITY_CLASS.get(word.lower(), "sev-medium")


def _badge_severity_in_strong_tags(fragment: str) -> str:
    def repl(m: re.Match[str]) -> str:
        w = m.group(1)
        cls = _sev_class_for_word(w)
        wl = w.lower()
        return (
            f'<span class="sev {cls}" data-sev-badge="1" data-sev="{html.escape(wl)}">'
            f"<strong>{w}</strong></span>"
        )

    return re.sub(
        r"<strong>(Critical|High|Medium|Low|Informational|Info|Severe)</strong>",
        repl,
        fragment,
        flags=re.IGNORECASE,
    )


def _badge_severity_after_labels(fragment: str) -> str:
    """e.g. Severity: High → Severity: <span class=sev...>High</span>"""

    def repl(m: re.Match[str]) -> str:
        label, w = m.group(1), m.group(2)
        cls = _sev_class_for_word(w)
        wl = w.lower()
        return (
            f'{label}: <span class="sev {cls}" data-sev-badge="1" data-sev="{html.escape(wl)}">'
            f"<strong>{w}</strong></span>"
        )

    return re.sub(
        r"(Severity|Priority|Impact|Risk)\s*:\s*(Critical|High|Medium|Low|Informational|Info|Severe)\b",
        repl,
        fragment,
        flags=re.IGNORECASE,
    )


def _badge_plain_severity_words(fragment: str) -> str:
    """Word-boundary severities in text nodes only (skip inside our sev spans)."""
    pattern = "|".join(re.escape(w) for w in _SEVERITY_WORDS_ORDERED)
    word_re = re.compile(rf"\b({pattern})\b", re.IGNORECASE)

    def replace_words(text: str) -> str:
        def wrepl(m: re.Match[str]) -> str:
            w = m.group(1)
            cls = _sev_class_for_word(w)
            wl = w.lower()
            return (
                f'<span class="sev {cls}" data-sev-badge="1" data-sev="{html.escape(wl)}">'
                f"<strong>{w}</strong></span>"
            )

        return word_re.sub(wrepl, text)

    parts = re.split(r"(<[^>]+>)", fragment)
    depth = 0
    out: list[str] = []
    for p in parts:
        if not p:
            continue
        if p.startswith("<span") and 'data-sev-badge="1"' in p:
            depth += 1
            out.append(p)
        elif p == "</span>" and depth > 0:
            depth -= 1
            out.append(p)
        elif p.startswith("<"):
            out.append(p)
        elif depth == 0:
            out.append(replace_words(p))
        else:
            out.append(p)
    return "".join(out)


def _highlight_action_phrases(fragment: str) -> str:
    """Mark Action: / Immediate action: style lead-ins for scannability."""

    def strong_action_repl(m: re.Match[str]) -> str:
        phrase = m.group(1)
        return f'<span class="action-label"><strong>{phrase}</strong>:</span> '

    fragment = re.sub(
        r"(?i)<strong>(Immediate action|Recommended action|Actions?)</strong>\s*:\s*",
        strong_action_repl,
        fragment,
    )

    def action_in_text(text: str) -> str:
        text = re.sub(
            r"(?i)^(\s*Immediate action\s*:\s*)",
            r'<span class="action-label">Immediate action:</span> ',
            text,
        )
        text = re.sub(
            r"(?i)^(\s*Recommended action\s*:\s*)",
            r'<span class="action-label">Recommended action:</span> ',
            text,
        )
        text = re.sub(
            r"(?i)^(\s*Action\s*:\s*)",
            r'<span class="action-label">Action:</span> ',
            text,
        )
        text = re.sub(
            r"(?i)(\n\s*)Action\s*:\s*",
            r'\1<span class="action-label">Action:</span> ',
            text,
        )
        text = re.sub(
            r"(?i)(\n\s*)Immediate action\s*:\s*",
            r'\1<span class="action-label">Immediate action:</span> ',
            text,
        )
        return text

    parts = re.split(r"(<[^>]+>)", fragment)
    out: list[str] = []
    for p in parts:
        if p.startswith("<"):
            out.append(p)
        else:
            out.append(action_in_text(p))
    return "".join(out)


_SVG_LABEL_IMPACT = (
    '<svg class="digest-label-svg" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="2" aria-hidden="true">'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    '<circle cx="12" cy="10" r="2.5" fill="currentColor" stroke="none" opacity="0.35"/>'
    "</svg>"
)
_SVG_LABEL_SECOPS = (
    '<svg class="digest-label-svg" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="2" aria-hidden="true">'
    '<rect x="3" y="4" width="18" height="14" rx="2"/>'
    '<path d="M7 9h6M7 12h4M7 15h8"/><path d="M17 8l1.5 1.5L17 11" stroke-linecap="round"/>'
    "</svg>"
)
_DIGEST_LABEL_IMPACT = (
    '<p class="digest-block-label digest-block-label--impact" title="Why it matters">'
    '<span class="digest-label-icon digest-label-icon--impact" aria-hidden="true">'
    f"{_SVG_LABEL_IMPACT}</span>"
    '<span class="digest-label-text">Impact</span></p>'
)
_DIGEST_LABEL_SECOPS = (
    '<p class="digest-block-label digest-block-label--actions" title="Recommended actions">'
    '<span class="digest-label-icon digest-label-icon--actions" aria-hidden="true">'
    f"{_SVG_LABEL_SECOPS}</span>"
    '<span class="digest-label-text">SecOps</span></p>'
)


def _structure_digest_labels(fragment: str) -> str:
    """
    Promote 'Why it matters' and 'Actions' rows into labeled sub-blocks instead of
    anonymous list peers (matches common LLM markdown shapes).
    """

    def _fold_actions_strong(m: re.Match[str]) -> str:
        items = m.group(1).strip()
        return (
            '<li class="digest-li-block digest-li-block--actions">'
            + _DIGEST_LABEL_SECOPS
            + "<ul>"
            + items
            + "</ul></li>"
        )

    fragment = re.sub(
        r"<li>\s*<strong>Actions:\s*</strong>\s*</li>\s*((?:<li\b[^>]*>[\s\S]*?</li>\s*)+)",
        _fold_actions_strong,
        fragment,
        flags=re.IGNORECASE,
    )
    fragment = re.sub(
        r"<li>\s*<p>Actions\s*</p>\s*<ul>",
        r'<li class="digest-li-block digest-li-block--actions">'
        + _DIGEST_LABEL_SECOPS
        + "<ul>",
        fragment,
        flags=re.IGNORECASE,
    )
    fragment = re.sub(
        r"<li>\s*<p>Actions:\s*</p>\s*<ul>",
        r'<li class="digest-li-block digest-li-block--actions">'
        + _DIGEST_LABEL_SECOPS
        + "<ul>",
        fragment,
        flags=re.IGNORECASE,
    )
    fragment = re.sub(
        r"<li>Actions\s*<ul>",
        r'<li class="digest-li-block digest-li-block--actions">'
        + _DIGEST_LABEL_SECOPS
        + "<ul>",
        fragment,
        flags=re.IGNORECASE,
    )
    fragment = re.sub(
        r"<li>\s*<p>\s*<strong>Why it matters:\s*</strong>\s*(.*?)</p>\s*</li>",
        r'<li class="digest-li-block digest-li-block--why">'
        + _DIGEST_LABEL_IMPACT
        + r'<div class="digest-subblock-body"><p>\1</p></div></li>',
        fragment,
        flags=re.IGNORECASE | re.DOTALL,
    )
    fragment = re.sub(
        r"<li>\s*<p>Why it matters:\s*(.*?)</p>\s*</li>",
        r'<li class="digest-li-block digest-li-block--why">'
        + _DIGEST_LABEL_IMPACT
        + r'<div class="digest-subblock-body"><p>\1</p></div></li>',
        fragment,
        flags=re.IGNORECASE | re.DOTALL,
    )
    fragment = re.sub(
        r"<li>\s*<strong>Why it matters:\s*</strong>\s*(.*?)</li>",
        '<li class="digest-li-block digest-li-block--why">'
        + _DIGEST_LABEL_IMPACT
        + r'<div class="digest-subblock-body">\1</div></li>',
        fragment,
        flags=re.IGNORECASE | re.DOTALL,
    )
    fragment = re.sub(
        r"<li>Why it matters:\s*(.*?)</li>",
        '<li class="digest-li-block digest-li-block--why">'
        + _DIGEST_LABEL_IMPACT
        + r'<div class="digest-subblock-body">\1</div></li>',
        fragment,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return fragment


def _enrich_digest_html(fragment: str) -> str:
    """Badges, action highlights — order matters to avoid double-wrapping."""
    fragment = _structure_digest_labels(fragment)
    fragment = _badge_severity_in_strong_tags(fragment)
    fragment = _badge_severity_after_labels(fragment)
    fragment = _badge_plain_severity_words(fragment)
    fragment = _highlight_action_phrases(fragment)
    return fragment


def _sectionize_prose_html(fragment: str) -> str:
    """
    Wrap each logical block (from one ``h2`` to the next) in a section card so the page
    is not one uninterrupted wall of text.
    """
    fragment = fragment.strip()
    if not fragment:
        return fragment
    pieces = re.split(r"(?=<h2\b)", fragment, flags=re.IGNORECASE)
    out: list[str] = []
    for piece in pieces:
        piece = piece.strip()
        if not piece:
            continue
        if re.match(r"<h2\b", piece, re.IGNORECASE):
            out.append(f'<section class="digest-section">{piece}</section>')
        else:
            out.append(f'<section class="digest-section digest-section--preamble">{piece}</section>')
    return "\n".join(out)


def _is_li_open(s: str, i: int) -> bool:
    if i + 3 > len(s) or s[i : i + 3].lower() != "<li":
        return False
    if s[i : i + 5].lower() == "<link":
        return False
    if s[i : i + 6].lower() == "<list":
        return False
    nxt = s[i + 3 : i + 4]
    return nxt in " \t\n\r/>" or nxt == ""


def _find_next_li_open(s: str, pos: int) -> int:
    n = len(s)
    i = pos
    while i < n:
        j = s.find("<li", i)
        if j < 0:
            return -1
        if _is_li_open(s, j):
            return j
        i = j + 3
    return -1


def _consume_balanced_li(s: str, start: int) -> tuple[str, int] | None:
    if start < 0 or not _is_li_open(s, start):
        return None
    depth = 0
    i = start
    n = len(s)
    while i < n:
        if _is_li_open(s, i):
            depth += 1
            gt = s.find(">", i)
            if gt < 0:
                return None
            i = gt + 1
            continue
        m = re.search(r"</li\s*>", s[i:], re.IGNORECASE)
        if not m:
            return None
        depth -= 1
        i += m.end()
        if depth == 0:
            return s[start:i], i
    return None


def _split_top_level_lis(ul_inner: str) -> list[str]:
    chunks: list[str] = []
    pos = 0
    while pos < len(ul_inner):
        li_start = _find_next_li_open(ul_inner, pos)
        if li_start < 0:
            break
        got = _consume_balanced_li(ul_inner, li_start)
        if not got:
            break
        chunk, pos = got
        chunks.append(chunk)
    return chunks


def _li_open_tag_attrs(li_html: str) -> str:
    m = re.match(r"<li(\s[^>]*)?>", li_html.strip(), re.IGNORECASE | re.DOTALL)
    return m.group(1) or "" if m else ""


def _is_why_li(li_html: str) -> bool:
    return "digest-li-block--why" in _li_open_tag_attrs(li_html)


def _is_actions_li(li_html: str) -> bool:
    return "digest-li-block--actions" in _li_open_tag_attrs(li_html)


def _li_inner(li_html: str) -> str:
    m = re.match(r"<li\b[^>]*>([\s\S]*)</li\s*>$", li_html.strip(), re.IGNORECASE)
    return m.group(1).strip() if m else li_html.strip()


_SEV_ANCHOR_PATTERNS = (
    re.compile(
        r'<span class="sev sev-critical[^"]*"[^>]*data-sev-badge="1"[^>]*>.*?</span>',
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r'<span class="sev sev-high[^"]*"[^>]*data-sev-badge="1"[^>]*>.*?</span>',
        re.IGNORECASE | re.DOTALL,
    ),
)


def _promote_severity_anchor(headline: str, impact: str) -> tuple[str, str, str]:
    """If Critical/High badge exists, duplicate into anchor slot (keeps body text intact)."""
    blob = headline + impact
    for pat in _SEV_ANCHOR_PATTERNS:
        m = pat.search(blob)
        if m:
            return f'<div class="brief-sev-anchor">{m.group(0)}</div>', headline, impact
    return "", headline, impact


def _threat_title_element(inner: str) -> str:
    """Return ``h3.threat-title`` when content is phrasing-safe; else div with role=heading."""
    s = inner.strip()
    m = re.match(r"^<p>([\s\S]*)</p>$", s, re.IGNORECASE)
    if m:
        return f'<h3 class="threat-title">{m.group(1).strip()}</h3>'
    if re.search(r"<\s*p\b|<\s*div\b|<\s*ul\b|<\s*ol\b|<\s*h[1-6]\b", s, re.IGNORECASE):
        return f'<div class="threat-title" role="heading" aria-level="3">{s}</div>'
    return f"<h3 class=\"threat-title\">{s}</h3>"


def _li_plain_text(li_html: str) -> str:
    inner = _li_inner(li_html)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", inner)).strip()


def _is_actions_heading_li(li_html: str) -> bool:
    """Peer ``Actions`` row from flat Markdown (not yet a digest-li-block)."""
    t = _li_plain_text(li_html).lower()
    return t in (
        "actions",
        "action",
        "actions:",
        "action:",
        "recommended actions",
        "recommended action",
        "next steps",
        "next step",
    )


_ACTION_STEP_PREFIXES = (
    "software ",
    "network ",
    "inventory",
    "remediation",
    "guardrail",
    "hardening",
    "verify ",
    "if ",
    "if present",
    "detection:",
    "detection ",
    "supply chain",
    "third-party",
    "third party",
    "network hardening",
    "patch",
    "enable ",
    "tune ",
    "ingest ",
    "access control",
    "monitoring",
    "remediate",
    "expose ",
    "strengthen",
    "reduce ",
    "targeted ",
    "vendor ",
    "vendors ",
    "build hygiene",
    "awareness:",
    "awareness ",
    "inventory",
    "confirm ",
    "push ",
    "enforce ",
    "lock down",
    "protect ",
    "implement ",
    "web hygiene",
    "payment ",
    "rollout ",
    "validate ",
    "add ",
    "ask ",
    "require ",
    "ensure ",
    "continue ",
    "deploy",
    "schedule ",
    "use ",
    "hone ",
    "identify ",
    "send ",
    "set up",
    "hunt ",
    "harden ",
    "obtain ",
    "rotate ",
    "review ",
    "restrict ",
    "blocklist",
    "block ",
    "tighten ",
    "brief ",
    "watch ",
    "query ",
    "scan ",
    "assess ",
    "upgrade ",
    "update ",
    "disable ",
    "remove ",
)


def _looks_like_action_step_li(li_html: str) -> bool:
    t = _li_plain_text(li_html).lower()
    return any(t.startswith(p) for p in _ACTION_STEP_PREFIXES)


def _looks_like_threat_headline_li(li_html: str) -> bool:
    """
    Start of a *new* threat when folding loose action bullets.

    We only split on high-confidence signals. Treating every long capitalised
    line as a headline (the old rule) broke folds for steps like
    “Software inventory…” — those became fake “threat” cards with H3 styling.
    """
    if _is_why_li(li_html) or _is_actions_li(li_html) or _is_actions_heading_li(li_html):
        return False
    t = _li_plain_text(li_html)
    if re.search(r"CVE-\d{4}-\d+", t, re.IGNORECASE):
        return True
    # Headline-style “Title — subtitle” rows (common in campaigns) without a CVE id
    if (
        len(t) > 24
        and t[0].isupper()
        and not _looks_like_action_step_li(li_html)
        and re.search(r"[—–-]\s*\S", t)
    ):
        return True
    return False


def _fold_loose_action_steps(chunks: list[str], j: int) -> tuple[str | None, int]:
    """
    If chunks[j] is a plain ``Actions`` heading, consume following list rows into
    synthetic tactical HTML. Returns (tactical_inner_html, new_index_after_steps).
    """
    if j >= len(chunks) or not _is_actions_heading_li(chunks[j]):
        return None, j
    k = j + 1
    step_chunks: list[str] = []
    while k < len(chunks):
        ck = chunks[k]
        if _is_why_li(ck) or _is_actions_li(ck):
            break
        if _looks_like_threat_headline_li(ck):
            break
        if _is_actions_heading_li(ck):
            if step_chunks:
                break
            k += 1
            continue
        # Any peer bullet after “Actions” belongs in this tactical list until a
        # new threat headline — do *not* require “Verify …” / “If …” prefixes.
        step_chunks.append(ck)
        k += 1
    if not step_chunks:
        if _is_actions_heading_li(chunks[j]):
            return None, j + 1
        return None, j
    lis = "".join(f"<li>{_li_inner(sc)}</li>" for sc in step_chunks)
    tactical = _DIGEST_LABEL_SECOPS + "<ul>" + lis + "</ul>"
    return tactical, k


def _render_intelligence_li(
    headline_chunk: str,
    why_chunk: str | None,
    tactical_inner: str | None,
) -> str:
    headline_inner = _li_inner(headline_chunk)
    impact_inner = _li_inner(why_chunk) if why_chunk else ""

    classes = ["brief-cluster", "intelligence-card"]
    if impact_inner:
        classes.append("brief-cluster--has-impact")
    if tactical_inner:
        classes.append("brief-cluster--has-tactical")

    sev_anchor, headline_inner, impact_inner = _promote_severity_anchor(
        headline_inner, impact_inner
    )
    summary_parts: list[str] = []
    if sev_anchor:
        summary_parts.append(sev_anchor)
    summary_parts.append(_threat_title_element(headline_inner))
    if impact_inner:
        summary_parts.append(f'<div class="impact-block">{impact_inner}</div>')
    summary_html = "".join(summary_parts)

    tactical_block = (
        f'<div class="tactical-block">{tactical_inner}</div>' if tactical_inner else ""
    )

    return (
        f'<li class="{" ".join(classes)}">'
        f'<div class="intelligence-card__body intelligence-card__thread">'
        f'<div class="brief-exec-summary">{summary_html}</div>'
        f"{tactical_block}"
        f"</div></li>"
    )


def _build_brief_cluster(chunks: list[str]) -> str:
    idx = 1
    why_chunk: str | None = None
    if idx < len(chunks) and _is_why_li(chunks[idx]):
        why_chunk = chunks[idx]
        idx += 1
    tactical_inner: str | None = None
    if idx < len(chunks) and _is_actions_li(chunks[idx]):
        tactical_inner = _li_inner(chunks[idx])
    return _render_intelligence_li(chunks[0], why_chunk, tactical_inner)


def _build_plain_cluster(li_chunk: str) -> str:
    inner = _li_inner(li_chunk)
    return (
        '<li class="brief-cluster intelligence-card">'
        '<div class="intelligence-card__body intelligence-card__thread">'
        '<div class="brief-exec-summary">'
        f"{_threat_title_element(inner)}"
        "</div></div></li>"
    )


def _regroup_ul_inner(ul_inner: str) -> str:
    chunks = _split_top_level_lis(ul_inner)
    if not chunks:
        return ul_inner
    out: list[str] = []
    i = 0
    while i < len(chunks):
        ch = chunks[i]
        if not _is_why_li(ch) and not _is_actions_li(ch):
            j = i + 1
            has_why = j < len(chunks) and _is_why_li(chunks[j])
            if has_why:
                j += 1
            has_act = j < len(chunks) and _is_actions_li(chunks[j])
            if has_act:
                j += 1
            tactical_syn: str | None = None
            j_consume = j
            if not has_act:
                folded, j2 = _fold_loose_action_steps(chunks, j)
                if folded:
                    tactical_syn = folded
                    j_consume = j2
                elif j2 > j:
                    j_consume = j2
            if has_why or has_act or tactical_syn:
                why_chunk = chunks[i + 1] if has_why else None
                if tactical_syn:
                    out.append(_render_intelligence_li(chunks[i], why_chunk, tactical_syn))
                    i = j_consume
                else:
                    out.append(_build_brief_cluster(chunks[i:j]))
                    i = j
                continue
        if _is_why_li(ch) or _is_actions_li(ch):
            out.append(_build_plain_cluster(ch))
            i += 1
            continue
        out.append(_build_plain_cluster(ch))
        i += 1
    return "\n".join(out)


def _find_balanced_ul_end(s: str, ul_start: int) -> int:
    m = re.match(r"<ul\b[^>]*>", s[ul_start:], re.IGNORECASE)
    if not m:
        return -1
    i = ul_start + m.end()
    depth = 1
    n = len(s)
    while i < n and depth > 0:
        chunk = s[i:]
        no = re.search(r"<ul\b", chunk, re.IGNORECASE)
        nc = re.search(r"</ul\s*>", chunk, re.IGNORECASE)
        if nc is None:
            return -1
        pos_o = i + no.start() if no else n + 1
        pos_c = i + nc.start()
        if no and pos_o < pos_c:
            depth += 1
            i = pos_o + (no.end() - no.start())
        else:
            depth -= 1
            i = pos_c + (nc.end() - nc.start())
    return i if depth == 0 else -1


def _transform_outer_ul(ul_full: str) -> str:
    raw = ul_full.strip()
    open_m = re.match(r"(<ul\b[^>]*>)", raw, re.IGNORECASE)
    if not open_m:
        return ul_full
    close_m = re.search(r"</ul\s*>$", raw, re.IGNORECASE)
    if not close_m:
        return ul_full
    open_tag = open_m.group(1)
    inner = raw[open_m.end() : close_m.start()]
    close_tag = raw[close_m.start() :]
    if "digest-li-block" not in inner:
        return ul_full
    if not _split_top_level_lis(inner):
        return ul_full
    return open_tag + _regroup_ul_inner(inner) + close_tag


def _cluster_lists_in_section_inner(sec_inner: str) -> str:
    out: list[str] = []
    pos = 0
    while pos < len(sec_inner):
        um = re.search(r"<ul\b", sec_inner[pos:], re.IGNORECASE)
        if not um:
            out.append(sec_inner[pos:])
            break
        abs_u = pos + um.start()
        out.append(sec_inner[pos:abs_u])
        end = _find_balanced_ul_end(sec_inner, abs_u)
        if end < 0:
            out.append(sec_inner[abs_u:])
            break
        out.append(_transform_outer_ul(sec_inner[abs_u:end]))
        pos = end
    return "".join(out)


def _cluster_brief_lists(fragment: str) -> str:
    """Group headline + impact + tactical list rows for view-mode toggling."""
    out: list[str] = []
    pos = 0
    for sec_m in re.finditer(
        r'(<section class="digest-section[^"]*"[^>]*>)([\s\S]*?)(</section>)',
        fragment,
        re.IGNORECASE,
    ):
        out.append(fragment[pos : sec_m.start()])
        inner = _cluster_lists_in_section_inner(sec_m.group(2))
        out.append(sec_m.group(1) + inner + sec_m.group(3))
        pos = sec_m.end()
    out.append(fragment[pos:])
    return "".join(out)


def _payload_severity_badge_prefix(severity: str | None) -> str:
    if not severity:
        return ""
    w = str(severity).strip()
    if not w or w.lower() in ("null", "none"):
        return ""
    cls = _sev_class_for_word(w)
    wl = w.lower()
    disp = w[:1].upper() + w[1:].lower() if len(w) > 1 else w.upper()
    # Plain text only — no <strong>: _enrich_digest_html would wrap <strong>High</strong>
    # again and nest a second `.sev` inside this badge.
    return (
        f'<span class="sev {cls}" data-sev-badge="1" data-sev="{html.escape(wl)}">'
        f"{html.escape(disp)}</span> "
    )


def _threat_li_from_payload_item(item: dict[str, Any]) -> str:
    title = str(item.get("title") or "").strip()
    impact = str(item.get("impact") or "").strip()
    sev = item.get("severity")
    severity = sev if isinstance(sev, str) else None
    actions_raw = item.get("actions")
    if isinstance(actions_raw, list):
        actions = [str(a).strip() for a in actions_raw if str(a).strip()]
    elif isinstance(actions_raw, str) and actions_raw.strip():
        actions = [actions_raw.strip()]
    else:
        actions = []

    impact_inner = ""
    if impact:
        impact_inner = (
            _DIGEST_LABEL_IMPACT
            + '<div class="digest-subblock-body"><p>'
            + html.escape(impact)
            + "</p></div>"
        )

    badge = _payload_severity_badge_prefix(severity)
    title_el = _threat_title_element(html.escape(title))
    headline_blob = (badge + title_el) if badge else title_el
    sev_anchor, headline_final, _ = _promote_severity_anchor(headline_blob, impact_inner)
    # Promote duplicates Critical/High into `.brief-sev-anchor`; drop the inline copy
    # from the headline so payload cards do not show two stacked badges.
    if sev_anchor:
        for pat in _SEV_ANCHOR_PATTERNS:
            if pat.search(headline_final):
                headline_final = pat.sub("", headline_final, count=1)
                break
        headline_final = headline_final.strip()

    classes = ["brief-cluster", "intelligence-card"]
    if impact_inner:
        classes.append("brief-cluster--has-impact")
    tactical_inner = ""
    if actions:
        lis = "".join(f"<li>{html.escape(a)}</li>" for a in actions)
        tactical_inner = _DIGEST_LABEL_SECOPS + "<ul>" + lis + "</ul>"
    if tactical_inner:
        classes.append("brief-cluster--has-tactical")

    summary_parts: list[str] = []
    if sev_anchor:
        summary_parts.append(sev_anchor)
    summary_parts.append(headline_final)
    if impact_inner:
        summary_parts.append(f'<div class="impact-block">{impact_inner}</div>')
    summary_html = "".join(summary_parts)

    tactical_block = (
        f'<div class="tactical-block">{tactical_inner}</div>' if tactical_inner else ""
    )

    return (
        f'<li class="{" ".join(classes)}">'
        f'<div class="intelligence-card__body intelligence-card__thread">'
        f'<div class="brief-exec-summary">{summary_html}</div>'
        f"{tactical_block}"
        f"</div></li>"
    )


def _payload_section_html(heading: str, items: list[dict[str, Any]]) -> str:
    if not items:
        return ""
    lis = "".join(_threat_li_from_payload_item(it) for it in items)
    return (
        f'<section class="digest-section"><h2>{html.escape(heading)}</h2><ul>{lis}</ul></section>'
    )


def _payload_recommended_section_html(lines: list[str]) -> str:
    if not lines:
        return ""
    lis = "".join(f"<li>{html.escape(x)}</li>" for x in lines)
    return (
        '<section class="digest-section"><h2>Recommended actions</h2><ul>'
        f"{lis}</ul></section>"
    )


def _html_body_from_digest_payload(payload: dict[str, Any]) -> str:
    from threat_digest.digest_payload import normalize_digest_payload

    p = normalize_digest_payload(payload)
    parts = [
        _payload_section_html("Key vulnerabilities to act on", p["key_vulnerabilities"]),
        _payload_section_html("Notable campaigns & incidents", p["notable_campaigns"]),
        _payload_recommended_section_html(p["recommended_actions"]),
    ]
    raw = "\n".join(x for x in parts if x)
    return _cluster_brief_lists(_enrich_digest_html(raw))


def _profile_sidebar_html(profile: dict[str, Any]) -> str:
    if not profile:
        return ""
    rows: list[str] = []
    if v := profile.get("company_name"):
        rows.append(f"<dt>Organisation</dt><dd>{html.escape(str(v))}</dd>")
    if v := profile.get("sector"):
        rows.append(f"<dt>Sector</dt><dd>{html.escape(str(v))}</dd>")
    tools = profile.get("tools_and_platforms")
    if isinstance(tools, list) and tools:
        chips = "".join(
            f"<span class='chip'>{html.escape(str(t))}</span>" for t in tools
        )
        rows.append(f"<dt>Stack</dt><dd class='chips'>{chips}</dd>")
    pri = profile.get("priority_threats")
    if isinstance(pri, list) and pri:
        lis = "".join(f"<li>{html.escape(str(p))}</li>" for p in pri)
        rows.append(f"<dt>Priorities</dt><dd><ul class='tool-list'>{lis}</ul></dd>")
    if not rows:
        return ""
    inner = "".join(rows)
    return f"""
    <aside class="profile-card glass" aria-label="Organisation context">
      <div class="profile-glow" aria-hidden="true"></div>
      <h2 class="profile-title"><span class="profile-title-icon" aria-hidden="true"></span>Your context</h2>
      <dl class="profile-dl">{inner}</dl>
    </aside>
    """


# CSS is static — avoids f-string brace hell; injected into the document.
_DIGEST_STYLES = """
:root {
  --void: #050508;
  --deep: #0a0c14;
  --surface: rgba(18, 22, 36, 0.65);
  --surface-solid: #12162a;
  --elevated: rgba(28, 34, 56, 0.85);
  --border: rgba(120, 140, 200, 0.12);
  --border-bright: rgba(100, 220, 255, 0.25);
  --text: #f0f3fa;
  --text-soft: #a8b4d0;
  --muted: #6b7a99;
  --accent: #00e5c8;
  --accent-dim: #00b89c;
  --violet: #a78bfa;
  --rose: #fb7185;
  --amber: #fbbf24;
  --glow-accent: rgba(0, 229, 200, 0.35);
  --glow-violet: rgba(167, 139, 250, 0.2);
  --radius: 16px;
  --radius-sm: 10px;
  --font: "DM Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: "JetBrains Mono", "Cascadia Code", "SF Mono", Consolas, monospace;
}

*, *::before, *::after { box-sizing: border-box; }

html { scroll-behavior: smooth; }

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

body {
  margin: 0;
  font-family: var(--font);
  background: var(--void);
  color: var(--text);
  line-height: 1.6;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

/* --- Atmospheric background --- */
.bg-stage {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  overflow: hidden;
}
.bg-mesh {
  position: absolute;
  inset: -50%;
  background:
    radial-gradient(ellipse 80% 50% at 20% -20%, rgba(0, 229, 200, 0.15), transparent 50%),
    radial-gradient(ellipse 60% 40% at 90% 10%, rgba(167, 139, 250, 0.12), transparent 45%),
    radial-gradient(ellipse 50% 60% at 50% 100%, rgba(251, 113, 133, 0.08), transparent 40%),
    linear-gradient(180deg, var(--void) 0%, var(--deep) 45%, #060814 100%);
}
.bg-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(120, 140, 200, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(120, 140, 200, 0.03) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse 70% 60% at 50% 0%, black 20%, transparent 75%);
}
.bg-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(80px);
  opacity: 0.5;
  animation: float-orb 18s ease-in-out infinite;
}
.bg-orb-1 {
  width: 420px; height: 420px;
  background: var(--glow-accent);
  top: -120px; right: -80px;
  animation-delay: 0s;
}
.bg-orb-2 {
  width: 320px; height: 320px;
  background: var(--glow-violet);
  bottom: 10%; left: -100px;
  animation-delay: -6s;
}
@keyframes float-orb {
  0%, 100% { transform: translate(0, 0) scale(1); }
  33% { transform: translate(20px, -15px) scale(1.05); }
  66% { transform: translate(-15px, 10px) scale(0.95); }
}

/* --- Top bar --- */
.top-shell {
  position: sticky;
  top: 0;
  z-index: 50;
  border-bottom: 1px solid var(--border);
  background: rgba(5, 5, 8, 0.72);
  backdrop-filter: blur(16px) saturate(1.3);
  -webkit-backdrop-filter: blur(16px) saturate(1.3);
}

/* Reading progress indicator */
.progress-bar {
  position: absolute;
  bottom: 0;
  left: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent), var(--violet));
  transform-origin: left;
  transform: scaleX(0);
  transition: transform 0.1s ease-out;
}

/* Sliding Blade System */
.blade-overlay {
  position: fixed;
  top: 0;
  right: -100%;
  width: 100%;
  max-width: 600px;
  height: 100vh;
  background: var(--surface-solid);
  backdrop-filter: blur(20px);
  border-left: 1px solid var(--border-bright);
  z-index: 2000;
  transition: right 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  overflow-y: auto;
  box-shadow: -20px 0 60px rgba(0, 0, 0, 0.5);
}

.blade-overlay.active {
  right: 0;
}

.blade-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100vh;
  background: rgba(0, 0, 0, 0.6);
  z-index: 1999;
  opacity: 0;
  visibility: hidden;
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.blade-backdrop.active {
  opacity: 1;
  visibility: visible;
}

.blade-header {
  position: sticky;
  top: 0;
  background: var(--surface-solid);
  border-bottom: 1px solid var(--border);
  padding: 1.5rem 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  z-index: 10;
}

.blade-title {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.blade-close {
  width: 40px;
  height: 40px;
  border: none;
  background: var(--elevated);
  border-radius: var(--radius-sm);
  color: var(--text-soft);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  transition: all 0.2s ease;
}

.blade-close:hover {
  background: var(--border-bright);
  color: var(--text);
  transform: scale(1.05);
}

.blade-content {
  padding: 2rem;
}

.blade-section {
  margin-bottom: 2rem;
}

.blade-section h3 {
  font-size: 1rem;
  font-weight: 600;
  color: var(--accent);
  margin: 0 0 1rem 0;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.actor-overview {
  background: var(--elevated);
  border-radius: var(--radius);
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  border: 1px solid var(--border);
}

.actor-id {
  font-family: var(--mono);
  font-size: 0.875rem;
  color: var(--accent);
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.actor-aliases {
  margin-bottom: 1rem;
}

.alias-tag {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 500;
  margin-right: 0.5rem;
  margin-bottom: 0.5rem;
  color: var(--text-soft);
}

.actor-description {
  font-size: 0.95rem;
  line-height: 1.6;
  color: var(--text-soft);
}

.technique-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
}

.technique-card {
  background: var(--elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem;
  transition: all 0.2s ease;
}

.technique-card:hover {
  border-color: var(--border-bright);
  transform: translateY(-2px);
}

.technique-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.technique-id {
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--accent);
  font-weight: 600;
}

.tactic-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 12px;
  font-size: 0.625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.tactic-initial-access { background: #ef4444; color: white; }
.tactic-execution { background: #f97316; color: white; }
.tactic-persistence { background: #eab308; color: white; }
.tactic-privilege-escalation { background: #84cc16; color: white; }
.tactic-defense-evasion { background: #22c55e; color: white; }
.tactic-credential-access { background: #06b6d4; color: white; }
.tactic-discovery { background: #3b82f6; color: white; }
.tactic-lateral-movement { background: #6366f1; color: white; }
.tactic-collection { background: #8b5cf6; color: white; }
.tactic-command-and-control { background: #a855f7; color: white; }
.tactic-exfiltration { background: #ec4899; color: white; }
.tactic-impact { background: #f43f5e; color: white; }

.technique-name {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text);
}

/* Actor mention capsules in main content */
.actor-mention {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  background: linear-gradient(135deg, var(--accent) 0%, var(--violet) 100%);
  color: white;
  border-radius: 20px;
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  text-decoration: none;
  margin: 0 0.25rem;
  position: relative;
  overflow: hidden;
}

.actor-mention::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
  transition: left 0.5s ease;
}

.actor-mention:hover {
  transform: translateY(-2px) scale(1.05);
  box-shadow: 0 8px 25px var(--glow-accent);
}

.actor-mention:hover::before {
  left: 100%;
}

/* Mobile responsiveness for blades */
@media (max-width: 768px) {
  .blade-overlay {
    max-width: 100%;
    width: 100%;
  }
  
  .blade-content {
    padding: 1rem;
  }
  
  .technique-grid {
    grid-template-columns: 1fr;
  }
}


.actors-header {
  text-align: center;
  margin-bottom: 3rem;
  padding: 0 2rem;
}

.actors-title {
  font-size: 2.5rem;
  font-weight: 800;
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  margin: 0 0 1rem;
}

.actors-subtitle {
  font-size: 1.125rem;
  color: var(--text-soft);
  margin: 0;
}

.actors-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 2rem;
}

.actor-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.actor-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0, 229, 200, 0.1), transparent);
  transition: left 0.5s ease;
}

.actor-card:hover {
  transform: translateY(-8px);
  border-color: var(--border-bright);
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
}

.actor-card:hover::before {
  left: 100%;
}

.actor-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.actor-avatar {
  width: 60px;
  height: 60px;
  border-radius: 50%;
  background: var(--gradient-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  font-weight: 700;
  color: white;
  text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
}

.actor-type-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.type-nation-state {
  background: #ef4444;
  color: white;
}

.type-financially-motivated {
  background: #f59e0b;
  color: white;
}

.type-hacktivist {
  background: #8b5cf6;
  color: white;
}

.actor-name {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text);
  margin: 0 0 0.5rem;
}

.actor-id {
  font-family: var(--mono);
  font-size: 0.875rem;
  color: var(--accent);
  font-weight: 600;
  margin-bottom: 1rem;
}

.actor-description {
  font-size: 0.875rem;
  color: var(--text-soft);
  line-height: 1.5;
  margin-bottom: 1.5rem;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.actor-stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}

.actor-stat {
  text-align: center;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--accent);
  display: block;
}

.stat-label {
  font-size: 0.75rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.actor-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.actor-tag {
  padding: 0.25rem 0.5rem;
  background: var(--elevated);
  border: 1px solid var(--border);
  border-radius: 12px;
  font-size: 0.75rem;
  color: var(--text-soft);
}

.page-nav {
  position: fixed;
  top: 50%;
  left: 2rem;
  transform: translateY(-50%);
  z-index: 1000;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.nav-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--border);
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
}

.nav-dot.active {
  background: var(--accent);
  box-shadow: 0 0 20px var(--glow-accent);
}

.nav-dot:hover {
  background: var(--accent-dim);
  transform: scale(1.2);
}

.nav-tooltip {
  position: absolute;
  left: 120%;
  top: 50%;
  transform: translateY(-50%);
  background: var(--surface-solid);
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  white-space: nowrap;
  opacity: 0;
  visibility: hidden;
  transition: all 0.3s ease;
  border: 1px solid var(--border);
}

.nav-dot:hover .nav-tooltip {
  opacity: 1;
  visibility: visible;
}

/* Add new actor button */
.add-actor-card {
  background: var(--elevated);
  border: 2px dashed var(--border);
  border-radius: var(--radius);
  padding: 2rem;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 200px;
  text-align: center;
}

.add-actor-card:hover {
  border-color: var(--accent);
  background: var(--surface);
}

.add-icon {
  font-size: 3rem;
  color: var(--accent);
  margin-bottom: 1rem;
}

.add-text {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 0.5rem;
}

.add-subtext {
  font-size: 0.875rem;
  color: var(--text-soft);
}

@media (max-width: 768px) {
  .actors-grid {
    grid-template-columns: 1fr;
    padding: 0 1rem;
  }
  
  .actors-title {
    font-size: 2rem;
  }
  
  .page-nav {
    display: none;
  }
}
.top-inner {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0.85rem 1.5rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}
.brand-lockup {
  display: flex;
  align-items: center;
  gap: 0.9rem;
}
.logo {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: linear-gradient(135deg, var(--accent) 0%, #4fd1c5 40%, var(--violet) 100%);
  display: grid;
  place-items: center;
  box-shadow: 0 0 32px var(--glow-accent), inset 0 1px 0 rgba(255,255,255,0.25);
  position: relative;
  overflow: hidden;
}
.logo::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(120deg, transparent 40%, rgba(255,255,255,0.35) 50%, transparent 60%);
  animation: sheen 4s ease-in-out infinite;
}
@keyframes sheen {
  0%, 100% { transform: translateX(-100%); }
  50% { transform: translateX(100%); }
}
.logo svg { width: 22px; height: 22px; color: var(--void); }
.brand-text h1 {
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  background: linear-gradient(90deg, var(--text) 0%, var(--text-soft) 100%);
  -webkit-background-clip: text;
  background-clip: text;
}
.brand-text .sub {
  margin: 0.2rem 0 0;
  font-size: 0.78rem;
  color: var(--muted);
  letter-spacing: 0.02em;
}
.top-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 0.65rem 1rem;
}

.export-btn {
  appearance: none;
  border: none;
  background: rgba(8, 10, 18, 0.55);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem;
  color: var(--muted);
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 36px;
  min-width: 36px;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

@media (hover: hover) and (pointer: fine) {
  .export-btn:hover {
    color: var(--accent);
    border-color: var(--border-bright);
    background: rgba(0, 229, 200, 0.1);
  }
}
.view-toggle {
  display: inline-flex;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: rgba(8, 10, 18, 0.55);
  padding: 3px;
  gap: 2px;
}
.view-toggle-btn {
  appearance: none;
  border: none;
  cursor: pointer;
  font-family: var(--font);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
  background: transparent;
  padding: 0.45rem 0.85rem;
  border-radius: 999px;
  transition: color 0.2s, background 0.2s;
  min-height: 44px; /* Ensure good touch target size */
  display: flex;
  align-items: center;
  justify-content: center;
}
@media (hover: hover) and (pointer: fine) {
  .view-toggle-btn:hover {
    color: var(--text-soft);
  }
}
.view-toggle-btn.is-active {
  color: var(--void);
  background: linear-gradient(120deg, var(--accent), #5eead4);
  box-shadow: 0 0 18px rgba(0, 229, 200, 0.2);
}
.pill-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
  align-items: center;
}
.pill {
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.4rem 0.75rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: rgba(255,255,255,0.03);
  color: var(--text-soft);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.pill-live {
  border-color: rgba(0, 229, 200, 0.35);
  color: var(--accent);
  box-shadow: 0 0 20px rgba(0, 229, 200, 0.12);
}
.pill-live .dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  margin-right: 0.35rem;
  animation: pulse-dot 2s ease-in-out infinite;
  vertical-align: middle;
}
@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.5; transform: scale(0.85); }
}

/* Table of contents */
.toc-toggle {
  appearance: none;
  border: none;
  background: rgba(8, 10, 18, 0.55);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem;
  color: var(--muted);
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 36px;
  min-width: 36px;
}

@media (hover: hover) and (pointer: fine) {
  .toc-toggle:hover {
    color: var(--text-soft);
    border-color: var(--border-bright);
  }
}

.toc-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.8);
  backdrop-filter: blur(8px);
  z-index: 100;
  opacity: 0;
  visibility: hidden;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
}

.toc-overlay.active {
  opacity: 1;
  visibility: visible;
}

.toc-content {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 2rem;
  max-width: 400px;
  width: 90%;
  transform: translateY(20px);
  transition: transform 0.3s ease;
}

.toc-overlay.active .toc-content {
  transform: translateY(0);
}

.toc-content h3 {
  margin: 0 0 1.5rem;
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text);
  text-align: center;
}

.toc-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.toc-list li {
  margin: 0 0 0.75rem;
}

.toc-list a {
  display: block;
  padding: 0.75rem 1rem;
  color: var(--text-soft);
  text-decoration: none;
  border-radius: 8px;
  border: 1px solid transparent;
  transition: all 0.2s ease;
  font-weight: 500;
}

@media (hover: hover) and (pointer: fine) {
  .toc-list a:hover {
    color: var(--accent);
    background: rgba(0, 229, 200, 0.1);
    border-color: rgba(0, 229, 200, 0.2);
  }
}

/* Notification system */
.notification {
  position: fixed;
  top: 20px;
  right: 20px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem 1.5rem;
  color: var(--text);
  font-size: 0.9rem;
  z-index: 200;
  transform: translateX(400px);
  transition: transform 0.3s ease;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(12px);
  max-width: 300px;
}

.notification.show {
  transform: translateX(0);
}

.notification.success {
  border-color: rgba(34, 197, 94, 0.3);
  background: rgba(34, 197, 94, 0.1);
}

.notification.success::before {
  content: "✓ ";
  color: #22c55e;
  font-weight: bold;
}

/* Severity distribution chart */
.severity-chart {
  margin: 2rem 0;
  padding: 1.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  backdrop-filter: blur(12px);
}

.severity-chart h3 {
  margin: 0 0 1.5rem;
  font-size: 1rem;
  font-weight: 700;
  color: var(--text);
  text-align: center;
  letter-spacing: 0.02em;
}

.chart-container {
  display: grid;
  gap: 1rem;
}

.severity-bar {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.bar-label {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-soft);
  min-width: 60px;
  text-transform: capitalize;
}

.bar-fill {
  flex: 1;
  height: 24px;
  border-radius: 12px;
  position: relative;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--border);
  transition: all 0.6s ease;
}

.bar-fill::before {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  width: 0;
  border-radius: inherit;
  transition: width 1.5s ease;
  animation: bar-fill-animation 1.5s ease forwards;
}

.bar-fill::after {
  content: attr(data-count);
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--text);
  opacity: 0;
  transition: opacity 0.3s ease 1s;
}

.severity-bar[data-severity="critical"] .bar-fill::before {
  background: linear-gradient(90deg, var(--rose), #dc2626);
}

.severity-bar[data-severity="high"] .bar-fill::before {
  background: linear-gradient(90deg, var(--amber), #d97706);
}

.severity-bar[data-severity="medium"] .bar-fill::before {
  background: linear-gradient(90deg, #ca8a04, #a16207);
}

.severity-bar[data-severity="low"] .bar-fill::before {
  background: linear-gradient(90deg, #16a34a, #15803d);
}

@keyframes bar-fill-animation {
  from { width: 0; }
  to { width: var(--fill-width, 0%); }
}

/* Show count after animation */
.bar-fill[data-count]:not([data-count="0"])::after {
  opacity: 1;
}

@media (max-width: 720px) {
  .severity-chart {
    margin: 1.5rem 0;
    padding: 1rem;
  }
  
  .chart-container {
    gap: 0.75rem;
  }
  
  .bar-fill {
    height: 20px;
  }
  
  .bar-label {
    min-width: 50px;
    font-size: 0.75rem;
  }
}

/* --- Hero --- */
.hero {
  position: relative;
  z-index: 1;
  max-width: 1200px;
  margin: 0 auto;
  padding: 2.5rem 1.5rem 1.5rem;
}
.hero-eyebrow {
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 0.65rem;
}
.hero-title {
  margin: 0;
  font-size: clamp(1.75rem, 4vw, 2.35rem);
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.15;
  max-width: 18ch;
}
.hero-title span {
  background: linear-gradient(105deg, var(--text) 0%, var(--accent) 45%, var(--violet) 90%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.hero-lede {
  margin: 1rem 0 0;
  max-width: 52ch;
  font-size: 1rem;
  color: var(--text-soft);
  line-height: 1.65;
}
.sector-chip {
  display: inline-flex;
  align-items: center;
  margin-top: 1.1rem;
  padding: 0.35rem 0.85rem;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--violet);
  border: 1px solid rgba(167, 139, 250, 0.35);
  background: rgba(167, 139, 250, 0.08);
}

/* --- Metrics --- */
.wrap {
  position: relative;
  z-index: 1;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 1.5rem 3rem;
}

/* Add visual separator */
.metrics::after {
  content: "";
  display: block;
  width: 60px;
  height: 2px;
  background: linear-gradient(90deg, var(--accent), var(--violet));
  margin: 2rem auto 0;
  border-radius: 1px;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-bottom: 1.75rem;
}
@media (max-width: 720px) {
  .metrics { grid-template-columns: 1fr; }
  
  /* Mobile navigation improvements */
  .top-inner {
    padding: 0.75rem 1rem;
    gap: 0.75rem;
  }
  
  .brand-lockup {
    gap: 0.65rem;
  }
  
  .logo {
    width: 36px;
    height: 36px;
  }
  
  .brand-text h1 {
    font-size: 0.95rem;
  }
  
  .brand-text .sub {
    font-size: 0.7rem;
  }
  
  .top-controls {
    gap: 0.5rem;
    width: 100%;
    justify-content: center;
  }
  
  .view-toggle-btn {
    font-size: 0.62rem;
    padding: 0.4rem 0.7rem;
  }
  
  .pill {
    font-size: 0.65rem;
    padding: 0.35rem 0.6rem;
  }
  
  /* Mobile hero improvements */
  .hero {
    padding: 2rem 1rem 1.25rem;
    text-align: center;
  }
  
  .hero-title {
    font-size: 1.5rem;
    max-width: none;
  }
  
  .hero-lede {
    font-size: 0.9rem;
    max-width: none;
  }
  
  /* Mobile content improvements */
  .wrap {
    padding: 0 1rem 2rem;
  }
  
  .main-card {
    padding: 1.25rem 1rem 1.5rem;
  }
  
  /* Mobile typography improvements */
  .digest-section h2 {
    font-size: 0.95rem;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.4rem;
  }
  
  .threat-title {
    font-size: 1.1rem;
  }
  
  /* Mobile table improvements */
  .digest-section table {
    font-size: 0.8rem;
  }
  
  .digest-section th,
  .digest-section td {
    padding: 0.5rem 0.6rem;
  }
}
.metric {
  position: relative;
  padding: 1.35rem 1.4rem;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--surface);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  overflow: hidden;
  transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
}
@media (hover: hover) and (pointer: fine) {
  .metric:hover {
    transform: translateY(-3px);
    border-color: var(--border-bright);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.35);
  }
}
.metric::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent), var(--violet));
  opacity: 0.85;
}
.metric-icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  margin-bottom: 0.85rem;
  background: rgba(0, 229, 200, 0.1);
  border: 1px solid rgba(0, 229, 200, 0.2);
}
.metric:nth-child(2) .metric-icon {
  background: rgba(167, 139, 250, 0.12);
  border-color: rgba(167, 139, 250, 0.25);
}
.metric:nth-child(3) .metric-icon {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.25);
}
.metric-icon svg { width: 18px; height: 18px; }
.metric-num {
  font-family: var(--mono);
  font-size: 2.1rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1;
  background: linear-gradient(180deg, #fff 0%, var(--text-soft) 100%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  position: relative;
}

/* Add animated counter effect */
.metric-num::after {
  content: "";
  position: absolute;
  bottom: -4px;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent), var(--violet));
  transform: scaleX(0);
  animation: metric-reveal 1.5s ease-out 0.5s forwards;
}

@keyframes metric-reveal {
  to { transform: scaleX(1); }
}

/* Stagger the animations */
.metric:nth-child(1) .metric-num::after { animation-delay: 0.5s; }
.metric:nth-child(2) .metric-num::after { animation-delay: 0.7s; }
.metric:nth-child(3) .metric-num::after { animation-delay: 0.9s; }
.metric-label {
  margin-top: 0.5rem;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--muted);
}

/* --- Layout --- */
.layout {
  display: grid;
  gap: 1.35rem;
  align-items: start;
}
.layout-full { grid-template-columns: minmax(0, 1fr); }
.layout-with-sidebar { grid-template-columns: minmax(0, 1fr) 300px; }
@media (max-width: 960px) {
  .layout-with-sidebar { grid-template-columns: 1fr; }
}

/* Sticky column wrapper — keeps profile visible without fighting grid stretch */
.layout-sidebar {
  position: sticky;
  top: 5.75rem;
  align-self: start;
  max-height: calc(100vh - 6.25rem);
  overflow-y: auto;
  overscroll-behavior: contain;
}
@media (max-width: 960px) {
  .layout-sidebar {
    position: static;
    max-height: none;
    overflow: visible;
  }
}

/* Small mobile devices */
@media (max-width: 480px) {
  .hero {
    padding: 1.5rem 0.75rem 1rem;
  }
  
  .hero-title {
    font-size: 1.35rem;
    line-height: 1.2;
  }
  
  .hero-lede {
    font-size: 0.85rem;
    line-height: 1.6;
  }
  
  .wrap {
    padding: 0 0.75rem 1.5rem;
  }
  
  .main-card {
    padding: 1rem 0.75rem 1.25rem;
  }
  
  .metrics {
    gap: 0.75rem;
  }
  
  .metric {
    padding: 1rem 1rem;
  }
  
  .top-inner {
    padding: 0.65rem 0.75rem;
  }
  
  .top-controls {
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .view-toggle {
    order: -1;
  }
  
  .pill-row {
    justify-content: center;
  }
  
  /* Improve readability on small screens */
  .digest-section {
    margin-bottom: 1.5rem;
  }
  
  .intelligence-card__body {
    padding: 0.5rem 0.65rem 0.85rem;
  }
  
  .threat-title {
    font-size: 1rem;
    margin-bottom: 0.45rem;
  }
  
  .sev {
    font-size: 0.62rem;
    padding: 0.12rem 0.35rem;
  }
  
  /* Profile card on mobile */
  .profile-card {
    padding: 1rem 1rem;
  }
  
  .profile-title {
    font-size: 0.68rem;
  }
  
  .profile-dl dt {
    font-size: 0.6rem;
  }
  
  .profile-dl dd {
    font-size: 0.8rem;
  }
  
  .chip {
    font-size: 0.68rem;
    padding: 0.24rem 0.45rem;
  }
}

.glass {
  background: var(--surface);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.main-card {
  position: relative;
  padding: 1.75rem 1.5rem 2rem;
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
}
.brief-main.main-card {
  background: rgba(12, 14, 24, 0.35);
  box-shadow: none;
  border: 1px solid rgba(120, 140, 200, 0.08);
}
.brief-main.main-card::before {
  display: none;
}
@media (min-width: 640px) {
  .main-card { padding: 2rem 2rem 2.25rem; }
}
.main-card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  padding: 1px;
  background: linear-gradient(135deg, rgba(0,229,200,0.25), transparent 40%, rgba(167,139,250,0.2));
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  pointer-events: none;
}

/* Readable column + section cards (breaks up wall of text) */
.prose-readable {
  font-size: 0.98rem;
  color: var(--text-soft);
  position: relative;
  z-index: 1;
  counter-reset: digest-section;
}
.digest-section:not(.digest-section--preamble) {
  counter-increment: digest-section;
}
.digest-section {
  margin-bottom: 2rem;
  padding: 0 0 1.5rem;
  border-radius: 0;
  border: none;
  border-bottom: 1px solid var(--border);
  background: transparent;
  box-shadow: none;
  border-left: none;
}
.digest-section--preamble {
  border-bottom: none;
  padding-bottom: 0.5rem;
}
.digest-section:last-child { margin-bottom: 0; border-bottom: none; }
.digest-section h2 {
  font-size: 1.05rem;
  font-weight: 800;
  margin: 0 0 1.25rem;
  padding: 0 0 0.65rem;
  margin-left: 0;
  margin-right: 0;
  border-radius: 0;
  background: transparent;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: 0.65rem;
  flex-wrap: wrap;
}
.digest-section:not(.digest-section--preamble) h2::before {
  content: counter(digest-section, decimal-leading-zero);
  font-family: var(--mono);
  font-size: 0.68rem;
  font-weight: 700;
  color: var(--accent);
  opacity: 0.85;
  letter-spacing: 0.06em;
}
.digest-section--preamble h2 {
  border-bottom: none;
  background: none;
  margin-left: 0;
  margin-right: 0;
  padding: 0 0 0.65rem;
  border-radius: 0;
  margin-bottom: 0.75rem;
  font-size: 1.05rem;
  font-weight: 700;
  text-transform: none;
  letter-spacing: -0.02em;
}
.digest-section p {
  margin: 0.85rem 0 0;
  line-height: 1.7;
  max-width: 68ch;
}
.digest-section p:first-of-type { margin-top: 0; }
.digest-section h2 + p {
  margin-top: 0.5rem;
  font-size: 1.02rem;
  line-height: 1.7;
  color: #c5cee0;
}
.digest-section h3 {
  font-size: 0.92rem;
  font-weight: 600;
  margin: 1.35rem 0 0.55rem;
  color: var(--violet);
  letter-spacing: 0.02em;
}
.digest-section h3:first-child { margin-top: 0; }
.digest-section ul,
.digest-section ol {
  margin: 0.5rem 0 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 0;
  max-width: 72ch;
}
.digest-section li {
  margin: 0;
  padding: 0;
  position: relative;
  line-height: 1.7;
  background: transparent;
  border: none;
  border-radius: 0;
  box-shadow: none;
}
.digest-section ol {
  counter-reset: item;
}
.digest-section ol ol {
  counter-reset: item;
}
.digest-section ol > li {
  counter-increment: item;
  padding-left: 1.75rem;
}
.digest-section ol > li::before {
  content: counter(item);
  position: absolute;
  left: 0;
  top: 0.35em;
  font-family: var(--mono);
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--accent);
  opacity: 0.75;
}
.digest-section ul > li::before {
  content: none;
}
/* Intelligence cards: one grouped unit per threat (Title + Impact + Tactical) */
.digest-section ul > li.brief-cluster {
  margin: 0 0 2rem;
  padding: 0;
  list-style: none;
  position: relative;
}

/* Add subtle card numbering */
.digest-section ul > li.brief-cluster::before {
  content: counter(threat-counter, decimal-leading-zero);
  counter-increment: threat-counter;
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  font-family: var(--mono);
  font-size: 0.65rem;
  font-weight: 700;
  color: var(--muted);
  opacity: 0.6;
  z-index: 1;
}

.digest-section ul {
  counter-reset: threat-counter;
}
.digest-section ul > li.brief-cluster:last-child {
  margin-bottom: 0;
}
.digest-section ul > li:not(.brief-cluster) {
  margin: 0.4rem 0;
  padding-left: 0.75rem;
  border-left: 1px solid rgba(120, 140, 200, 0.12);
}
.intelligence-card__body {
  margin: 0;
  padding: 0.65rem 0.85rem 1.15rem;
  border-bottom: 1px solid rgba(120, 140, 200, 0.12);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.02);
}
[data-brief-view="executive"] .intelligence-card__body {
  background: rgba(255, 255, 255, 0.028);
}
.intelligence-card:last-child .intelligence-card__body,
.digest-section ul > li.brief-cluster:last-child .intelligence-card__body {
  border-bottom: none;
  padding-bottom: 0;
}
/* Threading: SecOps only — connects headline through technical depth */
.intelligence-card__thread {
  margin: 0;
  padding-left: 0;
  border-left: none;
}
[data-brief-view="tactical"] .intelligence-card__thread {
  padding-left: 1rem;
  border-left: 1px solid var(--border);
}
.brief-exec-summary {
  display: block;
}
.digest-section .threat-title {
  font-size: 1.25rem;
  font-weight: 800;
  line-height: 1.28;
  margin: 0 0 0.55rem;
  padding: 0 0 0.45rem;
  color: var(--text);
  letter-spacing: -0.025em;
  position: relative;
  max-width: 72ch;
  cursor: pointer;
  transition: color 0.2s ease;
}

/* Add copy link functionality */
.digest-section .threat-title:hover {
  color: var(--accent);
}

.digest-section .threat-title::before {
  content: "🔗";
  position: absolute;
  left: -1.5rem;
  opacity: 0;
  transition: opacity 0.2s ease;
  font-size: 0.8rem;
}

@media (hover: hover) and (pointer: fine) {
  .digest-section .threat-title:hover::before {
    opacity: 0.6;
  }
}
.digest-section .threat-title::after {
  content: "";
  position: absolute;
  left: 0;
  bottom: 0;
  width: min(100%, 42ch);
  height: 3px;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--accent) 0%, var(--violet) 45%, var(--accent) 90%);
  background-size: 220% 100%;
  animation: threat-glitch-line 3.5s ease-in-out infinite;
  opacity: 0.95;
}
@keyframes threat-glitch-line {
  0%, 100% { background-position: 0% 50%; transform: translateX(0); }
  25% { transform: translateX(1px); }
  50% { background-position: 100% 50%; transform: translateX(-1px); }
  75% { transform: translateX(0); }
}
@media (prefers-reduced-motion: reduce) {
  .digest-section .threat-title::after {
    animation: none;
    background-position: 0% 50%;
  }
}
.digest-section .threat-title strong {
  font-weight: inherit;
  color: inherit;
}
.impact-block {
  margin-top: 0.65rem;
}
.tactical-block {
  margin-top: 0;
  padding: 0;
  border: none;
  background: transparent;
  border-radius: 0;
}
[data-brief-view="tactical"] .tactical-block {
  margin-top: 1.1rem;
  padding: 1rem 1rem 1.05rem;
  background: rgba(0, 229, 200, 0.07);
  border: 1px solid rgba(0, 229, 200, 0.2);
  border-radius: 10px;
  box-shadow: inset 0 1px 0 rgba(0, 229, 200, 0.08);
}
[data-brief-view="tactical"] .tactical-block li {
  font-family: var(--mono);
  font-size: 0.88rem;
  line-height: 1.62;
  color: #c5d4e8;
}
[data-brief-view="tactical"] .tactical-block li strong {
  color: var(--text);
}
[data-brief-view="executive"] .tactical-block {
  display: none !important;
}
/* Executive: editorial stack — no side thread, impact reads as summary prose */
[data-brief-view="executive"] .intelligence-card__thread {
  border-left: none !important;
  padding-left: 0 !important;
}
[data-brief-view="executive"] .brief-cluster--has-impact .impact-block .digest-block-label {
  display: none;
}
[data-brief-view="executive"] .brief-exec-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  gap: 0.35rem 0.65rem;
}
[data-brief-view="executive"] .brief-cluster--has-impact .brief-exec-summary {
  display: block;
}
[data-brief-view="executive"] .brief-sev-anchor {
  flex: 0 0 auto;
}
[data-brief-view="executive"] .brief-sev-anchor .sev {
  font-size: 0.72rem;
  padding: 0.22rem 0.55rem;
  letter-spacing: 0.08em;
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1);
}
[data-brief-view="executive"] .brief-cluster--has-impact .brief-sev-anchor {
  display: inline-block;
  margin: 0 0 0.35rem;
  vertical-align: middle;
}
[data-brief-view="executive"] .brief-cluster--has-impact .threat-title {
  margin-bottom: 0.75rem;
}
[data-brief-view="executive"] .brief-cluster--has-impact .impact-block {
  margin-top: 0;
  padding-top: 0;
  border-top: none;
}
[data-brief-view="executive"] .brief-cluster--has-impact .impact-block .digest-subblock-body {
  display: block;
  font-size: 1.04rem;
  line-height: 1.78;
  font-weight: 400;
  color: #b8c4dc;
  max-width: 65ch;
}
[data-brief-view="executive"] .brief-cluster--has-impact .impact-block .digest-subblock-body p {
  display: block;
  margin: 0 0 0.85rem;
}
[data-brief-view="executive"] .brief-cluster--has-impact .impact-block .digest-subblock-body p:last-child {
  margin-bottom: 0;
}
[data-brief-view="executive"] .brief-cluster:not(.brief-cluster--has-impact) .threat-title {
  flex: 1 1 200px;
  margin-bottom: 0;
  padding-bottom: 0.35rem;
}
/* Nested tactical lists — thread only, no boxes */
.digest-section li > ul,
.digest-section li > ol {
  margin-top: 0.5rem;
  margin-bottom: 0;
  margin-left: 0;
  padding-left: 1rem;
  border-left: 1px solid var(--border);
  gap: 0.35rem;
}
.digest-section li > ol {
  counter-reset: item;
}
.digest-section li li {
  font-size: 0.96rem;
}
.digest-section li ul > li::before {
  content: "";
  position: absolute;
  left: 0;
  top: 0.65em;
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: var(--muted);
  opacity: 0.5;
}
.digest-section li ol > li {
  padding-left: 1.75rem;
}
.digest-section li ol > li::before {
  content: counter(item);
  width: auto;
  height: auto;
  border-radius: 0;
  background: none;
  box-shadow: none;
  opacity: 0.75;
  left: 0;
  top: 0.35em;
  font-family: var(--mono);
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--accent);
}

.digest-section .digest-block-label {
  margin: 0 0 0.5rem;
  padding: 0.15rem 0 0.2rem;
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.62rem;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  line-height: 1.2;
  opacity: 0.95;
  vertical-align: middle;
}
.impact-block .digest-block-label,
.tactical-block .digest-block-label {
  display: inline-flex;
  min-width: 6.75rem;
  margin-right: 0.5rem;
  margin-bottom: 0.55rem;
  padding-right: 0.35rem;
  border-bottom: 1px solid rgba(120, 140, 200, 0.18);
}
.tactical-block .digest-block-label {
  color: var(--violet);
  border-bottom-color: rgba(0, 229, 200, 0.2);
}
.digest-section .digest-block-label--impact {
  color: var(--accent);
}
.digest-section .digest-block-label--actions {
  color: var(--violet);
}
.digest-label-icon {
  display: grid;
  place-items: center;
  width: 1.25rem;
  height: 1.25rem;
  min-width: 1.25rem;
  flex-shrink: 0;
}
.digest-label-svg {
  width: 14px;
  height: 14px;
  stroke-width: 2.2;
}
.digest-label-text {
  font-size: inherit;
  letter-spacing: inherit;
}
@keyframes brief-icon-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.72; transform: scale(0.94); }
}
.digest-label-icon--impact {
  animation: brief-icon-pulse 2.8s ease-in-out infinite;
}
@media (prefers-reduced-motion: reduce) {
  .digest-label-icon--impact { animation: none; }
}
.digest-section .digest-subblock-body {
  margin: 0;
  max-width: 68ch;
  line-height: 1.7;
  color: var(--text-soft);
}
.digest-section .digest-subblock-body > p:first-child {
  margin-top: 0;
}
.digest-section .tactical-block > ul,
.digest-section .tactical-block > ol {
  margin-top: 0.25rem;
}
[data-brief-view="tactical"] .impact-block {
  margin-top: 0.85rem;
}
[data-brief-view="tactical"] .impact-block .digest-subblock-body {
  margin-top: 0.15rem;
}
.digest-section .action-label {
  background: transparent;
  border: none;
  padding: 0;
  font-weight: 600;
  border-bottom: 1px dashed rgba(0, 229, 200, 0.35);
  border-radius: 0;
}
.digest-section a {
  color: var(--accent);
  text-decoration: none;
  border-bottom: 1px solid rgba(0, 229, 200, 0.35);
  transition: border-color 0.2s, color 0.2s;
}
@media (hover: hover) and (pointer: fine) {
  .digest-section a:hover {
    color: #7ff5e8;
    border-bottom-color: var(--accent);
  }
}

/* Touch-friendly link styling */
@media (hover: none) and (pointer: coarse) {
  .digest-section a {
    padding: 0.15rem 0.25rem;
    margin: -0.15rem -0.25rem;
    border-radius: 4px;
    background: rgba(0, 229, 200, 0.08);
  }
}
.digest-section code {
  font-family: var(--mono);
  font-size: 0.86em;
  background: rgba(0, 229, 200, 0.08);
  padding: 0.12rem 0.38rem;
  border-radius: 6px;
  border: 1px solid rgba(0, 229, 200, 0.15);
  color: #b8fff4;
}
.digest-section pre {
  margin: 1rem 0 0;
  background: var(--void);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem;
  overflow-x: auto;
  font-size: 0.82rem;
  max-width: 100%;
}
.digest-section pre code {
  background: none;
  border: none;
  padding: 0;
  color: var(--text-soft);
}
.digest-section strong { color: var(--text); font-weight: 600; }

/* Severity badges (inline, scannable) */
.digest-section .sev {
  display: inline-flex;
  align-items: center;
  vertical-align: baseline;
  margin: 0 0.1rem;
  padding: 0.15rem 0.45rem;
  border-radius: 6px;
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  line-height: 1.2;
  border: 1px solid transparent;
  position: relative;
  overflow: hidden;
  cursor: help;
  transition: all 0.2s ease;
}

.digest-section .sev::before {
  content: "";
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
  transition: left 0.5s ease;
}

@media (hover: hover) and (pointer: fine) {
  .digest-section .sev:hover::before {
    left: 100%;
  }
  
  .digest-section .sev:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  }
}
.digest-section .sev strong {
  color: inherit;
  font-weight: 800;
}
.digest-section .sev-critical {
  color: #fecaca;
  background: rgba(251, 113, 133, 0.18);
  border-color: rgba(251, 113, 133, 0.45);
}
.digest-section .sev-high {
  color: #fed7aa;
  background: rgba(251, 191, 36, 0.14);
  border-color: rgba(251, 191, 36, 0.4);
}
.digest-section .sev-medium {
  color: #fde68a;
  background: rgba(234, 179, 8, 0.12);
  border-color: rgba(234, 179, 8, 0.35);
}
.digest-section .sev-low {
  color: #a7f3d0;
  background: rgba(52, 211, 153, 0.12);
  border-color: rgba(52, 211, 153, 0.35);
}
.digest-section .sev-info {
  color: #c4b5fd;
  background: rgba(167, 139, 250, 0.14);
  border-color: rgba(167, 139, 250, 0.4);
}

/* Action lead-ins */
.digest-section .action-label {
  display: inline;
  font-weight: 700;
  font-size: 0.92em;
  color: var(--accent);
  background: rgba(0, 229, 200, 0.1);
  padding: 0.08rem 0.4rem;
  border-radius: 5px;
  border: 1px solid rgba(0, 229, 200, 0.28);
  box-decoration-break: clone;
  -webkit-box-decoration-break: clone;
}
.digest-section .action-label strong {
  color: inherit;
  font-weight: 800;
}

.digest-section hr {
  border: none;
  height: 1px;
  margin: 1.35rem 0;
  background: linear-gradient(90deg, transparent, var(--border), transparent);
}
.digest-section blockquote {
  margin: 1rem 0 0;
  padding: 0.25rem 0 0.25rem 1rem;
  border-left: 1px solid var(--border);
  background: transparent;
  border-radius: 0;
  color: var(--text-soft);
  font-size: 0.94rem;
  line-height: 1.7;
}
.digest-section table {
  width: 100%;
  max-width: 100%;
  margin: 1rem 0 0;
  border-collapse: collapse;
  font-size: 0.88rem;
  border-radius: var(--radius-sm);
  overflow: hidden;
  border: 1px solid var(--border);
}
.digest-section th,
.digest-section td {
  padding: 0.6rem 0.85rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.digest-section th {
  background: rgba(0, 229, 200, 0.07);
  color: var(--text);
  font-weight: 600;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.digest-section tr:last-child td { border-bottom: none; }
@media (hover: hover) and (pointer: fine) {
  .digest-section tr:hover td {
    background: rgba(255, 255, 255, 0.02);
  }
}

/* --- Profile --- */
.profile-card {
  position: relative;
  padding: 1.35rem 1.4rem;
}
.profile-glow {
  position: absolute;
  top: -40px;
  right: -40px;
  width: 120px;
  height: 120px;
  background: var(--glow-violet);
  filter: blur(40px);
  opacity: 0.5;
  pointer-events: none;
}
.profile-title {
  position: relative;
  margin: 0 0 1rem;
  font-size: 0.72rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.16em;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.profile-title-icon {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 12px var(--accent);
}
.profile-dl { margin: 0; position: relative; z-index: 1; }
.profile-dl dt {
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--muted);
  margin-top: 1rem;
}
.profile-dl dt:first-child { margin-top: 0; }
.profile-dl dd {
  margin: 0.35rem 0 0;
  font-size: 0.88rem;
  color: var(--text);
  line-height: 1.5;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.4rem !important;
}
.chip {
  display: inline-block;
  font-size: 0.72rem;
  padding: 0.28rem 0.55rem;
  border-radius: 6px;
  background: rgba(0, 229, 200, 0.1);
  border: 1px solid rgba(0, 229, 200, 0.2);
  color: #9cf5e8;
}
ul.tool-list {
  margin: 0.35rem 0 0;
  padding-left: 1rem;
  color: var(--text-soft);
  font-size: 0.84rem;
}
ul.tool-list li { margin: 0.35rem 0; }

/* --- Footer --- */
.site-footer {
  position: relative;
  z-index: 1;
  margin-top: 2.5rem;
  padding: 2rem 1.5rem 2.5rem;
  text-align: center;
  border-top: 1px solid var(--border);
  background: linear-gradient(180deg, transparent, rgba(0,0,0,0.35));
}
.site-footer p {
  margin: 0;
  font-size: 0.75rem;
  color: var(--muted);
  letter-spacing: 0.04em;
}
.site-footer strong {
  color: var(--text-soft);
  font-weight: 600;
}

/* Navigation Links */
.nav-links a:hover {
  color: var(--accent) !important;
  background: var(--surface) !important;
}

/* Financial Actor Mentions */
.financial-actor-mention {
  background: linear-gradient(135deg, var(--rose), var(--amber));
  color: white;
  padding: 0.2rem 0.4rem;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.3s ease;
  box-shadow: 0 2px 4px rgba(251, 113, 133, 0.3);
}

.financial-actor-mention:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(251, 113, 133, 0.4);
  background: linear-gradient(135deg, var(--accent), var(--violet));
}
"""


def build_digest_html(
    *,
    summary_markdown: str,
    profile: dict[str, Any],
    datestamp: str,
    days: int,
    kev_count: int,
    article_count: int,
    used_llm: bool,
    digest_payload: dict[str, Any] | None = None,
) -> str:
    if digest_payload:
        body_html = _html_body_from_digest_payload(digest_payload)
    else:
        body_html = _cluster_brief_lists(
            _enrich_digest_html(
                _sectionize_prose_html(_markdown_to_html(summary_markdown))
            )
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    company = html.escape(str(profile.get("company_name") or "Threat intelligence briefing"))
    mode = "AI synthesis" if used_llm else "Source intelligence"
    sidebar = _profile_sidebar_html(profile)
    layout_class = "layout layout-with-sidebar" if sidebar.strip() else "layout layout-full"
    sidebar_column = (
        f'<div class="layout-sidebar">{sidebar}</div>' if sidebar.strip() else ""
    )

    sector = profile.get("sector")
    sector_block = (
        f'<span class="sector-chip">{html.escape(str(sector))}</span>'
        if sector
        else ""
    )

    # Inline SVGs (no external assets)
    icon_shield = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"""
    icon_rss = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1" fill="currentColor" stroke="none"/></svg>"""
    icon_clock = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>"""
    logo_svg = """<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6l-8-4zm0 2.18l6 3v5.82c0 4.54-3.07 8.83-6 9.89-2.93-1.06-6-5.35-6-9.89V7.18l6-3zM11 7v6h4v-2h-2V7h-2z"/></svg>"""

    pill_class = "pill pill-live" if used_llm else "pill"

    return f"""<!DOCTYPE html>
<html lang="en" data-brief-view="executive">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta name="color-scheme" content="dark"/>
  <title>Executive intelligence briefing — {html.escape(datestamp)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet"/>
  <style>{_DIGEST_STYLES}</style>
</head>
<body class="brief-root">
  <div class="bg-stage" aria-hidden="true">
    <div class="bg-mesh"></div>
    <div class="bg-grid"></div>
    <div class="bg-orb bg-orb-1"></div>
    <div class="bg-orb bg-orb-2"></div>
  </div>

  <header class="top-shell">
    <div class="progress-bar" id="reading-progress"></div>
    <div class="top-inner">
      <div class="brand-lockup">
        <div class="logo" aria-hidden="true">{logo_svg}</div>
        <div class="brand-text">
          <h1>{company}</h1>
          <p class="sub">Cyber intelligence briefing · {html.escape(datestamp)}</p>
        </div>
      </div>
      <div class="nav-links" style="display: flex; gap: 1rem; align-items: center;">
        <a href="../actor_watch/index.html" style="color: var(--text-soft); text-decoration: none; padding: 0.5rem 1rem; border-radius: var(--radius-sm); transition: all 0.3s ease; font-weight: 500;">🎯 Actor Watch</a>
        <a href="history.html" style="color: var(--text-soft); text-decoration: none; padding: 0.5rem 1rem; border-radius: var(--radius-sm); transition: all 0.3s ease; font-weight: 500;">📚 History</a>
      </div>
      <div class="top-controls">
        <button type="button" class="toc-toggle" id="toc-toggle" aria-label="Table of contents">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px">
            <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/>
            <line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>
          </svg>
        </button>
        <button type="button" class="export-btn" id="export-btn" aria-label="Export summary">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
        </button>
        <div class="view-toggle" role="group" aria-label="View mode">
          <button type="button" class="view-toggle-btn is-active" data-brief-view="executive" aria-pressed="true">Executive Briefing</button>
          <button type="button" class="view-toggle-btn" data-brief-view="tactical" aria-pressed="false">SecOps Tactical</button>
        </div>
        <div class="pill-row">
          <span class="{pill_class}"><span class="dot"></span>{html.escape(mode)}</span>
          <span class="pill">{html.escape(generated)}</span>
        </div>
      </div>
    </div>
  </header>
  
  <nav class="toc-overlay" id="toc-overlay">
    <div class="toc-content">
      <h3>Contents</h3>
      <ul class="toc-list">
        <li><a href="#digest-body">Overview</a></li>
        <li><a href="#vulnerabilities">Key Vulnerabilities</a></li>
        <li><a href="#campaigns">Notable Campaigns</a></li>
        <li><a href="#actions">Recommended Actions</a></li>
      </ul>
    </div>
  </nav>

  <section class="hero">
    <p class="hero-eyebrow">Cyber intelligence</p>
    <h2 class="hero-title">Global Threat <span>Landscape</span></h2>
    <p class="hero-lede">CISA KEV and curated global headlines, framed against {company}&rsquo;s sector and security stack so leadership sees external risk in context—not in isolation.</p>
    {sector_block}
  </section>

  <div class="wrap">
    <div class="metrics">
      <div class="metric">
        <div class="metric-icon" style="color:var(--accent)">{icon_shield}</div>
        <div class="metric-num">{kev_count}</div>
        <div class="metric-label">CISA KEV items</div>
      </div>
      <div class="metric">
        <div class="metric-icon" style="color:var(--violet)">{icon_rss}</div>
        <div class="metric-num">{article_count}</div>
        <div class="metric-label">Headlines triaged</div>
      </div>
      <div class="metric">
        <div class="metric-icon" style="color:var(--amber)">{icon_clock}</div>
        <div class="metric-num">{days}d</div>
        <div class="metric-label">Lookback window</div>
      </div>
    </div>
    
    <div class="severity-chart" id="severity-chart">
      <h3>Threat Severity Distribution</h3>
      <div class="chart-container">
        <div class="severity-bar" data-severity="critical">
          <div class="bar-fill" data-count="0"></div>
          <span class="bar-label">Critical</span>
        </div>
        <div class="severity-bar" data-severity="high">
          <div class="bar-fill" data-count="0"></div>
          <span class="bar-label">High</span>
        </div>
        <div class="severity-bar" data-severity="medium">
          <div class="bar-fill" data-count="0"></div>
          <span class="bar-label">Medium</span>
        </div>
        <div class="severity-bar" data-severity="low">
          <div class="bar-fill" data-count="0"></div>
          <span class="bar-label">Low</span>
        </div>
      </div>
    </div>

    <div class="{layout_class}">
      <article class="main-card glass brief-main" id="digest-body">
        <div class="prose-readable">
        {body_html}
        </div>
      </article>
      {sidebar_column}
    </div>
  </div>

  <footer class="site-footer">
    <p><strong>SecOps Innovation</strong> · CISA KEV + curated RSS · Internal use only</p>
  </footer>
  
  <div id="notification" class="notification"></div>
  
  <!-- Sliding Blade System -->
  <div id="blade-backdrop" class="blade-backdrop" onclick="closeBlade()"></div>
  <div id="blade-overlay" class="blade-overlay">
    <div class="blade-header">
      <div class="blade-title">
        <span id="blade-icon">🎯</span>
        <span id="blade-actor-name">Threat Actor</span>
      </div>
      <button class="blade-close" onclick="closeBlade()" aria-label="Close">×</button>
    </div>
    <div class="blade-content" id="blade-content">
      <!-- Dynamic content will be loaded here -->
    </div>
  </div>
  
  <script>
  (function () {{
    var KEY = "threat-brief-view";
    var root = document.documentElement;
    
    // View toggle functionality
    function apply(v) {{
      var mode = v === "tactical" ? "tactical" : "executive";
      root.setAttribute("data-brief-view", mode);
      try {{ localStorage.setItem(KEY, mode); }} catch (e) {{}}
      document.querySelectorAll(".view-toggle-btn").forEach(function (btn) {{
        var on = btn.getAttribute("data-brief-view") === mode;
        btn.classList.toggle("is-active", on);
        btn.setAttribute("aria-pressed", on ? "true" : "false");
      }});
    }}
    
    var saved = null;
    try {{ saved = localStorage.getItem(KEY); }} catch (e) {{}}
    apply(saved === "tactical" ? "tactical" : "executive");
    
    var bar = document.querySelector(".view-toggle");
    if (bar) {{
      bar.addEventListener("click", function (e) {{
        var t = e.target.closest(".view-toggle-btn");
        if (!t || !bar.contains(t)) return;
        apply(t.getAttribute("data-brief-view"));
      }});
    }}
    
    // Reading progress indicator
    function updateProgress() {{
      var scrollTop = window.pageYOffset || document.documentElement.scrollTop;
      var scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
      var progress = scrollHeight > 0 ? (scrollTop / scrollHeight) * 100 : 0;
      var progressBar = document.getElementById("reading-progress");
      if (progressBar) {{
        progressBar.style.transform = "scaleX(" + (progress / 100) + ")";
      }}
    }}
    
    window.addEventListener("scroll", updateProgress);
    window.addEventListener("resize", updateProgress);
    updateProgress();
    
    // Table of contents functionality
    var tocToggle = document.getElementById("toc-toggle");
    var tocOverlay = document.getElementById("toc-overlay");
    
    if (tocToggle && tocOverlay) {{
      tocToggle.addEventListener("click", function () {{
        tocOverlay.classList.add("active");
      }});
      
      tocOverlay.addEventListener("click", function (e) {{
        if (e.target === tocOverlay || e.target.tagName === "A") {{
          tocOverlay.classList.remove("active");
        }}
      }});
      
      document.addEventListener("keydown", function (e) {{
        if (e.key === "Escape" && tocOverlay.classList.contains("active")) {{
          tocOverlay.classList.remove("active");
        }}
      }});
    }}
    
    // Export functionality
    var exportBtn = document.getElementById("export-btn");
    if (exportBtn) {{
      exportBtn.addEventListener("click", function () {{
        exportDigestSummary();
      }});
    }}
    
    function exportDigestSummary() {{
      var title = document.querySelector(".hero-title").textContent;
      var date = document.querySelector(".brand-text .sub").textContent;
      var company = document.querySelector(".brand-text h1").textContent;
      
      var summary = title + "\\n" + "=".repeat(title.length) + "\\n\\n";
      summary += company + " - " + date + "\\n\\n";
      
      // Add metrics
      var metrics = document.querySelectorAll(".metric");
      metrics.forEach(function (metric) {{
        var num = metric.querySelector(".metric-num").textContent;
        var label = metric.querySelector(".metric-label").textContent;
        summary += "• " + num + " " + label + "\\n";
      }});
      summary += "\\n";
      
      // Add sections
      var sections = document.querySelectorAll(".digest-section");
      sections.forEach(function (section) {{
        var heading = section.querySelector("h2").textContent;
        summary += heading.toUpperCase() + "\\n" + "-".repeat(heading.length) + "\\n";
        
        var threats = section.querySelectorAll(".threat-title");
        threats.forEach(function (threat, index) {{
          summary += (index + 1) + ". " + threat.textContent + "\\n";
        }});
        summary += "\\n";
      }});
      
      // Create and download file
      var blob = new Blob([summary], {{ type: "text/plain" }});
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "threat-digest-summary-" + new Date().toISOString().split('T')[0] + ".txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      showNotification("Summary exported successfully", "success");
    }}
    
    // Smooth scrolling for anchor links
    document.addEventListener("click", function (e) {{
      if (e.target.tagName === "A" && e.target.getAttribute("href") && e.target.getAttribute("href").startsWith("#")) {{
        e.preventDefault();
        var target = document.querySelector(e.target.getAttribute("href"));
        if (target) {{
          target.scrollIntoView({{ behavior: "smooth", block: "start" }});
        }}
      }}
    }});
    
    // Notification system
    function showNotification(message, type) {{
      var notification = document.getElementById("notification");
      if (notification) {{
        notification.textContent = message;
        notification.className = "notification " + (type || "");
        notification.classList.add("show");
        
        setTimeout(function () {{
          notification.classList.remove("show");
        }}, 3000);
      }}
    }}
    
    // Copy link functionality for threat titles
    document.addEventListener("click", function (e) {{
      if (e.target.classList.contains("threat-title")) {{
        var title = e.target.textContent;
        var url = window.location.href.split("#")[0] + "#threat-" + encodeURIComponent(title.toLowerCase().replace(/\\s+/g, "-"));
        
        if (navigator.clipboard) {{
          navigator.clipboard.writeText(url).then(function () {{
            showNotification("Link copied to clipboard", "success");
          }}).catch(function () {{
            showNotification("Could not copy link", "error");
          }});
        }} else {{
          // Fallback for older browsers
          var textArea = document.createElement("textarea");
          textArea.value = url;
          document.body.appendChild(textArea);
          textArea.select();
          try {{
            document.execCommand("copy");
            showNotification("Link copied to clipboard", "success");
          }} catch (err) {{
            showNotification("Could not copy link", "error");
          }}
          document.body.removeChild(textArea);
        }}
      }}
    }});
    
    // Add section IDs for navigation
    document.addEventListener("DOMContentLoaded", function () {{
      var sections = document.querySelectorAll(".digest-section h2");
      sections.forEach(function (section, index) {{
        var text = section.textContent.toLowerCase();
        var id = "";
        if (text.includes("vulnerabilities")) id = "vulnerabilities";
        else if (text.includes("campaigns")) id = "campaigns";
        else if (text.includes("actions")) id = "actions";
        else id = "section-" + (index + 1);
        
        section.parentElement.id = id;
      }});
      
      // Add IDs to threat titles for direct linking
      var threatTitles = document.querySelectorAll(".threat-title");
      threatTitles.forEach(function (title) {{
        var id = "threat-" + title.textContent.toLowerCase().replace(/\\s+/g, "-");
        title.id = id;
      }});
      
      // Populate severity chart
      populateSeverityChart();
    }});
    
    // Severity chart functionality
    function populateSeverityChart() {{
      var severityCounts = {{ critical: 0, high: 0, medium: 0, low: 0 }};
      
      // Count severity badges
      var severityBadges = document.querySelectorAll('.sev[data-sev-badge="1"]');
      severityBadges.forEach(function (badge) {{
        var severity = badge.getAttribute('data-sev');
        if (severity && severityCounts.hasOwnProperty(severity)) {{
          severityCounts[severity]++;
        }}
      }});
      
      // Find the maximum count for scaling
      var maxCount = Math.max.apply(Math, Object.values(severityCounts));
      if (maxCount === 0) maxCount = 1; // Avoid division by zero
      
      // Update the chart
      Object.keys(severityCounts).forEach(function (severity) {{
        var count = severityCounts[severity];
        var percentage = (count / maxCount) * 100;
        
        var bar = document.querySelector('.severity-bar[data-severity="' + severity + '"] .bar-fill');
        if (bar) {{
          bar.setAttribute('data-count', count);
          bar.style.setProperty('--fill-width', percentage + '%');
          
          // Trigger animation after a short delay
          setTimeout(function () {{
            bar.style.setProperty('--fill-width', percentage + '%');
          }}, 500);
        }}
      }});
    }}
    
    // Sliding Blade System
    window.actorData = {{
      'storm-1175': {{
        name: 'Storm-1175',
        id: 'storm-1175',
        aliases: ['Storm-1175', 'DEV-1175'],
        description: 'Financially motivated cybercriminal group conducting ransomware and extortion operations targeting various industries with sophisticated attack chains.',
        techniques: [
          {{ id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access' }},
          {{ id: 'T1059.001', name: 'PowerShell', tactic: 'execution' }},
          {{ id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion' }},
          {{ id: 'T1003', name: 'OS Credential Dumping', tactic: 'credential-access' }},
          {{ id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact' }},
          {{ id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration' }}
        ],
        tools: ['BlackCat', 'ALPHV', 'Cobalt Strike', 'Mimikatz', 'PowerShell', 'WMI'],
        sectors: ['healthcare', 'manufacturing', 'education', 'government', 'financial_services'],
        recent_activity: [
          '2024-Q1: Targeting healthcare organizations with BlackCat ransomware variants',
          '2023-Q4: Double extortion campaigns against manufacturing sector using data theft',
          '2023-Q3: Initial access broker activities selling network access to other threat actors'
        ]
      }},
      'apt29': {{
        name: 'APT29',
        id: 'G0016',
        aliases: ['APT29', 'Cozy Bear', 'NOBELIUM', 'Midnight Blizzard'],
        description: 'Russian state-sponsored threat group attributed to the SVR, active since at least 2008, targeting government networks and research institutes.',
        techniques: [
          {{ id: 'T1566.002', name: 'Spearphishing Link', tactic: 'initial-access' }},
          {{ id: 'T1059.001', name: 'PowerShell', tactic: 'execution' }},
          {{ id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion' }},
          {{ id: 'T1078', name: 'Valid Accounts', tactic: 'persistence' }},
          {{ id: 'T1071.001', name: 'Web Protocols', tactic: 'command-and-control' }}
        ],
        tools: ['HAMMERTOSS', 'CosmicDuke', 'SUNBURST', 'TEARDROP'],
        sectors: ['government', 'diplomatic', 'research', 'technology'],
        recent_activity: [
          '2024: Ongoing espionage campaigns against Western governments',
          '2023: SolarWinds supply chain compromise attribution',
          '2023: Advanced cloud infrastructure targeting'
        ]
      }}
    }};
    
    function openBlade(actorName) {{
      const actor = window.actorData[actorName.toLowerCase().replace(/[^a-z0-9]/g, '-')];
      if (!actor) {{
        console.warn('Actor data not found:', actorName);
        return;
      }}
      
      // Update blade header
      document.getElementById('blade-actor-name').textContent = actor.name;
      
      // Build blade content
      let content = `
        <div class="actor-overview">
          ${{actor.id ? `<div class="actor-id">ID: ${{actor.id}}</div>` : ''}}
          <div class="actor-aliases">
            ${{actor.aliases.map(alias => `<span class="alias-tag">${{alias}}</span>`).join('')}}
          </div>
          <div class="actor-description">${{actor.description}}</div>
        </div>
        
        <div class="blade-section">
          <h3>Attack Techniques</h3>
          <div class="technique-grid">
            ${{actor.techniques.map(tech => `
              <div class="technique-card">
                <div class="technique-header">
                  <span class="technique-id">${{tech.id}}</span>
                  <span class="tactic-badge tactic-${{tech.tactic.replace(/[^a-z]/g, '-')}}">${{tech.tactic.replace('-', ' ').toUpperCase()}}</span>
                </div>
                <div class="technique-name">${{tech.name}}</div>
              </div>
            `).join('')}}
          </div>
        </div>
        
        <div class="blade-section">
          <h3>Associated Tools</h3>
          <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
            ${{actor.tools.map(tool => `<span class="alias-tag">${{tool}}</span>`).join('')}}
          </div>
        </div>
        
        <div class="blade-section">
          <h3>Target Sectors</h3>
          <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
            ${{actor.sectors.map(sector => `<span class="alias-tag">${{sector.replace('_', ' ').toUpperCase()}}</span>`).join('')}}
          </div>
        </div>
        
        <div class="blade-section">
          <h3>Recent Activity</h3>
          <div style="space-y: 0.5rem;">
            ${{actor.recent_activity.map(activity => `
              <div style="padding: 0.75rem; background: var(--elevated); border-radius: var(--radius-sm); margin-bottom: 0.5rem;">
                ${{activity}}
              </div>
            `).join('')}}
          </div>
        </div>
      `;
      
      document.getElementById('blade-content').innerHTML = content;
      
      // Show blade
      document.getElementById('blade-backdrop').classList.add('active');
      document.getElementById('blade-overlay').classList.add('active');
      document.body.style.overflow = 'hidden';
    }}
    
    function closeBlade() {{
      document.getElementById('blade-backdrop').classList.remove('active');
      document.getElementById('blade-overlay').classList.remove('active');
      document.body.style.overflow = '';
    }}
    
    // Close blade on escape key
    document.addEventListener('keydown', function(e) {{
      if (e.key === 'Escape') {{
        closeBlade();
      }}
    }});
    
    // Character Select Screen
    let currentPage = 'digest';
    
    function showPage(page) {{
      // Hide all pages
      document.querySelectorAll('.wrap, .hero').forEach(el => {{
        el.style.display = page === 'digest' ? 'block' : 'none';
      }});
      document.getElementById('actors-page').classList.toggle('active', page === 'actors');
      
      // Update navigation
      document.querySelectorAll('.nav-dot').forEach(dot => {{
        dot.classList.toggle('active', dot.dataset.page === page);
      }});
      
      currentPage = page;
      
      if (page === 'actors') {{
        populateActorsGrid();
      }}
    }}
    
    function populateActorsGrid() {{
      const grid = document.getElementById('actors-grid');
      
      // Render known actor cards from the bundled actor data only.
      grid.innerHTML = '';
      
      Object.keys(window.actorData).forEach(actorKey => {{
        const actor = window.actorData[actorKey];
        const card = createActorCard(actor, actorKey);
        grid.appendChild(card);
      }});
    }}
    
    function createActorCard(actor, actorKey) {{
      const card = document.createElement('div');
      card.className = 'actor-card';
      card.onclick = () => openBlade(actorKey);
      
      const typeClass = `type-${{actor.type || 'unknown'}}`.replace(/_/g, '-');
      const typeLabel = (actor.type || 'unknown').replace(/_/g, ' ').toUpperCase();
      
      // Get first letter of actor name for avatar
      const avatarLetter = actor.name.charAt(0).toUpperCase();
      
      // Calculate stats
      const techniqueCount = actor.techniques ? actor.techniques.length : 0;
      const toolCount = actor.tools ? actor.tools.length : 0;
      const sectorCount = actor.sectors ? actor.sectors.length : 0;
      
      card.innerHTML = `
        <div class="actor-card-header">
          <div class="actor-avatar">${{avatarLetter}}</div>
          <div class="actor-type-badge ${{typeClass}}">${{typeLabel}}</div>
        </div>
        <h3 class="actor-name">${{actor.name}}</h3>
        ${{actor.id ? `<div class="actor-id">ID: ${{actor.id}}</div>` : ''}}
        <p class="actor-description">${{actor.description}}</p>
        <div class="actor-stats">
          <div class="actor-stat">
            <span class="stat-value">${{techniqueCount}}</span>
            <span class="stat-label">Techniques</span>
          </div>
          <div class="actor-stat">
            <span class="stat-value">${{toolCount}}</span>
            <span class="stat-label">Tools</span>
          </div>
          <div class="actor-stat">
            <span class="stat-value">${{sectorCount}}</span>
            <span class="stat-label">Sectors</span>
          </div>
        </div>
        <div class="actor-tags">
          ${{actor.aliases.slice(0, 3).map(alias => `<span class="actor-tag">${{alias}}</span>`).join('')}}
        </div>
      `;
      
      return card;
    }}
    
    // Make financial actor mentions clickable and trackable
    document.addEventListener('DOMContentLoaded', function() {{
      // Financial actors to track
      const financialActors = {{
        'fin7': ['FIN7', 'Carbanak Group', 'Navigator Group'],
        'fin8': ['FIN8', 'Syssphinx'],
        'fin6': ['FIN6', 'ITG08', 'Skeleton Spider'],
        'fin11': ['FIN11', 'TA505'],
        'fin12': ['FIN12', 'UNC1878'],
        'carbanak': ['Carbanak', 'Anunak'],
        'silence': ['Silence', 'Whisper Spider']
      }};
      
      const contentElements = document.querySelectorAll('.digest-section p, .digest-section li');
      
      contentElements.forEach(element => {{
        let html = element.innerHTML;
        Object.keys(financialActors).forEach(actorKey => {{
          const names = financialActors[actorKey];
          
          names.forEach(name => {{
            const regex = new RegExp('\\\\b' + name.replace(/[.*+?^${{}}()|[\\\\]\\\\\\\\]/g, '\\\\$&') + '\\\\b', 'gi');
            html = html.replace(regex, '<span class="financial-actor-mention" onclick="viewActorProfile(\\'' + actorKey + '\\', \\'' + name + '\\')" title="Click to view ' + name + ' profile in Actor Watch">' + name + '</span>');
          }});
        }});
        element.innerHTML = html;
      }});
    }});
    
    function viewActorProfile(actorKey, actorName) {{
      const confirmation = confirm('🎯 View ' + actorName + ' in Actor Watch?\\n\\nThis will open the dedicated Actor Watch page with detailed financial threat actor profiles.');
      if (confirmation) {{
        window.open('../actor_watch/index.html#' + actorKey, '_blank');
      }}
    }}
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {{
      if (e.key === '1' && e.ctrlKey) {{
        e.preventDefault();
        showPage('digest');
      }} else if (e.key === '2' && e.ctrlKey) {{
        e.preventDefault();
        showPage('actors');
      }}
    }});
    
  }})();
  </script>

</body>
</html>
"""


def _build_pdf_styles() -> str:
    """Generate print-optimized CSS for PDF export."""
    return """
    /* PDF-specific styles */
    @page {
        size: A4;
        margin: 2cm 1.5cm;
        @top-center {
            content: "Threat Intelligence Digest";
            font-family: var(--font);
            font-size: 10pt;
            color: var(--muted);
        }
        @bottom-center {
            content: "Page " counter(page) " of " counter(pages);
            font-family: var(--font);
            font-size: 9pt;
            color: var(--muted);
        }
    }
    
    /* Override dark theme for print */
    :root {
        --void: #ffffff;
        --deep: #f8f9fa;
        --surface: rgba(248, 249, 250, 0.8);
        --surface-solid: #f1f3f4;
        --elevated: rgba(241, 243, 244, 0.9);
        --border: rgba(0, 0, 0, 0.12);
        --border-bright: rgba(0, 0, 0, 0.25);
        --text: #1a1a1a;
        --text-soft: #4a4a4a;
        --muted: #6a6a6a;
        --accent: #0066cc;
        --accent-dim: #0052a3;
        --violet: #6366f1;
        --rose: #dc2626;
        --amber: #d97706;
    }
    
    body {
        background: white;
        color: var(--text);
        font-size: 11pt;
        line-height: 1.4;
    }
    
    /* Hide interactive elements */
    .bg-stage,
    .view-toggle,
    .bg-orb,
    .bg-mesh,
    .bg-grid {
        display: none !important;
    }
    
    /* Simplify header for print */
    .top-shell {
        position: static;
        background: white;
        border-bottom: 2px solid var(--border);
        backdrop-filter: none;
    }
    
    .top-inner {
        padding: 1rem 0;
    }
    
    .top-controls {
        display: none;
    }
    
    /* Adjust hero for print */
    .hero {
        padding: 1.5rem 0 1rem;
    }
    
    .hero-title {
        font-size: 18pt;
        color: var(--text);
    }
    
    .hero-lede {
        font-size: 11pt;
        color: var(--text-soft);
    }
    
    /* Simplify layout for print */
    .layout-with-sidebar {
        grid-template-columns: 2fr 1fr;
        gap: 1.5rem;
    }
    
    .main-card {
        background: white;
        border: 1px solid var(--border);
        box-shadow: none;
        page-break-inside: avoid;
    }
    
    .profile-card {
        background: var(--surface);
        border: 1px solid var(--border);
        page-break-inside: avoid;
    }
    
    /* Improve section breaks */
    .digest-section {
        page-break-inside: avoid;
        break-inside: avoid;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid var(--border);
    }
    
    .digest-section h2 {
        color: var(--text);
        font-size: 12pt;
        page-break-after: avoid;
    }
    
    /* Improve threat cards for print */
    .intelligence-card__body {
        background: var(--surface);
        border: 1px solid var(--border);
        page-break-inside: avoid;
        margin-bottom: 1rem;
    }
    
    .threat-title {
        font-size: 11pt;
        color: var(--text);
    }
    
    /* Adjust severity badges for print */
    .sev {
        border: 1px solid currentColor;
        background: transparent;
        font-weight: bold;
    }
    
    .sev-critical { color: var(--rose); }
    .sev-high { color: var(--amber); }
    .sev-medium { color: #ca8a04; }
    .sev-low { color: #16a34a; }
    .sev-info { color: var(--violet); }
    
    /* Improve links for print */
    .digest-section a {
        color: var(--accent);
        text-decoration: underline;
    }
    
    .digest-section a:after {
        content: " (" attr(href) ")";
        font-size: 9pt;
        color: var(--muted);
        word-break: break-all;
    }
    
    /* Improve tables for print */
    .digest-section table {
        border: 1px solid var(--border);
        page-break-inside: avoid;
    }
    
    .digest-section th {
        background: var(--surface);
        color: var(--text);
    }
    
    /* Improve metrics for print */
    .metrics {
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        page-break-inside: avoid;
    }
    
    .metric {
        background: var(--surface);
        border: 1px solid var(--border);
        box-shadow: none;
    }
    
    .metric-num {
        color: var(--text);
    }
    
    /* Footer adjustments */
    .site-footer {
        background: var(--surface);
        border-top: 1px solid var(--border);
        page-break-inside: avoid;
    }
    """


def generate_pdf(
    html_content: str,
    output_path: Path | str,
    *,
    base_url: str | None = None
) -> bool:
    """Generate PDF from HTML content using WeasyPrint."""
    try:
        import weasyprint
    except ImportError:
        logger.error("WeasyPrint not installed. Install with: pip install weasyprint")
        return False
    
    output_path = Path(output_path)
    
    try:
        # Create PDF-optimized HTML
        pdf_styles = _build_pdf_styles()
        
        # Insert PDF styles before closing </style> tag
        pdf_html = html_content.replace(
            '</style>',
            f'{pdf_styles}\n</style>'
        )
        
        # Remove JavaScript for PDF (not needed and can cause issues)
        pdf_html = re.sub(r'<script[^>]*>.*?</script>', '', pdf_html, flags=re.DOTALL)
        
        # Generate PDF
        logger.info(f"Generating PDF: {output_path}")
        
        html_doc = weasyprint.HTML(
            string=pdf_html,
            base_url=base_url,
            encoding='utf-8'
        )
        
        css = weasyprint.CSS(string="""
            @page {
                size: A4;
                margin: 2cm 1.5cm;
            }
        """)
        
        html_doc.write_pdf(
            str(output_path),
            stylesheets=[css],
            optimize_images=True
        )
        
        logger.info(f"Successfully generated PDF: {output_path}")
        return True
        
    except Exception as exc:
        logger.error(f"Failed to generate PDF: {exc}")
        return False
