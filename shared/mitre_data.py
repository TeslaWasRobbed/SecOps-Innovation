"""Load and query the MITRE ATT&CK Enterprise matrix via mitreattack-python."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests
from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache"
_STIX_PATH = _CACHE_DIR / "enterprise-attack.json"

_attack: MitreAttackData | None = None


def _ensure_stix_bundle() -> Path:
    """Download the Enterprise ATT&CK STIX bundle if not already cached."""
    if _STIX_PATH.exists():
        return _STIX_PATH
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading ATT&CK Enterprise STIX bundle (~25 MB, one-time)...")
    resp = requests.get(_STIX_URL, timeout=120)
    resp.raise_for_status()
    _STIX_PATH.write_bytes(resp.content)
    logger.info("Saved to %s", _STIX_PATH)
    return _STIX_PATH


def _get_attack() -> MitreAttackData:
    """Lazy-load the ATT&CK Enterprise STIX bundle."""
    global _attack
    if _attack is None:
        path = _ensure_stix_bundle()
        _attack = MitreAttackData(str(path))
    return _attack


# ── Techniques ───────────────────────────────────────────────────────────

def get_all_techniques() -> list[dict[str, Any]]:
    """Return all Enterprise techniques as lightweight dicts."""
    attack = _get_attack()
    techs = attack.get_techniques(remove_revoked_deprecated=True)
    results = []
    for t in techs:
        ext = t.get("external_references", [])
        tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
        if tid is None:
            continue
        tactics = [
            phase["phase_name"]
            for phase in (t.get("kill_chain_phases") or [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        results.append({
            "id": tid,
            "name": t["name"],
            "description": t.get("description", ""),
            "tactics": tactics,
            "data_sources": t.get("x_mitre_data_sources") or [],
        })
    return results


@lru_cache(maxsize=1)
def _technique_index() -> dict[str, dict[str, Any]]:
    return {t["id"]: t for t in get_all_techniques()}


def get_technique_by_id(tid: str) -> dict[str, Any] | None:
    return _technique_index().get(tid)


# ── Groups / Actors ──────────────────────────────────────────────────────

def get_all_groups() -> list[dict[str, Any]]:
    """Return all ATT&CK groups as lightweight dicts."""
    attack = _get_attack()
    groups = attack.get_groups(remove_revoked_deprecated=True)
    results = []
    for g in groups:
        ext = g.get("external_references", [])
        gid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
        aliases = list(g.get("aliases") or [])
        results.append({
            "stix_id": g["id"],
            "id": gid or "",
            "name": g["name"],
            "aliases": aliases,
            "description": g.get("description", ""),
        })
    results.sort(key=lambda g: g["name"])
    return results


def get_group_by_name(name: str) -> dict[str, Any] | None:
    """Case-insensitive lookup by name or alias."""
    query = name.lower()
    for g in get_all_groups():
        if query in (a.lower() for a in g["aliases"]) or g["name"].lower() == query:
            return g
    return None


def get_techniques_used_by_group(stix_id: str) -> list[dict[str, Any]]:
    """Return techniques used by a group (via its STIX ID)."""
    attack = _get_attack()
    relationships = attack.get_techniques_used_by_group(stix_id)
    results = []
    for rel in relationships:
        obj = rel.get("object") if isinstance(rel, dict) else rel
        if obj is None:
            continue
        ext = obj.get("external_references", [])
        tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
        if tid:
            results.append({"id": tid, "name": obj["name"]})
    results.sort(key=lambda t: t["id"])
    return results


def get_software_used_by_group(stix_id: str) -> list[dict[str, Any]]:
    """Return software used by a group."""
    attack = _get_attack()
    rels = attack.get_software_used_by_group(stix_id)
    results = []
    for rel in rels:
        obj = rel.get("object") if isinstance(rel, dict) else rel
        if obj is None:
            continue
        ext = obj.get("external_references", [])
        sid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
        if sid:
            results.append({"id": sid, "name": obj["name"]})
    results.sort(key=lambda s: s["id"])
    return results
