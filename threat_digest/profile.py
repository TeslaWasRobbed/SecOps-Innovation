"""Load optional company / sector profile for tailored threat digests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent


def resolve_profile_path(explicit: str | None) -> Path | None:
    """Pick profile file: CLI flag, then COMPANY_PROFILE env, then repo-root company_profile.yaml."""
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file():
            return p
        # Allow `company_profile.yaml` to resolve from repo root when cwd is elsewhere
        alt = _REPO_ROOT / explicit
        if alt.is_file():
            return alt
        return None
    env = (os.environ.get("COMPANY_PROFILE") or "").strip()
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return p
        alt = _REPO_ROOT / env
        if alt.is_file():
            return alt
    for candidate in (_REPO_ROOT / "company_profile.yaml", Path("company_profile.yaml")):
        if candidate.is_file():
            return candidate.resolve()
    return None


def load_company_profile(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    with path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return {}
    return raw


def profile_to_prompt_block(profile: dict[str, Any]) -> str:
    """Human-readable block injected into LLM prompts."""
    if not profile:
        return (
            "No organisation profile was supplied. Write a broadly applicable digest for a mid-sized "
            "enterprise with typical Microsoft / cloud tooling; still keep actions concrete."
        )
    parts: list[str] = []
    if v := profile.get("company_name"):
        parts.append(f"Organisation: {v}")
    if v := profile.get("sector"):
        parts.append(f"Sector / industry: {v}")
    regions = profile.get("primary_regions")
    if isinstance(regions, list) and regions:
        parts.append("Regions: " + ", ".join(str(x) for x in regions))
    tools = profile.get("tools_and_platforms")
    if isinstance(tools, list) and tools:
        parts.append("Security / IT tooling in use:\n  - " + "\n  - ".join(str(t) for t in tools))
    if v := profile.get("cloud_environment"):
        parts.append(f"Cloud / estate: {v}")
    pri = profile.get("priority_threats")
    if isinstance(pri, list) and pri:
        parts.append("Leadership priority themes:\n  - " + "\n  - ".join(str(p) for p in pri))
    if v := profile.get("audience"):
        parts.append(f"Primary audience: {v}")
    if v := profile.get("additional_context"):
        v = str(v).strip()
        if v:
            parts.append(f"Additional context:\n{v}")
    return "\n\n".join(parts)
