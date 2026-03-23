"""Thin wrapper around the Anthropic Claude API."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_PATH)

_client = None


def _get_client():
    global _client
    if _client is None:
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to your .env file (see .env.sample)."
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


def ask_claude(
    prompt: str,
    *,
    system: str = "You are a senior security operations analyst.",
    model: str = "claude-sonnet-4-20250514",
    max_tokens: int = 4096,
) -> str:
    """Send a single-turn message to Claude and return the text response."""
    response = _get_client().messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
