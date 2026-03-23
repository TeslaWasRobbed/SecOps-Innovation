"""LLM chat completions — provider-neutral surface; swap backends here as needed.

Today this module calls Anthropic's API. Other providers can be added behind the same
``complete()`` function (e.g. branch on ``LLM_PROVIDER`` in ``.env``).
"""

from __future__ import annotations

import logging
import os
import warnings
from pathlib import Path

import httpx
from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_PATH)

logger = logging.getLogger(__name__)

_client = None


def _env_truthy(name: str) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _build_httpx_client() -> httpx.Client:
    """
    Corporate TLS inspection often breaks Python's default trust store.
    Prefer pointing to your org's root CA bundle; disable verify only as a last resort.
    """
    if _env_truthy("LLM_SSL_VERIFY_DISABLE") or _env_truthy("ANTHROPIC_SSL_VERIFY_DISABLE"):
        warnings.warn(
            "LLM_SSL_VERIFY_DISABLE / ANTHROPIC_SSL_VERIFY_DISABLE: TLS verification is OFF for "
            "LLM API calls. Prefer LLM_CA_BUNDLE or ANTHROPIC_CA_BUNDLE with your corporate root CA.",
            UserWarning,
            stacklevel=2,
        )
        return httpx.Client(verify=False)

    for key in (
        "LLM_CA_BUNDLE",
        "ANTHROPIC_CA_BUNDLE",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ):
        path = os.environ.get(key)
        if path and Path(path).is_file():
            logger.info("Using TLS CA bundle from %s=%s", key, path)
            return httpx.Client(verify=path)

    return httpx.Client()


def _get_anthropic_client():
    global _client
    if _client is None:
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to your .env file (see .env.sample)."
            )
        _client = anthropic.Anthropic(api_key=api_key, http_client=_build_httpx_client())
    return _client


def complete(
    prompt: str,
    *,
    system: str = "You are a senior security operations analyst.",
    model: str | None = None,
    max_tokens: int = 4096,
) -> str:
    """
    Single-turn chat completion. Implementation is Anthropic until additional providers are wired in.
    """
    provider = (os.environ.get("LLM_PROVIDER") or "anthropic").strip().lower()
    if provider != "anthropic":
        raise RuntimeError(
            f"LLM_PROVIDER={provider!r} is not supported yet. "
            "Use anthropic or extend shared/llm.py."
        )

    resolved_model = model or os.environ.get("LLM_MODEL") or "claude-sonnet-4-20250514"
    response = _get_anthropic_client().messages.create(
        model=resolved_model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
