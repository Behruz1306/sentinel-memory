"""Provider-agnostic LLM wrapper (OpenAI / MiniMax / any OpenAI-compatible).

Design goals:
  * One call site, configured entirely by env — no provider lock-in.
  * MiniMax (and AWS Bedrock proxies, TrueFoundry gateway, etc.) all speak the
    OpenAI Chat Completions wire format, so we just override `base_url`.
  * Never raise. If no key, the call fails, or a param is unsupported, we
    degrade so the trust engine falls back to its deterministic heuristics.

Env:
  SENTINEL_LLM_PROVIDER   openai | minimax            (default: openai)
  SENTINEL_LLM_API_KEY    overrides provider key if set
  SENTINEL_LLM_BASE_URL   overrides provider base url if set
  SENTINEL_LLM_MODEL      model id                    (default per provider)
  OPENAI_API_KEY / MINIMAX_API_KEY  provider keys
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

# Provider presets. base_url=None means "use the SDK default" (OpenAI).
_PRESETS = {
    "openai": {
        "base_url": None,
        "key_env": "OPENAI_API_KEY",
        "model": "gpt-4o",
    },
    "minimax": {
        # MiniMax exposes an OpenAI-compatible endpoint (verified against
        # platform.minimax.io/docs/api-reference/text-openai-api).
        "base_url": "https://api.minimax.io/v1",
        "key_env": "MINIMAX_API_KEY",
        "model": "MiniMax-M3",
    },
}

_client = None
_resolved = False
_info: dict = {"provider": None, "model": None, "ready": False}

# Circuit breaker: only a *credentials* failure (bad key / no balance) disables
# the client. Transient errors (timeout, rate-limit, 5xx) just fall back for
# that one call and retry next time — so a burst of red-team calls never
# permanently darkens the LLM.
_disabled = False
_AUTH_MARKERS = ("insufficient balance", "invalid api key", "incorrect api key",
                 "401", "402", "403", "authentication", "unauthorized")


def _resolve():
    global _client, _resolved, _info
    if _resolved:
        return
    _resolved = True

    provider = os.getenv("SENTINEL_LLM_PROVIDER", "openai").strip().lower()
    preset = _PRESETS.get(provider, _PRESETS["openai"])

    api_key = os.getenv("SENTINEL_LLM_API_KEY") or os.getenv(preset["key_env"])
    base_url = os.getenv("SENTINEL_LLM_BASE_URL") or preset["base_url"]
    model = os.getenv("SENTINEL_LLM_MODEL") or preset["model"]
    _info.update(provider=provider, model=model, ready=False)

    if not api_key:
        return
    try:
        from openai import OpenAI  # optional dependency

        kwargs = {"api_key": api_key, "timeout": 25.0, "max_retries": 2}
        if base_url:
            kwargs["base_url"] = base_url
        _client = OpenAI(**kwargs)
        _info["ready"] = True
    except Exception:
        _client = None


def llm_available() -> bool:
    _resolve()
    return _client is not None


def llm_info() -> dict:
    _resolve()
    return dict(_info)


def _extract_json(text: str) -> Optional[dict]:
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def complete_json(system: str, user: str, *, max_tokens: int = 400) -> Optional[dict]:
    """Ask for a JSON object. Returns None if unavailable/failed.

    Tries response_format=json_object first; if the provider rejects that
    parameter, retries without it and extracts JSON from the text. This keeps
    us safe against provider-specific unsupported params.
    """
    global _disabled
    _resolve()
    if _client is None or _disabled:
        return None
    model = _info["model"]
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    def _maybe_disable(exc):
        # Only a credentials/balance error kills the client; transient errors
        # (timeout, rate-limit, 5xx) just fall back for this one call.
        global _disabled
        if any(m in str(exc).lower() for m in _AUTH_MARKERS):
            _disabled = True
            _info["ready"] = False

    # Attempt 1: strict JSON mode.
    try:
        resp = _client.chat.completions.create(
            model=model, temperature=0, max_tokens=max_tokens,
            response_format={"type": "json_object"}, messages=messages,
        )
        return _extract_json(resp.choices[0].message.content or "")
    except Exception as e:
        _maybe_disable(e)
        if _disabled:
            return None
    # Attempt 2: plain completion (provider may reject response_format).
    try:
        resp = _client.chat.completions.create(
            model=model, temperature=0, max_tokens=max_tokens, messages=messages,
        )
        return _extract_json(resp.choices[0].message.content or "")
    except Exception as e:
        _maybe_disable(e)
        return None
