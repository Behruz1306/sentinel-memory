"""Thin LLM wrapper with a deterministic fallback.

The whole point of Sentinel's demo is reliability on stage. If there's no
OPENAI_API_KEY (or the call fails), every LLM-backed function degrades to a
keyword heuristic instead of raising. The firewall still makes a sane
decision — it just explains itself a little less eloquently.
"""

from __future__ import annotations

import json
import os
from typing import Optional

_client = None
_checked = False


def _get_client():
    global _client, _checked
    if _checked:
        return _client
    _checked = True
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    try:
        from openai import OpenAI

        _client = OpenAI(api_key=key)
    except Exception:
        _client = None
    return _client


def llm_available() -> bool:
    return _get_client() is not None


def complete_json(system: str, user: str, *, max_tokens: int = 400) -> Optional[dict]:
    """Ask the LLM for a JSON object. Returns None if unavailable/failed."""
    client = _get_client()
    if client is None:
        return None
    model = os.getenv("SENTINEL_LLM_MODEL", "gpt-4o")
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return None
