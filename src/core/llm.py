"""Provider-agnostic LLM layer with a multi-provider ENSEMBLE.

Design goals:
  * No provider lock-in. OpenAI, MiniMax and Qwen all speak the OpenAI Chat
    Completions wire format, so we just swap `base_url` + key + model.
  * Defense in depth. Sentinel can run *several* providers at once and fuse
    their verdicts (see trust_engine): to slip an attack past the firewall an
    adversary must fool every independent analyst simultaneously. Two models
    disagreeing is itself a signal.
  * Never raise. Missing key, dead provider, or an unsupported param all
    degrade gracefully — a single provider, then the deterministic heuristics.

Env:
  SENTINEL_LLM_PROVIDERS  csv ensemble, e.g. "qwen,minimax"  (preferred)
  SENTINEL_LLM_PROVIDER   single provider (back-compat)       (default: openai)
  SENTINEL_LLM_API_KEY    override key  (single-provider mode only)
  SENTINEL_LLM_BASE_URL   override base url (single-provider mode only)
  SENTINEL_LLM_MODEL      override model    (single-provider mode only)
  OPENAI_API_KEY / MINIMAX_API_KEY / QWEN_API_KEY   per-provider keys
  SENTINEL_MODEL_OPENAI / SENTINEL_MODEL_MINIMAX / SENTINEL_MODEL_QWEN
                          per-provider model overrides (ensemble mode)
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
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
    "qwen": {
        # Alibaba Cloud Qwen via DashScope / Model Studio OpenAI-compatible mode.
        # International endpoint (verified live; the cn endpoint rejects intl
        # Model Studio keys). Override SENTINEL_MODEL_QWEN for qwen-max/turbo.
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "key_env": "QWEN_API_KEY",
        "model": "qwen-plus",
    },
}

_AUTH_MARKERS = ("insufficient balance", "invalid api key", "incorrect api key",
                 "401", "402", "403", "authentication", "unauthorized")


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


class _Client:
    """One OpenAI-compatible provider, with its own circuit breaker.

    A *credentials* failure (bad key / no balance) disables the client for the
    process; transient errors (timeout, rate-limit, 5xx) just fall back for that
    one call so a burst of red-team traffic never permanently darkens it.
    """

    def __init__(self, provider: str, *, api_key: Optional[str],
                 base_url: Optional[str], model: str):
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self._api_key = api_key
        self._client = None
        self.disabled = False
        self._init()

    def _init(self):
        if not self._api_key:
            return
        try:
            from openai import OpenAI  # optional dependency

            kwargs = {"api_key": self._api_key, "timeout": 25.0, "max_retries": 2}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        except Exception:
            self._client = None

    @property
    def ready(self) -> bool:
        return self._client is not None and not self.disabled

    def info(self) -> dict:
        return {"provider": self.provider, "model": self.model, "ready": self.ready}

    def _maybe_disable(self, exc):
        if any(m in str(exc).lower() for m in _AUTH_MARKERS):
            self.disabled = True

    def complete_json(self, system: str, user: str, *, max_tokens: int = 400) -> Optional[dict]:
        if not self.ready:
            return None
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        # Attempt 1: strict JSON mode.
        try:
            resp = self._client.chat.completions.create(
                model=self.model, temperature=0, max_tokens=max_tokens,
                response_format={"type": "json_object"}, messages=messages,
            )
            return _extract_json(resp.choices[0].message.content or "")
        except Exception as e:
            self._maybe_disable(e)
            if self.disabled:
                return None
        # Attempt 2: plain completion (provider may reject response_format).
        try:
            resp = self._client.chat.completions.create(
                model=self.model, temperature=0, max_tokens=max_tokens, messages=messages,
            )
            return _extract_json(resp.choices[0].message.content or "")
        except Exception as e:
            self._maybe_disable(e)
            return None


_clients_cache: Optional[list] = None
_lock = threading.Lock()


def _configured_providers() -> list:
    multi = os.getenv("SENTINEL_LLM_PROVIDERS", "").strip()
    if multi:
        names = [p.strip().lower() for p in multi.split(",") if p.strip()]
    else:
        names = [os.getenv("SENTINEL_LLM_PROVIDER", "openai").strip().lower()]
    # de-dupe, preserve order, keep only known providers
    seen, out = set(), []
    for n in names:
        if n in _PRESETS and n not in seen:
            seen.add(n)
            out.append(n)
    return out or ["openai"]


def _build_clients() -> list:
    providers = _configured_providers()
    single = len(providers) == 1
    clients = []
    for name in providers:
        preset = _PRESETS[name]
        if single:
            # Back-compat single-provider overrides.
            api_key = os.getenv("SENTINEL_LLM_API_KEY") or os.getenv(preset["key_env"])
            base_url = os.getenv("SENTINEL_LLM_BASE_URL") or preset["base_url"]
            model = os.getenv("SENTINEL_LLM_MODEL") or preset["model"]
        else:
            api_key = os.getenv(preset["key_env"])
            base_url = preset["base_url"]
            model = os.getenv(f"SENTINEL_MODEL_{name.upper()}") or preset["model"]
        clients.append(_Client(name, api_key=api_key, base_url=base_url, model=model))
    return clients


def _clients() -> list:
    global _clients_cache
    if _clients_cache is None:
        with _lock:
            if _clients_cache is None:
                _clients_cache = _build_clients()
    return _clients_cache


def reset():
    """Forget cached clients (used by tests that mutate provider env)."""
    global _clients_cache
    with _lock:
        _clients_cache = None


def _ready() -> list:
    return [c for c in _clients() if c.ready]


def ensemble() -> bool:
    return len(_clients()) > 1


def llm_available() -> bool:
    return any(c.ready for c in _clients())


def llm_info() -> dict:
    """Back-compat summary. `provider`/`model`/`ready` describe the primary
    (first ready) provider; `engines`/`providers`/`ensemble` describe the set.
    """
    clients = _clients()
    ready = _ready()
    primary = ready[0] if ready else clients[0]
    return {
        "provider": "+".join(c.provider for c in clients),
        "model": primary.model,
        "ready": bool(ready),
        "ensemble": len(clients) > 1,
        "providers": [c.provider for c in clients],
        "engines": [c.info() for c in clients],
    }


def complete_json(system: str, user: str, *, max_tokens: int = 400) -> Optional[dict]:
    """Single-result convenience: the first ready provider. (Back-compat.)"""
    for c in _ready():
        out = c.complete_json(system, user, max_tokens=max_tokens)
        if out is not None:
            return out
    return None


def complete_json_all(system: str, user: str, *, max_tokens: int = 400) -> list:
    """Run every ready provider concurrently and return all verdicts.

    Returns a list of {"provider", "model", "result"} (result may be None for a
    provider that failed this call). Concurrency keeps the wall-clock cost of an
    N-model ensemble close to a single call.
    """
    ready = _ready()
    if not ready:
        return []
    if len(ready) == 1:
        c = ready[0]
        return [{"provider": c.provider, "model": c.model,
                 "result": c.complete_json(system, user, max_tokens=max_tokens)}]

    def _run(c):
        return {"provider": c.provider, "model": c.model,
                "result": c.complete_json(system, user, max_tokens=max_tokens)}

    with ThreadPoolExecutor(max_workers=min(4, len(ready))) as pool:
        return list(pool.map(_run, ready))
