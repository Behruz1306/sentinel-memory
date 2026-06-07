"""Moss-backed retrieval — real-time semantic search (the Moss paradigm).

Queries a Moss index for relevance, then resolves each hit back to the graph
KB by document id so the authoritative sensitivity, PII map, and relationship
path are preserved. This is the seam Sentinel guards: Moss decides *what is
relevant*; the trust engine decides *what may be served*.

Degrades to None if the Moss SDK or credentials are absent, so SentinelRetriever
transparently falls back to the local lexical index.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

from .graph_kb import Document, KnowledgeGraph


class MossRetriever:
    def __init__(self, kb: KnowledgeGraph, index_name: Optional[str] = None):
        self.kb = kb
        self.index_name = index_name or os.getenv("MOSS_INDEX_NAME", "sentinel_knowledge")
        self._client = None
        self._loaded = False
        self._ok = False
        self._init_client()

    def _init_client(self):
        pid, pkey = os.getenv("MOSS_PROJECT_ID"), os.getenv("MOSS_PROJECT_KEY")
        if not pid or not pkey:
            return
        try:
            from moss import MossClient
            self._client = MossClient(pid, pkey)
            self._ok = True
        except Exception:
            self._client = None
            self._ok = False

    @property
    def available(self) -> bool:
        return self._ok

    async def _aquery(self, query: str, k: int):
        from moss import QueryOptions
        if not self._loaded:
            try:
                await self._client.load_index(self.index_name)
            except Exception:
                pass
            self._loaded = True
        return await self._client.query(self.index_name, query, QueryOptions(top_k=k))

    def _resolve(self, doc_id: str, text: str, metadata: dict) -> Document:
        """Prefer the authoritative graph-KB doc; synthesize one if unknown."""
        doc = self.kb.docs.get(doc_id)
        if doc is not None:
            return doc
        md = metadata or {}
        return Document(
            id=doc_id,
            title=md.get("title", doc_id),
            category=md.get("category", "misc"),
            sensitivity=md.get("sensitivity", "INTERNAL"),
            content=text or "",
            required_permission=md.get("required_permission", "perm:internal"),
        )

    def retrieve(self, query: str, k: int = 4):
        """Synchronous facade. Returns [(Document, score)] or None on failure."""
        if not self._ok:
            return None
        try:
            res = asyncio.run(self._aquery(query, k))
        except RuntimeError:
            # already inside an event loop — let the caller use the async path
            return None
        except Exception:
            return None
        out = []
        for d in getattr(res, "docs", None) or []:
            try:
                score = round(float(getattr(d, "score", 0.0)), 3)
            except (TypeError, ValueError):
                score = 0.0
            out.append((self._resolve(d.id, getattr(d, "text", ""), getattr(d, "metadata", {})), score))
        return out
