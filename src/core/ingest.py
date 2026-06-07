"""Document ingestion — Unsiloed parse → chunks → Moss (sensitivity-tagged).

Turns real PDFs/DOCX into the trust-gated knowledge base: Unsiloed parses the
document into markdown, we chunk it, tag every chunk with a sensitivity level,
and push it into the Moss index Sentinel guards.

Unsiloed v3:  POST https://prod.visionapi.unsiloed.ai/v3/parse  (X-API-Key)
              GET  .../v3/parse/{job_id}  ->  {status, pages:[{page, markdown}]}
"""

from __future__ import annotations

import os
import re
import time

import requests

UNSILOED_BASE = "https://prod.visionapi.unsiloed.ai/v3/parse"

PERMISSION_FOR = {
    "PUBLIC": "perm:public",
    "INTERNAL": "perm:internal",
    "CONFIDENTIAL": "perm:confidential",
    "RESTRICTED": "perm:financial",
    "FINANCIAL": "perm:financial",
}


def _headers():
    key = os.getenv("UNSILOED_API_KEY")
    if not key:
        raise RuntimeError("Set UNSILOED_API_KEY in .env for PDF parsing")
    return {"X-API-Key": key}


def parse_document(path_or_url: str, pages: str | None = None, timeout_s: int = 180) -> list[str]:
    """Parse a local file or remote URL via Unsiloed; return per-page markdown."""
    if path_or_url.startswith(("http://", "https://", "s3://")):
        resp = requests.post(UNSILOED_BASE, headers=_headers(),
                             json={"url": path_or_url}, timeout=60)
    else:
        with open(path_or_url, "rb") as fh:
            params = {"pages": pages} if pages else {}
            resp = requests.post(UNSILOED_BASE, headers=_headers(),
                                 files={"file": fh}, params=params, timeout=120)
    resp.raise_for_status()
    job_id = resp.json()["job_id"]

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(2)
        s = requests.get(f"{UNSILOED_BASE}/{job_id}", headers=_headers(), timeout=30).json()
        status = s.get("status")
        if status == "done":
            return [p.get("markdown", "") for p in s.get("pages", []) if p.get("markdown")]
        if status in ("failed", "error"):
            raise RuntimeError(f"Unsiloed parse failed: {s}")
    raise TimeoutError("Unsiloed parse timed out")


def chunk_markdown(pages: list[str], max_chars: int = 900) -> list[str]:
    """Split markdown into reasonably sized chunks on paragraph boundaries."""
    text = "\n\n".join(pages)
    blocks = re.split(r"\n\s*\n", text)
    chunks, cur = [], ""
    for b in blocks:
        b = b.strip()
        if not b:
            continue
        if len(cur) + len(b) + 2 <= max_chars:
            cur = (cur + "\n\n" + b).strip()
        else:
            if cur:
                chunks.append(cur)
            cur = b[:max_chars]
    if cur:
        chunks.append(cur)
    return chunks


async def ingest_to_moss(path_or_url: str, *, sensitivity: str = "CONFIDENTIAL",
                         title: str = "Ingested Document", doc_prefix: str = "ing",
                         index_name: str | None = None) -> int:
    """Parse a document and upsert its chunks into the Moss index."""
    from moss import DocumentInfo, MossClient, MutationOptions

    index = index_name or os.getenv("MOSS_INDEX_NAME", "sentinel_knowledge")
    sensitivity = sensitivity.upper()
    perm = PERMISSION_FOR.get(sensitivity, "perm:confidential")

    pages = parse_document(path_or_url)
    chunks = chunk_markdown(pages)
    docs = [
        DocumentInfo(
            id=f"{doc_prefix}-{i}",
            text=f"{title}. {c}",
            metadata={"sensitivity": sensitivity, "title": title,
                      "category": "ingested", "required_permission": perm},
        )
        for i, c in enumerate(chunks)
    ]
    client = MossClient(os.getenv("MOSS_PROJECT_ID"), os.getenv("MOSS_PROJECT_KEY"))
    await client.add_docs(index, docs, MutationOptions(upsert=True))
    await client.load_index(index)
    return len(docs)
