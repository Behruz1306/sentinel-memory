#!/usr/bin/env python3
"""Build the Sentinel knowledge index in Moss from the graph-KB corpus.

Each document is pushed with its sensitivity as metadata so retrieval results
arrive pre-tagged for the trust gate. Run once before the live demo:

    .venv/bin/python build_moss_index.py
"""

from __future__ import annotations

import asyncio
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from moss import DocumentInfo, MossClient, MutationOptions

from src.core.graph_kb import SEED_DOCS

INDEX = os.getenv("MOSS_INDEX_NAME", "sentinel_knowledge")
MODEL = os.getenv("MOSS_MODEL_ID", "moss-minilm")


def _docs():
    return [
        DocumentInfo(
            id=d.id,
            text=f"{d.title}. {d.content}",
            metadata={
                "sensitivity": d.sensitivity,
                "title": d.title,
                "category": d.category,
                "required_permission": d.required_permission,
            },
        )
        for d in SEED_DOCS
    ]


async def main():
    pid, pkey = os.getenv("MOSS_PROJECT_ID"), os.getenv("MOSS_PROJECT_KEY")
    if not pid or not pkey:
        raise SystemExit("Set MOSS_PROJECT_ID / MOSS_PROJECT_KEY in .env")
    client = MossClient(pid, pkey)
    docs = _docs()
    try:
        r = await client.create_index(INDEX, docs, MODEL)
        print(f"Created Moss index '{r.index_name}' with {r.doc_count} docs (job {r.job_id}).")
    except Exception as e:
        print(f"create_index failed ({repr(e)[:100]}); upserting instead...")
        await client.add_docs(INDEX, docs, MutationOptions(upsert=True))
        print(f"Upserted {len(docs)} docs into '{INDEX}'.")
    await client.load_index(INDEX)
    print(f"Index '{INDEX}' loaded and ready.")


if __name__ == "__main__":
    asyncio.run(main())
