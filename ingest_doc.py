#!/usr/bin/env python3
"""Ingest a real document into Sentinel's Moss knowledge base via Unsiloed.

    .venv/bin/python ingest_doc.py <file-or-url> --sensitivity CONFIDENTIAL --title "Q3 Contract"

The chunks land in the Moss index tagged with the given sensitivity, so the
trust engine gates them immediately. Sensitivities: PUBLIC, INTERNAL,
CONFIDENTIAL, RESTRICTED, FINANCIAL.
"""

from __future__ import annotations

import argparse
import asyncio

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from src.core.ingest import ingest_to_moss


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="local file path or http(s)/s3 URL")
    ap.add_argument("--sensitivity", default="CONFIDENTIAL")
    ap.add_argument("--title", default="Ingested Document")
    ap.add_argument("--prefix", default="ing", help="doc id prefix")
    args = ap.parse_args()

    print(f"Parsing '{args.source}' via Unsiloed and ingesting into Moss...")
    n = asyncio.run(ingest_to_moss(
        args.source, sensitivity=args.sensitivity, title=args.title, doc_prefix=args.prefix
    ))
    print(f"✅ Ingested {n} chunk(s) as {args.sensitivity} into the Moss index.")


if __name__ == "__main__":
    main()
