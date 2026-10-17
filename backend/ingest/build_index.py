"""Build the BM25 index and the ChromaDB vector index from data/chunks/*.jsonl.

Run from backend/:
    python -m ingest.build_index              # BM25 + vectors (downloads voyage-4-nano on first run)
    python -m ingest.build_index --bm25-only  # keyword index only, no model download
"""

from __future__ import annotations

import argparse
import json
import pickle
import shutil
import time
from datetime import datetime, timezone

from rank_bm25 import BM25Okapi

from app.config import settings
from app.text import tokenize
from ingest.common import read_jsonl

SOURCES = ["attack", "owasp", "kev"]
COLLECTION = "chunks"


def load_chunks() -> list[dict]:
    chunks = []
    for src in SOURCES:
        path = settings.chunks_dir / f"{src}.jsonl"
        if not path.exists():
            raise SystemExit(f"Missing {path}. Run: python -m ingest.{src}")
        chunks.extend(read_jsonl(path))
    ids = [c["id"] for c in chunks]
    if len(ids) != len(set(ids)):
        raise SystemExit("Duplicate chunk ids found; fix the ingest scripts before indexing.")
    return chunks


def build_bm25(chunks: list[dict]) -> None:
    corpus = [tokenize(c["text"]) for c in chunks]
    bm25 = BM25Okapi(corpus)
    with settings.bm25_path.open("wb") as fh:
        pickle.dump({"bm25": bm25, "chunks": chunks}, fh)
    print(f"BM25: {len(chunks)} chunks -> {settings.bm25_path.name}")


def build_vectors(chunks: list[dict], embedder) -> None:
    import chromadb

    if settings.chroma_dir.exists():
        shutil.rmtree(settings.chroma_dir)
    client = chromadb.PersistentClient(path=str(settings.chroma_dir))
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    t0 = time.time()
    batch = 64
    for i in range(0, len(chunks), batch):
        part = chunks[i : i + batch]
        col.add(
            ids=[c["id"] for c in part],
            documents=[c["text"] for c in part],
            metadatas=[c["metadata"] for c in part],
            embeddings=embedder.embed_documents([c["text"] for c in part]),
        )
        print(f"  embedded {min(i + batch, len(chunks))}/{len(chunks)}", end="\r")
    print(f"\nChroma: {col.count()} vectors ({embedder.name}) in {time.time() - t0:.0f}s -> {settings.chroma_dir.name}/")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bm25-only", action="store_true", help="skip embeddings")
    args = ap.parse_args()

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    chunks = load_chunks()
    build_bm25(chunks)

    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "chunks": len(chunks),
        "by_source": {s: sum(c["metadata"]["source"] == s for c in chunks) for s in SOURCES},
        "embedder": None,
        "dim": None,
    }
    if not args.bm25_only:
        from app.embeddings import get_embedder

        embedder = get_embedder()
        build_vectors(chunks, embedder)
        manifest.update(embedder=embedder.name, dim=embedder.dim)

    settings.manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"Manifest -> {settings.manifest_path.name}: {manifest['by_source']}")


if __name__ == "__main__":
    main()
