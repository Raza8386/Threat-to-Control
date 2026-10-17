"""Hybrid retrieval: vector (Chroma) + keyword (BM25), fused with Reciprocal Rank Fusion.

Exact IDs in the question (T1059.001, CVE-2015-5477, A03) pin the matching chunk(s) to the top,
because embeddings blur IDs that BM25 and a direct lookup get exactly right.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from typing import Literal

from app.config import Settings, settings as default_settings
from app.text import extract_ids, tokenize

Mode = Literal["hybrid", "vector", "bm25"]


@dataclass
class Hit:
    id: str
    text: str
    metadata: dict
    score: float
    ranks: dict = field(default_factory=dict)  # e.g. {"bm25": 1, "vector": 3, "id_boost": True}


def rrf(rankings: list[list[str]], k: int = 60) -> dict[str, float]:
    """Reciprocal Rank Fusion: score = sum over rankings of 1 / (k + rank)."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


class Retriever:
    def __init__(self, cfg: Settings = default_settings, embedder=None, load_vectors: bool = True):
        self.cfg = cfg
        with cfg.bm25_path.open("rb") as fh:
            data = pickle.load(fh)
        self.bm25 = data["bm25"]
        self.chunks: list[dict] = data["chunks"]
        self.by_id = {c["id"]: c for c in self.chunks}
        self.by_ref: dict[str, list[str]] = {}
        for c in self.chunks:
            self.by_ref.setdefault(c["metadata"]["ref_id"].upper(), []).append(c["id"])

        self.collection = None
        self.embedder = embedder
        if load_vectors and cfg.chroma_dir.exists():
            self._load_vectors()

    def _load_vectors(self) -> None:
        import chromadb

        manifest = json.loads(self.cfg.manifest_path.read_text()) if self.cfg.manifest_path.exists() else {}
        if self.embedder is None:
            from app.embeddings import get_embedder

            self.embedder = get_embedder(self.cfg)
        if manifest.get("embedder") and manifest["embedder"] != self.embedder.name:
            raise RuntimeError(
                f"Index was built with {manifest['embedder']} but the query embedder is {self.embedder.name}. "
                "Rebuild the index or fix EMBED_* settings."
            )
        client = chromadb.PersistentClient(path=str(self.cfg.chroma_dir))
        self.collection = client.get_collection("chunks")

    @property
    def has_vectors(self) -> bool:
        return self.collection is not None

    def _bm25_ranking(self, query: str, n: int) -> list[str]:
        scores = self.bm25.get_scores(tokenize(query))
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n]
        return [self.chunks[i]["id"] for i in order if scores[i] > 0]

    def _vector_ranking(self, query: str, n: int) -> list[str]:
        if not self.has_vectors:
            return []
        res = self.collection.query(query_embeddings=[self.embedder.embed_query(query)], n_results=n)
        return res["ids"][0]

    def search(self, query: str, mode: Mode = "hybrid", top_k: int | None = None) -> list[Hit]:
        top_k = top_k or self.cfg.top_k
        n = self.cfg.candidates
        if mode == "vector" and not self.has_vectors:
            raise RuntimeError("Vector index not built. Run: python -m ingest.build_index")

        bm25_ids = self._bm25_ranking(query, n) if mode in ("hybrid", "bm25") else []
        vec_ids = self._vector_ranking(query, n) if mode in ("hybrid", "vector") else []

        if mode == "bm25":
            fused = {doc_id: 1.0 / (self.cfg.rrf_k + r) for r, doc_id in enumerate(bm25_ids, 1)}
        elif mode == "vector":
            fused = {doc_id: 1.0 / (self.cfg.rrf_k + r) for r, doc_id in enumerate(vec_ids, 1)}
        else:
            fused = rrf([r for r in (bm25_ids, vec_ids) if r], k=self.cfg.rrf_k)

        # Exact-ID boost: pin chunks whose ref_id is named in the question above everything else.
        pinned: list[str] = []
        for ident in extract_ids(query):
            pinned.extend(self.by_ref.get(ident, []))
        boost = 1.0 + max(fused.values(), default=0.0)
        for i, doc_id in enumerate(pinned):
            fused[doc_id] = boost - i * 1e-6

        ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        bm25_rank = {d: r for r, d in enumerate(bm25_ids, 1)}
        vec_rank = {d: r for r, d in enumerate(vec_ids, 1)}
        hits = []
        for doc_id, score in ranked:
            c = self.by_id[doc_id]
            ranks = {"bm25": bm25_rank.get(doc_id), "vector": vec_rank.get(doc_id), "id_boost": doc_id in pinned}
            hits.append(Hit(doc_id, c["text"], c["metadata"], score, ranks))
        return hits
