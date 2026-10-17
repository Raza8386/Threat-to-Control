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
SOURCES = ("attack", "owasp", "kev")


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
        self.source_idx: dict[str, list[int]] = {}
        for i, c in enumerate(self.chunks):
            self.by_ref.setdefault(c["metadata"]["ref_id"].upper(), []).append(c["id"])
            self.source_idx.setdefault(c["metadata"]["source"], []).append(i)
        self.by_id_idx = {c["id"]: i for i, c in enumerate(self.chunks)}

        self.collection = None
        self.embedder = embedder
        if load_vectors and cfg.chroma_dir.exists():
            self._load_vectors()

    def _load_vectors(self) -> None:
        import chromadb

        manifest = json.loads(self.cfg.manifest_path.read_text()) if self.cfg.manifest_path.exists() else {}
        if not manifest.get("embedder"):
            # A chroma/ folder without a manifest is a build that never finished (e.g. interrupted).
            print("WARNING: vector index is incomplete (no manifest); using BM25 only. Run: python -m ingest.build_index")
            return
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

    def _top_bm25(self, scores, n: int, source: str | None = None) -> list[str]:
        idx = range(len(scores)) if source is None else self.source_idx.get(source, [])
        order = sorted(idx, key=lambda i: scores[i], reverse=True)[:n]
        return [self.chunks[i]["id"] for i in order if scores[i] > 0]

    def _vector_ranking(self, qvec: list[float] | None, n: int, source: str | None = None) -> list[tuple[str, float]]:
        """(chunk id, cosine similarity) pairs, best first."""
        if not self.has_vectors or qvec is None:
            return []
        where = {"source": source} if source else None
        res = self.collection.query(query_embeddings=[qvec], n_results=n, where=where, include=["distances"])
        return [(i, 1.0 - d) for i, d in zip(res["ids"][0], res["distances"][0])]

    def search(self, query: str, mode: Mode = "hybrid", top_k: int | None = None) -> list[Hit]:
        top_k = top_k or self.cfg.top_k
        n = self.cfg.candidates
        if mode == "vector" and not self.has_vectors:
            raise RuntimeError("Vector index not built. Run: python -m ingest.build_index")

        use_bm25 = mode in ("hybrid", "bm25")
        use_vec = mode in ("hybrid", "vector") and self.has_vectors
        scores = self.bm25.get_scores(tokenize(query)) if use_bm25 else None
        qvec = self.embedder.embed_query(query) if use_vec else None

        bm25_ids = self._top_bm25(scores, n) if use_bm25 else []
        vec_hits = self._vector_ranking(qvec, n) if use_vec else []
        vec_ids = [i for i, _ in vec_hits]
        fused = rrf([r for r in (bm25_ids, vec_ids) if r], k=self.cfg.rrf_k)

        # Exact-ID boost: pin chunks whose ref_id is named in the question above everything else.
        pinned: list[str] = []
        for ident in extract_ids(query):
            pinned.extend(self.by_ref.get(ident, []))
        boost = 1.0 + max(fused.values(), default=0.0)
        for i, doc_id in enumerate(pinned):
            fused[doc_id] = boost - i * 1e-6

        ranked = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        ranked = self._add_missing_sources(ranked, scores, vec_hits, qvec, set(pinned), top_k)

        bm25_rank = {d: r for r, d in enumerate(bm25_ids, 1)}
        vec_rank = {d: r for r, d in enumerate(vec_ids, 1)}
        hits = []
        for doc_id, score in ranked:
            c = self.by_id[doc_id]
            ranks = {"bm25": bm25_rank.get(doc_id), "vector": vec_rank.get(doc_id), "id_boost": doc_id in pinned}
            hits.append(Hit(doc_id, c["text"], c["metadata"], score, ranks))
        return hits

    def _add_missing_sources(self, ranked, scores, vec_hits, qvec, pinned: set[str], top_k: int):
        """Give an unrepresented source one slot when its best chunk is genuinely competitive.

        KEV has ~1,750 entries vs 10 OWASP categories, so a question like "what is SSRF?" can fill every
        slot with CVEs titled "Server-Side Request Forgery" and push out OWASP A10. A source's best chunk
        qualifies if its BM25 score reaches `source_bm25_ratio` (OWASP: `owasp_bm25_ratio`) of the overall best, or its vector
        similarity is within `source_vec_margin` of the best. Qualifiers replace the lowest unpinned slots.
        """
        present = {self.by_id[d]["metadata"]["source"] for d, _ in ranked}
        best_bm25 = max(scores) if scores is not None and len(scores) else 0.0
        best_sim = vec_hits[0][1] if vec_hits else None
        extras: list[str] = []
        for src in SOURCES:
            if src in present:
                continue
            candidate = None
            if scores is not None and best_bm25 > 0:
                top = self._top_bm25(scores, 1, src)
                ratio = self.cfg.owasp_bm25_ratio if src == "owasp" else self.cfg.source_bm25_ratio
                if top and scores[self.by_id_idx[top[0]]] >= ratio * best_bm25:
                    candidate = top[0]
            if candidate is None and best_sim is not None:
                top_v = self._vector_ranking(qvec, 1, src)
                if top_v and top_v[0][1] >= best_sim - self.cfg.source_vec_margin:
                    candidate = top_v[0][0]
            if candidate:
                extras.append(candidate)

        extras = extras[: self.cfg.max_extra_sources]
        if not extras:
            return ranked
        keep = list(ranked)
        for doc_id in extras:
            if len(keep) >= top_k:
                # drop the lowest-scored unpinned chunk
                for j in range(len(keep) - 1, -1, -1):
                    if keep[j][0] not in pinned:
                        keep.pop(j)
                        break
                else:
                    break
            keep.append((doc_id, keep[-1][1] - 1e-6 if keep else 0.0))
        return keep
