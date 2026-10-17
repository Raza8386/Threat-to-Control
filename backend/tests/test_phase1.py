"""Phase 1 unit tests. The hybrid path runs on a tiny fixture index with HashEmbedder, so no model download."""

from __future__ import annotations

import dataclasses

import pytest

from app.config import Settings
from app.embeddings import HashEmbedder
from app.retrieve import Retriever, rrf
from app.text import extract_ids, tokenize
from ingest.common import count_tokens, split_text

FIXTURE = [
    ("attack:T1059.001", "attack", "T1059.001", "T1059.001 PowerShell. Adversaries abuse PowerShell commands and scripts for execution."),
    ("attack:T1053.005", "attack", "T1053.005", "T1053.005 Scheduled Task. Adversaries abuse the Windows Task Scheduler for persistence."),
    ("owasp:A03:2021", "owasp", "A03:2021", "A03:2021 Injection. Use parameterized queries to prevent SQL injection."),
    ("kev:CVE-2015-5477", "kev", "CVE-2015-5477", "CVE-2015-5477 ISC BIND denial of service via TKEY queries. Apply vendor mitigations."),
    ("kev:CVE-2023-34362", "kev", "CVE-2023-34362", "CVE-2023-34362 MOVEit Transfer SQL injection vulnerability."),
]


@pytest.fixture()
def retriever(tmp_path, monkeypatch):
    import json

    from ingest import build_index

    cfg = dataclasses.replace(Settings(), data_dir=tmp_path, embed_backend="hash", embed_dim=128)
    chunks = [
        {"id": i, "text": t, "metadata": {"source": s, "ref_id": r, "title": t.split(".")[0], "url": "", "part": 1, "parts": 1}}
        for i, s, r, t in FIXTURE
    ]
    monkeypatch.setattr(build_index, "settings", cfg)
    build_index.build_bm25(chunks)
    emb = HashEmbedder(128)
    build_index.build_vectors(chunks, emb)
    cfg.manifest_path.write_text(json.dumps({"embedder": emb.name, "dim": emb.dim}))
    return Retriever(cfg, embedder=emb)


def test_rrf_rewards_agreement():
    scores = rrf([["a", "b", "c"], ["b", "a", "d"]], k=60)
    assert scores["a"] == scores["b"] > scores["c"] == scores["d"]


def test_extract_ids():
    q = "Map T1059.001 and t1053 to CVE-2015-5477 and a03"
    assert extract_ids(q) == ["T1059.001", "T1053", "CVE-2015-5477", "A03:2021"]
    assert extract_ids("how do I stop phishing?") == []


def test_tokenize_keeps_ids_whole_and_split():
    toks = tokenize("Detect T1059.001 and CVE-2015-5477")
    # Whole IDs plus their parts, so a sub-technique also matches its parent "t1059".
    assert "t1059.001" in toks and "t1059" in toks and "cve-2015-5477" in toks and "5477" in toks
    assert "and" not in toks


def test_split_text_small_unit_is_one_piece():
    assert split_text("Title", "short body") == ["Title\n\nshort body"]


def test_split_text_long_unit_repeats_title_and_respects_budget():
    body = "\n\n".join(" ".join(f"w{p}_{i}" for i in range(120)) for p in range(8))
    pieces = split_text("My Title", body)
    assert len(pieces) > 1
    assert all(p.startswith("My Title\n\n") for p in pieces)
    assert all(count_tokens(p) <= 520 for p in pieces)


@pytest.mark.parametrize("mode", ["hybrid", "bm25", "vector"])
def test_exact_id_is_pinned_to_rank_one(retriever, mode):
    hits = retriever.search("What does CISA require for CVE-2015-5477?", mode=mode, top_k=3)
    assert hits[0].id == "kev:CVE-2015-5477"
    assert hits[0].ranks["id_boost"] is True


def test_hybrid_uses_both_rankings(retriever):
    hits = retriever.search("prevent SQL injection", mode="hybrid", top_k=3)
    ids = [h.id for h in hits]
    assert "owasp:A03:2021" in ids
    top = hits[0]
    assert top.ranks["bm25"] is not None and top.ranks["vector"] is not None


def test_embedder_mismatch_is_refused(tmp_path, retriever):
    with pytest.raises(RuntimeError, match="Rebuild the index"):
        Retriever(retriever.cfg, embedder=HashEmbedder(64))
