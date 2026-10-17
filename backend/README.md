# Backend

## Phase 1: build the knowledge base

From this folder, with Python 3.11+:

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m ingest.attack        # MITRE ATT&CK Enterprise -> data/chunks/attack.jsonl
python -m ingest.owasp         # OWASP Top 10 2021      -> data/chunks/owasp.jsonl
python -m ingest.kev           # CISA KEV               -> data/chunks/kev.jsonl

python -m ingest.build_index   # BM25 + ChromaDB vectors (downloads voyage-4-nano, ~0.3B params, first run only)
python -m scripts.phase1_check # gate: counts match sources, exact IDs at rank 1
python -m pytest -q            # unit tests
```

Add `--force` to an ingest script to re-download its source (do this for KEV when CISA updates the catalog).

Embedding ~2,500 chunks with voyage-4-nano takes roughly 10 to 30 minutes on a laptop CPU and a few minutes on a GPU. `python -m ingest.build_index --bm25-only` builds just the keyword index if you want to test without the model.

### Layout

| Path | What it does |
| --- | --- |
| `ingest/attack.py` `owasp.py` `kev.py` | Download and chunk each source, one natural unit per chunk |
| `ingest/build_index.py` | BM25 pickle + Chroma collection + `index_manifest.json` |
| `app/retrieve.py` | `Retriever.search(query, mode="hybrid"|"vector"|"bm25")`, RRF k=60, exact-ID boost |
| `app/embeddings.py` | voyage-4-nano (local), Voyage API, or a hash stand-in for tests |
| `app/text.py` | Tokenizer and ID extraction (T-numbers, CVEs, OWASP A01 to A10) |
| `scripts/phase1_check.py` | Phase 1 gate |
