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

Before the full build, check the speed: `python -m ingest.build_index --speed-test 32` embeds 32 chunks and projects the total time. Sequence length is capped at 768 tokens (`EMBED_MAX_TOKENS`), because uncapped voyage-4-nano runs crawl on CPU.

If the projection is too long for your machine, pick one:

| Option | Set in `.env` / shell | Speed on a laptop CPU | Cost |
| --- | --- | --- | --- |
| voyage-4-nano (default) | `EMBED_BACKEND=nano` | depends on the speed test | free |
| Small local model | `EMBED_BACKEND=local` and `EMBED_MODEL=BAAI/bge-small-en-v1.5` | a few minutes | free |
| Hosted Voyage API | `EMBED_BACKEND=voyage` and `VOYAGE_API_KEY=...` | about 1 minute | small (~600k tokens) |

The query side must use the same model the index was built with; the retriever refuses a mismatch.
`python -m ingest.build_index --bm25-only` builds just the keyword index if you want to test without any model.

### Layout

| Path | What it does |
| --- | --- |
| `ingest/attack.py` `owasp.py` `kev.py` | Download and chunk each source, one natural unit per chunk |
| `ingest/build_index.py` | BM25 pickle + Chroma collection + `index_manifest.json` |
| `app/retrieve.py` | `Retriever.search(query, mode="hybrid"|"vector"|"bm25")`, RRF k=60, exact-ID boost |
| `app/embeddings.py` | voyage-4-nano (local), Voyage API, or a hash stand-in for tests |
| `app/text.py` | Tokenizer and ID extraction (T-numbers, CVEs, OWASP A01 to A10) |
| `scripts/phase1_check.py` | Phase 1 gate |
